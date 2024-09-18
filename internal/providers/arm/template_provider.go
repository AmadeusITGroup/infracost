package arm

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/infracost/infracost/internal/config"
	"github.com/infracost/infracost/internal/logging"
	"github.com/infracost/infracost/internal/schema"
	"github.com/tidwall/gjson"
)

type TemplateProvider struct {
	ctx                  *config.ProjectContext
	Path                 string
	includePastResources bool
	content              Content
}

type Content struct {
	FileContents map[string]FileContent
	MergedBytes  []byte
}

type FileContent struct {
	Schema         string                 `json:"$schema"`
	Parameters     map[string]interface{} `json:"parameters"`
	Variables      map[string]interface{} `json:"variables"`
	ContentVersion string                 `json:"contentVersion"`
	Resources      []interface{}          `json:"resources"`
}

func NewTemplateProvider(ctx *config.ProjectContext, includePastResources bool, path string) *TemplateProvider {
	return &TemplateProvider{
		ctx:                  ctx,
		Path:                 path,
		includePastResources: includePastResources,
		content:              Content{FileContents: map[string]FileContent{}},
	}
}

func (p *TemplateProvider) Type() string {
	return "arm"
}
func (p *TemplateProvider) Context() *config.ProjectContext { return p.ctx }

func (p *TemplateProvider) DisplayType() string {
	return "Azure Resource Manager"
}

func (p *TemplateProvider) AddMetadata(metadata *schema.ProjectMetadata) {
	// no op
}

func (p *TemplateProvider) ProjectName() string {
	return config.CleanProjectName(p.ctx.ProjectConfig.Path)
}

func (p *TemplateProvider) RelativePath() string {
	return p.ctx.ProjectConfig.Path
}

func (p *TemplateProvider) VarFiles() []string {
	path := p.ctx.RunContext.Config.ArmVarFile
	if path != "" {
		fullPath, _ := filepath.Abs(path)
		return []string{fullPath}
	}
	return nil
}

func (p *TemplateProvider) LoadParamsFromFile() (map[string]map[string]interface{}, error) {
	if p.VarFiles() == nil {
		return nil, errors.New("no var file was read")
	}
	data, err := os.ReadFile(p.VarFiles()[0])
	if err != nil {
		return nil, err
	}

	// Store the file content in the content struct
	var vars map[string]map[string]interface{}
	if err = json.Unmarshal(data, &vars); err != nil {
		return nil, err
	}
	return vars, nil
}

func (p *TemplateProvider) SetParams() error {
	vars, err := p.LoadParamsFromFile()
	if err != nil {
		return err
	}
	for _, content := range p.content.FileContents {
		for key := range content.Parameters {
			if val, ok := vars["parameters"][key]; ok {
				content.Parameters[key] = val
			}
		}
	}
	return nil
}

func (p *TemplateProvider) LoadResources(usage schema.UsageMap) ([]*schema.Project, error) {

	logging.Logger.Debug().Msg("Extracting only cost-related params from arm template")

	rootPath := p.ctx.ProjectConfig.Path
	if rootPath == "" {
		log.Fatal("Root path is not provided")
	}

	projects := make([]*schema.Project, 0)

	// Merge all the resources from the files in the directory
	p.MergeFileResources(p.Path)

	p.SetParams()

	p.LoadModules()

	p.content.MergeBytes()

	project, _ := p.loadProject(p.Path, usage)
	projects = append(projects, project)

	return projects, nil

}

func (p *TemplateProvider) loadProject(filePath string, usage schema.UsageMap) (*schema.Project, error) {

	metadata := schema.DetectProjectMetadata(filePath)
	metadata.Type = p.Type()
	p.AddMetadata(metadata)
	name := p.ctx.ProjectConfig.Name
	if name == "" {
		name = metadata.GenerateProjectName(p.ctx.RunContext.VCSMetadata.Remote, p.ctx.RunContext.IsCloudEnabled())
	}

	project := schema.NewProject(name, metadata)
	p.parseFiles(project, usage)
	p.content.MergedBytes = nil
	return project, nil
}

func (p *TemplateProvider) parseFiles(project *schema.Project, usage schema.UsageMap) {
	parser := NewParser(p.ctx, p.includePastResources)
	content := gjson.ParseBytes(p.content.MergedBytes)
	resources, err := parser.ParseJSON(content, usage)
	if err != nil {
		log.Fatal(err, "Error parsing ARM template JSON")
	}

	for _, res := range resources {
		project.PartialResources = append(project.PartialResources, res.PartialResource)
	}

}

func (p *TemplateProvider) LoadFileContent(filePath string) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	// Store the file content in the content struct
	var content FileContent
	if err = json.Unmarshal(data, &content); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}
	// If it is not an ARM template, return
	if !IsARMTemplate(content) {
		return
	}
	p.content.FileContents[filePath] = content

}

func (p *TemplateProvider) LoadModules() {
	for path, content := range p.content.FileContents {
		p.AccessModules(&content, path)
	}
}

func transmitParameters(source map[string]interface{}, destination map[string]interface{}) {
	for key := range destination {
		if val, ok := source[key]; ok {
			destination[key] = val
		}
	}
}

func resolveParameters(global map[string]interface{}, local map[string]interface{}, variables map[string]interface{}) {
	for key, param := range local {
		value := (param.(map[string]interface{}))["value"]
		if value != nil {
			switch value.(type) {
			case string:
				parameter := getParameter(value.(string))
				if parameter != "" {
					local[key].(map[string]interface{})["value"] = global[parameter].(map[string]interface{})["value"]
				} else if variable := getVariable(value.(string)); variable != "" {
					local[key].(map[string]interface{})["value"] = variables[variable]
				}
			case map[string]interface{}:
				resolveObjectParameter(global, value.(map[string]interface{}))
			}
		}
	}
}

func resolveObjectParameter(parameters map[string]interface{}, objectParameter map[string]interface{}) {
	for key, value := range objectParameter {
		switch value.(type) {
		case string:
			parameter := getParameter(value.(string))
			if parameter != "" {
				objectParameter[key] = parameters[parameter].(map[string]interface{})["value"]
			}
		case map[string]interface{}:
			resolveObjectParameter(parameters, value.(map[string]interface{}))
		}
	}
}

func getParameter(parameterCall string) string {
	splitValue := strings.Split(parameterCall, "[parameters('")
	if len(splitValue) != 2 {
		return ""
	}
	key := strings.Split(splitValue[1], "')]")[0]

	return key
}

func getVariable(variableCall string) string {
	splitValue := strings.Split(variableCall, "[variables('")
	if len(splitValue) != 2 {
		return ""
	}
	key := strings.Split(splitValue[1], "')]")[0]

	return key
}

func resolveModules(parameters map[string]interface{}, variables map[string]interface{}, resources []interface{}) {
	for _, resource := range resources {
		if variables != nil {
			resolveVariables(parameters, variables)
		}
		res := resource.(map[string]interface{})
		if res["type"] == "Microsoft.Resources/deployments" {
			localParams := res["properties"].(map[string]interface{})["parameters"]
			embedTemplate := res["properties"].(map[string]interface{})["template"].(map[string]interface{})
			resolveParameters(parameters, localParams.(map[string]interface{}), variables)
			transmitParameters(localParams.(map[string]interface{}), embedTemplate["parameters"].(map[string]interface{}))
			var embedVariables map[string]interface{}
			if embedTemplate["variables"] != nil {
				embedVariables = embedTemplate["variables"].(map[string]interface{})
			}
			resolveModules(embedTemplate["parameters"].(map[string]interface{}), embedVariables, embedTemplate["resources"].([]interface{}))
		} else {
			handleExpressions(parameters, variables, resource)
		}
	}
}

func resolveVariables(parameters map[string]interface{}, variables map[string]interface{}) {
	for key, value := range variables {
		switch value.(type) {
		case string:
			if isExpression(value.(string)) {
				variables[key], _ = evaluateExpression(value.(string)[1:len(value.(string))-1], parameters, variables)
			}
		case map[string]interface{}:
			resolveObjectVariable(parameters, variables, value.(map[string]interface{}))
		case []interface{}:
			resolveArrayVariable(parameters, variables, value.([]interface{}))
		}
	}
}

func resolveObjectVariable(parameters map[string]interface{}, variables map[string]interface{}, objectVariable map[string]interface{}) {
	for key, value := range objectVariable {
		switch value.(type) {
		case string:
			if isExpression(value.(string)) {
				objectVariable[key], _ = evaluateExpression(value.(string)[1:len(value.(string))-1], parameters, variables)
			}
		case map[string]interface{}:
			resolveObjectVariable(parameters, variables, value.(map[string]interface{}))
		case []interface{}:
			resolveArrayVariable(parameters, variables, value.([]interface{}))
		}
	}
}

func resolveArrayVariable(parameters map[string]interface{}, variables map[string]interface{}, arrayVariable []interface{}) {
	for index, value := range arrayVariable {
		switch value.(type) {
		case string:
			if isExpression(value.(string)) {
				arrayVariable[index], _ = evaluateExpression(value.(string)[1:len(value.(string))-1], parameters, variables)
			}
		case map[string]interface{}:
			resolveObjectVariable(parameters, variables, value.(map[string]interface{}))
		case []interface{}:
			resolveArrayVariable(parameters, variables, value.([]interface{}))
		}
	}
}

func handleExpressions(parameters map[string]interface{}, variables map[string]interface{}, resource interface{}) {
	res := resource.(map[string]interface{})
	for key, value := range res {
		switch value.(type) {
		case string:
			if isExpression(value.(string)) {
				res[key], _ = evaluateExpression(value.(string)[1:len(value.(string))-1], parameters, variables)
			}
		case map[string]interface{}:
			handleExpressions(parameters, variables, value)
		}
	}
}

func (p *TemplateProvider) AccessModules(content *FileContent, path string) {
	resolveModules(content.Parameters, content.Variables, content.Resources)
}

func isAccessingObject(expression string) bool {
	pattern := `(\w+\((?:[^)(]+|\((?:[^)(]+|\([^)(]*\))*\))*\))\.\w+`
	re := regexp.MustCompile(pattern)
	return re.MatchString(expression)
}

func isExpression(expression string) bool {
	pattern := `(\w+\((?:[^)(]+|\((?:[^)(]+|\([^)(]*\))*\))*\))`
	re := regexp.MustCompile(pattern)
	return re.MatchString(expression)
}

func evaluateExpression(expression string, parameters map[string]interface{}, variables map[string]interface{}) (interface{}, error) {
	if !isAccessingObject(expression) && isExpression(expression) {
		tokens := Tokenize(expression)
		return Evaluate(&tokens, parameters, variables)
	} else if isAccessingObject(expression) {
		expression, err := resolveObjectAccess(expression, parameters, variables)
		if err != nil {
			return nil, err
		}
		return evaluateExpression(expression, parameters, variables)
	} else if !isExpression(expression) {
		return expression[1 : len(expression)-1], nil
	}
	return nil, fmt.Errorf("unsupported expression format")
}

func resolveObjectAccess(expression string, parameters map[string]interface{}, variables map[string]interface{}) (string, error) {
	if !isAccessingObject(expression) && !isExpression(expression) {
		return expression, nil
	}
	splitExpression := strings.Split(expression, ".")
	restOfExpression := strings.Join(splitExpression[1:], ".")
	var expr string
	pattern := `(\w+\((?:[^)(]+|\((?:[^)(]+|\([^)(]*\))*\))*\))\.\w+`
	re := regexp.MustCompile(pattern)
	if re.MatchString(expression) {
		match := re.FindStringSubmatch(expression)
		expr = match[1]
	}
	startOfExpression := strings.Split(expression, expr)[0]
	res, err := evaluateExpression(expr, parameters, variables)
	if err != nil {
		return "", err
	}
	value, restOfExpression := getValueFromObject(restOfExpression, res.(map[string]interface{}))
	newExpression := startOfExpression + value + restOfExpression
	return newExpression, nil
}

func getValueFromObject(expression string, object map[string]interface{}) (string, string) {
	var j int
	for j = 0; j < len(expression); j++ {
		if expression[j] == ',' || expression[j] == ' ' || expression[j] == ')' || expression[j] == '.' {
			break
		}
	}
	key := expression[0:j]
	val := object[key]
	var value string
	var restOfExpression string
	var delimiter string
	if len(expression) >= j {
		restOfExpression = expression[j:]
	}
	switch val.(type) {
	case string:
		value = val.(string)
		delimiter = "'"
	case float64:
		value = fmt.Sprintf("%g", val.(float64))
	case bool:
		value = fmt.Sprintf("%t", val.(bool))
	case map[string]interface{}:
		value, restOfExpression = getValueFromObject(expression[j+1:], val.(map[string]interface{}))
	}
	return delimiter + value + delimiter, restOfExpression
}

func (p *TemplateProvider) MergeFileResources(dirPath string) {

	// If the path is a file, load the file resources
	if strings.HasSuffix(dirPath, ".json") {
		p.LoadFileContent(dirPath)
		return

	}
	// If the path is a directory, load all the file resources in the directory that have a .json extension
	fileInfos, _ := os.ReadDir(dirPath)
	for _, info := range fileInfos {

		if info.IsDir() {
			continue
		}

		name := info.Name()
		filePath := dirPath + "/" + name

		if !strings.HasSuffix(name, ".json") {
			continue
		}
		p.LoadFileContent(filePath)

	}

}

func (c *Content) MergeBytes() {
	var resources []interface{}
	for _, content := range c.FileContents {
		resources = append(resources, content.Resources...)
	}

	mergedBytes, err := json.Marshal(resources)
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	c.MergedBytes = mergedBytes
}

func IsARMTemplate(content FileContent) bool {
	/*
		The schema property is the location of the JavaScript Object Notation (JSON) schema file that describes the version of the template language.
		Since it is a required property in an ARM Template, then it will be used to detect whether the file is an ARM Template or not.

		For more information, see: https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/syntax
	*/
	if content.Schema == "" {
		return false
	}

	schemaPattern := "^https://schema\\.management\\.azure\\.com/schemas/\\d{4}-\\d{2}-\\d{2}/(tenant|managementGroup|subscription)?deploymentTemplate\\.json#$"
	matched, err := regexp.Match(schemaPattern, []byte(content.Schema))
	if err != nil {
		return false
	}

	// Another way to check if the file is an ARM template is to check if the contentVersion and resources properties are present, since they are required in an ARM template
	return matched && content.ContentVersion != "" && content.Resources != nil
}
