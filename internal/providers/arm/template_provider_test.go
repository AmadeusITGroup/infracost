package arm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/infracost/infracost/internal/config"
	"github.com/infracost/infracost/internal/resources/azure"
	"github.com/infracost/infracost/internal/schema"
	"github.com/sirupsen/logrus"
	"gopkg.in/go-playground/assert.v1"
)

var filePath string = "testdata"

func TestARMTemplateDetection(t *testing.T) {
	expected := map[string]bool{
		"template_valid":     true,
		"template_invalid_1": false,
	}

	for fileName, expectedValue := range expected {
		filePath := filepath.Join(filePath, fileName+".json")
		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("Failed to read file: %v", err)
		}

		var content FileContent
		if err = json.Unmarshal(data, &content); err != nil {
			t.Fatalf("Failed to unmarshal JSON: %v", err)
		}
		assert.Equal(t, IsARMTemplate(content), expectedValue)
	}
}

func TestDetectInvalidTemplates(t *testing.T) {
	expected := 4
	actual := 0
	// Get all files in testdata directory
	fileInfos, _ := os.ReadDir(filePath)
	for _, info := range fileInfos {
		file := info.Name()
		data, err := os.ReadFile(filePath + "/" + file)
		if err != nil {
			t.Fatalf("Failed to read file: %v", err)
		}

		var content FileContent
		if err = json.Unmarshal(data, &content); err != nil {
			t.Fatalf("Failed to unmarshal JSON: %v", err)
		}
		if !IsARMTemplate(content) {
			actual++
		}
	}
	assert.Equal(t, actual, expected)
}

func TestLoadFileContent(t *testing.T) {

	provider := TemplateProvider{
		content: Content{FileContents: map[string]FileContent{}},
	}

	fileInfos, _ := os.ReadDir(filePath)
	for _, info := range fileInfos {
		if info.IsDir() {
			continue
		}
		name := info.Name()
		filePath := filepath.Join(filePath, name)
		provider.LoadFileContent(filePath)
	}
	assert.Equal(t, len(provider.content.FileContents), 4)

}

func TestParseFiles(t *testing.T) {

	data := `{
		"type": "Microsoft.Compute/disks",
		"apiVersion": "2023-10-02",
		"name": "ultra",
		"location": "francecentral",
		"properties": {
		  "creationData": {
			"createOption": "Empty"
		  },
		  "diskSizeGB": 2000,
		  "diskIOPSReadWrite": 4000,
		  "diskMBpsReadWrite": 20
		},
		"sku": {
		  "name": "UltraSSD_LRS"
		}
	  }`
	provider := NewTemplateProvider(&config.ProjectContext{ProjectConfig: &config.Project{Path: ""}}, false, "")
	project := schema.NewProject("azurerm", &schema.ProjectMetadata{})
	provider.content.MergedBytes = []byte(data)
	provider.parseFiles(project, schema.UsageMap{})

	expected := &azure.ManagedDisk{
		Address: "Microsoft.Compute/disks/ultra",
		Region:  "francecentral",
		ManagedDiskData: azure.ManagedDiskData{
			DiskType:          "UltraSSD_LRS",
			DiskSizeGB:        2000,
			DiskIOPSReadWrite: 4000,
			DiskMBPSReadWrite: 20,
		},
	}

	assert.Equal(t, project.PartialResources[0].CoreResource, expected)

}

func TestLoadResources(t *testing.T) {
	ctx := config.NewProjectContext(config.EmptyRunContext(), &config.Project{Path: filePath}, logrus.Fields{})
	provider := NewTemplateProvider(ctx, false, filePath)
	projects, err := provider.LoadResources(schema.UsageMap{})
	if err != nil {
		t.Fatalf("Failed to load resources: %v", err)
	}
	assert.Equal(t, len(projects), 1)
	assert.Equal(t, len(projects[0].PartialResources), 3)
}

func TestEvaluateExpression(t *testing.T) {
	data := `{
		"first": {
			"type":  "string",
			"value": "_"
		},
		"second": {
			"type": "array",
			"value": [1, 2, 3]
		},
		"third": {
			"type": "array",
			"value": ["1", "2", "3"]
		}
	}`
	var parameters map[string]interface{}
	json.Unmarshal([]byte(data), &parameters)

	expressions := []string{"[concat('first',  parameters('first'), 'second')]",
		"[contains(parameters('second'), 1)]",
		"[contains(parameters('third'), '1')]",
		"[format('{0}/test/test:1.0.12', parameters('first'))]"}

	expected := []interface{}{"first_second", true, true, "_/test/test:1.0.12"}

	for i := range expressions {
		actual, _ := evaluateExpression(expressions[i][1:len(expressions[i])-1], parameters, nil)
		assert.Equal(t, expected[i], actual)
	}
}

func TestEvaluateExpressionWithObjectAccesses(t *testing.T) {
	variables := map[string]interface{}{
		"object": map[string]interface{}{
			"name": "object_name",
			"nested_object": map[string]interface{}{
				"nested_name": "nested_object_name",
				"nested_object": map[string]interface{}{
					"nested_name": "nested_object_name",
				},
			},
		},
	}

	expressions := []string{"concat(variables('object').name, '_', variables('object').nested_object.nested_object.nested_name)",
		"variables('object').name", "toLower(variables('object').nested_object.nested_object.nested_name)"}

	expected := []interface{}{"object_name_nested_object_name", "object_name", "nested_object_name"}

	for i := range expressions {
		result, _ := evaluateExpression(expressions[i], nil, variables)
		assert.Equal(t, result, expected[i])
	}
}
