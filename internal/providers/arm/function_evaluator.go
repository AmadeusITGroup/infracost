package arm

import (
	"fmt"
	"strconv"
	"strings"
)

type FunctionArguments struct {
	args       []interface{}
	parameters map[string]interface{}
	variables  map[string]interface{}
}

var SupportedFunctions = map[string]func(FunctionArguments) interface{}{
	"contains":   contains,
	"parameters": parameters,
	"concat":     concat,
	"toLower":    toLower,
	"variables":  variables,
	"format":     format,
}

func format(arguments FunctionArguments) interface{} {
	var newString string
	result := arguments.args[0].(string)
	for i := range arguments.args {
		if i == 0 {
			continue
		}
		switch arguments.args[i].(type) {
		case string:
			newString = arguments.args[i].(string)
		case float64:
			newString = fmt.Sprintf("%g", arguments.args[i].(float64))
		case bool:
			newString = fmt.Sprintf("%t", arguments.args[i].(bool))
		}
		result = strings.ReplaceAll(result, "{"+strconv.Itoa(i-1)+"}", newString)
	}
	return result
}

func contains(arguments FunctionArguments) interface{} {
	switch arguments.args[0].(type) {
	case string:
		return strings.Contains(arguments.args[0].(string), arguments.args[1].(string))
	case []interface{}:
		switch arguments.args[0].([]interface{})[0].(type) {
		case string:
			for _, element := range arguments.args[0].([]interface{}) {
				if arguments.args[1] == element.(string) {
					return true
				}
			}
		case float64:
			number, _ := strconv.Atoi(arguments.args[1].(string))
			for _, element := range arguments.args[0].([]interface{}) {
				if float64(number) == element.(float64) {
					return true
				}
			}
		}
		return false
	}
	return nil
}

func concat(arguments FunctionArguments) interface{} {
	switch arguments.args[0].(type) {
	case string:
		var arg []string
		for _, a := range arguments.args {
			arg = append(arg, a.(string))
		}
		return strings.Join(arg, "")
	}
	return nil
}

func parameters(arguments FunctionArguments) interface{} {
	return (arguments.parameters[arguments.args[0].(string)]).(map[string]interface{})["value"]
}

func variables(arguments FunctionArguments) interface{} {
	return arguments.variables[arguments.args[0].(string)]
}

func toLower(arguments FunctionArguments) interface{} {
	return strings.ToLower(arguments.args[0].(string))
}

type Node struct {
	token string
	next  *Node
}

func NewNode(data string) *Node {
	return &Node{
		token: data,
		next:  nil,
	}
}

func Tokenize(expression string) *Node {
	var head *Node
	var current *Node
	for i := 0; i < len(expression); i++ {
		if expression[i] == ' ' || expression[i] == '"' || expression[i] == '\'' {
			continue
		}
		var newNode *Node
		if expression[i] == '(' || expression[i] == ')' || expression[i] == ',' {
			newNode = NewNode(string(expression[i]))
		} else {
			start := i
			for i < len(expression) && expression[i] != ' ' && expression[i] != '(' && expression[i] != ')' && expression[i] != '\'' && expression[i] != '"' {
				i++
			}
			newNode = NewNode(expression[start:i])
			i--
		}

		if head == nil {
			head = newNode
			current = head
		} else {
			current.next = newNode
			current = current.next
		}
	}
	return head
}

func Evaluate(tokens **Node, parameters map[string]interface{}, variables map[string]interface{}) (interface{}, error) {
	args := make([]interface{}, 0)
	fun := (*tokens).token         // an expression should always start with the functions name
	if !isSupportedFunction(fun) { // if it's not a supported function
		return nil, fmt.Errorf("%s unsupported function", fun)
	}
	(*tokens) = (*tokens).next
	for (*tokens) != nil && (*tokens).next != nil && (*tokens).token != ")" {
		if isSupportedFunction((*tokens).token) && (*tokens).next.token == "(" { // if it's a supported function
			res, err := Evaluate(tokens, parameters, variables) // evaluate the nested function
			if err != nil {
				return nil, err
			}
			args = append(args, res) // append the result to the arguments of the current function
			(*tokens) = (*tokens).next
		} else if (*tokens).next.token == "(" { // if it's an unsupported function
			return nil, fmt.Errorf("%s unsupported function", (*tokens).token)
		} else if (*tokens).token != "," && (*tokens).token != "(" && (*tokens).token != ")" { // if it's a string that is not one of the special characters
			args = append(args, (*tokens).token) // then it's considered an argument of the current function
		}
		(*tokens) = (*tokens).next
	}
	return applyFunction(fun, args, parameters, variables), nil
}

func isSupportedFunction(token string) bool {
	_, ok := SupportedFunctions[token]
	return ok
}

func applyFunction(funcName string, args []interface{}, parameters map[string]interface{}, variables map[string]interface{}) interface{} {
	arguments := FunctionArguments{
		args:       args,
		parameters: parameters,
		variables:  variables,
	}
	return SupportedFunctions[funcName](arguments)
}
