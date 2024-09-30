# Guide to contributing to Infracost's ARM component

This guide should help contributers, who wish to contribute to the ARM component in particular, and show them the ropes on how to do it. This guide will walk you through the main steps that should be followed in order to do so.

## Overview

The following are the main axes that still need to be handled:

- Adding support for more resources
- Adding implementations of functions
- Handling loops
- Handling arrays in expressions

## Table of contents

- [Overview](#overview)
- [How to add support for a new resource?](#how-to-add-support-for-a-new-resource?)
- [How to implement a function?](#how-to-implement-a-function?)
- [How to handle arrays in expressions?](#how-to-handle-arrays-in-expressions?)
- [How to handle loops?](#how-to-handle-loops?)

## How to add support for a new resource?

There are two ways of adding support for a new resource to the ARM component:

### Case 1: The resource is already supported by Infracost for Terraform

In this case, you should find the equivalent resource in ARM, and create the corresponding go file that would create the resource structure in internal/providers/arm/azure. To illustrate that, we'll take the example of the azurerm_managed_disk resource. You just need to uncomment the get function of that resource from the internal/providers/arm/azure/registry.go and implement it along with the function that creates the resource structure. Following the same example that was used to create the resource for Terraform, this is how we did it for ARM.

```
func getManagedDiskRegistryItem() *schema.RegistryItem {
	return &schema.RegistryItem{
		Name:      "Microsoft.Compute/disks",
		CoreRFunc: NewManagedDisk,
	}
}

func NewManagedDisk(d *schema.ResourceData) schema.CoreResource {
	r := &azure.ManagedDisk{
		Address: d.Address,
		Region:  d.Region,
		ManagedDiskData: azure.ManagedDiskData{
			DiskType:          d.Get("sku.name").String(),
			DiskSizeGB:        d.Get("properties.diskSizeGB").Int(),
			DiskIOPSReadWrite: d.Get("properties.diskIOPSReadWrite").Int(),
			DiskMBPSReadWrite: d.Get("properties.diskMBpsReadWrite").Int(),
		},
	}

	return r
}
```

### Case 2: The resource is not supported by Infracost

In this case, you should add support for this resource, and to do so you have to follow [the provided guide](add_new_resource_guide.md) for that. Then once it's done, follow Case 1.

## How to implement a function?

A function evaluator already exists, which is capable of interpreting functions, extract their arguments and mapping them to their correct implementation in golang. However, that implementation in golang is not fully done, so you could add support for more functions and it's really simple to do. You should go to internal/providers/arm/function_evaluator.go and there you could add the mapping and the implementation. We'll take the example of the function format that creates a formatted string from input values. So if we want to add support for it, first of all we need to add it inside the SupportedFunctions map, as follows:

```
var SupportedFunctions = map[string]func(FunctionArguments) interface{}{
	"contains":   contains,
	"parameters": parameters,
	"concat":     concat,
	"toLower":    toLower,
	"variables":  variables,
	"format":     format,
	"empty":      empty,
	"not":        not,
}
```

Here you can see all the functions supported so far. Then after that, you need to implement format in golang.

```
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
```

As you can see, all these functions take a FunctionArguments struct and return an interface{}. The struct is composed of the actual list of arguments, the list of variables and the list of parameters. Most of the time, we only need that list of arguments, that we need to use to implement the function. And this case we had to also handle the type of the arguments, because depending on what they are, we treat them differently.

## How to handle arrays in expressions?

This is still an unresolved issue that we need to handle. Basically, the issue is that if we have an access to an element of an array inside an expression, we're uncapable of handling that. For example if we have a parameter `example` that is an array, we cannot do something like `parameters(example)[0]` for example.

## How to handle loops??

This issue is tied to the previous one, as we need to be able to handle arrays to be capable of handling loops inside an ARM Template. They are represented by a block called copy. This is still an unresolved issue in this Infracost ARM component.
