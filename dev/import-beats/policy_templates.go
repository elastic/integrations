// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/elastic/package-registry/packages"
)

type policyTemplateContent struct {
	moduleName  string
	moduleTitle string

	inputs map[string]policyTemplateInput // map[inputType]..
}

type policyTemplateInput struct {
	dataStreamNames []string
	packageType     string
	inputType       string
	vars            []packages.Variable
}

func (ptc policyTemplateContent) toMetadataPolicyTemplates() []packages.PolicyTemplate {
	var inputTypes []string
	var packageTypes []string
	for k, input := range ptc.inputs {
		inputTypes = append(inputTypes, k)
		packageTypes = append(packageTypes, input.packageType)
	}

	packageTypes = uniqueStringValues(packageTypes)
	sort.Strings(packageTypes)

	var title, description string
	if len(packageTypes) == 2 {
		title = toPolicyTemplateTitleForTwoTypes(ptc.moduleTitle, packageTypes[0], packageTypes[1])
		description = toPolicyTemplateDescriptionForTwoTypes(ptc.moduleTitle, packageTypes[0], packageTypes[1])
	} else {
		title = toPolicyTemplateTitle(ptc.moduleTitle, packageTypes[0])
		description = toPolicyTemplateDescription(ptc.moduleTitle, packageTypes[0])
	}

	var inputs []packages.Input
	for _, packageType := range packageTypes {
		for inputType, input := range ptc.inputs {
			if input.packageType == packageType {
				inputs = append(inputs, packages.Input{
					Type:        input.inputType,
					Title:       toPolicyTemplateInputTitle(ptc.moduleTitle, packageType, ptc.inputs[inputType].dataStreamNames, inputType),
					Description: toPolicyTemplateInputDescription(ptc.moduleTitle, packageType, ptc.inputs[inputType].dataStreamNames, inputType),
					Vars:        input.vars,
				})
			}
		}
	}
	return []packages.PolicyTemplate{
		{
			Name:        ptc.moduleName,
			Title:       title,
			Description: description,
			Inputs:      inputs,
		},
	}
}

type updatePolicyTemplateParameters struct {
	moduleName  string
	moduleTitle string
	packageType string

	dataStreams dataStreamContentArray
	inputVars   map[string][]packages.Variable
}

func updatePolicyTemplate(dsc policyTemplateContent, params updatePolicyTemplateParameters) (policyTemplateContent, error) {
	dsc.moduleName = params.moduleName
	dsc.moduleTitle = params.moduleTitle

	if dsc.inputs == nil {
		dsc.inputs = map[string]policyTemplateInput{}
	}

	for _, dataStream := range params.dataStreams {
		for _, stream := range dataStream.manifest.Streams {
			inputType := stream.Input

			v, ok := dsc.inputs[inputType]
			if !ok {
				v = policyTemplateInput{
					packageType: params.packageType,
					inputType:   inputType,
					vars:        params.inputVars[inputType],
				}
			}

			v.dataStreamNames = append(v.dataStreamNames, dataStream.name)
			dsc.inputs[inputType] = v
		}
	}

	return dsc, nil
}

func toPolicyTemplateTitle(moduleTitle, packageType string) string {
	return fmt.Sprintf("%s %s", moduleTitle, packageType)
}

func toPolicyTemplateDescription(moduleTitle, packageType string) string {
	return fmt.Sprintf("Collect %s from %s instances", packageType, moduleTitle)
}

func toPolicyTemplateTitleForTwoTypes(moduleTitle, firstPackageType, secondPackageType string) string {
	return fmt.Sprintf("%s %s and %s", moduleTitle, firstPackageType, secondPackageType)
}

func toPolicyTemplateDescriptionForTwoTypes(moduleTitle, firstPackageType, secondPackageType string) string {
	return fmt.Sprintf("Collect %s and %s from %s instances", firstPackageType, secondPackageType, moduleTitle)
}

func toPolicyTemplateInputTitle(moduleTitle, packageType string, dataStreams []string, inputType string) string {
	dataStreams = adjustDataStreamNamesForInputDescription(dataStreams)

	firstPart := dataStreams[:len(dataStreams)-1]
	secondPart := dataStreams[len(dataStreams)-1:]

	var description strings.Builder
	description.WriteString("Collect ")
	description.WriteString(moduleTitle)
	description.WriteString(" ")

	if len(firstPart) > 0 {
		fp := strings.Join(firstPart, ", ")
		description.WriteString(fp)
		description.WriteString(" and ")
	}

	description.WriteString(secondPart[0])
	description.WriteString(" ")
	description.WriteString(packageType)

	if packageType == "logs" && inputType != "logs" {
		description.WriteString(fmt.Sprintf(" (input: %s)", inputType))
	}
	return description.String()
}

func toPolicyTemplateInputDescription(moduleTitle, packageType string, dataStreams []string, inputType string) string {
	dataStreams = adjustDataStreamNamesForInputDescription(dataStreams)

	firstPart := dataStreams[:len(dataStreams)-1]
	secondPart := dataStreams[len(dataStreams)-1:]

	var description strings.Builder
	description.WriteString("Collecting ")

	if len(firstPart) > 0 {
		fp := strings.Join(firstPart, ", ")
		description.WriteString(fp)
		description.WriteString(" and ")
	}

	description.WriteString(secondPart[0])
	description.WriteString(" ")
	description.WriteString(packageType)
	description.WriteString(" from ")
	description.WriteString(moduleTitle)
	description.WriteString(" instances")

	if packageType == "logs" && inputType != "logs" {
		description.WriteString(fmt.Sprintf(" (input: %s)", inputType))
	}
	return description.String()
}

func adjustDataStreamNamesForInputDescription(names []string) []string {
	var adjusted []string
	for _, name := range names {
		if name == "log" {
			adjusted = append(adjusted, "application")
			continue
		}
		adjusted = append(adjusted, name)
	}
	return adjusted
}
