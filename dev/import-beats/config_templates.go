// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/elastic/package-registry/util"
)

type configTemplateContent struct {
	moduleName  string
	moduleTitle string

	inputs map[string]configTemplateInput // map[inputType]..
}

type configTemplateInput struct {
	dataStreamNames []string
	packageType  string
	inputType    string
	vars         []util.Variable
}

func (ds configTemplateContent) toMetadataConfigTemplates() []util.ConfigTemplate {
	var inputTypes []string
	var packageTypes []string
	for k, input := range ds.inputs {
		inputTypes = append(inputTypes, k)
		packageTypes = append(packageTypes, input.packageType)
	}

	packageTypes = uniqueStringValues(packageTypes)
	sort.Strings(packageTypes)

	var title, description string
	if len(packageTypes) == 2 {
		title = toConfigTemplateTitleForTwoTypes(ds.moduleTitle, packageTypes[0], packageTypes[1])
		description = toConfigTemplateDescriptionForTwoTypes(ds.moduleTitle, packageTypes[0], packageTypes[1])
	} else {
		title = toConfigTemplateTitle(ds.moduleTitle, packageTypes[0])
		description = toConfigTemplateDescription(ds.moduleTitle, packageTypes[0])
	}

	var inputs []util.Input
	for _, packageType := range packageTypes {
		for inputType, input := range ds.inputs {
			if input.packageType == packageType {
				inputs = append(inputs, util.Input{
					Type:        input.inputType,
					Title:       toConfigTemplateInputTitle(ds.moduleTitle, packageType, ds.inputs[inputType].dataStreamNames, inputType),
					Description: toConfigTemplateInputDescription(ds.moduleTitle, packageType, ds.inputs[inputType].dataStreamNames, inputType),
					Vars:        input.vars,
				})
			}
		}
	}
	return []util.ConfigTemplate{
		{
			Name:        ds.moduleName,
			Title:       title,
			Description: description,
			Inputs:      inputs,
		},
	}
}

type updateConfigTemplateParameters struct {
	moduleName  string
	moduleTitle string
	packageType string

	dataStreams  dataStreamContentArray
	inputVars map[string][]util.Variable
}

func updateConfigTemplate(dsc configTemplateContent, params updateConfigTemplateParameters) (configTemplateContent, error) {
	dsc.moduleName = params.moduleName
	dsc.moduleTitle = params.moduleTitle

	if dsc.inputs == nil {
		dsc.inputs = map[string]configTemplateInput{}
	}

	for _, dataStream := range params.dataStreams {
		for _, stream := range dataStream.manifest.Streams {
			inputType := stream.Input

			v, ok := dsc.inputs[inputType]
			if !ok {
				v = configTemplateInput{
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

func toConfigTemplateTitle(moduleTitle, packageType string) string {
	return fmt.Sprintf("%s %s", moduleTitle, packageType)
}

func toConfigTemplateDescription(moduleTitle, packageType string) string {
	return fmt.Sprintf("Collect %s from %s instances", packageType, moduleTitle)
}

func toConfigTemplateTitleForTwoTypes(moduleTitle, firstPackageType, secondPackageType string) string {
	return fmt.Sprintf("%s %s and %s", moduleTitle, firstPackageType, secondPackageType)
}

func toConfigTemplateDescriptionForTwoTypes(moduleTitle, firstPackageType, secondPackageType string) string {
	return fmt.Sprintf("Collect %s and %s from %s instances", firstPackageType, secondPackageType, moduleTitle)
}

func toConfigTemplateInputTitle(moduleTitle, packageType string, dataStreams []string, inputType string) string {
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

func toConfigTemplateInputDescription(moduleTitle, packageType string, dataStreams []string, inputType string) string {
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
