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

type datasourceContent struct {
	moduleName  string
	moduleTitle string

	inputs map[string]datasourceInput // map[inputType]..
}

type datasourceInput struct {
	datasetNames []string
	packageType  string
	vars         []util.Variable
}

func (ds datasourceContent) toMetadataDatasources() []util.Datasource {
	var packageTypes []string
	for _, input := range ds.inputs {
		packageTypes = append(packageTypes, input.packageType)
	}
	sort.Strings(packageTypes)

	var title, description string
	if len(ds.inputs) == 2 {
		title = toDatasourceTitleForTwoTypes(ds.moduleTitle, packageTypes[0], packageTypes[1])
		description = toDatasourceDescriptionForTwoTypes(ds.moduleTitle, packageTypes[0], packageTypes[1])
	} else {
		title = toDatasourceTitle(ds.moduleTitle, packageTypes[0])
		description = toDatasourceDescription(ds.moduleTitle, packageTypes[0])
	}

	var inputs []util.Input
	for _, packageType := range packageTypes {
		for inputType, input := range ds.inputs {
			if input.packageType == packageType {
				inputs = append(inputs, util.Input{
					Type:        inputType,
					Title:       toDatasourceInputTitle(ds.moduleTitle, packageType),
					Description: toDatasourceInputDescription(ds.moduleTitle, packageType, ds.inputs[inputType].datasetNames),
					Vars:        input.vars,
				})
			}
		}
	}
	return []util.Datasource{
		{
			Name:        ds.moduleName,
			Title:       title,
			Description: description,
			Inputs:      inputs,
		},
	}
}

type updateDatasourcesParameters struct {
	moduleName  string
	moduleTitle string
	packageType string

	datasetNames []string
	inputVars    map[string][]util.Variable
}

func updateDatasource(dsc datasourceContent, params updateDatasourcesParameters) (datasourceContent, error) {
	dsc.moduleName = params.moduleName
	dsc.moduleTitle = params.moduleTitle

	if dsc.inputs == nil {
		dsc.inputs = map[string]datasourceInput{}
	}

	inputType := params.packageType
	if inputType == "metrics" {
		inputType = fmt.Sprintf("%s/%s", dsc.moduleName, inputType)
	}

	dsc.inputs[inputType] = datasourceInput{
		datasetNames: params.datasetNames,
		packageType:  params.packageType,
		vars:         params.inputVars[inputType],
	}
	return dsc, nil
}

func toDatasourceTitle(moduleTitle, packageType string) string {
	return fmt.Sprintf("%s %s", moduleTitle, packageType)
}

func toDatasourceDescription(moduleTitle, packageType string) string {
	return fmt.Sprintf("Collect %s from %s instances", packageType, moduleTitle)
}

func toDatasourceTitleForTwoTypes(moduleTitle, firstPackageType, secondPackageType string) string {
	return fmt.Sprintf("%s %s and %s", moduleTitle, firstPackageType, secondPackageType)
}

func toDatasourceDescriptionForTwoTypes(moduleTitle, firstPackageType, secondPackageType string) string {
	return fmt.Sprintf("Collect %s and %s from %s instances", firstPackageType, secondPackageType, moduleTitle)
}

func toDatasourceInputTitle(moduleTitle, packageType string) string {
	return fmt.Sprintf("Collect %s from %s instances", packageType, moduleTitle)
}

func toDatasourceInputDescription(moduleTitle, packageType string, datasets []string) string {
	firstPart := datasets[:len(datasets)-1]
	secondPart := datasets[len(datasets)-1:]

	var description strings.Builder
	description.WriteString("Collecting ")
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
	return description.String()
}
