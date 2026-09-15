// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v3"

	"github.com/elastic/package-registry/packages"
)

type manifestWithVars struct {
	Vars []packages.Variable `yaml:"var"`
}

var ignoredConfigOptions = []string{
	"module",
	"metricsets",
	"enabled",
}

func createLogStreamVariables(manifestFile []byte) ([]packages.Variable, error) {
	var mwv manifestWithVars
	err := yaml.Unmarshal(manifestFile, &mwv)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshalling manifest file failed")
	}

	adjusted, err := adjustVariablesFormat(mwv)
	if err != nil {
		return nil, errors.Wrap(err, "adjusting log stream variables failed")
	}
	return adjusted.Vars, nil
}

func createMetricStreamVariables(configFileContent []byte, moduleName, dataStreamName string) ([]packages.Variable, error) {
	var vars []packages.Variable
	if len(configFileContent) == 0 {
		return vars, nil
	}

	var moduleConfig []mapStr
	err := yaml.Unmarshal(configFileContent, &moduleConfig)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshalling module config failed")
	}

	foundConfigEntries := map[string]bool{}

	for _, moduleConfigEntry := range moduleConfig {
		flatEntry := moduleConfigEntry.flatten()
		related, err := isConfigEntryRelatedToMetricset(flatEntry, dataStreamName)
		if err != nil {
			return nil, errors.Wrapf(err, "checking if config entry is related failed")
		}

		for name, value := range flatEntry {
			if shouldConfigOptionBeIgnored(name, value) {
				continue
			}

			if _, ok := foundConfigEntries[name]; ok {
				continue // already processed this config option
			}

			if related || strings.HasPrefix(name, fmt.Sprintf("%s.", dataStreamName)) {
				var isArray bool
				variableType := determineInputVariableType(name, value)
				if variableType == "yaml" {
					m, err := yaml.Marshal(value)
					if err != nil {
						return nil, errors.Wrapf(err, "marshalling object configuration variable failed")
					}
					value = string(m)
				} else {
					_, isArray = value.([]interface{})
				}
				aVar := packages.Variable{
					Name:     name,
					Type:     variableType,
					Title:    toVariableTitle(name),
					Multi:    isArray,
					Required: determineInputVariableIsRequired(value),
					ShowUser: true,
					Default:  value,
				}

				vars = append(vars, aVar)
				foundConfigEntries[name] = true
			}
		}
	}

	// sort variables to keep them in order while using version control.
	sort.Slice(vars, func(i, j int) bool {
		return sort.StringsAreSorted([]string{vars[i].Name, vars[j].Name})
	})
	return vars, nil
}

// adjustVariablesFormat method adjusts the format of variables defined in manifest:
// - ensure that all variable values are wrapped with a "default" field
// - add field "multi: true" if value is an array
func adjustVariablesFormat(mwvs manifestWithVars) (manifestWithVars, error) {
	var withDefaults manifestWithVars
	for _, aVar := range mwvs.Vars {
		var isArray bool
		variableType := determineInputVariableType(aVar.Name, aVar.Default)
		if variableType == "yaml" {
			m, err := yaml.Marshal(aVar.Default)
			if err != nil {
				return manifestWithVars{}, errors.Wrapf(err, "marshalling object configuration variable failed")
			}
			aVar.Default = string(m)
		} else {
			_, isArray = aVar.Default.([]interface{})
		}

		aVarWithDefaults := aVar
		aVarWithDefaults.Title = toVariableTitle(aVar.Name)
		aVarWithDefaults.Type = variableType
		aVarWithDefaults.Required = determineInputVariableIsRequired(aVar.Default)
		aVarWithDefaults.ShowUser = true
		aVarWithDefaults.Multi = isArray
		withDefaults.Vars = append(withDefaults.Vars, aVarWithDefaults)
	}
	return withDefaults, nil
}

// shouldConfigOptionBeIgnored method checks if the configuration option name should be skipped (not used, duplicate, etc.)
func shouldConfigOptionBeIgnored(optionName string, value interface{}) bool {
	if value == nil {
		return true
	}

	for _, ignored := range ignoredConfigOptions {
		if ignored == optionName {
			return true
		}
	}
	return false
}

// isConfigEntryRelatedToMetricset method checks if the configuration entry may affect the dataStream settings,
// in other words, checks if the "metricsets" field is present and contains the given dataStreamName.
func isConfigEntryRelatedToMetricset(entry mapStr, dataStreamName string) (bool, error) {
	var metricsetRelated bool
	if metricsets, ok := entry["metricsets"]; ok {
		metricsetsMapped, ok := metricsets.([]interface{}) // nats: connection data stream doesn't define a config, but this is fine
		if ok {
			for _, metricset := range metricsetsMapped {
				if metricset.(string) == dataStreamName {
					metricsetRelated = true
					break
				}
			}
		}
	}
	return metricsetRelated, nil
}

// determineInputVariableIsRequired method determines is the configuration variable should be marked as "required".
// If the variable is string and its default value is empty, it can be assumed that isn't required.
func determineInputVariableIsRequired(v interface{}) bool {
	if v == nil {
		return false
	}

	val, isString := v.(string)
	if isString && val == "" {
		return false
	}
	return true
}

// determineInputVariableType method determines the most appropriate type of the value or the value in array.
// Support types: text, password, bool, integer
func determineInputVariableType(name, v interface{}) string {
	if arr, isArray := v.([]interface{}); isArray {
		if len(arr) == 0 {
			return "text" // array doesn't contain any items, assuming default type
		}
		return determineInputVariableType(name, arr[0])
	}

	if _, isBool := v.(bool); isBool {
		return "bool"
	} else if _, isInt := v.(int); isInt {
		return "integer"
	}

	if name == "password" {
		return "password"
	}

	if _, isString := v.(string); isString || v == nil {
		return "text"
	}
	return "yaml"
}

func toVariableTitle(name string) string {
	name = strings.ReplaceAll(name, "_", " ")
	name = strings.ReplaceAll(name, ".", " ")
	return strings.Title(name)
}
