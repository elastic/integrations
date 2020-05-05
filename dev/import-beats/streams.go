// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/elastic/package-registry/util"
)

// createStreams method builds a set of stream inputs including configuration variables.
// Stream definitions depend on a beat type - log or metric.
// At the moment, the array returns only one stream.
func createStreams(modulePath, moduleName, moduleTitle, datasetName, beatType string) ([]util.Stream, agentContent, error) {
	var streams []util.Stream
	var agent agentContent
	var err error

	switch beatType {
	case "logs":
		streams, agent, err = createLogStreams(modulePath, moduleTitle, datasetName)
		if err != nil {
			return nil, agentContent{}, errors.Wrapf(err, "creating log streams failed (modulePath: %s, datasetName: %s)",
				modulePath, datasetName)
		}
	case "metrics":
		streams, agent, err = createMetricStreams(modulePath, moduleName, moduleTitle, datasetName)
		if err != nil {
			return nil, agentContent{}, errors.Wrapf(err, "creating metric streams failed (modulePath: %s, datasetName: %s)",
				modulePath, datasetName)
		}
	default:
		return nil, agentContent{}, fmt.Errorf("invalid beat type: %s", beatType)
	}
	return streams, agent, nil
}

// createLogStreams method builds a set of stream inputs for logs oriented dataset.
// The method unmarshals "manifest.yml" file and picks all configuration variables.
func createLogStreams(modulePath, moduleTitle, datasetName string) ([]util.Stream, agentContent, error) {
	manifestPath := filepath.Join(modulePath, datasetName, "manifest.yml")
	manifestFile, err := ioutil.ReadFile(manifestPath)
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "reading manifest file failed (path: %s)", manifestPath)
	}

	vars, err := createLogStreamVariables(manifestFile)
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "creating log stream variables failed (path: %s)", manifestPath)
	}

	configFilePaths, err := filepath.Glob(filepath.Join(modulePath, datasetName, "config", "*.*"))
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "locating config files failed (modulePath: %s, datasetName: %s)", modulePath, datasetName)
	}

	if len(configFilePaths) == 0 {
		return nil, agentContent{}, fmt.Errorf("expected at least one config file (modulePath: %s, datasetName: %s)", modulePath, datasetName)
	}

	var streams []util.Stream
	var agent agentContent
	for _, configFilePath := range configFilePaths {
		fileName := extractInputConfigFilename(configFilePath)
		fileContent, err := ioutil.ReadFile(configFilePath)
		if err != nil {
			return nil, agentContent{}, errors.Wrapf(err, "reading file from config directory failed (filePath: %s)", configFilePath)
		}

		if strings.HasSuffix(configFilePath, ".js") {
			agent.streams = append(agent.streams, streamContent{
				targetFileName: fileName,
				body:           fileContent,
			})
			continue
		}

		root, err := parseStreamConfig(fileContent)
		if err != nil {
			return nil, agentContent{}, errors.Wrapf(err, "parsing stream config failed")
		}

		for _, inputType := range root.inputTypes() {
			aType := inputType
			if inputType == "log" {
				aType = "logs"
			}
			targetFileName := inputType + ".yml.hbs"

			inputConfig := root.configForInput(inputType)
			agent.streams = append(agent.streams, streamContent{
				targetFileName: targetFileName,
				body:           inputConfig,
			})

			streams = append(streams, util.Stream{
				Input:        aType,
				Title:        fmt.Sprintf("%s %s logs (%s)", moduleTitle, datasetName, inputType),
				Description:  fmt.Sprintf("Collect %s %s logs using %s input", moduleTitle, datasetName, inputType),
				TemplatePath: targetFileName,
				Vars:         root.filterVarsForInput(inputType, vars),
			})
		}
	}
	return streams, agent, nil
}

// wrapVariablesWithDefault method builds a set of stream inputs for metrics oriented dataset.
// The method combines all config files in module's _meta directory, unmarshals all configuration entries and selects
// ones related to the particular metricset (first seen, first occurrence, next occurrences skipped).
//
// The method skips commented variables, but keeps arrays of structures (even if it's not possible to render them using
// UI).
func createMetricStreams(modulePath, moduleName, moduleTitle, datasetName string) ([]util.Stream, agentContent, error) {
	merged, err := mergeMetaConfigFiles(modulePath)
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "merging config files failed")
	}

	vars, err := createMetricStreamVariables(merged, moduleName, datasetName)
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "creating metric stream variables failed (modulePath: %s)", modulePath)
	}
	streams := []util.Stream{
		{
			Input:       moduleName + "/metrics",
			Title:       fmt.Sprintf("%s %s metrics", moduleTitle, datasetName),
			Description: fmt.Sprintf("Collect %s %s metrics", moduleTitle, datasetName),
			Vars:        vars,
		},
	}

	agent, err := createAgentContentForMetrics(moduleName, datasetName, streams)
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "creating agent content for logs failed (modulePath: %s, datasetName: %s)",
			modulePath, datasetName)
	}
	return streams, agent, nil
}

// mergeMetaConfigFiles method visits all configuration YAML files and combines them into single document.
func mergeMetaConfigFiles(modulePath string) ([]byte, error) {
	configFilePaths, err := filepath.Glob(filepath.Join(modulePath, "_meta", "config*.yml"))
	if err != nil {
		return nil, errors.Wrapf(err, "locating config files failed (modulePath: %s)", modulePath)
	}

	var mergedConfig bytes.Buffer
	for _, configFilePath := range configFilePaths {
		configFile, err := ioutil.ReadFile(configFilePath)
		if err != nil && !os.IsNotExist(err) {
			return nil, errors.Wrapf(err, "reading config file failed (path: %s)", configFilePath)
		}
		mergedConfig.Write(configFile)
		mergedConfig.WriteString("\n")
	}
	return mergedConfig.Bytes(), nil
}
