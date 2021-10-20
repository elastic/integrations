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

	"github.com/elastic/package-registry/packages"
)

// createStreams method builds a set of stream inputs including configuration variables.
// Stream definitions depend on a beat type - log or metric.
// At the moment, the array returns only one stream.
func createStreams(modulePath, moduleName, moduleTitle, dataStreamName, beatType string) ([]packages.Stream, agentContent, error) {
	var streams []packages.Stream
	var agent agentContent
	var err error

	switch beatType {
	case "logs":
		streams, agent, err = createLogStreams(modulePath, moduleTitle, dataStreamName)
		if err != nil {
			return nil, agentContent{}, errors.Wrapf(err, "creating log streams failed (modulePath: %s, dataStreamName: %s)",
				modulePath, dataStreamName)
		}
	case "metrics":
		streams, agent, err = createMetricStreams(modulePath, moduleName, moduleTitle, dataStreamName)
		if err != nil {
			return nil, agentContent{}, errors.Wrapf(err, "creating metric streams failed (modulePath: %s, dataStreamName: %s)",
				modulePath, dataStreamName)
		}
	default:
		return nil, agentContent{}, fmt.Errorf("invalid beat type: %s", beatType)
	}
	return streams, agent, nil
}

// createLogStreams method builds a set of stream inputs for logs oriented dataStream.
// The method unmarshals "manifest.yml" file and picks all configuration variables.
func createLogStreams(modulePath, moduleTitle, dataStreamName string) ([]packages.Stream, agentContent, error) {
	manifestPath := filepath.Join(modulePath, dataStreamName, "manifest.yml")
	manifestFile, err := ioutil.ReadFile(manifestPath)
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "reading manifest file failed (path: %s)", manifestPath)
	}

	vars, err := createLogStreamVariables(manifestFile)
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "creating log stream variables failed (path: %s)", manifestPath)
	}

	configFilePaths, err := filepath.Glob(filepath.Join(modulePath, dataStreamName, "config", "*.*"))
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "locating config files failed (modulePath: %s, dataStreamName: %s)", modulePath, dataStreamName)
	}

	if len(configFilePaths) == 0 {
		return nil, agentContent{}, fmt.Errorf("expected at least one config file (modulePath: %s, dataStreamName: %s)", modulePath, dataStreamName)
	}

	var streams []packages.Stream
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
				aType = "logfile"
			}
			targetFileName := inputType + ".yml.hbs"

			inputConfig := root.configForInput(inputType)
			agent.streams = append(agent.streams, streamContent{
				targetFileName: targetFileName,
				body:           inputConfig,
			})

			streams = append(streams, packages.Stream{
				Input:        aType,
				Title:        fmt.Sprintf("%s %s logs (%s)", moduleTitle, dataStreamName, inputType),
				Description:  fmt.Sprintf("Collect %s %s logs using %s input", moduleTitle, dataStreamName, inputType),
				TemplatePath: targetFileName,
				Vars:         root.filterVarsForInput(inputType, vars),
			})
		}
	}
	return streams, agent, nil
}

// wrapVariablesWithDefault method builds a set of stream inputs for metrics oriented dataStream.
// The method combines all config files in module's _meta directory, unmarshals all configuration entries and selects
// ones related to the particular metricset (first seen, first occurrence, next occurrences skipped).
//
// The method skips commented variables, but keeps arrays of structures (even if it's not possible to render them using
// UI).
func createMetricStreams(modulePath, moduleName, moduleTitle, dataStreamName string) ([]packages.Stream, agentContent, error) {
	merged, err := mergeMetaConfigFiles(modulePath)
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "merging config files failed")
	}

	vars, err := createMetricStreamVariables(merged, moduleName, dataStreamName)
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "creating metric stream variables failed (modulePath: %s)", modulePath)
	}
	streams := []packages.Stream{
		{
			Input:       moduleName + "/metrics",
			Title:       fmt.Sprintf("%s %s metrics", moduleTitle, dataStreamName),
			Description: fmt.Sprintf("Collect %s %s metrics", moduleTitle, dataStreamName),
			Vars:        vars,
		},
	}

	agent, err := createAgentContentForMetrics(moduleName, dataStreamName, streams)
	if err != nil {
		return nil, agentContent{}, errors.Wrapf(err, "creating agent content for logs failed (modulePath: %s, dataStreamName: %s)",
			modulePath, dataStreamName)
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
