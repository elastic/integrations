// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/elastic/package-registry/util"
)

type agentContent struct {
	streams []streamContent
}

type streamContent struct {
	targetFileName string
	body           []byte
}

func extractInputConfigFilename(configFilePath string) string {
	i := strings.LastIndex(configFilePath, "/")
	return configFilePath[i+1:]
}

func createAgentContentForMetrics(moduleName, datasetName string, streams []util.Stream) (agentContent, error) {
	inputName := moduleName + "/metrics"
	vars := extractVarsFromStream(streams, inputName)

	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("metricsets: [\"%s\"]\n", datasetName))

	for _, aVar := range vars {
		variableName := aVar.Name

		if !isAgentConfigOptionRequired(variableName) {
			buffer.WriteString(fmt.Sprintf("{{#if %s}}\n", variableName))
		}

		if isArrayConfigOption(variableName) {
			buffer.WriteString(fmt.Sprintf("%s:\n{{#each %s}}\n  - {{this}}\n{{/each}}\n", variableName, variableName))
		} else {
			buffer.WriteString(fmt.Sprintf("%s: {{%s}}\n", variableName, variableName))
		}

		if !isAgentConfigOptionRequired(variableName) {
			buffer.WriteString("{{/if}}\n")
		}
	}
	return agentContent{
		streams: []streamContent{
			{
				targetFileName: "stream.yml.hbs",
				body:           buffer.Bytes(),
			},
		},
	}, nil
}

func extractVarsFromStream(streams []util.Stream, inputName string) []util.Variable {
	for _, stream := range streams {
		if stream.Input == inputName {
			return stream.Vars
		}
	}
	return []util.Variable{}
}

func isAgentConfigOptionRequired(optionName string) bool {
	return optionName == "hosts" || optionName == "period"
}

func isArrayConfigOption(optionName string) bool {
	return optionName == "hosts"
}
