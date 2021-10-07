// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/elastic/package-registry/packages"
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

func createAgentContentForMetrics(moduleName, dataStreamName string, streams []packages.Stream) (agentContent, error) {
	inputName := moduleName + "/metrics"
	vars := extractVarsFromStream(streams, inputName)

	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("metricsets: [\"%s\"]\n", dataStreamName))

	for _, aVar := range vars {
		variableName := aVar.Name

		if !aVar.Required {
			buffer.WriteString(fmt.Sprintf("{{#if %s}}\n", variableName))
		}

		if aVar.Multi {
			buffer.WriteString(fmt.Sprintf("%s:\n{{#each %s}}\n  - {{this}}\n{{/each}}\n", variableName, variableName))
		} else {
			buffer.WriteString(fmt.Sprintf("%s: {{%s}}\n", variableName, variableName))
		}

		if !aVar.Required {
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

func extractVarsFromStream(streams []packages.Stream, inputName string) []packages.Variable {
	for _, stream := range streams {
		if stream.Input == inputName {
			return stream.Vars
		}
	}
	return []packages.Variable{}
}
