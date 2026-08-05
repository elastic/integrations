// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"strings"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v3"

	"github.com/elastic/package-registry/packages"
)

func compactDataStreamVariables(dataStreams dataStreamContentArray) (dataStreamContentArray, map[string][]packages.Variable, error) { // map[inputType][]util.Variable
	varsPerInputType := map[string][]packages.Variable{}
	var compacted dataStreamContentArray

	for _, dataStream := range dataStreams {
		for i, stream := range dataStream.manifest.Streams {
			var notCompactedVars []packages.Variable
			for _, aVar := range stream.Vars {
				isAlreadyCompacted := isVariableAlreadyCompacted(varsPerInputType, aVar, stream.Input)
				if !isAlreadyCompacted {
					canBeCompacted, err := canVariableBeCompacted(dataStreams, aVar, stream.Input)
					if err != nil {
						return nil, nil, errors.Wrap(err, "checking compactibility failed")
					}
					if canBeCompacted {
						varsPerInputType[stream.Input] = append(varsPerInputType[stream.Input], aVar)
					} else {
						notCompactedVars = append(notCompactedVars, aVar)
					}
				}
			}
			stream.Vars = notCompactedVars
			dataStream.manifest.Streams[i] = stream
		}
		compacted = append(compacted, dataStream)
	}
	return compacted, varsPerInputType, nil
}

func isVariableAlreadyCompacted(varsPerInputType map[string][]packages.Variable, aVar packages.Variable, inputType string) bool {
	if vars, ok := varsPerInputType[inputType]; ok {
		for _, v := range vars {
			if v.Name == aVar.Name {
				return true // variable already compacted
			}
		}
	}
	return false
}

func canVariableBeCompacted(dataStreams dataStreamContentArray, aVar packages.Variable, inputType string) (bool, error) {
	for _, dataStream := range dataStreams {
		var varUsed bool

		for _, stream := range dataStream.manifest.Streams {
			if stream.Input != inputType {
				break // input is not related with this var
			}

			for _, streamVar := range stream.Vars {
				if isNonCompactableVariable(aVar) {
					continue
				}

				equal, err := areVariablesEqual(streamVar, aVar)
				if err != nil {
					return false, errors.Wrap(err, "comparing variables failed")
				}
				if equal {
					varUsed = true
					break
				}
			}
		}

		if !varUsed {
			return false, nil // variable not present in this dataStream
		}
	}
	return true, nil
}

func areVariablesEqual(first packages.Variable, second packages.Variable) (bool, error) {
	if first.Name != second.Name || first.Type != second.Type {
		return false, nil
	}

	firstValue, err := yaml.Marshal(first.Default)
	if err != nil {
		return false, errors.Wrap(err, "marshalling first value failed")
	}
	secondValue, err := yaml.Marshal(second.Default)
	if err != nil {
		return false, errors.Wrap(err, "marshalling second value failed")
	}

	firstValueStr := strings.TrimSpace(string(firstValue))
	secondValueStr := strings.TrimSpace(string(secondValue))
	return firstValueStr == secondValueStr, nil
}

func isNonCompactableVariable(aVar packages.Variable) bool {
	return aVar.Name == "period" || aVar.Name == "paths"
}
