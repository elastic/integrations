// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

const sampleEventFile = "sample_event.json"

func renderSampleEvent(options generateOptions, packageName, datasetName string) (string, error) {
	eventPath := filepath.Join(options.packagesSourceDir, packageName, "dataset", datasetName, sampleEventFile)

	body, err := ioutil.ReadFile(eventPath)
	if err != nil {
		return "", errors.Wrapf(err, "reading sample event file failed (path: %s)", eventPath)
	}

	formatted, err := formatSampleEvent(body)
	if err != nil {
		return "", errors.Wrapf(err, "formatting sample event file failed (path: %s)", eventPath)
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("An example event for `%s` looks as following:\n\n",
		stripDatasetFolderSuffix(datasetName)))
	builder.WriteString("```$json\n")
	builder.Write(formatted)
	builder.WriteString("\n```")
	return builder.String(), nil
}

func formatSampleEvent(body []byte) ([]byte, error) {
	var d map[string]interface{}
	err := json.Unmarshal(body, &d)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling sample event file failed")
	}

	body, err = json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, errors.Wrap(err, "marshaling sample event file failed")
	}
	return body, nil
}

func stripDatasetFolderSuffix(datasetName string) string {
	datasetName = strings.ReplaceAll(datasetName, "_metrics", "")
	datasetName = strings.ReplaceAll(datasetName, "_logs", "")
	return datasetName
}
