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
	eventPath := filepath.Join(options.packagesSourceDir, packageName, datasetName, sampleEventFile)

	body, err := ioutil.ReadFile(eventPath)
	if err != nil {
		return "", errors.Wrapf(err, "reading sample event file failed (path: %s)", eventPath)
	}

	formatted, err := formatSampleEvent(body)
	if err != nil {
		return "", errors.Wrapf(err, "formatting sample event file failed (path: %s)", eventPath)
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("An example event for %s looks as following:\n\n", datasetName))
	builder.WriteString("```$json")
	builder.Write(formatted)
	builder.WriteString("\n```\n")
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