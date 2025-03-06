// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"text/template"
)

//go:embed _static/summary.tmpl
var summaryTmpl string

//go:embed _static/description.tmpl
var descriptionTmpl string

const defaultMaxLengthMessages = 1000

type resultsFormatter struct {
	result           failureObserver
	maxPreviousLinks int
}

func (r resultsFormatter) Title() string {
	return r.result.String()
}

func (r resultsFormatter) Owners() []string {
	return r.result.Teams()
}

func (r resultsFormatter) Summary() (string, error) {
	var rendered bytes.Buffer
	templ := template.Must(template.New("summary").Parse(summaryTmpl))
	data := r.result.SummaryData()
	err := templ.Execute(&rendered, data)
	if err != nil {
		return "", fmt.Errorf("failed to render summary: %w", err)
	}
	return rendered.String(), nil
}

func (r resultsFormatter) Description() (string, error) {
	var rendered bytes.Buffer
	templ := template.Must(template.New("description").Parse(descriptionTmpl))

	summary, err := r.Summary()
	if err != nil {
		return "", err
	}

	data := r.result.DescriptionData()
	data["summary"] = summary
	data["maxPreviousLinks"] = r.maxPreviousLinks

	err = templ.Execute(&rendered, data)
	if err != nil {
		return "", fmt.Errorf("failed to render description: %w", err)
	}

	return rendered.String(), nil
}

func truncateText(message string, maxLength int) string {
	if len(message) <= maxLength {
		return message
	}
	return message[:strings.LastIndexAny(message[:maxLength], " ,.;:-}")]
}
