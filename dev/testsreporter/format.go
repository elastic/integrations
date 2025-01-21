// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"bytes"
	_ "embed"
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

func (r resultsFormatter) Summary() string {
	var rendered bytes.Buffer
	templ := template.Must(template.New("summary").Parse(summaryTmpl))
	templ.Execute(&rendered, r.result.SummaryData())

	return rendered.String()
}

func (r resultsFormatter) Description() string {
	var rendered bytes.Buffer
	templ := template.Must(template.New("description").Parse(descriptionTmpl))

	data := r.result.DescriptionData()
	data["summary"] = r.Summary()
	data["maxPreviousLinks"] = r.maxPreviousLinks

	templ.Execute(&rendered, data)

	return rendered.String()
}

func truncateText(message string, maxLength int) string {
	if len(message) <= maxLength {
		return message
	}
	return message[:strings.LastIndexAny(message[:maxLength], " ,.;:-}")]
}
