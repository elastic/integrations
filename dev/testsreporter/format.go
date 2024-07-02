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

type ResultsFormatter struct {
	result           PackageError
	maxPreviousLinks int
}

func (r ResultsFormatter) Title() string {
	return r.result.String()
}

func (r ResultsFormatter) Owners() []string {
	return r.result.Teams
}

func (r ResultsFormatter) Summary() string {
	var rendered bytes.Buffer
	templ := template.Must(template.New("summary").Parse(summaryTmpl))
	templ.Execute(&rendered, map[string]interface{}{
		"stackVersion":      r.result.StackVersion,
		"serverless":        r.result.Serverless,
		"serverlessProject": r.result.ServerlessProject,
		"packageName":       r.result.PackageName,
		"testName":          r.result.Name,
		"dataStream":        r.result.DataStream,
		"owners":            r.Owners(),
	})

	return rendered.String()
}

func (r ResultsFormatter) Description() string {
	var rendered bytes.Buffer
	templ := template.Must(template.New("description").Parse(descriptionTmpl))
	templ.Execute(&rendered, map[string]interface{}{
		"summary":          r.Summary(),
		"failure":          truncateText(r.result.Failure, defaultMaxLengthMessages),
		"error":            truncateText(r.result.Error, defaultMaxLengthMessages),
		"firstBuild":       r.result.BuildURL,
		"closedIssueURL":   r.result.ClosedIssueURL,
		"previousBuilds":   r.result.PreviousBuilds,
		"maxPreviousLinks": r.maxPreviousLinks,
	})

	return rendered.String()
}

func truncateText(message string, maxLength int) string {
	if len(message) <= maxLength {
		return message
	}
	return message[:strings.LastIndexAny(message[:maxLength], " ,.;:-}")]
}
