// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package issuesreporter

import (
	"fmt"
	"strings"
)

const defaultMaxLengthMessages = 1000

type ResultsFormatter struct {
	result PackageError
}

func (r ResultsFormatter) Title() string {
	// TODO: remove ignore statement
	return fmt.Sprintf("%s - IGNORE testing", r.result.String())
}

func (r ResultsFormatter) Owners() []string {
	// TODO: remove replace to allow mention teams
	// teams := []string{}
	// for _, t := range r.result.Teams {
	// 	teams = append(teams, strings.ReplaceAll(t, "@", ""))
	// }
	// return teams
	return r.result.Teams
}

func (r ResultsFormatter) Summary() string {
	var sb strings.Builder
	if r.result.StackVersion != "" {
		sb.WriteString("- Stack version: `")
		sb.WriteString(r.result.StackVersion)
		sb.WriteString("`\n")
	}
	if r.result.Serverless {
		sb.WriteString("- Serverless run\n")
	}
	sb.WriteString("- Package: `")
	sb.WriteString(r.result.PackageName)
	sb.WriteString("`\n")
	sb.WriteString("- Failing test: `")
	sb.WriteString(r.result.Name)
	sb.WriteString("`\n")

	if r.result.DataStream != "" {
		sb.WriteString("- DataStream: `")
		sb.WriteString(r.result.DataStream)
		sb.WriteString("`\n")
	}
	if len(r.Owners()) > 0 {
		sb.WriteString("\n")
		sb.WriteString("Owners:\n")
		for _, owner := range r.Owners() {
			sb.WriteString("- ")
			sb.WriteString(owner)
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func (r ResultsFormatter) Description() string {
	var sb strings.Builder
	sb.WriteString(r.Summary())
	sb.WriteString("\n")

	if r.result.Failure != "" {
		sb.WriteString("Failure:\n")
		sb.WriteString("```\n")
		sb.WriteString(truncateText(r.result.Failure, defaultMaxLengthMessages))
		sb.WriteString("\n")
		sb.WriteString("```\n")
		sb.WriteString("\n")
	}
	if r.result.Error != "" {
		sb.WriteString("Error:\n")
		sb.WriteString("```\n")
		sb.WriteString(truncateText(r.result.Error, defaultMaxLengthMessages))
		sb.WriteString("\n")
		sb.WriteString("```\n")
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString("CI Builds:\n")
	sb.WriteString("- ")
	sb.WriteString(r.result.BuildURL)
	sb.WriteString("\n")

	if len(r.result.PreviousBuilds) > 0 {
		sb.WriteString("Previous failed builds:\n")
		for _, link := range r.result.PreviousBuilds {
			sb.WriteString("- ")
			sb.WriteString(link)
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func truncateText(message string, maxLength int) string {
	if len(message) <= maxLength {
		return message
	}
	return message[:strings.LastIndexAny(message[:maxLength], " ,.;:-}")]
}
