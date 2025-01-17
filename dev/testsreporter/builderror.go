// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"fmt"
	"strings"
)

const reportingTeam = "@elastic/ecosystem"

type buildError struct {
	errorLinks
	serverless        bool
	serverlessProject string
	logsDB            bool
	stackVersion      string
	teams             []string
	packages          []string
}

type buildErrorOptions struct {
	Serverless        bool
	ServerlessProject string
	LogsDB            bool
	StackVersion      string
	Teams             []string
	Packages          []string
	BuildURL          string
	PreviousBuilds    []string
	ClosedIssueURL    string
}

func newBuildError(options buildErrorOptions) (*buildError, error) {
	b := buildError{
		serverless:        options.Serverless,
		serverlessProject: options.ServerlessProject,
		logsDB:            options.LogsDB,
		stackVersion:      options.StackVersion,
		packages:          options.Packages,
		teams:             []string{reportingTeam},
		errorLinks: errorLinks{
			firstBuild:     options.BuildURL,
			closedIssueURL: options.ClosedIssueURL,
			previousBuilds: options.PreviousBuilds,
		},
	}

	return &b, nil
}

func (b *buildError) String() string {
	var sb strings.Builder

	if b.logsDB {
		sb.WriteString("[LogsDB] ")
	}
	if b.serverless {
		sb.WriteString(fmt.Sprintf("[Serverless %s] ", b.serverlessProject))
	}
	if b.stackVersion != "" {
		sb.WriteString("[Stack ")
		sb.WriteString(b.stackVersion)
		sb.WriteString("] ")
	}
	sb.WriteString("Many packages failing in daily job")

	return sb.String()
}

func (p *buildError) FirstBuild() string {
	return p.errorLinks.firstBuild
}

func (p *buildError) UpdateLinks(links errorLinks) {
	p.errorLinks = links
}

func (p *buildError) Teams() []string {
	return p.teams
}

func (p *buildError) SummaryData() map[string]any {
	return map[string]any{
		"stackVersion":      p.stackVersion,
		"serverless":        p.serverless,
		"serverlessProject": p.serverlessProject,
		"logsDB":            p.logsDB,
		"packages":          p.packages,
		"owners":            p.teams,
	}
}

func (p *buildError) DescriptionData() map[string]any {
	return map[string]any{
		"firstBuild":     p.errorLinks.firstBuild,
		"closedIssueURL": p.errorLinks.closedIssueURL,
		"previousBuilds": p.errorLinks.previousBuilds,
	}
}
