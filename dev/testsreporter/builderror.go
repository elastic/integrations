// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"strings"
)

const (
	buildReportingTeam      = "@elastic/ecosystem"
	buildReportingTeamLabel = "Team:Ecosystem"
)

type buildError struct {
	dataError
	teams    []string
	packages []string
}

type buildErrorOptions struct {
	Serverless        bool
	ServerlessProject string
	LogsDB            bool
	StackVersion      string
	Packages          []string
	BuildURL          string
	PreviousBuilds    []string
	ClosedIssueURL    string
}

// Ensures that buildError implements failureObserver interface
var _ failureObserver = new(buildError)

func newBuildError(options buildErrorOptions) (*buildError, error) {
	b := buildError{
		dataError: dataError{
			serverless:        options.Serverless,
			serverlessProject: options.ServerlessProject,
			logsDB:            options.LogsDB,
			stackVersion:      options.StackVersion,
			errorLinks: errorLinks{
				firstBuild:     options.BuildURL,
				closedIssueURL: options.ClosedIssueURL,
				previousBuilds: options.PreviousBuilds,
			},
		},
		packages: options.Packages,
		teams:    []string{buildReportingTeam},
	}

	return &b, nil
}

func (b *buildError) String() string {
	var sb strings.Builder

	sb.WriteString(b.dataError.String())
	sb.WriteString("Too many packages failing in daily job")

	return sb.String()
}

func (b *buildError) FirstBuild() string {
	return b.errorLinks.firstBuild
}

func (b *buildError) UpdateLinks(links errorLinks) {
	b.errorLinks = links
}

func (b *buildError) Teams() []string {
	return b.teams
}

func (b *buildError) SummaryData() map[string]any {
	data := b.dataError.Data()
	data["packages"] = b.packages
	data["owners"] = b.teams
	return data
}

func (b *buildError) DescriptionData() map[string]any {
	return b.errorLinks.Data()
}

func (b *buildError) Labels() []string {
	return []string{buildReportingTeamLabel}
}
