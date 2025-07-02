// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"fmt"
	"strings"

	"github.com/elastic/integrations/dev/codeowners"
)

type packageError struct {
	testCase
	dataError
	teams       []string
	packageName string
	dataStream  string
}

type packageErrorOptions struct {
	Serverless        bool
	ServerlessProject string
	LogsDB            bool
	StackVersion      string
	Subscription      string
	BuildURL          string
	TestCase          testCase
	CodeownersPath    string
	ClosedIssueURL    string
	PreviousBuilds    []string
	Teams             []string
}

// Ensures that packageError implements failureObserver interface
var _ failureObserver = new(packageError)

func newPackageError(options packageErrorOptions) (*packageError, error) {
	p := packageError{
		dataError: dataError{
			serverless:        options.Serverless,
			serverlessProject: options.ServerlessProject,
			logsDB:            options.LogsDB,
			stackVersion:      options.StackVersion,
			subscription:      options.Subscription,
			errorLinks: errorLinks{
				firstBuild:     options.BuildURL,
				closedIssueURL: options.ClosedIssueURL,
				previousBuilds: options.PreviousBuilds,
			},
		},
		testCase: options.TestCase,
		teams:    options.Teams,
	}

	p.packageName = p.testCase.PackageName()
	p.dataStream = p.testCase.DataStream()

	if len(options.Teams) == 0 {
		owners, err := codeowners.PackageOwners(p.packageName, p.dataStream, options.CodeownersPath)
		if err != nil {
			return nil, fmt.Errorf("failed to find owners for package %s: %w", p.packageName, err)
		}
		p.teams = owners
	}

	return &p, nil
}

func (p *packageError) FirstBuild() string {
	return p.errorLinks.firstBuild
}

func (p *packageError) UpdateLinks(links errorLinks) {
	p.errorLinks = links
}

func (p *packageError) Teams() []string {
	return p.teams
}

func (p *packageError) String() string {
	var sb strings.Builder

	sb.WriteString(p.dataError.String())
	sb.WriteString("[")
	sb.WriteString(p.packageName)
	sb.WriteString("] ")
	sb.WriteString("Failing test daily: ")
	sb.WriteString(p.testCase.String())

	return sb.String()
}

func (p *packageError) SummaryData() map[string]any {
	data := p.dataError.Data()
	data["packageName"] = p.packageName
	data["testName"] = p.Name
	data["dataStream"] = p.dataStream
	data["owners"] = p.teams
	return data
}

func (p *packageError) DescriptionData() map[string]any {
	data := p.SummaryData()
	for key, value := range p.errorLinks.Data() {
		data[key] = value
	}
	data["failure"] = truncateText(p.Failure, defaultMaxLengthMessages)
	data["error"] = truncateText(p.Error, defaultMaxLengthMessages)
	return data
}

func (p *packageError) Labels() []string {
	return nil
}
