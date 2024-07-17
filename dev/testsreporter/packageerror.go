// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"fmt"
	"strings"

	"github.com/elastic/integrations/dev/codeowners"
	"github.com/elastic/integrations/dev/teamlabels"
)

type PackageError struct {
	testCase
	Serverless        bool
	ServerlessProject string
	StackVersion      string
	BuildURL          string
	Teams             []string
	TeamLabels        []string
	PackageName       string
	DataStream        string
	PreviousBuilds    []string
	ClosedIssueURL    string
}

type PackageErrorOptions struct {
	Serverless        bool
	ServerlessProject string
	StackVersion      string
	BuildURL          string
	TestCase          testCase
	CodeownersPath    string
}

func NewPackageError(options PackageErrorOptions) (*PackageError, error) {
	p := PackageError{
		Serverless:        options.Serverless,
		ServerlessProject: options.ServerlessProject,
		StackVersion:      options.StackVersion,
		BuildURL:          options.BuildURL,
		testCase:          options.TestCase,
	}

	values := strings.Split(p.testCase.ClassName, ".")
	p.PackageName = values[0]
	if len(values) == 2 {
		p.DataStream = values[1]
	}

	var owners []string
	var err error
	if options.CodeownersPath != "" {
		owners, err = codeowners.PackageOwnersCustomCodeowners(p.PackageName, p.DataStream, options.CodeownersPath)
	} else {
		owners, err = codeowners.PackageOwners(p.PackageName, p.DataStream)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find owners for package %s: %w", p.PackageName, err)
	}
	p.Teams = owners

	// Get Team:Labels to add to Github Issue Labels
	ghTeamLabels, err := teamlabels.GetTeamLabels()
	if err != nil {
		fmt.Printf("Error while fetching team labels: %s", err)
	}
	for _, owner := range owners {
		if teamlabel, ok := ghTeamLabels[owner]; ok {
			p.TeamLabels = append(p.TeamLabels, teamlabel)
		} else {
			fmt.Printf("No Team: label for owner %s", owner)
		}
	}

	return &p, nil
}

func (p PackageError) String() string {
	var sb strings.Builder

	if p.Serverless {
		sb.WriteString(fmt.Sprintf("[Serverless %s] ", p.ServerlessProject))
	}
	if p.StackVersion != "" {
		sb.WriteString("[Stack ")
		sb.WriteString(p.StackVersion)
		sb.WriteString("] ")
	}
	sb.WriteString("[")
	sb.WriteString(p.PackageName)
	sb.WriteString("] ")
	sb.WriteString("Failing test daily: ")
	sb.WriteString(p.testCase.String())

	return sb.String()
}

func (p *PackageError) SetClosedURL(url string) {
	p.ClosedIssueURL = url
}

func (p *PackageError) SetPreviousLinks(builds []string) {
	p.PreviousBuilds = builds
}

func (p *PackageError) SetFirstBuild(url string) {
	p.BuildURL = url
}

func (p *PackageError) SetClosedIssue(url string) {
	p.ClosedIssueURL = url
}
