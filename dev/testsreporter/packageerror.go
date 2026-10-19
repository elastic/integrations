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
	packagePath string
	dataStream  string
	// ownersErr is the problem found looking for the owners, if the error was created without them.
	ownersErr error
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

	// OwnersResolver is used to find the owners of the package. If it is not set,
	// the owners are looked up using the name of the package as the name of its folder.
	OwnersResolver *ownersResolver

	// OwnersError is a previous problem preparing the lookup of owners (e.g. invalid CODEOWNERS file).
	// If it is set, no owners are looked up and the error is kept in the package error.
	// It requires AllowMissingOwners.
	OwnersError error

	// AllowMissingOwners avoids failing when the owners of the package are not found,
	// the package error is created without owners.
	AllowMissingOwners bool
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
		var owners []string
		err := options.OwnersError
		switch {
		case err != nil:
		case options.OwnersResolver != nil:
			var details packageDetails
			details, err = options.OwnersResolver.lookup(p.packageName, p.dataStream)
			owners = details.owners
			p.packagePath = details.path
		default:
			owners, err = codeowners.PackageOwners(p.packageName, p.dataStream, options.CodeownersPath)
		}
		switch {
		case err != nil && options.AllowMissingOwners:
			p.ownersErr = err
			fmt.Printf("WARNING: the failure of %q will be reported without owners: %s\n", p.testCase.String(), err)
		case err != nil:
			return nil, fmt.Errorf("failed to find owners for package %s: %w", p.packageName, err)
		default:
			p.teams = owners
		}
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
	data["packagePath"] = p.packagePath
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
