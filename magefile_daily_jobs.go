// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/elastic/integrations/dev/requiresupdate"
	"github.com/elastic/integrations/dev/testsreporter"
)

// These targets are only invoked from main-branch pipelines (daily Buildkite
// runs and GitHub workflows). They import go-gh/v2 which requires a modern Go
// toolchain. Keeping them in a separate file allows backport_branch.sh to
// exclude this file and drop the go-gh/v2 dependency so that backport branches
// can retain their original Go version.

const (
	defaultResultsPath           = "build/test-results/"
	defaultPreviousLinksNumber   = 5
	defaultMaximumTestsReported  = 20
	defaultServerlessProjectType = "observability"
)

func ReportFailedTests(ctx context.Context, testResultsFolder string) error {
	stackVersion := os.Getenv("STACK_VERSION")
	serverlessEnv := os.Getenv("SERVERLESS")
	dryRunEnv := os.Getenv("DRY_RUN")
	serverlessProjectEnv := os.Getenv("SERVERLESS_PROJECT")
	buildURL := os.Getenv("BUILDKITE_BUILD_URL")
	subscription := os.Getenv("ELASTIC_SUBSCRIPTION")

	serverless := false
	if serverlessEnv != "" {
		var err error
		serverless, err = strconv.ParseBool(serverlessEnv)
		if err != nil {
			return fmt.Errorf("failed to parse SERVERLESS value: %w", err)
		}
		if serverlessProjectEnv == "" {
			serverlessProjectEnv = defaultServerlessProjectType
		}
	}

	logsDBEnabled := false
	if v, found := os.LookupEnv("STACK_LOGSDB_ENABLED"); found && v == "true" {
		logsDBEnabled = true
	}

	verboseMode := false
	if v, found := os.LookupEnv("VERBOSE_MODE_ENABLED"); found && v == "true" {
		verboseMode = true
	}

	maxIssuesString := os.Getenv("CI_MAX_TESTS_REPORTED")
	maxIssues := defaultMaximumTestsReported
	if maxIssuesString != "" {
		var err error
		maxIssues, err = strconv.Atoi(maxIssuesString)
		if err != nil {
			return fmt.Errorf("failed to convert env. variable CI_MAX_TESTS_REPORTED to int (%s): %w", maxIssuesString, err)
		}
	}

	dryRun := false
	if dryRunEnv != "" {
		var err error
		dryRun, err = strconv.ParseBool(dryRunEnv)
		if err != nil {
			return fmt.Errorf("failed to parse DRY_RUN value: %w", err)
		}
	}

	options := testsreporter.CheckOptions{
		Serverless:        serverless,
		ServerlessProject: serverlessProjectEnv,
		LogsDB:            logsDBEnabled,
		StackVersion:      stackVersion,
		Subscription:      subscription,
		BuildURL:          buildURL,
		MaxPreviousLinks:  defaultPreviousLinksNumber,
		MaxTestsReported:  maxIssues,
		DryRun:            dryRun,
		Verbose:           verboseMode,
	}
	return testsreporter.Check(ctx, testResultsFolder, options)
}

// RequiresUpdate updates required package versions for all integration packages,
// adds a changelog entry per modified package, and opens one PR (or issue) per
// package.
//
// Usage: mage RequiresUpdate [-dryRun] [-preview]
//
// Pass -dryRun to preview proposals without applying changes (also skips
// publishing, since no files would be written); pass -preview to print what
// would be published without touching git or GitHub.
func RequiresUpdate(dryRun, preview *bool) error {
	return requiresupdate.Run(dryRun != nil && *dryRun, preview != nil && *preview)
}
