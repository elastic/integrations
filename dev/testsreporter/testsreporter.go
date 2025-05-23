// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/elastic/integrations/dev/codeowners"
)

type CheckOptions struct {
	Serverless        bool
	ServerlessProject string
	LogsDB            bool
	StackVersion      string
	Subscription      string
	BuildURL          string
	CodeownersPath    string

	MaxPreviousLinks int
	MaxTestsReported int

	DryRun  bool
	Verbose bool
}

func Check(ctx context.Context, resultsPath string, options CheckOptions) error {
	if options.CodeownersPath == "" {
		// set default value for the GitHub CODEOWNERS file
		options.CodeownersPath = codeowners.DefaultCodeownersPath
	}

	if options.DryRun {
		fmt.Println("DRY_RUN mode enabled")
	}

	fmt.Println("path: ", resultsPath)
	packageErrors, err := errorsFromTests(resultsPath, options)
	if err != nil {
		return err
	}

	ghCli := newGhCli(githubOptions{
		DryRun: options.DryRun,
	})

	aReporter := newReporter(reporterOptions{
		GhCli:            ghCli,
		MaxPreviousLinks: options.MaxPreviousLinks,
		Verbose:          options.Verbose,
	})

	if len(packageErrors) > options.MaxTestsReported {
		fmt.Printf("Skip creating GitHub issues, hit the maximum number (%d) of tests to be reported. Total failing tests: %d.\n", options.MaxTestsReported, len(packageErrors))
		packages, err := packagesFromTests(resultsPath)
		if err != nil {
			return fmt.Errorf("failed to get packages from results files: %w", err)
		}
		bError, err := newBuildError(buildErrorOptions{
			Serverless:        options.Serverless,
			ServerlessProject: options.ServerlessProject,
			LogsDB:            options.LogsDB,
			StackVersion:      options.StackVersion,
			Subscription:      options.Subscription,
			BuildURL:          options.BuildURL,
			Packages:          packages,
		})
		if err != nil {
			return fmt.Errorf("failed to create the build information error: %w", err)
		}

		ghIssue, err := createInitialIssue(bError, options.MaxPreviousLinks)
		if err != nil {
			return fmt.Errorf("failed to create initial issue: %w", err)
		}

		if err := aReporter.Report(ctx, ghIssue, bError); err != nil {
			return err
		}
		return nil
	}

	var multiErr error
	for _, pError := range packageErrors {
		ghIssue, err := createInitialIssue(pError, options.MaxPreviousLinks)
		if err != nil {
			return fmt.Errorf("failed to create initial issue: %w", err)
		}

		if err := aReporter.Report(ctx, ghIssue, pError); err != nil {
			multiErr = errors.Join(multiErr, err)
		}
	}
	return multiErr
}

func errorsFromTests(resultsPath string, options CheckOptions) ([]*packageError, error) {
	var packageErrors []*packageError
	err := filepath.Walk(resultsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) != ".xml" {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		cases, err := testFailures(path)
		if err != nil {
			return err
		}

		for _, c := range cases {
			packageError, err := newPackageError(packageErrorOptions{
				Serverless:        options.Serverless,
				ServerlessProject: options.ServerlessProject,
				LogsDB:            options.LogsDB,
				StackVersion:      options.StackVersion,
				Subscription:      options.Subscription,
				BuildURL:          options.BuildURL,
				TestCase:          c,
				CodeownersPath:    options.CodeownersPath,
			})
			if err != nil {
				return fmt.Errorf("failed to create package error: %w", err)
			}
			packageErrors = append(packageErrors, packageError)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to look for errors: %w", err)
	}

	return packageErrors, nil
}

// packagesFromTests returns the sorted packages failing given the results file
func packagesFromTests(resultsPath string) ([]string, error) {
	packages := []string{}
	err := filepath.Walk(resultsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) != ".xml" {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		cases, err := testFailures(path)
		if err != nil {
			return err
		}
		if len(cases) > 0 {
			name := cases[0].PackageName()
			packages = append(packages, name)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to look for errors: %w", err)
	}

	sort.Strings(packages)

	return packages, nil
}

func createInitialIssue(resultError failureObserver, maxPreviousLinks int) (*githubIssue, error) {
	r := resultsFormatter{
		result:           resultError,
		maxPreviousLinks: maxPreviousLinks,
	}

	description, err := r.Description()
	if err != nil {
		return nil, fmt.Errorf("failed to render initial description: %w", err)
	}
	issue := newGithubIssue(githubIssueOptions{
		Title:       r.Title(),
		Description: description,
		Labels:      []string{"flaky-test", "automation"},
		Repository:  "elastic/integrations",
	})
	return issue, nil
}
