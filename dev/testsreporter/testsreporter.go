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
	"strings"

	"github.com/elastic/integrations/dev/codeowners"
)

type CheckOptions struct {
	Serverless        bool
	ServerlessProject string
	LogsDB            bool
	StackVersion      string
	BuildURL          string
	CodeownersPath    string

	MaxPreviousLinks int
	MaxTestsReported int

	DryRun bool
}

func Check(resultsPath string, options CheckOptions) error {
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

	if len(packageErrors) > options.MaxTestsReported {
		fmt.Printf("Skip creating GitHub issues, hit the maximum number (%d) of tests to be reported. Total failing tests: %d.\n", options.MaxTestsReported, len(packageErrors))
		return nil
	}

	ghCli := newGhCli(githubOptions{
		DryRun: options.DryRun,
	})

	aReporter := newReporter(ghCli, options.MaxPreviousLinks)

	var multiErr error
	for _, pError := range packageErrors {
		ctx := context.TODO()
		r := resultsFormatter{
			result:           &pError,
			maxPreviousLinks: options.MaxPreviousLinks,
		}
		fmt.Println()
		fmt.Println("---- Issue ----")
		fmt.Printf("Title: %q\n", r.Title())
		fmt.Printf("Teams: %q\n", strings.Join(r.Owners(), ", "))
		fmt.Printf("Summary:\n%s\n", r.Summary())
		fmt.Println("----")
		fmt.Println()

		ghIssue := newGithubIssue(githubIssueOptions{
			Title:       r.Title(),
			Description: r.Description(),
			Labels:      []string{"flaky-test", "automation"},
			Repository:  "elastic/integrations",
		})

		if err := aReporter.Report(ctx, ghIssue, &pError); err != nil {
			multiErr = errors.Join(multiErr, err)
		}
	}
	return multiErr
}

func errorsFromTests(resultsPath string, options CheckOptions) ([]packageError, error) {
	var packageErrors []packageError
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
				BuildURL:          options.BuildURL,
				TestCase:          c,
				CodeownersPath:    options.CodeownersPath,
			})
			if err != nil {
				return fmt.Errorf("failed to create package error: %w", err)
			}
			packageErrors = append(packageErrors, *packageError)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to look for errors: %w", err)
	}

	return packageErrors, nil
}
