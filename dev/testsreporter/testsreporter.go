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
)

type checkOptions struct {
	ResultsPath       string
	Serverless        bool
	ServerlessProject string
	StackVersion      string
	BuildURL          string
	CodeownersPath    string
}

func Check(resultsPath, buildURL, stackVersion string, serverless bool, serverlessProject string, maxPreviousLinks, maxTestsReported int) error {
	fmt.Println("path: ", resultsPath)
	packageErrors, err := errorsFromTests(checkOptions{
		ResultsPath:       resultsPath,
		Serverless:        serverless,
		ServerlessProject: serverlessProject,
		StackVersion:      stackVersion,
		BuildURL:          buildURL,
	})
	if err != nil {
		return err
	}
	ghCli := NewGhCli(GithubOptions{
		DryRun: false,
	})

	aReporter := reporter{
		ghCli:            ghCli,
		maxPreviousLinks: maxPreviousLinks,
	}

	if len(packageErrors) > maxTestsReported {
		fmt.Printf("Skip creating GitHub issues, hit the maximum number (%d) of tests to be reported. Total failing tests: %d.\n", maxTestsReported, len(packageErrors))
		return nil
	}

	var multiErr error
	for _, pError := range packageErrors {
		ctx := context.TODO()
		r := ResultsFormatter{
			result:           pError,
			maxPreviousLinks: maxPreviousLinks,
		}
		fmt.Println()
		fmt.Println("---- Issue ----")
		fmt.Printf("Title: %q\n", r.Title())
		fmt.Printf("Teams: %q\n", strings.Join(r.Owners(), ", "))
		fmt.Printf("Summary:\n%s\n", r.Summary())
		fmt.Println("----")
		fmt.Println()

		ghIssue := NewGithubIssue(GithubIssueOptions{
			Title:       r.Title(),
			Description: r.Description(),
			Labels:      []string{"flaky-test", "automation"},
			Repository:  "elastic/integrations",
		})

		if err := aReporter.Report(ctx, ghIssue, pError); err != nil {
			multiErr = errors.Join(multiErr, err)
		}
	}
	return multiErr
}

func errorsFromTests(options checkOptions) ([]PackageError, error) {
	var packageErrors []PackageError
	err := filepath.Walk(options.ResultsPath, func(path string, info os.FileInfo, err error) error {
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
			packageError, err := NewPackageError(PackageErrorOptions{
				Serverless:        options.Serverless,
				ServerlessProject: options.ServerlessProject,
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
