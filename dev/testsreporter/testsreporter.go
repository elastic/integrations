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

const defaultPackagesPath = "packages"

type CheckOptions struct {
	Serverless        bool
	ServerlessProject string
	LogsDB            bool
	StackVersion      string
	Subscription      string
	BuildURL          string
	CodeownersPath    string
	// PackagesPath is the path to the folder with the packages, relative to the root of the repository.
	// The owners of the packages are found using the name of the package in its manifest.
	// Defaults to "packages".
	PackagesPath string

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
	if options.PackagesPath == "" {
		options.PackagesPath = defaultPackagesPath
	}

	if options.DryRun {
		fmt.Println("DRY_RUN mode enabled")
	}

	fmt.Println("path: ", resultsPath)
	packageErrors, err := errorsFromTests(resultsPath, options)
	if err != nil {
		return err
	}

	// Failures are reported even if their owners cannot be found, the problems with the
	// owners are returned once all the failures have been reported.
	reportErr := reportPackageErrors(ctx, resultsPath, options, packageErrors)
	return errors.Join(reportErr, ownersProblems(packageErrors))
}

// ownersProblems returns the distinct errors found looking for the owners of the packages.
func ownersProblems(packageErrors []*packageError) error {
	var problems error
	seen := map[string]struct{}{}
	for _, pError := range packageErrors {
		if pError.ownersErr == nil {
			continue
		}
		msg := pError.ownersErr.Error()
		if _, found := seen[msg]; found {
			continue
		}
		seen[msg] = struct{}{}
		problems = errors.Join(problems, pError.ownersErr)
	}
	if problems == nil {
		return nil
	}
	return fmt.Errorf("failures reported without owners: %w", problems)
}

func reportPackageErrors(ctx context.Context, resultsPath string, options CheckOptions, packageErrors []*packageError) error {
	ghCli := newGhCli(githubOptions{
		DryRun: options.DryRun,
	})

	aReporter := newReporter(reporterOptions{
		GhCli:            ghCli,
		MaxPreviousLinks: options.MaxPreviousLinks,
		Verbose:          options.Verbose,
	})

	if len(packageErrors) > options.MaxTestsReported {
		fmt.Printf("Skip creating GitHub issues, hit the maximum number (%d) of tests to report. Total failing tests: %d.\n", options.MaxTestsReported, len(packageErrors))
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
	// Failures are still reported, without owners, if the resolver cannot be created,
	// and the error is returned at the end.
	var resolverErr error
	resolver, err := newOwnersResolver(options.CodeownersPath, options.PackagesPath)
	if err != nil {
		resolverErr = fmt.Errorf("failed to create resolver of package owners: %w", err)
	}

	var packageErrors []*packageError
	err = filepath.Walk(resultsPath, func(path string, info os.FileInfo, err error) error {
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
				OwnersResolver:    resolver,
				OwnersError:       resolverErr,
				// A package without owners must not avoid reporting the rest of failures.
				AllowMissingOwners: true,
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
