// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package issuesreporter

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/elastic/integrations/dev/codeowners"
)

type PackageError struct {
	testCase
	Serverless     bool
	StackVersion   string
	BuildURL       string
	Teams          []string
	PackageName    string
	DataStream     string
	PreviousBuilds []string
}

type PackageErrorOptions struct {
	Serverless     bool
	StackVersion   string
	BuildURL       string
	TestCase       testCase
	CodeownersPath string
}

func NewPackageError(options PackageErrorOptions) (*PackageError, error) {
	p := PackageError{
		Serverless:   options.Serverless,
		StackVersion: options.StackVersion,
		BuildURL:     options.BuildURL,
		testCase:     options.TestCase,
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

	return &p, nil
}

func (p PackageError) String() string {
	var sb strings.Builder

	if p.Serverless {
		sb.WriteString("[Serverless] ")
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

type checkOptions struct {
	ResultsPath    string
	Serverless     bool
	StackVersion   string
	BuildURL       string
	CodeownersPath string
}

func Check(username, resultsPath, buildURL, stackVersion string, serverless bool) error {
	fmt.Println("path: ", resultsPath)
	packageErrors, err := errorsFromTests(checkOptions{
		ResultsPath:  resultsPath,
		Serverless:   serverless,
		StackVersion: stackVersion,
		BuildURL:     buildURL,
	})
	if err != nil {
		return err
	}
	ghCli := NewGhCli(GithubOptions{
		DryRun: true,
	})
	for _, e := range packageErrors {
		r := ResultsFormatter{e}
		fmt.Println()
		fmt.Println("---- Issue ----")
		fmt.Printf("Title: %q\n", r.Title())
		fmt.Printf("Teams: %q\n", strings.Join(r.Owners(), ", "))
		fmt.Printf("Description:\n%s\n", r.Description())
		fmt.Println("----")
		fmt.Println()

		ghIssue := NewGithubIssue(GithubIssueOptions{
			Title:       r.Title(),
			Description: r.Description(),
			Labels:      []string{"failed-test", "automation"},
			Repository:  "elastic/integrations",
			User:        username,
		})

		ctx := context.TODO()
		found, issue, err := ghCli.Exists(ctx, *ghIssue)
		if err != nil {
			return fmt.Errorf("failed to check if issue exists: %w", err)
		}
		fmt.Printf("Issue found: %t (%d)\n", found, issue.Number())
		if !found {
			// create issue
			err := ghCli.Create(ctx, *ghIssue)
			if err != nil {
				log.Printf("Failed to create issue: %s", err)
			}
			continue
		}
		// update issue

		return nil
	}
	return nil
}

func buildLinksFromDescription(issue GithubIssue) ([]string, error) {
	description := issue.description
	re := regexp.MustCompile(`- (?P<url>https://buildkite\.com/elastic/integrations(-serverless)?/builds/\d+)`)

	links := []string{}
	for _, matches := range re.FindAllStringSubmatch(description, -1) {
		for i, name := range re.SubexpNames() {
			if i == 0 || name != "url" {
				continue
			}

			fmt.Println("Match found:", matches[i])
			links = append(links, matches[i])
		}
	}
	return links, nil
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
		fmt.Println("Reading file:", path)
		cases, err := testFailures(path)
		if err != nil {
			return err
		}

		for _, c := range cases {
			packageError, err := NewPackageError(PackageErrorOptions{
				Serverless:     options.Serverless,
				StackVersion:   options.StackVersion,
				BuildURL:       options.BuildURL,
				TestCase:       c,
				CodeownersPath: options.CodeownersPath,
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
