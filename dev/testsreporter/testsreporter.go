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
	"regexp"
	"strings"

	"github.com/elastic/integrations/dev/codeowners"
)

type PackageError struct {
	testCase
	Serverless        bool
	ServerlessProject string
	StackVersion      string
	BuildURL          string
	Teams             []string
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

type checkOptions struct {
	ResultsPath       string
	Serverless        bool
	ServerlessProject string
	StackVersion      string
	BuildURL          string
	CodeownersPath    string
}

func Check(username, resultsPath, buildURL, stackVersion string, serverless bool, serverlessProject string, maxPreviousLinks int) error {
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
			User:        username,
		})

		found, issue, err := ghCli.Exists(ctx, *ghIssue, true)
		if err != nil {
			return fmt.Errorf("failed to check if issue already exists: %w", err)
		}

		if !found {
			fmt.Println("Issue not found, creating a new one...")
			if err := createNewIssueForError(ctx, ghCli, *ghIssue, pError, maxPreviousLinks); err != nil {
				multiErr = errors.Join(multiErr, err)
			}
			continue
		}

		fmt.Printf("Issue found: %t (%d)\n", found, issue.Number())
		fmt.Println("Updating issue...")
		if err := updateIssueLatestBuildLinks(ctx, ghCli, issue, pError, maxPreviousLinks); err != nil {
			multiErr = errors.Join(multiErr, fmt.Errorf("failed to update previous links in issue (title: %s): %w", ghIssue.title, err))
		}

	}
	return multiErr
}

func createNewIssueForError(ctx context.Context, ghCli *GhCli, issue GithubIssue, packageError PackageError, maxPreviousLinks int) error {
	found, closedIssue, err := ghCli.Exists(ctx, issue, false)
	if err != nil {
		return fmt.Errorf("failed to check if there is a closed issue: %w", err)
	}
	if found {
		issue = updateDescriptionClosedIssueURL(issue, closedIssue.URL(), packageError, maxPreviousLinks)
	}

	if err := ghCli.Create(ctx, issue); err != nil {
		return fmt.Errorf("failed to create issue (title: %s): %w", issue.title, err)
	}
	return nil
}

func updateDescriptionClosedIssueURL(issue GithubIssue, closedIssueURL string, packageError PackageError, maxPreviousLinks int) GithubIssue {
	packageError.ClosedIssueURL = closedIssueURL
	formatter := ResultsFormatter{
		result:           packageError,
		maxPreviousLinks: maxPreviousLinks,
	}
	updatedIssue := NewGithubIssue(GithubIssueOptions{
		Title:       issue.title,
		Number:      issue.number,
		Description: formatter.Description(),
		Labels:      issue.labels,
		State:       issue.state,
		User:        issue.user,
		URL:         issue.url,
		Repository:  issue.repository,
	})

	return *updatedIssue
}

func updateIssueLatestBuildLinks(ctx context.Context, ghCli *GhCli, issue GithubIssue, packageError PackageError, maxPreviousLinks int) error {
	currentBuild := packageError.BuildURL

	firstBuild, err := firstBuildLinkFromDescription(issue)
	if err != nil {
		return fmt.Errorf("failed to read first link from issue (title: %s): %w", issue.title, err)
	}

	if firstBuild == currentBuild {
		return nil
	}

	previousLinks, err := previousBuildLinksFromDescription(issue)
	if err != nil {
		return fmt.Errorf("failed to read previous links from issue (title: %s): %w", issue.title, err)
	}

	packageError.PreviousBuilds = updatePreviousLinks(previousLinks, currentBuild, maxPreviousLinks)
	packageError.BuildURL = firstBuild
	formatter := ResultsFormatter{
		result:           packageError,
		maxPreviousLinks: maxPreviousLinks,
	}
	issue.description = formatter.Description()

	if err := ghCli.Update(ctx, issue); err != nil {
		return fmt.Errorf("failed to update issue (title: %s): %w", issue.title, err)
	}
	return nil
}

func updatePreviousLinks(previousLinks []string, currentBuild string, maxPreviousLinks int) []string {
	var newLinks []string
	newLinks = append(newLinks, previousLinks...)
	newLinks = append(newLinks, currentBuild)

	if len(newLinks) > maxPreviousLinks {
		firstIndex := len(newLinks) - maxPreviousLinks
		newLinks = newLinks[firstIndex:]
	}

	return newLinks
}

func firstBuildLinkFromDescription(issue GithubIssue) (string, error) {
	description := issue.description
	fmt.Printf("description:\n%s\n", description)
	re := regexp.MustCompile(`First build failed: (?P<url>https://buildkite\.com/elastic/integrations(-serverless)?/builds/\d+)`)

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
	if len(links) != 1 {
		return "", fmt.Errorf("incorrect number of links found for the first build: %d", len(links))
	}
	return links[0], nil
}

func previousBuildLinksFromDescription(issue GithubIssue) ([]string, error) {
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
