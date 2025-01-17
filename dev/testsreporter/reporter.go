// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"context"
	"fmt"
	"regexp"
)

type reporter struct {
	ghCli            *ghCli
	maxPreviousLinks int
}

func newReporter(ghCli *ghCli, maxPreviousLinks int) reporter {
	return reporter{
		ghCli:            ghCli,
		maxPreviousLinks: maxPreviousLinks,
	}
}

func (r reporter) Report(ctx context.Context, issue *githubIssue, packageError packageError) error {
	pTestError, existingIssue, err := r.updatePackageError(ctx, issue, packageError)
	if err != nil {
		return fmt.Errorf("found error updating issue information: %w", err)
	}

	if !existingIssue {
		fmt.Println("Issue not found, creating a new one...")
		if err := r.ghCli.Create(ctx, issue); err != nil {
			return fmt.Errorf("failed to create issue (title: %s): %w", issue.title, err)
		}
		return nil
	}

	fmt.Printf("Updating issue %s...\n", issue.url)
	if err := r.updateIssueLatestData(ctx, issue, *pTestError); err != nil {
		return fmt.Errorf("failed to update previous links in issue (title: %s): %w", issue.title, err)
	}

	return nil
}

func (r reporter) updatePackageError(ctx context.Context, issue *githubIssue, packageTestError packageError) (*packageError, bool, error) {
	pErrorOptions := packageErrorOptions{
		Serverless:        packageTestError.Serverless,
		ServerlessProject: packageTestError.ServerlessProject,
		LogsDB:            packageTestError.LogsDB,
		StackVersion:      packageTestError.StackVersion,
		TestCase:          packageTestError.testCase,
		BuildURL:          packageTestError.BuildURL,
		Teams:             packageTestError.Teams,
		PreviousBuilds:    []string{},
	}
	// Look for an existing issue
	found, prevIssue, err := r.ghCli.Exists(ctx, issue, true)
	if err != nil {
		return nil, false, fmt.Errorf("failed to check if issue already exists: %w", err)
	}

	if found {
		fmt.Println("Found existing open issue", prevIssue.URL())

		// update links
		// Retrieve information from the Issue description (first build, closed issue, previous links)
		firstBuild, err := firstBuildLinkFromDescription(prevIssue)
		if err != nil {
			return nil, false, fmt.Errorf("failed to read first link from issue (title: %s): %w", issue.title, err)
		}
		fmt.Printf("First build found: %s\n", firstBuild)
		pErrorOptions.BuildURL = firstBuild

		closedIssueURL, err := closedIssueFromDescription(prevIssue)
		if err != nil {
			return nil, false, fmt.Errorf("failed to read closed issue from issue (title: %s): %w", issue.title, err)
		}
		pErrorOptions.ClosedIssueURL = closedIssueURL

		if firstBuild == packageTestError.BuildURL {
			fmt.Println("First time failing, no need to update previous build links.")
		} else {
			previousLinks, err := previousBuildLinksFromDescription(prevIssue)
			if err != nil {
				return nil, false, fmt.Errorf("failed to read previous links from issue (title: %s): %w", issue.title, err)
			}
			previousLinks = updatePreviousLinks(previousLinks, packageTestError.BuildURL, r.maxPreviousLinks)

			pErrorOptions.PreviousBuilds = previousLinks
		}
	} else {
		// is there any closed issue
		closedIssueURL, err := r.closedIssueURL(ctx, issue)
		if err != nil {
			return nil, false, fmt.Errorf("failed to check if there is a closed issue: %w", err)
		}

		pErrorOptions.ClosedIssueURL = closedIssueURL
	}

	pTestError, err := newPackageError(pErrorOptions)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create package error with links updated: %w", err)
	}

	return pTestError, found, nil
}

func (r reporter) closedIssueURL(ctx context.Context, issue *githubIssue) (string, error) {
	found, closedIssue, err := r.ghCli.Exists(ctx, issue, false)
	if err != nil {
		return "", fmt.Errorf("failed to check if there is a closed issue: %w", err)
	}
	if found {
		return closedIssue.URL(), nil
	}
	return "", nil
}

func (r reporter) updateIssueLatestData(ctx context.Context, issue *githubIssue, packageError packageError) error {
	formatter := resultsFormatter{
		result:           packageError,
		maxPreviousLinks: r.maxPreviousLinks,
	}
	issue.SetDescription(formatter.Description())

	if err := r.ghCli.Update(ctx, issue); err != nil {
		return fmt.Errorf("failed to update issue (title: %s): %w", issue.title, err)
	}
	return nil
}

func updatePreviousLinks(previousLinks []string, currentBuild string, maxPreviousLinks int) []string {
	newLinks := []string{}
	newLinks = append(newLinks, previousLinks...)
	newLinks = append(newLinks, currentBuild)

	if len(newLinks) > maxPreviousLinks {
		firstIndex := len(newLinks) - maxPreviousLinks
		newLinks = newLinks[firstIndex:]
	}

	return newLinks
}

func firstBuildLinkFromDescription(issue *githubIssue) (string, error) {
	description := issue.description
	re := regexp.MustCompile(`First build failed: (?P<url>https://buildkite\.com/elastic/integrations(-serverless)?/builds/\d+)`)

	links := []string{}
	for _, matches := range re.FindAllStringSubmatch(description, -1) {
		for i, name := range re.SubexpNames() {
			if i == 0 || name != "url" {
				continue
			}

			links = append(links, matches[i])
		}
	}
	if len(links) != 1 {
		return "", fmt.Errorf("incorrect number of links found for the first build: %d", len(links))
	}
	return links[0], nil
}

func closedIssueFromDescription(issue *githubIssue) (string, error) {
	description := issue.description
	re := regexp.MustCompile(`Latest issue closed for the same test: (?P<url>https://github\.com/elastic/integrations/issues/\d+)`)

	links := []string{}
	for _, matches := range re.FindAllStringSubmatch(description, -1) {
		for i, name := range re.SubexpNames() {
			if i == 0 || name != "url" {
				continue
			}

			links = append(links, matches[i])
		}
	}
	if len(links) > 1 {
		return "", fmt.Errorf("incorrect number of issues found for the previous closed issue: %d", len(links))
	}
	if len(links) == 0 {
		return "", nil
	}
	return links[0], nil
}

func previousBuildLinksFromDescription(issue *githubIssue) ([]string, error) {
	description := issue.description
	re := regexp.MustCompile(`- (?P<url>https://buildkite\.com/elastic/integrations(-serverless)?/builds/\d+)`)

	links := []string{}
	for _, matches := range re.FindAllStringSubmatch(description, -1) {
		for i, name := range re.SubexpNames() {
			if i == 0 || name != "url" {
				continue
			}

			links = append(links, matches[i])
		}
	}
	return links, nil
}
