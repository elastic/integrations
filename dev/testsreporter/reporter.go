// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

type reporter struct {
	ghCli            *ghCli
	maxPreviousLinks int
	verbose          bool
}

type reporterOptions struct {
	GhCli            *ghCli
	MaxPreviousLinks int
	Verbose          bool
}

func newReporter(options reporterOptions) reporter {
	return reporter{
		ghCli:            options.GhCli,
		maxPreviousLinks: options.MaxPreviousLinks,
		verbose:          options.Verbose,
	}
}

func (r reporter) Report(ctx context.Context, issue *githubIssue, resultError failureObserver) error {
	links, nextIssue, err := r.updateLinks(ctx, issue, resultError.FirstBuild())
	if err != nil {
		return fmt.Errorf("failed to update links from the error: %w", err)
	}

	resultError.UpdateLinks(*links)

	formatter := resultsFormatter{
		result:           resultError,
		maxPreviousLinks: r.maxPreviousLinks,
	}

	description, err := formatter.Description()
	if err != nil {
		return err
	}

	summary, err := formatter.Summary()
	if err != nil {
		return fmt.Errorf("failed to render issue summary: %w", err)
	}

	nextIssue.SetDescription(description)
	nextIssue.AddLabels(resultError.Labels())

	fmt.Println()
	fmt.Println("---- Issue ----")
	fmt.Printf("Title: %q\n", formatter.Title())
	fmt.Printf("Teams: %q\n", strings.Join(formatter.Owners(), ", "))
	fmt.Printf("Labels: %s\n", strings.Join(nextIssue.Labels(), ", "))
	fmt.Printf("Summary:\n%s", summary)
	fmt.Println("----")
	fmt.Println()
	if r.verbose {
		fmt.Println("---- Full Description ----")
		fmt.Print(description)
		fmt.Println("----")
		fmt.Println()
	}

	return r.createOrUpdateIssue(ctx, nextIssue)
}

func (r reporter) createOrUpdateIssue(ctx context.Context, issue *githubIssue) error {
	if issue.number == 0 {
		fmt.Println("Issue not found, creating a new one...")
		if err := r.ghCli.Create(ctx, issue); err != nil {
			return fmt.Errorf("failed to create issue (title: %s): %w", issue.title, err)
		}
		return nil
	}

	fmt.Printf("Updating issue %s...\n", issue.url)
	if err := r.ghCli.Update(ctx, issue); err != nil {
		return fmt.Errorf("failed to update issue (title: %s): %w", issue.title, err)
	}
	return nil
}

// updateLinks returns the links to buildkite and Github updated depending on whether or not
// it existed a previous Github issue
func (r reporter) updateLinks(ctx context.Context, issue *githubIssue, currentBuild string) (*errorLinks, *githubIssue, error) {
	nextIssue := issue
	links := errorLinks{
		currentIssueURL: "",
		firstBuild:      currentBuild,
		previousBuilds:  []string{},
		closedIssueURL:  "",
	}
	// Look for an existing issue
	found, prevIssue, err := r.ghCli.Exists(ctx, issue, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to check if issue already exists: %w", err)
	}

	if found {
		nextIssue = prevIssue

		fmt.Printf("Found existing open issue: %s\n", prevIssue.URL())
		links.currentIssueURL = prevIssue.URL()

		// Retrieve information from the Issue description (first build, closed issue, previous links)
		firstBuild, err := firstBuildLinkFromDescription(prevIssue)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read first link from issue (title: %s): %w", issue.title, err)
		}
		fmt.Printf("First build found: %s\n", firstBuild)
		links.firstBuild = firstBuild

		closedIssueURL, err := closedIssueFromDescription(prevIssue)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read closed issue from issue (title: %s): %w", issue.title, err)
		}
		links.closedIssueURL = closedIssueURL

		if firstBuild == currentBuild {
			fmt.Println("First time failing, no need to update previous build links.")
		} else {
			previousLinks, err := previousBuildLinksFromDescription(prevIssue)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read previous links from issue (title: %s): %w", issue.title, err)
			}
			previousLinks = updatePreviousLinks(previousLinks, currentBuild, r.maxPreviousLinks)

			links.previousBuilds = previousLinks
		}
	} else {
		fmt.Println("No open issue found for this error.")
		// is there any closed issue
		closedIssueURL, err := r.closedIssueURL(ctx, issue)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to check if there is a closed issue: %w", err)
		}

		links.closedIssueURL = closedIssueURL
	}

	return &links, nextIssue, nil
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
