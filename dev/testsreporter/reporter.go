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
	ghCli            *GhCli
	maxPreviousLinks int
}

func (r reporter) Report(ctx context.Context, issue *GithubIssue, packageError PackageError) error {
	found, issue, err := r.ghCli.Exists(ctx, issue, true)
	if err != nil {
		return fmt.Errorf("failed to check if issue already exists: %w", err)
	}

	if !found {
		fmt.Println("Issue not found, creating a new one...")
		if err := r.createNewIssueForError(ctx, issue, packageError); err != nil {
			return err
		}
	}

	fmt.Printf("Issue found: %t (%d)\n", found, issue.Number())
	fmt.Println("Updating issue...")
	if err := r.updateIssueLatestBuildLinks(ctx, issue, packageError); err != nil {
		return fmt.Errorf("failed to update previous links in issue (title: %s): %w", issue.title, err)
	}

	return nil
}

func (r reporter) createNewIssueForError(ctx context.Context, issue *GithubIssue, packageError PackageError) error {
	found, closedIssue, err := r.ghCli.Exists(ctx, issue, false)
	if err != nil {
		return fmt.Errorf("failed to check if there is a closed issue: %w", err)
	}
	if found {
		issue = updateDescriptionClosedIssueURL(issue, closedIssue.URL(), packageError, r.maxPreviousLinks)
	}

	if err := r.ghCli.Create(ctx, issue); err != nil {
		return fmt.Errorf("failed to create issue (title: %s): %w", issue.title, err)
	}
	return nil
}

func updateDescriptionClosedIssueURL(issue *GithubIssue, closedIssueURL string, packageError PackageError, maxPreviousLinks int) *GithubIssue {
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

	return updatedIssue
}

func (r reporter) updateIssueLatestBuildLinks(ctx context.Context, issue *GithubIssue, packageError PackageError) error {
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

	packageError.PreviousBuilds = updatePreviousLinks(previousLinks, currentBuild, r.maxPreviousLinks)
	packageError.BuildURL = firstBuild
	formatter := ResultsFormatter{
		result:           packageError,
		maxPreviousLinks: r.maxPreviousLinks,
	}
	issue.description = formatter.Description()

	if err := r.ghCli.Update(ctx, issue); err != nil {
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

func firstBuildLinkFromDescription(issue *GithubIssue) (string, error) {
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

func previousBuildLinksFromDescription(issue *GithubIssue) ([]string, error) {
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
