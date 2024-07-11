// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cli/go-gh/v2"
)

type CommandRunner interface {
	Exec(ctx context.Context, args ...string) (stdout, stdErr bytes.Buffer, err error)
}

type GhRunner struct {
	DryRun bool
}

type GithubOptions struct {
	DryRun bool
	Runner CommandRunner
}

func (g *GhRunner) Exec(ctx context.Context, args ...string) (stdout, stdErr bytes.Buffer, err error) {
	log.Printf("Running command: %s", strings.Join(args[:4], " "))
	if g.DryRun {
		if args[0] != "issue" || args[1] != "list" {
			log.Printf("DRY-RUN> not run command")
			return bytes.Buffer{}, bytes.Buffer{}, nil
		}
	}
	return gh.ExecContext(ctx, args...)
}

type GhCli struct {
	runner CommandRunner
}

func NewGhCli(options GithubOptions) *GhCli {
	var runner CommandRunner
	runner = options.Runner
	if runner == nil {
		runner = &GhRunner{
			DryRun: options.DryRun,
		}
	}

	return &GhCli{
		runner: runner,
	}
}

func (g *GhCli) Exists(ctx context.Context, issue *GithubIssue, open bool) (bool, *GithubIssue, error) {
	stateIssue := "open"
	if !open {
		stateIssue = "closed"
	}
	stdout, stderr, err := g.runner.Exec(ctx,
		"issue",
		"list",
		"--json",
		"title,body,number,labels,state,url,createdAt,closedAt",
		"--repo",
		issue.repository,
		"--search",
		fmt.Sprintf("%s in:title sort:created-desc", issue.title),
		"--limit",
		"1000",
		"--jq",
		"map(select((.labels | length) > 0))| map(.labels = (.labels | map(.name)))",
		"--state",
		stateIssue,
	)
	if err != nil {
		return false, nil, fmt.Errorf("failed to list issues: %w\n%s", err, stderr.String())
	}

	type ResponseListIssue struct {
		CreatedAt time.Time `json:"createdAt"`
		ClosedAt  time.Time `json:"closedAt"`
		Title     string    `json:"title"`
		Body      string    `json:"body"`
		Number    int       `json:"number"`
		Labels    []string  `json:"labels"`
		State     string    `json:"state"`
		URL       string    `json:"url"`
	}

	var list []ResponseListIssue
	err = json.Unmarshal(stdout.Bytes(), &list)
	if err != nil {
		return false, nil, fmt.Errorf("failed to unmarshal list of issues: %w", err)
	}

	if !open {
		// There is no query available to sort by closing time of issues
		sort.Slice(list, func(i, j int) bool {
			return list[i].ClosedAt.After(list[j].ClosedAt)
		})
	}

	for _, i := range list {
		if i.Title == issue.title {
			issueGot := NewGithubIssue(GithubIssueOptions{
				Number:      i.Number,
				Title:       i.Title,
				Description: i.Body,
				Labels:      i.Labels,
				State:       i.State,
				Repository:  issue.repository,
				URL:         i.URL,
			})
			return true, issueGot, nil
		}
	}

	return false, nil, nil
}

func (g *GhCli) Create(ctx context.Context, issue *GithubIssue) error {
	params := []string{
		"issue",
		"create",
		"--title",
		issue.title,
		"--body",
		issue.description,
		"--repo",
		issue.repository,
	}
	for _, label := range issue.labels {
		params = append(params, "--label", label)
	}
	stdout, stderr, err := g.runner.Exec(ctx, params...)
	if err != nil {
		return fmt.Errorf("failed to create issue: %w\n%s", err, stderr.String())
	}
	fmt.Println("Created issue:", stdout.String())
	return nil
}

func (g *GhCli) Update(ctx context.Context, issue *GithubIssue) error {
	params := []string{
		"issue",
		"edit",
		strconv.Itoa(issue.number),
		"--body",
		issue.description,
		"--repo",
		issue.repository,
	}
	_, stderr, err := g.runner.Exec(ctx, params...)
	if err != nil {
		return fmt.Errorf("failed to update issue: %w\n%s", err, stderr.String())
	}
	return nil
}
