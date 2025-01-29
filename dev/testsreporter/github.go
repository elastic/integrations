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

type commandRunner interface {
	Exec(ctx context.Context, args ...string) (stdout, stdErr bytes.Buffer, err error)
}

type ghRunner struct {
	DryRun bool
}

type githubOptions struct {
	DryRun bool
	Runner commandRunner
}

func (g *ghRunner) Exec(ctx context.Context, args ...string) (stdout, stdErr bytes.Buffer, err error) {
	log.Printf("Running command: %s", strings.Join(args[:4], " "))
	if g.DryRun {
		if args[0] != "issue" || args[1] != "list" {
			log.Printf("DRY-RUN> not run command")
			return bytes.Buffer{}, bytes.Buffer{}, nil
		}
	}
	return gh.ExecContext(ctx, args...)
}

type ghCli struct {
	runner commandRunner
}

func newGhCli(options githubOptions) *ghCli {
	var runner commandRunner
	runner = options.Runner
	if runner == nil {
		runner = &ghRunner{
			DryRun: options.DryRun,
		}
	}

	return &ghCli{
		runner: runner,
	}
}

func (g *ghCli) Exists(ctx context.Context, issue *githubIssue, open bool) (bool, *githubIssue, error) {
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

	type responseListIssue struct {
		CreatedAt time.Time `json:"createdAt"`
		ClosedAt  time.Time `json:"closedAt"`
		Title     string    `json:"title"`
		Body      string    `json:"body"`
		Number    int       `json:"number"`
		Labels    []string  `json:"labels"`
		State     string    `json:"state"`
		URL       string    `json:"url"`
	}

	var list []responseListIssue
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
			issueGot := newGithubIssue(githubIssueOptions{
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

func (g *ghCli) Create(ctx context.Context, issue *githubIssue) error {
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

func (g *ghCli) Update(ctx context.Context, issue *githubIssue) error {
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
