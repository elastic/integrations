// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package issuesreporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

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

func (g *GhCli) Exists(ctx context.Context, issue GithubIssue) (bool, GithubIssue, error) {
	stdout, stderr, err := g.runner.Exec(ctx,
		"issue",
		"list",
		"--author",
		issue.user,
		"--json",
		"title,body,number,labels,createdAt",
		"--repo",
		issue.repository,
		"--search",
		fmt.Sprintf("%s in:title sort:created-desc", issue.title),
		"--limit",
		"1000",
		"--jq",
		"map(select((.labels | length) > 0))| map(.labels = (.labels | map(.name)))",
	)
	if err != nil {
		return false, GithubIssue{}, fmt.Errorf("failed to list issues: %w\n%s", err, stderr.String())
	}

	type ResponseListIssue struct {
		CreatedAt string   `json:"createdAt"`
		Title     string   `json:"title"`
		Body      string   `json:"body"`
		Number    int      `json:"number"`
		Labels    []string `json:"labels"`
	}

	var list []ResponseListIssue
	err = json.Unmarshal(stdout.Bytes(), &list)
	if err != nil {
		return false, GithubIssue{}, fmt.Errorf("failed to unmarshal list of issues: %w", err)
	}

	for _, i := range list {
		if i.Title == issue.title {
			issue.number = i.Number
			issue.description = i.Body
			issue.labels = i.Labels
			return true, issue, nil
		}
	}

	return false, GithubIssue{}, nil
}

func (g *GhCli) Create(ctx context.Context, issue GithubIssue) error {
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
	_, stderr, err := g.runner.Exec(ctx, params...)
	if err != nil {
		return fmt.Errorf("failed to create issue: %w\n%s", err, stderr.String())
	}
	return nil
}

func (g *GhCli) Update(ctx context.Context, issue GithubIssue) error {
	params := []string{
		"issue",
		"edit",
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
