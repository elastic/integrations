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
	"os"
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
	log.Printf("Running command: %s", strings.Join(args, " "))
	if g.DryRun {
		if !(args[0] == "issue" && args[1] == "list") {
			log.Printf("DRY-RUN> not run command")
			return bytes.Buffer{}, bytes.Buffer{}, nil
		}
	}
	return gh.ExecContext(ctx, args...)
}

type GithubIssue struct {
	repository  string
	user        string
	number      int
	title       string
	description string
	labels      []string
}

func (i *GithubIssue) Number() int {
	return i.number
}

type GithubIssueOptions struct {
	Repository  string
	Title       string
	Description string
	Labels      []string
}

func NewGithubIssue(options GithubIssueOptions) *GithubIssue {
	issue := GithubIssue{
		title:       options.Title,
		description: options.Description,
		repository:  options.Repository,
		labels:      options.Labels,
	}

	user := os.Getenv("GITHUB_USERNAME_SECRET")
	issue.user = user
	if user == "" {
		issue.user = "mrodm"
	}

	return &issue
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
		"title,body,number,createdAt",
		"--repo",
		issue.repository,
	)
	if err != nil {
		return false, GithubIssue{}, fmt.Errorf("failed to list issues: %w\n%s", err, stderr.String())
	}

	type ResponseListIssue struct {
		CreatedAt string `json:"createdAt"`
		Title     string `json:"title"`
		Body      string `json:"body"`
		Number    int    `json:"number"`
	}

	var list []ResponseListIssue
	err = json.Unmarshal(stdout.Bytes(), &list)
	if err != nil {
		return false, GithubIssue{}, fmt.Errorf("failed to unmarshal list of issues: %w", err)
	}

	for _, i := range list {
		if i.Title == issue.title {
			issue.number = i.Number
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

func addGithubComment() error {
	return nil
}

type githubData struct {
	owner        string
	name         string
	id           string
	resourceType string
}

// func (g githubData) repository() string {
// 	return fmt.Sprintf("%s/%s", g.owner, g.name)
// }
//
// func (g githubData) resource() (string, error) {
// 	switch g.resourceType {
// 	case "pull":
// 		return "pr", nil
// 	case "issues":
// 		return "issue", nil
// 	default:
// 		return "", fmt.Errorf("unexpected resource type %q", g.resourceType)
// 	}
// }
//
// func newGithubData(link string) (githubData, error) {
// 	u, err := url.Parse(link)
// 	if err != nil {
// 		return githubData{}, err
// 	}
//
// 	// Example of PR link https://github.com/elastic/integrations/pull/1
// 	// Path /elastic/integrations/pull/1
// 	fields := strings.Split(u.Path, "/")
// 	if len(fields) != 5 {
// 		return githubData{}, fmt.Errorf("link in changelog is not valid: %s", link)
// 	}
// 	data := githubData{
// 		owner:        fields[1],
// 		name:         fields[2],
// 		resourceType: fields[3],
// 		id:           fields[4],
// 	}
// 	return data, nil
// }
//
// func addComments(options Options, cases []testCase) error {
// 	for _, entry := range cases {
// 		data, err := newGithubData(entry.Link)
// 		if err != nil {
// 			log.Printf("Package link not able to be parsed: %s", entry.Link)
// 			continue
// 		}
//
// 		comment := buildCommentPR(packageName, packageVersion)
//
// 		resource, err := data.resource()
// 		if err != nil {
// 			log.Printf("Resource link not valid: %s", err)
// 			continue
// 		}
// 		if options.DryRun {
// 			log.Printf("Would Run command: gh %s comment %s --body \"%s\" -R %s", resource, data.id, comment, data.repository())
// 			continue
// 		}
//
// 		_, stdErr, err := options.Runner.Exec(resource, "comment", data.id, "--body", comment, "-R", data.repository())
// 		if err != nil {
// 			log.Printf("Not able to add comment into %s: %s", entry.Link, stdErr.String())
// 		}
// 	}
// 	return nil
// }
//
// func buildCommentPR(packageName, packageVersion string) string {
// 	return fmt.Sprintf("Package %s - %s containing this change is available at https://epr.elastic.co/search?package=%s", packageName, packageVersion, packageName)
// }
//
