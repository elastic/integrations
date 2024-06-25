// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"bytes"
	"context"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testRunner struct {
	args     []string
	response string
}

func (t *testRunner) Exec(ctx context.Context, args ...string) (stdout, stderr bytes.Buffer, err error) {
	t.args = args
	log.Printf("Adding args: %s", args)
	if t.response == "" {
		return bytes.Buffer{}, bytes.Buffer{}, nil
	}

	return *bytes.NewBufferString(t.response), bytes.Buffer{}, nil
}

func TestCreateIssue(t *testing.T) {
	cases := []struct {
		title    string
		issue    *GithubIssue
		expected []string
	}{
		{
			title: "issue without labels",
			issue: NewGithubIssue(GithubIssueOptions{
				Title:       "my issue",
				Description: "This is my issue",
				Repository:  "myorg/repo",
			}),
			expected: []string{
				"issue",
				"create",
				"--title",
				"my issue",
				"--body",
				"This is my issue",
				"--repo",
				"myorg/repo",
			},
		},
		{
			title: "issue with labels",
			issue: NewGithubIssue(GithubIssueOptions{
				Title:       "my issue labels",
				Description: "This is my issue",
				Repository:  "myorg/repo",
				Labels:      []string{"automation", "test"},
			}),
			expected: []string{
				"issue",
				"create",
				"--title",
				"my issue labels",
				"--body",
				"This is my issue",
				"--repo",
				"myorg/repo",
				"--label",
				"automation",
				"--label",
				"test",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			runner := testRunner{}
			ghCli := NewGhCli(GithubOptions{
				DryRun: true,
				Runner: &runner,
			})

			err := ghCli.Create(context.Background(), c.issue)
			require.NoError(t, err)

			assert.Equal(t, c.expected, runner.args)
		})
	}
}

func TestGithubIssueExists(t *testing.T) {
	cases := []struct {
		title    string
		issue    *GithubIssue
		response string
		found    bool
		open     bool
		expected *GithubIssue
	}{
		{
			title: "issue found",
			response: `
			[
			  {
			     "createdAt": "2024-06-24T15:04:05Z",
				 "title": "my issue",
				 "body": "my issue description",
				 "number": 42,
				 "state": "OPEN"
			  }
			]
			`,
			issue: NewGithubIssue(GithubIssueOptions{
				Title:      "my issue",
				Repository: "myorg/repo",
				User:       "foo",
			}),
			found: true,
			open:  true,
			expected: &GithubIssue{
				repository:  "myorg/repo",
				number:      42,
				title:       "my issue",
				description: "my issue description",
				user:        "foo",
				state:       "OPEN",
			},
		},
		{
			title: "issue not found",
			response: `
			[
			  {
			     "createdAt": "2024-06-24T15:04:05Z",
				 "title": "not my issue",
				 "body": "my issue description",
				 "number": 42,
				 "state": "OPEN"
			  }
			]
			`,
			issue: NewGithubIssue(GithubIssueOptions{
				Title:      "my issue",
				Repository: "myorg/repo",
				User:       "foo",
			}),
			open:     true,
			found:    false,
			expected: nil,
		},
		{
			title: "issue closed found",
			response: `
			[
			  {
			     "createdAt": "2024-06-24T15:04:05Z",
			     "closedAt": "2024-06-24T16:04:05Z",
				 "title": "my issue",
				 "body": "my issue description",
				 "number": 42,
				 "state": "CLOSED"
			  }
			]
			`,
			issue: NewGithubIssue(GithubIssueOptions{
				Title:      "my issue",
				Repository: "myorg/repo",
				User:       "foo",
				Number:     42,
			}),
			open:  false,
			found: true,
			expected: &GithubIssue{
				repository:  "myorg/repo",
				number:      42,
				title:       "my issue",
				description: "my issue description",
				user:        "foo",
				state:       "CLOSED",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			runner := testRunner{
				response: c.response,
			}
			ghCli := NewGhCli(GithubOptions{
				DryRun: true,
				Runner: &runner,
			})

			found, issue, err := ghCli.Exists(context.Background(), c.issue, c.open)
			require.NoError(t, err)
			assert.Equal(t, c.found, found)
			assert.Equal(t, c.expected, issue)
		})
	}
}

func TestUpdateIssue(t *testing.T) {
	cases := []struct {
		title    string
		issue    *GithubIssue
		expected []string
	}{
		{
			title: "issue",
			issue: NewGithubIssue(GithubIssueOptions{
				Title:       "my issue",
				Description: "This is my new issue",
				Repository:  "myorg/repo",
				Number:      42,
			}),
			expected: []string{
				"issue",
				"edit",
				"42",
				"--body",
				"This is my new issue",
				"--repo",
				"myorg/repo",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			runner := testRunner{}
			ghCli := NewGhCli(GithubOptions{
				DryRun: true,
				Runner: &runner,
			})

			err := ghCli.Update(context.Background(), c.issue)
			require.NoError(t, err)

			assert.Equal(t, c.expected, runner.args)
		})
	}
}
