// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"bytes"
	"context"
	"log"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testReporterRunner struct {
	args     []string
	response map[string]string
}

func (t *testReporterRunner) Exec(ctx context.Context, args ...string) (stdout, stderr bytes.Buffer, err error) {
	t.args = args
	log.Printf("Adding args: %s", args)
	response := ""
	if slices.Contains(args, "open") {
		response = t.response["open"]
	} else {
		response = t.response["closed"]
	}
	if response == "" {
		return bytes.Buffer{}, bytes.Buffer{}, nil
	}

	return *bytes.NewBufferString(response), bytes.Buffer{}, nil
}

func TestReporterUpdateLinks(t *testing.T) {
	cases := []struct {
		title         string
		issue         *githubIssue
		firstBuild    string
		response      map[string]string
		expectedLinks errorLinks
		expectedIssue *githubIssue
	}{
		{
			title: "no previous issue",
			response: map[string]string{
				"open":   `[]`,
				"closed": `[]`,
			},
			firstBuild: "https://buildkite.com/elastic/integrations/builds/100",
			issue: newGithubIssue(githubIssueOptions{
				Title:      "my issue",
				Repository: "myorg/repo",
			}),
			expectedLinks: errorLinks{
				firstBuild:     "https://buildkite.com/elastic/integrations/builds/100",
				closedIssueURL: "",
				previousBuilds: []string{},
			},
			expectedIssue: &githubIssue{
				title:      "my issue",
				repository: "myorg/repo",
			},
		},
		{
			title: "existing just open issue",
			response: map[string]string{
				"open": `
			[
			  {
			     "createdAt": "2024-06-24T15:04:05Z",
				 "title": "my issue",
				 "body": "First build failed: https://buildkite.com/elastic/integrations/builds/1\nLatest issue closed for the same test: https://github.com/elastic/integrations/issues/5\nPrevious builds:\n- https://buildkite.com/elastic/integrations/builds/11",
				 "number": 42,
				 "state": "OPEN",
				 "url": "https://github.com/elastic/integrations/issues/42"
			  }
			]`,
				"closed": `[]`,
			},
			firstBuild: "https://buildkite.com/elastic/integrations/builds/100",
			issue: newGithubIssue(githubIssueOptions{
				Title:      "my issue",
				Repository: "myorg/repo",
			}),
			expectedLinks: errorLinks{
				currentIssueURL: "https://github.com/elastic/integrations/issues/42",
				firstBuild:      "https://buildkite.com/elastic/integrations/builds/1",
				closedIssueURL:  "https://github.com/elastic/integrations/issues/5",
				previousBuilds: []string{
					"https://buildkite.com/elastic/integrations/builds/11",
					"https://buildkite.com/elastic/integrations/builds/100",
				},
			},
			expectedIssue: &githubIssue{
				title:       "my issue",
				repository:  "myorg/repo",
				number:      42,
				state:       "OPEN",
				description: "First build failed: https://buildkite.com/elastic/integrations/builds/1\nLatest issue closed for the same test: https://github.com/elastic/integrations/issues/5\nPrevious builds:\n- https://buildkite.com/elastic/integrations/builds/11",
				url:         "https://github.com/elastic/integrations/issues/42",
			},
		},
		{
			title: "existing open and close issue",
			response: map[string]string{
				"open": `
			[
			  {
			     "createdAt": "2024-06-24T15:04:05Z",
				 "title": "my issue",
				 "body": "First build failed: https://buildkite.com/elastic/integrations/builds/1\nLatest issue closed for the same test: https://github.com/elastic/integrations/issues/5",
				 "number": 42,
				 "state": "OPEN",
				 "url": "https://github.com/elastic/integrations/issues/42"
			  }
			]`,
				"closed": `
			[
			  {
			     "createdAt": "2024-06-24T15:04:05Z",
				 "title": "my issue",
				 "body": "First build failed: https://buildkite.com/elastic/integrations/builds/1\nLatest issue closed for the same test: https://github.com/elastic/integrations/issues/42",
				 "number": 21,
				 "state": "CLOSED",
				 "url": "https://github.com/elastic/integrations/issues/21"
			  }
			]`,
			},
			firstBuild: "https://buildkite.com/elastic/integrations/builds/100",
			issue: newGithubIssue(githubIssueOptions{
				Title:      "my issue",
				Repository: "myorg/repo",
			}),
			expectedLinks: errorLinks{
				currentIssueURL: "https://github.com/elastic/integrations/issues/42",
				firstBuild:      "https://buildkite.com/elastic/integrations/builds/1",
				closedIssueURL:  "https://github.com/elastic/integrations/issues/5",
				previousBuilds: []string{
					"https://buildkite.com/elastic/integrations/builds/100",
				},
			},
			expectedIssue: &githubIssue{
				title:       "my issue",
				repository:  "myorg/repo",
				number:      42,
				state:       "OPEN",
				description: "First build failed: https://buildkite.com/elastic/integrations/builds/1\nLatest issue closed for the same test: https://github.com/elastic/integrations/issues/5",
				url:         "https://github.com/elastic/integrations/issues/42",
			},
		},
		{
			title: "existing just closed issue",
			response: map[string]string{
				"open": `[]`,
				"closed": `
			[
			  {
			     "createdAt": "2024-06-24T15:04:05Z",
				 "title": "my issue",
				 "body": "First build failed: https://buildkite.com/elastic/integrations/builds/1\nLatest issue closed for the same test: https://github.com/elastic/integrations/issues/2",
				 "number": 21,
				 "state": "CLOSED",
				 "url": "https://github.com/elastic/integrations/issues/21"
			  }
			]`,
			},
			firstBuild: "https://buildkite.com/elastic/integrations/builds/100",
			issue: newGithubIssue(githubIssueOptions{
				Title:      "my issue",
				Repository: "myorg/repo",
			}),
			expectedLinks: errorLinks{
				currentIssueURL: "",
				firstBuild:      "https://buildkite.com/elastic/integrations/builds/100",
				closedIssueURL:  "https://github.com/elastic/integrations/issues/21",
				previousBuilds:  []string{},
			},
			expectedIssue: &githubIssue{
				title:       "my issue",
				repository:  "myorg/repo",
				number:      0,
				state:       "",
				description: "",
				url:         "",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			runner := testReporterRunner{
				response: c.response,
			}
			ghCli := newGhCli(githubOptions{
				DryRun: true,
				Runner: &runner,
			})

			reporter := newReporter(reporterOptions{
				GhCli:            ghCli,
				MaxPreviousLinks: 5,
			})

			links, newIssue, err := reporter.updateLinks(context.Background(), c.issue, c.firstBuild)
			require.NoError(t, err)
			assert.Equal(t, c.expectedLinks, *links)
			assert.Equal(t, c.expectedIssue, newIssue)
		})
	}
}
