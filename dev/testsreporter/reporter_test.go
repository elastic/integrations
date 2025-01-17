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

func TestReporterUpdatePackageError(t *testing.T) {
	cases := []struct {
		title    string
		issue    *githubIssue
		response map[string]string
		found    bool
		options  packageErrorOptions
		expected packageError
	}{
		{
			title: "no previous issue",
			response: map[string]string{
				"open":   `[]`,
				"closed": `[]`,
			},
			options: packageErrorOptions{
				Serverless:     false,
				LogsDB:         false,
				StackVersion:   "9.0.0",
				BuildURL:       "https://buildkite.com/elastic/integrations/builds/100",
				ClosedIssueURL: "",
				PreviousBuilds: []string{},
				CodeownersPath: "./testdata/CODEOWNERS-default-tests",
				TestCase: testCase{
					ClassName: "elastic_package_registry.metrics",
				},
			},
			issue: newGithubIssue(githubIssueOptions{
				Title:      "my issue",
				Repository: "myorg/repo",
			}),
			found: false,
			expected: packageError{
				Serverless:     false,
				LogsDB:         false,
				StackVersion:   "9.0.0",
				BuildURL:       "https://buildkite.com/elastic/integrations/builds/100",
				Teams:          []string{"@elastic/ecosystem"},
				ClosedIssueURL: "",
				PreviousBuilds: []string{},
				testCase: testCase{
					ClassName: "elastic_package_registry.metrics",
				},
				PackageName: "elastic_package_registry",
				DataStream:  "metrics",
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
				 "body": "First build failed: https://buildkite.com/elastic/integrations/builds/1\nLatest issue closed for the same test: https://github.com/elastic/integrations/issues/42\nPrevious builds:\n- https://buildkite.com/elastic/integrations/builds/11",
				 "number": 42,
				 "state": "OPEN",
				 "url": "https://github.com/elastic/integrations/issues/42"
			  }
			]`,
				"closed": `[]`,
			},
			options: packageErrorOptions{
				Serverless:     false,
				LogsDB:         false,
				StackVersion:   "9.0.0",
				BuildURL:       "https://buildkite.com/elastic/integrations/builds/100",
				ClosedIssueURL: "",
				PreviousBuilds: []string{},
				CodeownersPath: "./testdata/CODEOWNERS-default-tests",
				TestCase: testCase{
					ClassName: "elastic_package_registry.metrics",
				},
			},
			issue: newGithubIssue(githubIssueOptions{
				Title:      "my issue",
				Repository: "myorg/repo",
			}),
			found: true,
			expected: packageError{
				Serverless:     false,
				LogsDB:         false,
				StackVersion:   "9.0.0",
				BuildURL:       "https://buildkite.com/elastic/integrations/builds/1",
				Teams:          []string{"@elastic/ecosystem"},
				ClosedIssueURL: "https://github.com/elastic/integrations/issues/42",
				PreviousBuilds: []string{
					"https://buildkite.com/elastic/integrations/builds/11",
					"https://buildkite.com/elastic/integrations/builds/100",
				},
				testCase: testCase{
					ClassName: "elastic_package_registry.metrics",
				},
				PackageName: "elastic_package_registry",
				DataStream:  "metrics",
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
				 "body": "First build failed: https://buildkite.com/elastic/integrations/builds/1\nLatest issue closed for the same test: https://github.com/elastic/integrations/issues/42",
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
			options: packageErrorOptions{
				Serverless:     false,
				LogsDB:         false,
				StackVersion:   "9.0.0",
				BuildURL:       "https://buildkite.com/elastic/integrations/builds/100",
				ClosedIssueURL: "",
				PreviousBuilds: []string{},
				CodeownersPath: "./testdata/CODEOWNERS-default-tests",
				TestCase: testCase{
					ClassName: "elastic_package_registry.metrics",
				},
			},
			issue: newGithubIssue(githubIssueOptions{
				Title:      "my issue",
				Repository: "myorg/repo",
			}),
			found: true,
			expected: packageError{
				Serverless:     false,
				LogsDB:         false,
				StackVersion:   "9.0.0",
				BuildURL:       "https://buildkite.com/elastic/integrations/builds/1",
				Teams:          []string{"@elastic/ecosystem"},
				ClosedIssueURL: "https://github.com/elastic/integrations/issues/42",
				PreviousBuilds: []string{
					"https://buildkite.com/elastic/integrations/builds/100",
				},
				testCase: testCase{
					ClassName: "elastic_package_registry.metrics",
				},
				PackageName: "elastic_package_registry",
				DataStream:  "metrics",
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
				 "body": "First build failed: https://buildkite.com/elastic/integrations/builds/1\nLatest issue closed for the same test: https://github.com/elastic/integrations/issues/42",
				 "number": 21,
				 "state": "CLOSED",
				 "url": "https://github.com/elastic/integrations/issues/21"
			  }
			]`,
			},
			options: packageErrorOptions{
				Serverless:     false,
				LogsDB:         false,
				StackVersion:   "9.0.0",
				BuildURL:       "https://buildkite.com/elastic/integrations/builds/100",
				ClosedIssueURL: "",
				PreviousBuilds: []string{},
				CodeownersPath: "./testdata/CODEOWNERS-default-tests",
				TestCase: testCase{
					ClassName: "elastic_package_registry.metrics",
				},
			},
			issue: newGithubIssue(githubIssueOptions{
				Title:      "my issue",
				Repository: "myorg/repo",
			}),
			found: false,
			expected: packageError{
				Serverless:     false,
				LogsDB:         false,
				StackVersion:   "9.0.0",
				BuildURL:       "https://buildkite.com/elastic/integrations/builds/100",
				Teams:          []string{"@elastic/ecosystem"},
				ClosedIssueURL: "https://github.com/elastic/integrations/issues/21",
				PreviousBuilds: []string{},
				testCase: testCase{
					ClassName: "elastic_package_registry.metrics",
				},
				PackageName: "elastic_package_registry",
				DataStream:  "metrics",
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

			reporter := newReporter(ghCli, 5)

			pError, err := newPackageError(c.options)
			require.NoError(t, err)

			newPError, existingIssue, err := reporter.updatePackageError(context.Background(), c.issue, *pError)
			require.NoError(t, err)
			assert.Equal(t, c.found, existingIssue)
			assert.Equal(t, c.expected, *newPError)
		})
	}
}
