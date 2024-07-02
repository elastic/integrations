// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSummary(t *testing.T) {
	cases := []struct {
		title        string
		packageError PackageError
		expected     string
	}{
		{
			title: "summary stack version with data stream",
			packageError: PackageError{
				StackVersion: "8.14",
				PackageName:  "foo",
				DataStream:   "data",
				testCase: testCase{
					Name: "mytest",
				},
			},
			expected: `- Stack version: 8.14
- Package: foo
- Failing test: mytest
- DataStream: data
`,
		},
		{
			title: "summary stack version with owners wihtout data stream",
			packageError: PackageError{
				StackVersion: "8.14",
				PackageName:  "foo",
				testCase: testCase{
					Name: "mytest",
				},
				Teams: []string{"team1", "team2"},
			},
			expected: `- Stack version: 8.14
- Package: foo
- Failing test: mytest
- Owners:
    - team1
    - team2
`,
		},
		{
			title: "summary stack version with data stream and owners",
			packageError: PackageError{
				StackVersion: "8.14",
				PackageName:  "foo",
				DataStream:   "data",
				testCase: testCase{
					Name: "mytest",
				},
				Teams: []string{"team1", "team2"},
			},
			expected: `- Stack version: 8.14
- Package: foo
- Failing test: mytest
- DataStream: data
- Owners:
    - team1
    - team2
`,
		},
		{
			title: "summary serverless with data stream and owners",
			packageError: PackageError{
				Serverless:        true,
				ServerlessProject: "observability",
				PackageName:       "foo",
				DataStream:        "data",
				testCase: testCase{
					Name: "mytest",
				},
				Teams: []string{"team1", "team2"},
			},
			expected: `- Serverless: observability
- Package: foo
- Failing test: mytest
- DataStream: data
- Owners:
    - team1
    - team2
`,
		},
		{
			title: "summary serverless with owners without data stream",
			packageError: PackageError{
				Serverless:        true,
				ServerlessProject: "observability",
				PackageName:       "foo",
				testCase: testCase{
					Name: "mytest",
				},
				Teams: []string{"team1", "team2"},
			},
			expected: `- Serverless: observability
- Package: foo
- Failing test: mytest
- Owners:
    - team1
    - team2
`,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			formatter := ResultsFormatter{
				result: c.packageError,
			}
			summary := formatter.Summary()

			assert.Equal(t, c.expected, summary)
		})
	}
}

func TestDescription(t *testing.T) {
	cases := []struct {
		title        string
		summary      string
		packageError PackageError
		maxLinks     int
		expected     string
	}{
		{
			title:   "description error all fields",
			summary: "summary",
			packageError: PackageError{
				StackVersion:   "8.14",
				BuildURL:       "http://link/1",
				ClosedIssueURL: "http://link/old",
				PackageName:    "foo",
				PreviousBuilds: []string{
					"http://link/2",
					"http://link/3",
				},
				testCase: testCase{
					Name:  "mytest",
					Error: "myerror",
				},
			},
			expected: `- Stack version: 8.14
- Package: foo
- Failing test: mytest

Error:
` + "```" + `
myerror
` + "```" + `

Latest issue closed for the same test: http://link/old

First build failed: http://link/1

Latest failed builds:
- http://link/2
- http://link/3
`,
		},
		{
			title:   "description failure all fields",
			summary: "summary",
			packageError: PackageError{
				StackVersion:   "8.14",
				BuildURL:       "http://link/1",
				ClosedIssueURL: "http://link/old",
				PackageName:    "foo",
				PreviousBuilds: []string{
					"http://link/2",
					"http://link/3",
				},
				testCase: testCase{
					Name:    "mytest",
					Failure: "myfailure",
				},
			},
			expected: `- Stack version: 8.14
- Package: foo
- Failing test: mytest

Failure:
` + "```" + `
myfailure
` + "```" + `

Latest issue closed for the same test: http://link/old

First build failed: http://link/1

Latest failed builds:
- http://link/2
- http://link/3
`,
		},
		{
			title:   "description no closed issue",
			summary: "summary",
			packageError: PackageError{
				StackVersion: "8.14",
				BuildURL:     "http://link/1",
				PackageName:  "foo",
				PreviousBuilds: []string{
					"http://link/2",
					"http://link/3",
				},
				testCase: testCase{
					Name:  "mytest",
					Error: "myerror",
				},
			},
			expected: `- Stack version: 8.14
- Package: foo
- Failing test: mytest

Error:
` + "```" + `
myerror
` + "```" + `

First build failed: http://link/1

Latest failed builds:
- http://link/2
- http://link/3
`,
		},
		{
			title:    "description max links",
			summary:  "summary",
			maxLinks: 2,
			packageError: PackageError{
				StackVersion: "8.14",
				BuildURL:     "http://link/1",
				PackageName:  "foo",
				PreviousBuilds: []string{
					"http://link/2",
					"http://link/3",
				},
				testCase: testCase{
					Name:  "mytest",
					Error: "myerror",
				},
			},
			expected: `- Stack version: 8.14
- Package: foo
- Failing test: mytest

Error:
` + "```" + `
myerror
` + "```" + `

First build failed: http://link/1

Latest 2 failed builds:
- http://link/2
- http://link/3
`,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			formatter := ResultsFormatter{
				result:           c.packageError,
				maxPreviousLinks: c.maxLinks,
			}
			description := formatter.Description()

			assert.Equal(t, c.expected, description)
		})
	}
}
