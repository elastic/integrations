// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummary(t *testing.T) {
	cases := []struct {
		title       string
		resultError failureObserver
		expected    string
	}{
		{
			title: "summary stack version with data stream",
			resultError: &packageError{
				dataError: dataError{
					stackVersion: "8.14",
				},
				packageName: "foo",
				dataStream:  "data",
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
			title: "summary stack version with owners without data stream",
			resultError: &packageError{
				dataError: dataError{
					stackVersion: "8.14",
				},
				packageName: "foo",
				testCase: testCase{
					Name: "mytest",
				},
				teams: []string{"team1", "team2"},
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
			resultError: &packageError{
				dataError: dataError{
					stackVersion: "8.14",
				},
				packageName: "foo",
				dataStream:  "data",
				testCase: testCase{
					Name: "mytest",
				},
				teams: []string{"team1", "team2"},
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
			resultError: &packageError{
				dataError: dataError{
					serverless:        true,
					serverlessProject: "observability",
				},
				packageName: "foo",
				dataStream:  "data",
				testCase: testCase{
					Name: "mytest",
				},
				teams: []string{"team1", "team2"},
			},
			expected: `- Stack version: Same as in Pull Request builds
- Serverless: observability
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
			resultError: &packageError{
				dataError: dataError{
					serverless:        true,
					serverlessProject: "observability",
				},
				packageName: "foo",
				testCase: testCase{
					Name: "mytest",
				},
				teams: []string{"team1", "team2"},
			},
			expected: `- Stack version: Same as in Pull Request builds
- Serverless: observability
- Package: foo
- Failing test: mytest
- Owners:
    - team1
    - team2
`,
		},
		{
			title: "summary logsdb without stack version defined",
			resultError: &packageError{
				dataError: dataError{
					logsDB: true,
				},
				packageName: "foo",
				testCase: testCase{
					Name: "mytest",
				},
				teams: []string{"team1", "team2"},
			},
			expected: `- Stack version: maximum of either the version used in PR builds or 8.17.0 (GA version for LogsDB index mode)
- LogsDB: enabled
- Package: foo
- Failing test: mytest
- Owners:
    - team1
    - team2
`,
		},
		{
			title: "summary broad failure",
			resultError: &buildError{
				dataError: dataError{
					logsDB:       false,
					serverless:   false,
					stackVersion: "8.16",
				},
				packages: []string{
					"foo",
					"bar",
				},
				teams: []string{"team1"},
			},
			expected: `- Stack version: 8.16
- Packages:
    - foo
    - bar
- Owners:
    - team1
`,
		},
		{
			title: "summary with basic license",
			resultError: &buildError{
				dataError: dataError{
					logsDB:       false,
					serverless:   false,
					subscription: "basic",
					stackVersion: "8.16",
				},
				packages: []string{
					"foo",
					"bar",
				},
				teams: []string{"team1"},
			},
			expected: `- Stack version: 8.16
- Subscription: basic
- Packages:
    - foo
    - bar
- Owners:
    - team1
`,
		},
		{
			title: "summary with basic license no stack",
			resultError: &buildError{
				dataError: dataError{
					logsDB:       false,
					serverless:   false,
					subscription: "basic",
				},
				packages: []string{
					"foo",
					"bar",
				},
				teams: []string{"team1"},
			},
			expected: `- Stack version: Same as in Pull Request builds
- Subscription: basic
- Packages:
    - foo
    - bar
- Owners:
    - team1
`,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			formatter := resultsFormatter{
				result: c.resultError,
			}
			summary, err := formatter.Summary()
			require.NoError(t, err)

			assert.Equal(t, c.expected, summary)
		})
	}
}

func TestDescription(t *testing.T) {
	cases := []struct {
		title       string
		resultError failureObserver
		maxLinks    int
		expected    string
	}{
		{
			title: "description error all fields",
			resultError: &packageError{
				dataError: dataError{
					stackVersion: "8.14",
					errorLinks: errorLinks{
						firstBuild:     "http://link/1",
						closedIssueURL: "http://link/old",
						previousBuilds: []string{
							"http://link/2",
							"http://link/3",
						},
					},
				},
				packageName: "foo",
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
			title: "description failure all fields",
			resultError: &packageError{
				dataError: dataError{
					stackVersion: "8.14",
					errorLinks: errorLinks{
						firstBuild:     "http://link/1",
						closedIssueURL: "http://link/old",
						previousBuilds: []string{
							"http://link/2",
							"http://link/3",
						},
					},
				},
				packageName: "foo",
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
			title: "description no closed issue",
			resultError: &packageError{
				dataError: dataError{
					stackVersion: "8.14",
					errorLinks: errorLinks{
						firstBuild: "http://link/1",
						previousBuilds: []string{
							"http://link/2",
							"http://link/3",
						},
					},
				},
				packageName: "foo",
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
			maxLinks: 2,
			resultError: &packageError{
				dataError: dataError{
					stackVersion: "8.14",
					errorLinks: errorLinks{
						firstBuild: "http://link/1",
						previousBuilds: []string{
							"http://link/2",
							"http://link/3",
						},
					},
				},
				packageName: "foo",
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
		{
			title: "description broad failure",
			resultError: &buildError{
				dataError: dataError{
					logsDB:       false,
					serverless:   false,
					stackVersion: "8.16",
					errorLinks: errorLinks{
						firstBuild: "http://link/1",
						previousBuilds: []string{
							"http://link/2",
							"http://link/3",
						},
						closedIssueURL: "http://issue.link/1",
					},
				},
				packages: []string{
					"foo",
					"bar",
				},
				teams: []string{"team1"},
			},
			expected: `- Stack version: 8.16
- Packages:
    - foo
    - bar
- Owners:
    - team1



Latest issue closed for the same test: http://issue.link/1

First build failed: http://link/1

Latest failed builds:
- http://link/2
- http://link/3
`,
		},
		{
			title: "description basic license no stack",
			resultError: &buildError{
				dataError: dataError{
					logsDB:       false,
					serverless:   false,
					subscription: "basic",
					errorLinks: errorLinks{
						firstBuild: "http://link/1",
						previousBuilds: []string{
							"http://link/2",
							"http://link/3",
						},
						closedIssueURL: "http://issue.link/1",
					},
				},
				packages: []string{
					"foo",
					"bar",
				},
				teams: []string{"team1"},
			},
			expected: `- Stack version: Same as in Pull Request builds
- Subscription: basic
- Packages:
    - foo
    - bar
- Owners:
    - team1



Latest issue closed for the same test: http://issue.link/1

First build failed: http://link/1

Latest failed builds:
- http://link/2
- http://link/3
`,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			formatter := resultsFormatter{
				result:           c.resultError,
				maxPreviousLinks: c.maxLinks,
			}
			description, err := formatter.Description()
			require.NoError(t, err)

			assert.Equal(t, c.expected, description)
		})
	}
}
