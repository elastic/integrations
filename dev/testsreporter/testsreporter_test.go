// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorsFromTest(t *testing.T) {
	cases := []struct {
		title     string
		xmlFolder string
		expected  []PackageError
	}{
		{
			title:     "read XML files",
			xmlFolder: "testdata",
			expected: []PackageError{
				{
					testCase: testCase{
						Name:          "system test: default",
						ClassName:     "cisco_umbrella.log",
						TimeInSeconds: 1368.349501429,
						Failure:       "could not find hits in logs-cisco_umbrella.log-ep data stream",
					},
					Teams:       []string{"@elastic/security-service-integrations"},
					TeamLabels:  []string{"Team:Security-Service Integrations"},
					DataStream:  "log",
					PackageName: "cisco_umbrella",
					Serverless:  false,
				},
				{
					testCase: testCase{
						Name:          "system test: default",
						ClassName:     "elastic_package_registry.metrics",
						TimeInSeconds: 1368.349501429,
						Error:         "could not find hits in logs-elastic_package_registry.metrics-ep data stream",
					},
					Teams:       []string{"@elastic/ecosystem"},
					TeamLabels:  []string{"Team:Ecosystem"},
					DataStream:  "metrics",
					PackageName: "elastic_package_registry",
					Serverless:  false,
				},
				{
					testCase: testCase{
						Name:          "pipeline test: test-fortinet-7-4.log",
						ClassName:     "fortinet_fortigate.log",
						TimeInSeconds: 0.209966522,
						Failure: `test case failed: Expected results are different from actual ones: --- want
+++ got
@@ -2302,7 +2302,6 @@
                 "preserve_original_event"
             ],
             "url": {
-                "extension": "fortianalyzer/setting",
                 "path": "/api/v2/cmdb/log.fortianalyzer/setting",
                 "query": "vdom=root"
             }
`,
					},
					PackageName: "fortinet_fortigate",
					DataStream:  "log",
					Teams:       []string{"@elastic/sec-deployment-and-devices"},
					TeamLabels:  []string{"Team:Security-Deployment and Devices"},
					Serverless:  false,
				},
				{
					testCase: testCase{
						Name:          "system test: mssql",
						ClassName:     "sql_input.",
						TimeInSeconds: 34.296986222,
						Failure:       "one or more errors found in documents stored in metrics-sql.sql-12466 data stream: [0] found error.message in event: cannot open connection: testing connection: mssql: login error: Login failed for user 'SA'.",
					},
					PackageName: "sql_input",
					DataStream:  "",
					Teams:       []string{"@elastic/obs-infraobs-integrations"},
					TeamLabels:  []string{"Team:Obs-InfraObs"},
					Serverless:  false,
				},
				{
					testCase: testCase{
						Name:          "system test: mysql",
						ClassName:     "sql_input.",
						TimeInSeconds: 34.25843055,
						Failure:       "one or more errors found in documents stored in metrics-sql.sql-98584 data stream: [0] found error.message in event: cannot open connection: testing connection: dial tcp 172.21.0.6:3306: connect: connection refused",
					},
					PackageName: "sql_input",
					DataStream:  "",
					Teams:       []string{"@elastic/obs-infraobs-integrations"},
					TeamLabels:  []string{"Team:Obs-InfraObs"},
					Serverless:  false,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			errors, err := errorsFromTests(checkOptions{
				ResultsPath:    c.xmlFolder,
				Serverless:     false,
				StackVersion:   "",
				BuildURL:       "",
				CodeownersPath: "testdata/CODEOWNERS-default-tests",
				TeamLabelsPath: "testdata/team_labels-default-tests",
			})
			require.NoError(t, err)

			assert.Len(t, errors, len(c.expected))

			assert.Equal(t, c.expected, errors)
		})
	}
}

func TestErrorDataStream(t *testing.T) {
	cases := []struct {
		title     string
		xmlFolder string
		expected  []string
	}{
		{
			title:     "read XML files",
			xmlFolder: "testdata",
			expected: []string{
				"log",
				"metrics",
				"log",
				"", // input package
				"", // input package
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			errors, err := errorsFromTests(checkOptions{
				ResultsPath:    c.xmlFolder,
				Serverless:     false,
				StackVersion:   "",
				BuildURL:       "",
				CodeownersPath: "testdata/CODEOWNERS-default-tests",
				TeamLabelsPath: "testdata/team_labels-default-tests",
			})
			require.NoError(t, err)

			assert.Len(t, errors, len(c.expected))

			dataStreams := []string{}
			for _, e := range errors {
				dataStreams = append(dataStreams, e.DataStream)
			}
			assert.Equal(t, c.expected, dataStreams)
		})
	}
}

func TestErrorPackageName(t *testing.T) {
	cases := []struct {
		title     string
		xmlFolder string
		expected  []string
	}{
		{
			title:     "read XML files",
			xmlFolder: "testdata",
			expected: []string{
				"cisco_umbrella",
				"elastic_package_registry",
				"fortinet_fortigate",
				"sql_input", // input package
				"sql_input", // input package
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			errors, err := errorsFromTests(checkOptions{
				ResultsPath:    c.xmlFolder,
				Serverless:     false,
				StackVersion:   "",
				BuildURL:       "",
				CodeownersPath: "testdata/CODEOWNERS-default-tests",
				TeamLabelsPath: "testdata/team_labels-default-tests",
			})
			require.NoError(t, err)

			assert.Len(t, errors, len(c.expected))

			packages := []string{}
			for _, e := range errors {
				packages = append(packages, e.PackageName)
			}
			assert.Equal(t, c.expected, packages)
		})
	}
}

func TestPreviousBuildLinksFromDescription(t *testing.T) {
	cases := []struct {
		title       string
		description string
		expected    []string
	}{
		{
			title: "happy case",
			description: `
First build failed: https://buildkite.com/elastic/integrations/builds/10
Test description
- https://buildkite.com/elastic/integrations/builds/1
- https://buildkite.com/elastic/integrations/builds/2
   - https://buildkite.com/elastic/integrations/builds/3
- https://buildkite.com/elastic/integrations-serverless/builds/5
`,
			expected: []string{
				"https://buildkite.com/elastic/integrations/builds/1",
				"https://buildkite.com/elastic/integrations/builds/2",
				"https://buildkite.com/elastic/integrations/builds/3",
				"https://buildkite.com/elastic/integrations-serverless/builds/5",
			},
		},
		{
			title: "no links",
			description: `
Test description
`,
			expected: []string{},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			links, err := previousBuildLinksFromDescription(&GithubIssue{description: c.description})
			require.NoError(t, err)

			assert.Len(t, links, len(c.expected))
			assert.Equal(t, c.expected, links)
		})
	}
}

func TestFirstLinkFromDescription(t *testing.T) {
	cases := []struct {
		title         string
		description   string
		expected      string
		expectedError bool
	}{
		{
			title: "happy case",
			description: `
First build failed: https://buildkite.com/elastic/integrations/builds/10
Test description
- https://buildkite.com/elastic/integrations/builds/1
- https://buildkite.com/elastic/integrations/builds/2
   - https://buildkite.com/elastic/integrations/builds/3
- https://buildkite.com/elastic/integrations-serverless/builds/5
`,
			expected:      "https://buildkite.com/elastic/integrations/builds/10",
			expectedError: false,
		},
		{
			title: "no links",
			description: `
Test description
`,
			expected:      "",
			expectedError: true,
		},
		{
			title: "more than one link",
			description: `
First build failed: https://buildkite.com/elastic/integrations/builds/10
First build failed: https://buildkite.com/elastic/integrations/builds/12
`,
			expected:      "",
			expectedError: true,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			link, err := firstBuildLinkFromDescription(&GithubIssue{description: c.description})
			if c.expectedError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, c.expected, link)
		})
	}
}

func TestUpdatePreviousLinksSlice(t *testing.T) {
	cases := []struct {
		title        string
		currentLinks []string
		newLink      string
		maxLinks     int
		expected     []string
	}{
		{
			title: "add new link",
			currentLinks: []string{
				"https://buildkite.com/elastic/integrations/builds/1",
				"https://buildkite.com/elastic/integrations/builds/2",
				"https://buildkite.com/elastic/integrations/builds/3",
				"https://buildkite.com/elastic/integrations/builds/4",
			},
			maxLinks: 5,
			newLink:  "https://buildkite.com/elastic/integrations/builds/5",
			expected: []string{
				"https://buildkite.com/elastic/integrations/builds/1",
				"https://buildkite.com/elastic/integrations/builds/2",
				"https://buildkite.com/elastic/integrations/builds/3",
				"https://buildkite.com/elastic/integrations/builds/4",
				"https://buildkite.com/elastic/integrations/builds/5",
			},
		},
		{
			title: "add new link remove oldest one",
			currentLinks: []string{
				"https://buildkite.com/elastic/integrations/builds/1",
				"https://buildkite.com/elastic/integrations/builds/2",
				"https://buildkite.com/elastic/integrations/builds/3",
				"https://buildkite.com/elastic/integrations/builds/4",
			},
			maxLinks: 4,
			newLink:  "https://buildkite.com/elastic/integrations/builds/5",
			expected: []string{
				"https://buildkite.com/elastic/integrations/builds/2",
				"https://buildkite.com/elastic/integrations/builds/3",
				"https://buildkite.com/elastic/integrations/builds/4",
				"https://buildkite.com/elastic/integrations/builds/5",
			},
		},
		{
			title:        "no current links",
			currentLinks: []string{},
			maxLinks:     4,
			newLink:      "https://buildkite.com/elastic/integrations/builds/5",
			expected: []string{
				"https://buildkite.com/elastic/integrations/builds/5",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			links := updatePreviousLinks(c.currentLinks, c.newLink, c.maxLinks)
			assert.Equal(t, c.expected, links)
		})
	}
}
