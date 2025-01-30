// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBuildError(t *testing.T) {
	cases := []struct {
		title         string
		options       buildErrorOptions
		expectedError bool
		expected      buildError
	}{
		{
			title: "Sample build error",
			options: buildErrorOptions{
				Serverless:        true,
				ServerlessProject: "observability",
				LogsDB:            false,
				StackVersion:      "8.16.0-SNAPSHOT",
				Packages: []string{
					"elastic_package_registry",
					"nginx",
				},
				BuildURL:       "https://buildkite.com/elastic/integrations/build/10",
				ClosedIssueURL: "https://github.com/elastic/integrations/issues/2",
				PreviousBuilds: []string{
					"https://buildkite.com/elastic/integrations/builds/1",
					"https://buildkite.com/elastic/integrations/builds/3",
				},
			},
			expectedError: false,
			expected: buildError{
				dataError: dataError{
					serverless:        true,
					serverlessProject: "observability",
					logsDB:            false,
					stackVersion:      "8.16.0-SNAPSHOT",
					errorLinks: errorLinks{
						firstBuild:     "https://buildkite.com/elastic/integrations/build/10",
						closedIssueURL: "https://github.com/elastic/integrations/issues/2",
						previousBuilds: []string{
							"https://buildkite.com/elastic/integrations/builds/1",
							"https://buildkite.com/elastic/integrations/builds/3",
						},
					},
				},
				packages: []string{
					"elastic_package_registry",
					"nginx",
				},
				teams: []string{"@elastic/ecosystem"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			buildError, err := newBuildError(c.options)
			if c.expectedError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, c.expected, *buildError)
		})
	}

}
