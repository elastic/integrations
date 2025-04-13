// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPackageError(t *testing.T) {
	cases := []struct {
		title         string
		options       packageErrorOptions
		expectedError bool
		expected      packageError
	}{
		{
			title: "Sample package error",
			options: packageErrorOptions{
				Serverless:        true,
				ServerlessProject: "observability",
				LogsDB:            false,
				StackVersion:      "8.16.0-SNAPSHOT",
				Subscription:      "basic",
				BuildURL:          "https://buildkite.com/elastic/integrations/build/1",
				TestCase: testCase{
					Name:      "failing test",
					ClassName: "elastic_package_registry.datastream",
					Error:     "could not find hits",
				},
				CodeownersPath: "./testdata/CODEOWNERS-default-tests",
			},
			expectedError: false,
			expected: packageError{
				dataError: dataError{
					serverless:        true,
					serverlessProject: "observability",
					logsDB:            false,
					stackVersion:      "8.16.0-SNAPSHOT",
					subscription:      "basic",
					errorLinks: errorLinks{
						firstBuild: "https://buildkite.com/elastic/integrations/build/1",
					},
				},
				testCase: testCase{
					Name:      "failing test",
					ClassName: "elastic_package_registry.datastream",
					Error:     "could not find hits",
				},
				packageName: "elastic_package_registry",
				dataStream:  "datastream",
				teams:       []string{"@elastic/ecosystem"},
			},
		},
		{
			title: "Sample package error no datastream",
			options: packageErrorOptions{
				Serverless:        true,
				ServerlessProject: "observability",
				LogsDB:            false,
				StackVersion:      "8.16.0-SNAPSHOT",
				BuildURL:          "https://buildkite.com/elastic/integrations/build/1",
				TestCase: testCase{
					Name:      "failing test",
					ClassName: "elastic_package_registry",
					Error:     "could not find hits",
				},
				CodeownersPath: "./testdata/CODEOWNERS-default-tests",
			},
			expectedError: false,
			expected: packageError{
				dataError: dataError{
					serverless:        true,
					serverlessProject: "observability",
					logsDB:            false,
					stackVersion:      "8.16.0-SNAPSHOT",
					errorLinks: errorLinks{
						firstBuild: "https://buildkite.com/elastic/integrations/build/1",
					},
				},
				testCase: testCase{
					Name:      "failing test",
					ClassName: "elastic_package_registry",
					Error:     "could not find hits",
				},
				packageName: "elastic_package_registry",
				dataStream:  "",
				teams:       []string{"@elastic/ecosystem"},
			},
		},
		{
			title: "Not found package",
			options: packageErrorOptions{
				Serverless:        true,
				ServerlessProject: "observability",
				LogsDB:            false,
				StackVersion:      "8.16.0-SNAPSHOT",
				BuildURL:          "https://buildkite.com/elastic/integrations/build/1",
				TestCase: testCase{
					Name:      "failing test",
					ClassName: "notexist.datastream",
					Error:     "could not find hits",
				},
				CodeownersPath: "./testdata/CODEOWNERS-default-tests",
			},
			expectedError: true,
		},
	}
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			packageError, err := newPackageError(c.options)
			if c.expectedError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, c.expected, *packageError)
		})
	}
}
