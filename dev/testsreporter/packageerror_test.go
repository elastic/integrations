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
		options       PackageErrorOptions
		expectedError bool
		expected      PackageError
	}{
		{
			title: "Sample package error",
			options: PackageErrorOptions{
				Serverless:        true,
				ServerlessProject: "observability",
				LogsDB:            false,
				StackVersion:      "8.16.0-SNAPSHOT",
				BuildURL:          "https://buildkite.com/elastic/integrations/build/1",
				TestCase: testCase{
					Name:      "failing test",
					ClassName: "elastic_package_registry.datastream",
					Error:     "could not find hits",
				},
				CodeownersPath: "./testdata/CODEOWNERS-default-tests",
			},
			expectedError: false,
			expected: PackageError{
				testCase: testCase{
					Name:      "failing test",
					ClassName: "elastic_package_registry.datastream",
					Error:     "could not find hits",
				},
				Serverless:        true,
				ServerlessProject: "observability",
				LogsDB:            false,
				StackVersion:      "8.16.0-SNAPSHOT",
				BuildURL:          "https://buildkite.com/elastic/integrations/build/1",
				PackageName:       "elastic_package_registry",
				DataStream:        "datastream",
				Teams:             []string{"@elastic/ecosystem"},
			},
		},
		{
			title: "Sample package error no datastream",
			options: PackageErrorOptions{
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
			expected: PackageError{
				testCase: testCase{
					Name:      "failing test",
					ClassName: "elastic_package_registry",
					Error:     "could not find hits",
				},
				Serverless:        true,
				ServerlessProject: "observability",
				LogsDB:            false,
				StackVersion:      "8.16.0-SNAPSHOT",
				BuildURL:          "https://buildkite.com/elastic/integrations/build/1",
				PackageName:       "elastic_package_registry",
				DataStream:        "",
				Teams:             []string{"@elastic/ecosystem"},
			},
		},
		{
			title: "Not found package",
			options: PackageErrorOptions{
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
			packageError, err := NewPackageError(c.options)
			if c.expectedError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, c.expected, *packageError)
		})
	}
}
