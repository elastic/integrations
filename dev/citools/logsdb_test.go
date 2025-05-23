// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package citools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsVersionLessThanLogsDBGA(t *testing.T) {
	cases := []struct {
		title    string
		version  *semver.Version
		expected bool
	}{
		{
			title:    "less than LogsDB GA",
			version:  semver.MustParse("8.12.0"),
			expected: true,
		},
		{
			title:    "greater or equal than LogsSB GA",
			version:  semver.MustParse("8.17.0"),
			expected: false,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			value := IsVersionLessThanLogsDBGA(c.version)
			assert.Equal(t, c.expected, value)
		})
	}

}

func TestIsLogsDBSupportedInPackage(t *testing.T) {
	cases := []struct {
		title         string
		contents      string
		expectedError bool
		supported     bool
	}{
		{
			title: "Supported LogsDB field",
			contents: `name: "logsdb"
conditions:
  kibana:
    version: "^7.16.0 || ^8.0.0 || ^9.0.0"
`,
			expectedError: false,
			supported:     true,
		},
		{
			title: "Kibana constraint dotted field",
			contents: `name: "subscription"
conditions:
  kibana.version: "^7.16.0 || ^8.0.0 || ^9.0.0"
`,
			expectedError: false,
			supported:     true,
		},
		{
			title: "LogsDB not supported",
			contents: `name: "subscription"
conditions:
  kibana.version: "^7.16.0"
`,
			expectedError: false,
			supported:     false,
		},
		{
			title: "No Kibana constraint",
			contents: `name: "subscription"
`,
			expectedError: false,
			supported:     true,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			directory := t.TempDir()
			pkgManifestPath := filepath.Join(directory, "manifest.yml")
			err := os.WriteFile(pkgManifestPath, []byte(c.contents), 0o644)
			require.NoError(t, err)
			supported, err := IsLogsDBSupportedInPackage(pkgManifestPath)
			if c.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.supported, supported)
			}
		})
	}

}
