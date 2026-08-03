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

func TestKibanaConstraintPackage(t *testing.T) {
	constraintTest, err := semver.NewConstraint("^8.0.0")
	require.NoError(t, err)

	cases := []struct {
		title    string
		contents string
		expected *semver.Constraints
	}{
		{
			title: "kibana constrasint defined",
			contents: `name: "version"
conditions:
  kibana:
    version: "^8.0.0"
`,
			expected: constraintTest,
		},
		{
			title: "kibana constraint defined with dotted field",
			contents: `name: "version"
conditions:
  kibana.version: "^8.0.0"
`,
			expected: constraintTest,
		},
		{
			title: "kibana constraint not defined",
			contents: `name: "version"
`,
			expected: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			directory := t.TempDir()
			pkgManifestPath := filepath.Join(directory, "manifest.yml")
			err := os.WriteFile(pkgManifestPath, []byte(c.contents), 0o644)
			require.NoError(t, err)
			constraint, err := KibanaConstraintPackage(pkgManifestPath)
			require.NoError(t, err)
			assert.Equal(t, c.expected, constraint)
		})
	}
}

func TestIsPackageSupportedInStackVersion(t *testing.T) {
	cases := []struct {
		title        string
		contents     string
		stackVersion string
		supported    bool
	}{
		{
			title:        "Test simple kibana constraint",
			stackVersion: "8.18.0",
			contents: `name: "stack"
conditions:
  kibana:
    version: "^8.0.0"
`,
			supported: true,
		},
		{
			title:        "Test or condition",
			stackVersion: "8.18.0",
			contents: `name: "stack"
conditions:
  kibana:
    version: "^8.0.0 || ^9.0.0"
`,
			supported: true,
		},
		{
			title:        "Test snapshot",
			stackVersion: "8.18.0-SNAPSHOT",
			contents: `name: "stack"
conditions:
  kibana:
    version: "^8.0.0 || ^9.0.0"
`,
			supported: true,
		},
		{
			title:        "Test greater or equal",
			stackVersion: "8.18.0-SNAPSHOT",
			contents: `name: "stack"
conditions:
  kibana:
    version: ">=8.0.0"
`,
			supported: true,
		},
		{
			title:        "Test not supported",
			stackVersion: "8.18.0-SNAPSHOT",
			contents: `name: "stack"
conditions:
  kibana:
    version: "^9.0.0"
`,
			supported: false,
		},
		{
			title:        "Test missing kibana version",
			stackVersion: "8.18.0-SNAPSHOT",
			contents: `name: "stack"
`,
			supported: true,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			directory := t.TempDir()
			pkgManifestPath := filepath.Join(directory, "manifest.yml")
			err := os.WriteFile(pkgManifestPath, []byte(c.contents), 0o644)
			require.NoError(t, err)
			supported, err := IsPackageSupportedInStackVersion(c.stackVersion, pkgManifestPath)
			require.NoError(t, err)
			assert.Equal(t, c.supported, supported)
		})
	}
}
