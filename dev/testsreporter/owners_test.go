// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createPackagesTree creates a packages folder with the given packages (folder => name in manifest)
// and a CODEOWNERS file with the given rules (path => owners). It returns the path to both of them.
func createPackagesTree(t *testing.T, packages map[string]string, owners []string) (string, string) {
	t.Helper()

	root := t.TempDir()
	t.Chdir(root)

	const packagesPath = "packages"
	for folder, name := range packages {
		dir := filepath.Join(packagesPath, filepath.FromSlash(folder))
		require.NoError(t, os.MkdirAll(dir, 0o755))

		manifest := fmt.Sprintf("format_version: 3.0.0\nname: %s\ntype: integration\nversion: 1.0.0\n", name)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.yml"), []byte(manifest), 0o644))
	}

	const codeownersPath = "CODEOWNERS"
	var content string
	for _, rule := range owners {
		content += rule + "\n"
	}
	require.NoError(t, os.WriteFile(codeownersPath, []byte(content), 0o644))

	return codeownersPath, packagesPath
}

func TestOwnersResolverPackageOwners(t *testing.T) {
	codeownersPath, packagesPath := createPackagesTree(t,
		map[string]string{
			// Folder and name in the manifest are the same.
			"apache": "apache",
			// Folder and name in the manifest are different.
			"sql_input": "sql",
			// Nested packages, the name of the folder is not unique.
			"technology/input_otel": "technology_input_otel",
			"other/input_otel":      "other_input_otel",
		},
		[]string{
			"/packages/apache @elastic/apache-team",
			"/packages/apache/data_stream/error @elastic/apache-error-team",
			"/packages/sql_input @elastic/sql-team",
			"/packages/technology/input_otel @elastic/technology-team",
			"/packages/other/input_otel @elastic/other-team",
		},
	)

	resolver, err := newOwnersResolver(codeownersPath, packagesPath)
	require.NoError(t, err)

	cases := []struct {
		title         string
		packageName   string
		dataStream    string
		expected      []string
		expectedError string
	}{
		{
			title:       "name and folder are the same",
			packageName: "apache",
			expected:    []string{"@elastic/apache-team"},
		},
		{
			title:       "data stream with its own owners",
			packageName: "apache",
			dataStream:  "error",
			expected:    []string{"@elastic/apache-error-team"},
		},
		{
			title:       "data stream without its own owners",
			packageName: "apache",
			dataStream:  "access",
			expected:    []string{"@elastic/apache-team"},
		},
		{
			title:       "name in manifest different to folder",
			packageName: "sql",
			expected:    []string{"@elastic/sql-team"},
		},
		{
			title:       "folder name, as reported by previous versions of elastic-package",
			packageName: "sql_input",
			expected:    []string{"@elastic/sql-team"},
		},
		{
			title:       "nested package",
			packageName: "technology_input_otel",
			expected:    []string{"@elastic/technology-team"},
		},
		{
			title:       "other nested package with the same folder name",
			packageName: "other_input_otel",
			expected:    []string{"@elastic/other-team"},
		},
		{
			title:         "folder name of nested packages is ambiguous",
			packageName:   "input_otel",
			expectedError: "ambiguous",
		},
		{
			title:         "unknown package",
			packageName:   "unknown",
			expectedError: "unknown",
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			teams, err := resolver.packageOwners(c.packageName, c.dataStream)
			if c.expectedError != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, c.expectedError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.expected, teams)
		})
	}
}

func TestOwnersResolverMissingFiles(t *testing.T) {
	codeownersPath, packagesPath := createPackagesTree(t,
		map[string]string{"apache": "apache"},
		[]string{"/packages/apache @elastic/apache-team"},
	)

	t.Run("missing CODEOWNERS", func(t *testing.T) {
		_, err := newOwnersResolver("missing-CODEOWNERS", packagesPath)
		require.Error(t, err)
	})

	t.Run("missing packages folder", func(t *testing.T) {
		_, err := newOwnersResolver(codeownersPath, "missing-packages")
		require.Error(t, err)
	})
}
