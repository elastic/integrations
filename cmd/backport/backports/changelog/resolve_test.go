// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makePackage(t *testing.T, baseDir, dirName, manifestName string) {
	t.Helper()
	dir := filepath.Join(baseDir, dirName)
	require.NoError(t, os.MkdirAll(dir, 0700))
	manifest := "format_version: \"1.0.0\"\nname: " + manifestName + "\ntype: integration\nversion: \"1.0.0\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.yml"), []byte(manifest), 0600))
}

func TestBuildPackageIndex(t *testing.T) {
	t.Run("indexes all packages by manifest name", func(t *testing.T) {
		base := t.TempDir()
		makePackage(t, base, "aws", "aws")
		makePackage(t, base, "azure", "azure")

		idx, err := BuildPackageIndex(base)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(base, "aws"), idx["aws"])
		assert.Equal(t, filepath.Join(base, "azure"), idx["azure"])
	})

	t.Run("manifest name differs from directory name", func(t *testing.T) {
		base := t.TempDir()
		makePackage(t, base, "my_pkg_dir", "actual_manifest_name")

		idx, err := BuildPackageIndex(base)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(base, "my_pkg_dir"), idx["actual_manifest_name"])
	})

	t.Run("unknown package returns empty string from map lookup", func(t *testing.T) {
		base := t.TempDir()
		makePackage(t, base, "aws", "aws")

		idx, err := BuildPackageIndex(base)
		require.NoError(t, err)
		assert.Empty(t, idx["no_such_package"])
	})

	t.Run("invalid packages dir returns error", func(t *testing.T) {
		_, err := BuildPackageIndex("/no/such/dir")
		assert.Error(t, err)
	})

	t.Run("package nested in a subdirectory is indexed", func(t *testing.T) {
		// packagesDir
		//   └── group/
		//         └── aws/   ← manifest.yml lives here
		base := t.TempDir()
		makePackage(t, filepath.Join(base, "group"), "aws", "aws")

		idx, err := BuildPackageIndex(base)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(base, "group", "aws"), idx["aws"])
	})

	t.Run("package nested inside another package is not indexed", func(t *testing.T) {
		// ListPackages returns SkipDir once a package is found, so a manifest.yml
		// inside a valid package directory is never visited.
		base := t.TempDir()
		makePackage(t, base, "aws", "aws")
		makePackage(t, filepath.Join(base, "aws"), "subpkg", "aws_subpkg")

		idx, err := BuildPackageIndex(base)
		require.NoError(t, err)
		assert.Empty(t, idx["aws_subpkg"], "nested package inside a found package must not be indexed")
	})
}
