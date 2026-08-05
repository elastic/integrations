// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package packages

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeManifest creates a valid manifest.yml in dir with the given package name.
func writeManifest(t *testing.T, dir, name string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0700))
	manifest := "format_version: \"1.0.0\"\nname: " + name + "\ntype: integration\nversion: \"1.0.0\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.yml"), []byte(manifest), 0600))
}

// pkgsDir creates a temp packages/ directory and returns its path.
func pkgsDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "packages")
}

func TestDetectPackages(t *testing.T) {
	t.Run("flat package detected from nested file", func(t *testing.T) {
		pkgs := pkgsDir(t)
		writeManifest(t, filepath.Join(pkgs, "nginx"), "nginx")

		result, err := DetectPackages([]string{
			filepath.Join(pkgs, "nginx", "data_stream", "access", "fields.yml"),
		}, pkgs)
		require.NoError(t, err)
		assert.Equal(t, []string{"nginx"}, result)
	})

	t.Run("nested package detected when intermediate dir has no manifest", func(t *testing.T) {
		pkgs := pkgsDir(t)
		// packages/technology/ has no manifest.yml
		writeManifest(t, filepath.Join(pkgs, "technology", "apache"), "apache")

		result, err := DetectPackages([]string{
			filepath.Join(pkgs, "technology", "apache", "data_stream", "access", "fields.yml"),
		}, pkgs)
		require.NoError(t, err)
		assert.Equal(t, []string{"apache"}, result)
	})

	t.Run("file not under packagesDir is skipped", func(t *testing.T) {
		pkgs := pkgsDir(t)
		writeManifest(t, filepath.Join(pkgs, "nginx"), "nginx")

		result, err := DetectPackages([]string{
			".buildkite/scripts/common.sh",
			"dev/backports/inventory.go",
		}, pkgs)
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("multiple files from same package deduplicated", func(t *testing.T) {
		pkgs := pkgsDir(t)
		writeManifest(t, filepath.Join(pkgs, "aws"), "aws")

		result, err := DetectPackages([]string{
			filepath.Join(pkgs, "aws", "manifest.yml"),
			filepath.Join(pkgs, "aws", "changelog.yml"),
			filepath.Join(pkgs, "aws", "data_stream", "ec2", "fields.yml"),
		}, pkgs)
		require.NoError(t, err)
		assert.Equal(t, []string{"aws"}, result)
	})

	t.Run("multiple packages returned in order of first encounter", func(t *testing.T) {
		pkgs := pkgsDir(t)
		writeManifest(t, filepath.Join(pkgs, "aws"), "aws")
		writeManifest(t, filepath.Join(pkgs, "kubernetes"), "kubernetes")

		result, err := DetectPackages([]string{
			filepath.Join(pkgs, "aws", "manifest.yml"),
			filepath.Join(pkgs, "kubernetes", "manifest.yml"),
		}, pkgs)
		require.NoError(t, err)
		assert.Equal(t, []string{"aws", "kubernetes"}, result)
	})

	t.Run("package name read from manifest not from directory name", func(t *testing.T) {
		pkgs := pkgsDir(t)
		// directory name is "my_pkg_dir" but manifest says name: actual_name
		writeManifest(t, filepath.Join(pkgs, "my_pkg_dir"), "actual_name")

		result, err := DetectPackages([]string{
			filepath.Join(pkgs, "my_pkg_dir", "manifest.yml"),
		}, pkgs)
		require.NoError(t, err)
		assert.Equal(t, []string{"actual_name"}, result)
	})

	t.Run("manifest.yml itself is detected as belonging to its package", func(t *testing.T) {
		pkgs := pkgsDir(t)
		writeManifest(t, filepath.Join(pkgs, "nginx"), "nginx")

		result, err := DetectPackages([]string{
			filepath.Join(pkgs, "nginx", "manifest.yml"),
		}, pkgs)
		require.NoError(t, err)
		assert.Equal(t, []string{"nginx"}, result)
	})

	t.Run("empty file list returns empty result", func(t *testing.T) {
		pkgs := pkgsDir(t)
		writeManifest(t, filepath.Join(pkgs, "nginx"), "nginx")

		result, err := DetectPackages([]string{}, pkgs)
		require.NoError(t, err)
		assert.Empty(t, result)
		assert.NotNil(t, result) // must be [] not null when JSON-marshalled
	})

	t.Run("mix of package and non-package files", func(t *testing.T) {
		pkgs := pkgsDir(t)
		writeManifest(t, filepath.Join(pkgs, "aws"), "aws")

		result, err := DetectPackages([]string{
			".github/workflows/test.yml",
			filepath.Join(pkgs, "aws", "changelog.yml"),
			"dev/backports/inventory.go",
		}, pkgs)
		require.NoError(t, err)
		assert.Equal(t, []string{"aws"}, result)
	})

	t.Run("nonexistent packagesDir returns error", func(t *testing.T) {
		_, err := DetectPackages([]string{"packages/aws/foo.yml"}, "/no/such/packages")
		require.Error(t, err)
	})
}
