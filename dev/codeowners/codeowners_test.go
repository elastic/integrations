// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package codeowners

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the exported Owners API (ParseOwners, LoadOwners, Resolve,
// EntriesUnder, ExplicitEntry, PackageOwnersByPath). These mirror the
// behaviours the dev/backports/owners package relies on, ensuring the shared
// implementation stays consistent.

func TestParseOwners(t *testing.T) {
	t.Run("valid content parses successfully", func(t *testing.T) {
		const content = `/packages/aws @elastic/obs-infraobs-integrations
/packages/aws/data_stream/cloudtrail @elastic/security-service-integrations
# a comment line is skipped
`
		o, err := ParseOwners(content)
		require.NoError(t, err)
		owners, ok := o.ExplicitEntry("/packages/aws")
		require.True(t, ok)
		assert.Equal(t, []string{"@elastic/obs-infraobs-integrations"}, owners)
	})

	t.Run("single-field exclusion rule that removes owners from a defined path is rejected", func(t *testing.T) {
		// checkSingleField must reject any exclusion-only line that would strip
		// ownership from a path already covered by an explicit entry — same
		// validation readGithubOwners performs when reading from disk.
		const content = `/packages/aws @elastic/obs-infraobs-integrations
/packages/aws/data_stream/cloudtrail
`
		_, err := ParseOwners(content)
		assert.Error(t, err)
	})

	t.Run("trailing slash on path is stripped", func(t *testing.T) {
		const content = "/packages/aws/ @elastic/obs-infraobs-integrations\n"
		o, err := ParseOwners(content)
		require.NoError(t, err)
		_, ok := o.ExplicitEntry("/packages/aws")
		assert.True(t, ok)
	})
}

func TestResolve(t *testing.T) {
	const content = `
/packages/aws @elastic/obs-infraobs-integrations
/packages/aws/data_stream/cloudtrail @elastic/security-service-integrations
/packages/nested/foo @elastic/ecosystem
`
	o, err := ParseOwners(content)
	require.NoError(t, err)

	cases := []struct {
		name     string
		path     string
		expected []string
		found    bool
	}{
		{
			name:     "explicit package root",
			path:     "/packages/aws",
			expected: []string{"@elastic/obs-infraobs-integrations"},
			found:    true,
		},
		{
			name:     "explicit data stream override",
			path:     "/packages/aws/data_stream/cloudtrail",
			expected: []string{"@elastic/security-service-integrations"},
			found:    true,
		},
		{
			name:     "data stream without override falls back to package owner",
			path:     "/packages/aws/data_stream/vpcflow",
			expected: []string{"@elastic/obs-infraobs-integrations"},
			found:    true,
		},
		{
			name:     "nested category package",
			path:     "/packages/nested/foo",
			expected: []string{"@elastic/ecosystem"},
			found:    true,
		},
		{
			name:  "unknown path with no ancestor entry",
			path:  "/packages/does-not-exist",
			found: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, found := o.Resolve(c.path)
			assert.Equal(t, c.found, found)
			if c.found {
				assert.Equal(t, c.expected, got)
			}
		})
	}
}

func TestEntriesUnder(t *testing.T) {
	const content = `
/packages/aws @elastic/obs-infraobs-integrations
/packages/aws/data_stream/cloudtrail @elastic/security-service-integrations
/packages/aws/kibana @elastic/obs-infraobs-integrations
/packages/awsome @elastic/unrelated-team
`
	o, err := ParseOwners(content)
	require.NoError(t, err)

	got := o.EntriesUnder("/packages/aws")
	assert.ElementsMatch(t, []string{
		"/packages/aws/data_stream/cloudtrail",
		"/packages/aws/kibana",
	}, got)
}

func TestExplicitEntry(t *testing.T) {
	const content = `
/packages/aws @elastic/obs-infraobs-integrations
/packages/aws/data_stream/cloudtrail @elastic/security-service-integrations
`
	o, err := ParseOwners(content)
	require.NoError(t, err)

	t.Run("returns entry for an explicitly defined path", func(t *testing.T) {
		got, ok := o.ExplicitEntry("/packages/aws/data_stream/cloudtrail")
		require.True(t, ok)
		assert.Equal(t, []string{"@elastic/security-service-integrations"}, got)
	})

	t.Run("returns false for a path that only resolves via walk-up", func(t *testing.T) {
		_, ok := o.ExplicitEntry("/packages/aws/data_stream/vpcflow")
		assert.False(t, ok)
	})

	t.Run("returns false for an unknown path", func(t *testing.T) {
		_, ok := o.ExplicitEntry("/packages/other")
		assert.False(t, ok)
	})
}

func TestCheckManifest(t *testing.T) {
	cases := []struct {
		codeownersPath string
		manifestPath   string
		valid          bool
	}{
		{
			codeownersPath: "testdata/CODEOWNERS-valid",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-valid",
			manifestPath:   "testdata/noowner/manifest.yml",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-multiple-owners",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-no-owner",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-empty",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-wrong-devexp",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-precedence",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-wrong-precedence",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          false,
		},
	}

	for _, c := range cases {
		t.Run(c.codeownersPath+"_"+c.manifestPath, func(t *testing.T) {
			owners, err := readGithubOwners(c.codeownersPath)
			require.NoError(t, err)

			err = owners.checkManifest(c.manifestPath)
			if c.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidatePackages(t *testing.T) {
	cases := []struct {
		codeownersPath string
		packageDir     string
		valid          bool
	}{
		{
			codeownersPath: "testdata/CODEOWNERS-streams-missing-owners",
			packageDir:     "testdata/test_packages",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-streams-multiple-owners",
			packageDir:     "testdata/test_packages",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-streams-valid",
			packageDir:     "testdata/test_packages",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-nested-valid",
			packageDir:     "testdata/nested_packages",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-nested-missing-owner",
			packageDir:     "testdata/nested_packages",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-nested-category-owner",
			packageDir:     "testdata/nested_packages",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-nested-streams-valid",
			packageDir:     "testdata/nested_packages",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-nested-streams-missing-owners",
			packageDir:     "testdata/nested_packages",
			valid:          false,
		},
	}

	for _, c := range cases {
		t.Run(c.codeownersPath, func(t *testing.T) {
			owners, err := readGithubOwners(c.codeownersPath)
			require.NoError(t, err)

			err = validatePackages(owners, c.packageDir)
			if c.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestReadGithubOwners(t *testing.T) {
	cases := []struct {
		codeownersPath string
		valid          bool
	}{
		{
			codeownersPath: "testdata/CODEOWNERS-valid",
			valid:          true,
		},
		{
			codeownersPath: "notexsists",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-no-owner",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-multiple-owners",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-invalid-override",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-invalid-override-wildcard",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-owners-trailing-slash",
			valid:          true,
		},
	}

	for _, c := range cases {
		t.Run(c.codeownersPath, func(t *testing.T) {
			_, err := readGithubOwners(c.codeownersPath)
			if c.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestReturnPackageOwners(t *testing.T) {
	cases := []struct {
		title          string
		codeownersPath string
		packageName    string
		datastream     string
		expected       []string
		expectedError  bool
	}{
		{
			title:          "just package",
			codeownersPath: "testdata/CODEOWNERS-owners-packages-datastreams",
			packageName:    "aws",
			datastream:     "",
			expected:       []string{"@elastic/obs-infraobs-integrations", "@elastic/obs-ds-hosted-services", "@elastic/security-service-integrations"},
			expectedError:  false,
		},
		{
			title:          "package with trailing slash",
			codeownersPath: "testdata/CODEOWNERS-owners-trailing-slash",
			packageName:    "content",
			datastream:     "",
			expected:       []string{"@elastic/integrations"},
			expectedError:  false,
		},
		{
			title:          "data stream with trailing slash",
			codeownersPath: "testdata/CODEOWNERS-owners-trailing-slash",
			packageName:    "aws",
			datastream:     "apigateway_logs",
			expected:       []string{"@elastic/obs-infraobs-integrations"},
			expectedError:  false,
		},
		{
			title:          "nested package with trailing slash",
			codeownersPath: "testdata/CODEOWNERS-owners-trailing-slash",
			packageName:    "elastic_package_registry",
			datastream:     "",
			expected:       []string{"@elastic/integrations"},
			expectedError:  false,
		},
		{
			title:          "package and datastream",
			codeownersPath: "testdata/CODEOWNERS-owners-packages-datastreams",
			packageName:    "aws",
			datastream:     "cloudtrail",
			expected:       []string{"@elastic/obs-infraobs-integrations"},
			expectedError:  false,
		},
		{
			title:          "package and other datastream",
			codeownersPath: "testdata/CODEOWNERS-owners-packages-datastreams",
			packageName:    "aws",
			datastream:     "cloudwatch_logs",
			expected:       []string{"@elastic/obs-ds-hosted-services"},
			expectedError:  false,
		},
		{
			title:          "package not found",
			codeownersPath: "testdata/CODEOWNERS-owners-packages-datastreams",
			packageName:    "other",
			datastream:     "",
			expected:       []string{},
			expectedError:  true,
		},
		{
			title:          "package found but not data stream defined",
			codeownersPath: "testdata/CODEOWNERS-owners-packages-datastreams",
			packageName:    "aws",
			datastream:     "other",
			expected:       []string{"@elastic/obs-infraobs-integrations", "@elastic/obs-ds-hosted-services", "@elastic/security-service-integrations"},
			expectedError:  false,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			owners, err := PackageOwners(c.packageName, c.datastream, c.codeownersPath)
			if c.expectedError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.expected, owners)
		})
	}
}

func TestPackageOwnersByPath(t *testing.T) {
	cases := []struct {
		title          string
		codeownersPath string
		pkgPath        string
		datastream     string
		expected       []string
		expectedError  bool
	}{
		{
			title:          "nested package",
			codeownersPath: "testdata/CODEOWNERS-nested-valid",
			pkgPath:        "testdata/nested_packages/category/package_nested_1",
			datastream:     "",
			expected:       []string{"@elastic/integrations-developer-experience"},
			expectedError:  false,
		},
		{
			title:          "nested package inherits category owner",
			codeownersPath: "testdata/CODEOWNERS-nested-category-owner",
			pkgPath:        "testdata/nested_packages/category/package_nested_2",
			datastream:     "",
			expected:       []string{"@elastic/integrations-developer-experience"},
			expectedError:  false,
		},
		{
			title:          "nested package data stream",
			codeownersPath: "testdata/CODEOWNERS-nested-streams-valid",
			pkgPath:        "testdata/nested_packages/category/package_nested_1",
			datastream:     "stream_1",
			expected:       []string{"@pkoutsovasilis"},
			expectedError:  false,
		},
		{
			title:          "top-level package",
			codeownersPath: "testdata/CODEOWNERS-nested-valid",
			pkgPath:        "testdata/nested_packages/package_top",
			datastream:     "",
			expected:       []string{"@elastic/integrations-developer-experience"},
			expectedError:  false,
		},
		{
			title:          "data stream not in CODEOWNERS falls back to package owner",
			codeownersPath: "testdata/CODEOWNERS-nested-streams-valid",
			pkgPath:        "testdata/nested_packages/category/package_nested_1",
			datastream:     "stream_unknown",
			expected:       []string{"@elastic/integrations-developer-experience"},
			expectedError:  false,
		},
		{
			title:          "package path not found",
			codeownersPath: "testdata/CODEOWNERS-owners-packages-datastreams",
			pkgPath:        "packages/other",
			datastream:     "",
			expected:       []string{},
			expectedError:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			owners, err := LoadOwners(c.codeownersPath)
			require.NoError(t, err)

			got, err := owners.PackageOwnersByPath(c.pkgPath, c.datastream)
			if c.expectedError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.expected, got)
		})
	}
}
