// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package backports

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "backports.yml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

// writePackagesDir creates a minimal packages/ directory under t.TempDir()
// containing one package per name, each with a valid manifest.yml.
// Returns the path to the packages/ directory.
func writePackagesDir(t *testing.T, packageNames ...string) string {
	t.Helper()
	base := t.TempDir()
	for _, name := range packageNames {
		dir := filepath.Join(base, "packages", name)
		require.NoError(t, os.MkdirAll(dir, 0700))
		manifest := "format_version: \"1.0.0\"\nname: " + name + "\ntype: integration\nversion: \"1.0.0\"\n"
		require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.yml"), []byte(manifest), 0600))
	}
	return filepath.Join(base, "packages")
}

const validEntry = `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`

func TestValidateInventory(t *testing.T) {
	cases := []struct {
		title       string
		contents    string
		wantErr     bool
		errContains []string
	}{
		{
			title:    "valid entry with null maintained_until",
			contents: validEntry,
		},
		{
			title: "valid entry with date maintained_until",
			contents: `backports:
  - package: security_detection_engine
    branch: backport-security_detection_engine-8.19
    base_version: "8.19.0"
    base_commit: "abcdef1234"
    maintained_until: "2027-01-15"
    archived: false
`,
		},
		{
			title: "valid entry with prerelease base_version",
			contents: `backports:
  - package: apm
    branch: backport-apm-8.15
    base_version: "8.15.0-preview-1716438434"
    base_commit: "86356203eb"
    maintained_until: null
    archived: false
`,
		},
		{
			title:    "empty backports list",
			contents: "backports: []\n",
		},
		{
			title: "missing package field",
			contents: `backports:
  - branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"missing required field 'package'"},
		},
		{
			title: "missing branch field",
			contents: `backports:
  - package: aws
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"missing required field 'branch'"},
		},
		{
			title: "missing base_version field",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"missing required field 'base_version'"},
		},
		{
			title: "missing base_commit field",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"missing required field 'base_commit'"},
		},
		{
			title: "missing archived field",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
`,
			wantErr:     true,
			errContains: []string{"missing required field 'archived'"},
		},
		{
			title: "invalid base_version — not a semver",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "not-a-version"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid base_version", "semantic version"},
		},
		{
			title: "invalid base_version — missing patch segment",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid base_version"},
		},
		{
			title: "invalid base_commit — not hex",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "xyz_not_hex"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid base_commit", "lowercase hex SHA"},
		},
		{
			title: "invalid base_commit — too short",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "abc12"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid base_commit", "lowercase hex SHA"},
		},
		{
			title: "invalid base_commit — uppercase hex",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5B593F6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid base_commit", "lowercase hex SHA"},
		},
		{
			title: "valid branch with x wildcard version",
			contents: `backports:
  - package: aws
    branch: backport-aws-6.x
    base_version: "6.0.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
		},
		{
			title: "valid branch with x wildcard and minor",
			contents: `backports:
  - package: aws
    branch: backport-aws-6.14.x
    base_version: "6.14.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
		},
		{
			title: "invalid branch — missing backport- prefix",
			contents: `backports:
  - package: aws
    branch: aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid branch"},
		},
		{
			title: "invalid branch — version does not start with a digit",
			contents: `backports:
  - package: aws
    branch: backport-aws-v3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid branch"},
		},
		{
			title: "invalid branch — contains whitespace",
			contents: `backports:
  - package: aws
    branch: "backport-aws 3.17"
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid branch"},
		},
		{
			title: "invalid branch — contains colon",
			contents: `backports:
  - package: aws
    branch: "backport-aws:3.17"
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid branch"},
		},
		{
			title:       "invalid branch — contains single quote",
			contents:    "backports:\n  - package: aws\n    branch: \"backport-aws-3'17\"\n    base_version: \"3.17.0\"\n    base_commit: \"5b593f6681\"\n    maintained_until: null\n    archived: false\n",
			wantErr:     true,
			errContains: []string{"invalid branch"},
		},
		{
			title: "invalid branch — no version segment",
			contents: `backports:
  - package: aws
    branch: backport-aws
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid branch"},
		},
		{
			title: "invalid maintained_until format",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: "01/15/2027"
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid maintained_until", "must be YYYY-MM-DD"},
		},
		{
			title: "multiple entries with errors are all reported",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
  - branch: backport-aws-1.51
    base_version: "1.51.2"
    base_commit: "88ad4b8432"
    maintained_until: "not-a-date"
    archived: true
`,
			wantErr:     true,
			errContains: []string{"missing required field 'package'", "invalid maintained_until"},
		},
		{
			title: "duplicate branch name",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.18.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{`duplicate branch "backport-aws-3.17"`},
		},
		{
			title: "duplicate package and base_version",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
  - package: aws
    branch: backport-aws-3.17x
    base_version: "3.17.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"duplicate package/version", "aws", "3.17.0"},
		},
		{
			title: "same package different versions is valid",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
  - package: aws
    branch: backport-aws-3.13
    base_version: "3.13.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
`,
		},
		{
			title: "same version different packages is valid",
			contents: `backports:
  - package: aws
    branch: backport-aws-1.0
    base_version: "1.0.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
  - package: azure
    branch: backport-azure-1.0
    base_version: "1.0.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
`,
		},
		{
			title: "security_detection_engine 8.17.7 duplicate is allowed (known exception)",
			contents: `backports:
  - package: security_detection_engine
    branch: backport-security_detection_engine-8.17
    base_version: "8.17.7"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
  - package: security_detection_engine
    branch: backport-security_detection_engine-8.18
    base_version: "8.17.7"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
`,
		},
		{
			title: "both duplicate branch and duplicate package/version are reported",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"duplicate branch", "duplicate package/version"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			path := writeTemp(t, tc.contents)
			err := ValidateInventory(path, "")
			if tc.wantErr {
				require.Error(t, err)
				for _, substr := range tc.errContains {
					assert.True(t, strings.Contains(err.Error(), substr),
						"expected error to contain %q, got: %s", substr, err.Error())
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateInventoryPackageValidation(t *testing.T) {
	contents := func(pkg string) string {
		return `backports:
  - package: ` + pkg + `
    branch: backport-` + pkg + `-1.0
    base_version: "1.0.0"
    base_commit: "abcdef1234"
    maintained_until: null
    archived: false
`
	}

	t.Run("known package passes", func(t *testing.T) {
		packagesDir := writePackagesDir(t, "aws", "kubernetes")
		path := writeTemp(t, contents("aws"))
		require.NoError(t, ValidateInventory(path, packagesDir))
	})

	t.Run("unknown package fails", func(t *testing.T) {
		packagesDir := writePackagesDir(t, "aws")
		path := writeTemp(t, contents("no_such_package"))
		err := ValidateInventory(path, packagesDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown package")
		assert.Contains(t, err.Error(), "no_such_package")
	})

	t.Run("empty packagesDir skips package check", func(t *testing.T) {
		path := writeTemp(t, contents("totally_made_up"))
		require.NoError(t, ValidateInventory(path, ""))
	})
}

func TestValidateInventoryFileNotFound(t *testing.T) {
	err := ValidateInventory("/no/such/file.yml", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading inventory")
}
