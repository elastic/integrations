// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package backports

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
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
			errContains: []string{"missing required field 'archived'", "missing required field 'remove_other_packages'"},
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
`,
		},
		{
			title: "valid branch — three-component version (major.minor.x)",
			contents: `backports:
  - package: aws
    branch: backport-aws-6.14.x
    base_version: "6.14.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
    remove_other_packages: false
`,
		},
		{
			title: "valid branch — three-component version (major.minor.patch)",
			contents: `backports:
  - package: aws
    branch: backport-aws-1.2.3
    base_version: "1.2.3"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
    remove_other_packages: false
`,
		},
		{
			title: "valid branch — three-component version (major.minor.patch) for aws",
			contents: `backports:
  - package: aws
    branch: backport-aws-7.15.0
    base_version: "7.15.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
    remove_other_packages: false
`,
		},
		{
			title: "valid branch — three-component version (major.minor.patch) for security_detection_engine",
			contents: `backports:
  - package: security_detection_engine
    branch: backport-security_detection_engine-8.9.10
    base_version: "8.9.10"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
    remove_other_packages: false
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
    remove_other_packages: false
`,
			wantErr:     true,
			errContains: []string{"invalid branch"},
		},
		{
			title: "invalid branch — package name mismatch",
			contents: `backports:
  - package: aws
    branch: backport-nginx-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
    remove_other_packages: false
`,
			wantErr:     true,
			errContains: []string{`must start with "backport-aws-"`},
		},
		{
			title: "valid branch — suffix starting with a letter",
			contents: `backports:
  - package: aws
    branch: backport-aws-v3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
    remove_other_packages: false
`,
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
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
    remove_other_packages: false
  - branch: backport-aws-1.51
    base_version: "1.51.2"
    base_commit: "88ad4b8432"
    maintained_until: "not-a-date"
    archived: true
    remove_other_packages: false
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
    remove_other_packages: false
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.18.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
    remove_other_packages: false
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
    remove_other_packages: false
  - package: aws
    branch: backport-aws-3.17x
    base_version: "3.17.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
    remove_other_packages: false
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
    remove_other_packages: false
  - package: aws
    branch: backport-aws-3.13
    base_version: "3.13.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
    remove_other_packages: false
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
    remove_other_packages: false
  - package: azure
    branch: backport-azure-1.0
    base_version: "1.0.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
    remove_other_packages: false
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
    remove_other_packages: false
  - package: security_detection_engine
    branch: backport-security_detection_engine-8.18
    base_version: "8.17.7"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
    remove_other_packages: false
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
    remove_other_packages: false
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
    remove_other_packages: false
`,
			wantErr:     true,
			errContains: []string{"duplicate branch", "duplicate package/version"},
		},
		{
			title: "invalid branch with missing package",
			contents: `backports:
  - package: ""
    branch: totally-wrong
    base_version: "1.0.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
    remove_other_packages: false
`,
			wantErr:     true,
			errContains: []string{"invalid branch"},
		},
		{
			title: "missing remove_other_packages field",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"missing required field 'remove_other_packages'"},
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
    remove_other_packages: false
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

const checkActiveInventory = `backports:
  - package: mypkg
    branch: backport-mypkg-1.0
    base_version: "1.0.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
    remove_other_packages: false

  - package: mypkg
    branch: backport-mypkg-2.0
    base_version: "2.0.0"
    base_commit: "11223344ff"
    maintained_until: null
    archived: true
    remove_other_packages: false

  - package: mypkg
    branch: backport-mypkg-3.0
    base_version: "3.0.0"
    base_commit: "aabbccddee"
    maintained_until: "2020-01-01"
    archived: false
    remove_other_packages: false

  - package: mypkg
    branch: backport-mypkg-4.0
    base_version: "4.0.0"
    base_commit: "aabbccddee"
    maintained_until: "2099-12-31"
    archived: false
    remove_other_packages: false

  - package: mypkg
    branch: backport-mypkg-5.0
    base_version: "5.0.0"
    base_commit: "aabbccddee"
    maintained_until: "2099-12-31"
    archived: true
    remove_other_packages: false
`

func TestCheckActive(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	path := writeTemp(t, checkActiveInventory)

	cases := []struct {
		branch         string
		wantActive     bool
		wantArchived   bool
		wantMaintained *string
		wantErr        bool
	}{
		{
			branch:       "backport-mypkg-1.0",
			wantActive:   true,
			wantArchived: false,
		},
		{
			branch:       "backport-mypkg-2.0",
			wantActive:   false,
			wantArchived: true,
		},
		{
			branch:         "backport-mypkg-3.0",
			wantActive:     false,
			wantArchived:   false,
			wantMaintained: ptr("2020-01-01"),
		},
		{
			branch:         "backport-mypkg-4.0",
			wantActive:     true,
			wantArchived:   false,
			wantMaintained: ptr("2099-12-31"),
		},
		{
			branch:         "backport-mypkg-5.0",
			wantActive:     false,
			wantArchived:   true,
			wantMaintained: ptr("2099-12-31"),
		},
		{
			branch:  "backport-mypkg-no-such",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.branch, func(t *testing.T) {
			result, err := CheckActive(path, tc.branch, now)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.branch, result.Branch)
			assert.Equal(t, tc.wantActive, result.Active)
			assert.Equal(t, tc.wantArchived, result.Archived)
			assert.Equal(t, tc.wantMaintained, result.MaintainedUntil)
		})
	}
}

func TestCheckActiveMaintainedUntilBoundary(t *testing.T) {
	mu := "2026-06-04"
	inv := `backports:
  - package: mypkg
    branch: backport-mypkg-1.0
    base_version: "1.0.0"
    base_commit: "aabbccddee"
    maintained_until: "` + mu + `"
    archived: false
    remove_other_packages: false
`
	path := writeTemp(t, inv)

	t.Run("same day is still active", func(t *testing.T) {
		now := time.Date(2026, 6, 4, 23, 59, 59, 0, time.UTC)
		result, err := CheckActive(path, "backport-mypkg-1.0", now)
		require.NoError(t, err)
		assert.True(t, result.Active)
	})

	t.Run("day after is inactive", func(t *testing.T) {
		now := time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
		result, err := CheckActive(path, "backport-mypkg-1.0", now)
		require.NoError(t, err)
		assert.False(t, result.Active)
	})
}

func TestCheckActiveFileNotFound(t *testing.T) {
	_, err := CheckActive("/no/such/file.yml", "some-branch", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading inventory")
}

func readInventory(t *testing.T, path string) inventory {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var inv inventory
	require.NoError(t, yaml.Unmarshal(data, &inv))
	return inv
}

func TestValidateBranchFormat(t *testing.T) {
	tests := []struct {
		branch      string
		wantErr     bool
		errContains string
	}{
		{branch: "backport-aws-3.17", wantErr: false},
		{branch: "backport-aws-6.x", wantErr: false},
		{branch: "backport-aws-2024-hotfix", wantErr: false},
		{branch: "backport-security_detection_engine-8.9", wantErr: false},
		{branch: "aws-3.17", wantErr: true, errContains: "invalid branch"},
		{branch: "backport-aws-", wantErr: true, errContains: "invalid branch"},
		{branch: "backport-aws-3.17 extra", wantErr: true, errContains: "invalid branch"},
		{branch: "totally-wrong", wantErr: true, errContains: "invalid branch"},
	}
	for _, tt := range tests {
		t.Run(tt.branch, func(t *testing.T) {
			err := validateBranchFormat(tt.branch)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateBranchName(t *testing.T) {
	tests := []struct {
		packageName string
		branch      string
		wantErr     bool
		errContains string
	}{
		{packageName: "aws", branch: "backport-aws-3.17", wantErr: false},
		{packageName: "aws", branch: "backport-aws-6.x", wantErr: false},
		{packageName: "aws", branch: "backport-aws-7.15.0", wantErr: false},
		{packageName: "aws", branch: "backport-aws-2024-hotfix", wantErr: false},
		{packageName: "security_detection_engine", branch: "backport-security_detection_engine-8.9", wantErr: false},
		{
			packageName: "aws", branch: "backport-nginx-3.17",
			wantErr: true, errContains: `must start with "backport-aws-"`,
		},
		{
			packageName: "aws", branch: "aws-3.17",
			wantErr: true, errContains: "invalid branch",
		},
		{
			packageName: "aws", branch: "backport-aws-3.17 extra",
			wantErr: true, errContains: "invalid branch",
		},
		{
			packageName: "aws", branch: "backport-aws-",
			wantErr: true, errContains: "invalid branch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.branch, func(t *testing.T) {
			err := ValidateBranchName(tt.packageName, tt.branch)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAddEntry(t *testing.T) {
	const twoEntries = `backports:
  - package: aws
    branch: backport-aws-3.0
    base_version: "3.0.0"
    base_commit: "def5678901"
    maintained_until: null
    archived: false
    remove_other_packages: false
  - package: aws
    branch: backport-aws-1.19
    base_version: "1.19.5"
    base_commit: "abc1234567"
    maintained_until: null
    archived: false
    remove_other_packages: false
`

	t.Run("inserts between versions of the same package", func(t *testing.T) {
		path := writeTemp(t, twoEntries)
		branch, err := AddEntry(path, "aws", "2.1.0", "aabbccddee", "")
		require.NoError(t, err)
		assert.Equal(t, "backport-aws-2.1", branch)

		inv := readInventory(t, path)
		require.Len(t, inv.Backports, 3)
		assert.Equal(t, "backport-aws-3.0", inv.Backports[0].Branch)
		assert.Equal(t, "backport-aws-2.1", inv.Backports[1].Branch)
		assert.Equal(t, "backport-aws-1.19", inv.Backports[2].Branch)
	})

	t.Run("inserts between packages alphabetically", func(t *testing.T) {
		inv := `backports:
  - package: aws
    branch: backport-aws-1.0
    base_version: "1.0.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
    remove_other_packages: false
  - package: gcp
    branch: backport-gcp-1.0
    base_version: "1.0.0"
    base_commit: "ffeeddccbb"
    maintained_until: null
    archived: false
    remove_other_packages: false
`
		path := writeTemp(t, inv)
		branch, err := AddEntry(path, "elastic_agent", "2.3.0", "112233aabb", "")
		require.NoError(t, err)
		assert.Equal(t, "backport-elastic_agent-2.3", branch)

		result := readInventory(t, path)
		require.Len(t, result.Backports, 3)
		assert.Equal(t, "backport-aws-1.0", result.Backports[0].Branch)
		assert.Equal(t, "backport-elastic_agent-2.3", result.Backports[1].Branch)
		assert.Equal(t, "backport-gcp-1.0", result.Backports[2].Branch)
	})

	t.Run("appends when new entry is last", func(t *testing.T) {
		path := writeTemp(t, twoEntries)
		branch, err := AddEntry(path, "zz_pkg", "1.0.0", "aabbccddee", "")
		require.NoError(t, err)
		assert.Equal(t, "backport-zz_pkg-1.0", branch)

		inv := readInventory(t, path)
		require.Len(t, inv.Backports, 3)
		assert.Equal(t, "backport-zz_pkg-1.0", inv.Backports[2].Branch)
	})

	t.Run("prepends when new entry is first", func(t *testing.T) {
		path := writeTemp(t, twoEntries)
		branch, err := AddEntry(path, "aaa_pkg", "1.0.0", "aabbccddee", "")
		require.NoError(t, err)
		assert.Equal(t, "backport-aaa_pkg-1.0", branch)

		inv := readInventory(t, path)
		require.Len(t, inv.Backports, 3)
		assert.Equal(t, "backport-aaa_pkg-1.0", inv.Backports[0].Branch)
		assert.Equal(t, "backport-aws-3.0", inv.Backports[1].Branch)
	})

	t.Run("derives branch from major.minor only", func(t *testing.T) {
		path := writeTemp(t, twoEntries)
		branch, err := AddEntry(path, "aws", "2.5.3", "aabbccddee", "")
		require.NoError(t, err)
		assert.Equal(t, "backport-aws-2.5", branch)
	})

	t.Run("new entry has correct fields", func(t *testing.T) {
		path := writeTemp(t, twoEntries)
		_, err := AddEntry(path, "aws", "2.1.0", "aabbccddee", "")
		require.NoError(t, err)

		inv := readInventory(t, path)
		require.Len(t, inv.Backports, 3)
		e := inv.Backports[1]
		assert.Equal(t, "aws", e.Package)
		assert.Equal(t, "backport-aws-2.1", e.Branch)
		assert.Equal(t, "2.1.0", e.BaseVersion)
		assert.Equal(t, "aabbccddee", e.BaseCommit)
		assert.Nil(t, e.MaintainedUntil)
		require.NotNil(t, e.Archived)
		assert.False(t, *e.Archived)
		require.NotNil(t, e.RemoveOtherPackages)
		assert.True(t, *e.RemoveOtherPackages)
	})

	t.Run("existing entries keep double-quoted style", func(t *testing.T) {
		path := writeTemp(t, twoEntries)
		_, err := AddEntry(path, "aws", "2.1.0", "aabbccddee", "")
		require.NoError(t, err)

		out, _ := os.ReadFile(path)
		content := string(out)
		assert.Contains(t, content, `base_version: "1.19.5"`)
		assert.Contains(t, content, `base_version: "3.0.0"`)
	})

	t.Run("header comment is preserved", func(t *testing.T) {
		inv := `# Backport inventory header
#
backports:
  - package: aws
    branch: backport-aws-1.0
    base_version: "1.0.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false
    remove_other_packages: false
`
		path := writeTemp(t, inv)
		_, err := AddEntry(path, "aws", "2.0.0", "ffeeddccbb", "")
		require.NoError(t, err)

		out, _ := os.ReadFile(path)
		assert.Contains(t, string(out), "# Backport inventory header")
	})

	t.Run("invalid base_version returns error", func(t *testing.T) {
		path := writeTemp(t, twoEntries)
		_, err := AddEntry(path, "aws", "not-a-version", "aabbccddee", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid base_version")
	})

	t.Run("file not found returns error", func(t *testing.T) {
		_, err := AddEntry("/no/such/file.yml", "aws", "1.0.0", "aabbccddee", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading inventory")
	})
}

func ptr(s string) *string { return &s }
