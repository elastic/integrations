// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apply

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveBranchName(t *testing.T) {
	tests := []struct {
		target  string
		pkg     string
		want    string
		wantErr bool
	}{
		{target: "6.14", pkg: "aws", want: "backport-aws-6.14"},
		{target: "6.x", pkg: "aws", want: "backport-aws-6.x"},
		{target: "backport-aws-6.14", pkg: "aws", want: "backport-aws-6.14"},
		{target: "backport-prometheus-1.24", pkg: "prometheus", want: "backport-prometheus-1.24"},
		{target: "bad version!", pkg: "aws", wantErr: true},
		{target: "6.14", pkg: "bad pkg!", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.target+"/"+tc.pkg, func(t *testing.T) {
			got, err := resolveBranchName(tc.target, tc.pkg)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestWorkingBranchName(t *testing.T) {
	tests := []struct {
		pkg, branch, sha8, want string
	}{
		{"aws", "backport-aws-6.14", "abc12345", "auto-backport/aws-6.14-abc12345"},
		{"prometheus", "backport-prometheus-1.24", "deadbeef", "auto-backport/prometheus-1.24-deadbeef"},
	}
	for _, tc := range tests {
		got := workingBranchName(tc.pkg, tc.branch, tc.sha8)
		assert.Equal(t, tc.want, got)
	}
}

func TestBumpPatchVersion(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantVersion string
		wantContent string
		wantErr     bool
	}{
		{
			name:        "unquoted",
			content:     "name: aws\nversion: 6.14.2\nformat_version: 3.0.0\n",
			wantVersion: "6.14.3",
			wantContent: "name: aws\nversion: 6.14.3\nformat_version: 3.0.0\n",
		},
		{
			name:        "double-quoted",
			content:     "name: zscaler\nversion: \"1.23.3\"\nformat_version: 3.0.0\n",
			wantVersion: "1.23.4",
			wantContent: "name: zscaler\nversion: \"1.23.4\"\nformat_version: 3.0.0\n",
		},
		{
			name:        "single-quoted",
			content:     "name: prom\nversion: '2.0.1'\nformat_version: 3.0.0\n",
			wantVersion: "2.0.2",
			wantContent: "name: prom\nversion: '2.0.2'\nformat_version: 3.0.0\n",
		},
		{
			name:        "patch zero",
			content:     "version: 1.0.0\n",
			wantVersion: "1.0.1",
			wantContent: "version: 1.0.1\n",
		},
		{
			name:        "preserves rest of file",
			content:     "name: mypackage\nformat_version: 3.0.0\nversion: 2.5.9\ndescription: A package.\n",
			wantVersion: "2.5.10",
			wantContent: "name: mypackage\nformat_version: 3.0.0\nversion: 2.5.10\ndescription: A package.\n",
		},
		{
			name:    "missing version field",
			content: "name: pkg\nformat_version: 3.0.0\n",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.yml")
			require.NoError(t, os.WriteFile(path, []byte(tc.content), 0o644))

			got, err := bumpPatchVersion(path)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantVersion, got)

			updated, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, tc.wantContent, string(updated))
		})
	}
}

// TestResolveManifestVersionConflict follows the version convention of a
// real backport: "ours" (the HEAD side of the conflict) is the backport
// branch's own, older version — the branch was cut from an elder commit and
// only advances through its own independent patch bumps. "theirs" is the
// version the cherry-picked commit carries on main, which is normally ahead
// since main keeps advancing on its own. Resolving a version-only conflict
// keeps "theirs" content verbatim for now (including its higher version and
// any adjacent field it added) — cherryPickOrConflict normalizes the version
// back to the branch's own lineage immediately afterward, so the version
// value seen here never survives into the final commit.
func TestResolveManifestVersionConflict(t *testing.T) {
	tests := []struct {
		name            string
		content         string
		wantContent     string
		wantHadConflict bool
		wantResolved    bool
	}{
		{
			name:            "no conflict markers",
			content:         "name: aws\nversion: 6.14.2\nformat_version: 3.0.0\n",
			wantContent:     "name: aws\nversion: 6.14.2\nformat_version: 3.0.0\n",
			wantHadConflict: false,
			wantResolved:    true,
		},
		{
			// Branch is at 6.14.2 (its own lineage); main's commit shows 6.15.0,
			// having advanced past where the branch branched off. Resolved content
			// keeps 6.15.0 for now — bumpPatchVersion later produces 6.14.3, not
			// 6.15.x, once cherryPickOrConflict normalizes the version back down.
			name: "version-only conflict on our side keeps theirs",
			content: "name: aws\n" +
				"<<<<<<< HEAD\n" +
				"version: 6.14.2\n" +
				"=======\n" +
				"version: 6.15.0\n" +
				">>>>>>> abc1234 (Add feature)\n" +
				"format_version: 3.0.0\n",
			wantContent: "name: aws\n" +
				"version: 6.15.0\n" +
				"format_version: 3.0.0\n",
			wantHadConflict: true,
			wantResolved:    true,
		},
		{
			// Branch is at 6.14.2; by the time this fix landed, main had advanced
			// much further (6.18.0) and also added a "categories" field in the
			// same commit. The resolved content preserves both the higher version
			// and the new field — the field survives into the final commit, but
			// the version is later normalized back to the branch's own lineage
			// (6.14.3), same as the previous case.
			name: "version-only conflict on our side preserves theirs' adjacent addition",
			content: "name: aws\n" +
				"<<<<<<< HEAD\n" +
				"version: 6.14.2\n" +
				"=======\n" +
				"version: 6.18.0\n" +
				"categories:\n" +
				"  - kubernetes\n" +
				">>>>>>> abc1234 (Add categories field)\n" +
				"format_version: 3.0.0\n",
			wantContent: "name: aws\n" +
				"version: 6.18.0\n" +
				"categories:\n" +
				"  - kubernetes\n" +
				"format_version: 3.0.0\n",
			wantHadConflict: true,
			wantResolved:    true,
		},
		{
			// Not a realistic git shape: theirs dropping the version field
			// without re-adding it anywhere else in the file would require an
			// already-invalid, schema-violating main commit. This exists to
			// exercise the versionLines-count safety net in
			// resolveManifestVersionConflict as defense-in-depth, per its doc
			// comment, not to simulate a plausible cherry-pick conflict.
			name: "version-only conflict that would drop the version field entirely is left untouched",
			content: "name: aws\n" +
				"<<<<<<< HEAD\n" +
				"version: 6.14.2\n" +
				"=======\n" +
				">>>>>>> abc1234 (Delete version)\n" +
				"format_version: 3.0.0\n",
			wantContent: "name: aws\n" +
				"<<<<<<< HEAD\n" +
				"version: 6.14.2\n" +
				"=======\n" +
				">>>>>>> abc1234 (Delete version)\n" +
				"format_version: 3.0.0\n",
			wantHadConflict: true,
			wantResolved:    false,
		},
		{
			name: "conflict with other content is left untouched",
			content: "name: aws\n" +
				"<<<<<<< HEAD\n" +
				"version: 6.14.2\n" +
				"owner:\n" +
				"  github: elastic/obs-infraobs-integrations\n" +
				"=======\n" +
				"version: 6.15.0\n" +
				">>>>>>> abc1234 (Add feature)\n" +
				"format_version: 3.0.0\n",
			wantContent: "name: aws\n" +
				"<<<<<<< HEAD\n" +
				"version: 6.14.2\n" +
				"owner:\n" +
				"  github: elastic/obs-infraobs-integrations\n" +
				"=======\n" +
				"version: 6.15.0\n" +
				">>>>>>> abc1234 (Add feature)\n" +
				"format_version: 3.0.0\n",
			wantHadConflict: true,
			wantResolved:    false,
		},
		{
			name: "unrelated conflict on both sides is left untouched",
			content: "name: aws\n" +
				"version: 6.14.2\n" +
				"<<<<<<< HEAD\n" +
				"description: Old description.\n" +
				"=======\n" +
				"description: New description.\n" +
				">>>>>>> abc1234 (Add feature)\n",
			wantContent: "name: aws\n" +
				"version: 6.14.2\n" +
				"<<<<<<< HEAD\n" +
				"description: Old description.\n" +
				"=======\n" +
				"description: New description.\n" +
				">>>>>>> abc1234 (Add feature)\n",
			wantHadConflict: true,
			wantResolved:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.yml")
			require.NoError(t, os.WriteFile(path, []byte(tc.content), 0o644))

			gotHadConflict, gotResolved, err := resolveManifestVersionConflict(path)
			require.NoError(t, err)
			assert.Equal(t, tc.wantHadConflict, gotHadConflict, "hadConflict")
			assert.Equal(t, tc.wantResolved, gotResolved, "resolved")

			updated, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, tc.wantContent, string(updated))
		})
	}
}

func TestSetManifestVersion(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		version     string
		wantContent string
	}{
		{
			name:        "unquoted",
			content:     "name: aws\nversion: 6.14.2\nformat_version: 3.0.0\n",
			version:     "6.14.5",
			wantContent: "name: aws\nversion: 6.14.5\nformat_version: 3.0.0\n",
		},
		{
			name:        "double-quoted",
			content:     "name: zscaler\nversion: \"1.23.3\"\nformat_version: 3.0.0\n",
			version:     "1.23.9",
			wantContent: "name: zscaler\nversion: \"1.23.9\"\nformat_version: 3.0.0\n",
		},
		{
			name:        "no-op when already set",
			content:     "name: aws\nversion: 6.14.2\nformat_version: 3.0.0\n",
			version:     "6.14.2",
			wantContent: "name: aws\nversion: 6.14.2\nformat_version: 3.0.0\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.yml")
			require.NoError(t, os.WriteFile(path, []byte(tc.content), 0o644))

			require.NoError(t, setManifestVersion(path, tc.version))

			updated, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, tc.wantContent, string(updated))
		})
	}
}

func TestParseEntryFields(t *testing.T) {
	tests := []struct {
		name  string
		block string
		want  []changeItem
	}{
		{
			name: "single item",
			block: `- version: "1.2.3"
  changes:
    - description: Fix a bug in the ingestion pipeline.
      type: bugfix
      link: https://github.com/elastic/integrations/pull/123`,
			want: []changeItem{
				{Description: "Fix a bug in the ingestion pipeline.", Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/123"},
			},
		},
		{
			name: "multiple items",
			block: `- version: "1.2.3"
  changes:
    - description: Fix a bug.
      type: bugfix
      link: https://github.com/elastic/integrations/pull/1
    - description: Add a feature.
      type: enhancement
      link: https://github.com/elastic/integrations/pull/2`,
			want: []changeItem{
				{Description: "Fix a bug.", Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/1"},
				{Description: "Add a feature.", Type: "enhancement", Link: "https://github.com/elastic/integrations/pull/2"},
			},
		},
		{
			name: "missing link",
			block: `- version: "1.2.3"
  changes:
    - description: Some enhancement.
      type: enhancement`,
			want: []changeItem{{Description: "Some enhancement.", Type: "enhancement"}},
		},
		{
			name:  "empty block",
			block: "",
			want:  nil,
		},
		{
			name:  "invalid yaml",
			block: "not: [valid yaml: {",
			want:  nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseEntryFields(tc.block)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestBuildEntryBlock(t *testing.T) {
	tests := []struct {
		name    string
		version string
		changes []changeItem
		want    string
	}{
		{
			name:    "single item",
			version: "1.2.4",
			changes: []changeItem{{Description: "Fix the thing.", Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/999"}},
			want: "- version: \"1.2.4\"\n" +
				"  changes:\n" +
				"    - description: Fix the thing.\n" +
				"      type: bugfix\n" +
				"      link: https://github.com/elastic/integrations/pull/999",
		},
		{
			name:    "multiple items",
			version: "1.2.4",
			changes: []changeItem{
				{Description: "Fix a bug.", Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/1"},
				{Description: "Add a feature.", Type: "enhancement", Link: "https://github.com/elastic/integrations/pull/2"},
			},
			want: "- version: \"1.2.4\"\n" +
				"  changes:\n" +
				"    - description: Fix a bug.\n" +
				"      type: bugfix\n" +
				"      link: https://github.com/elastic/integrations/pull/1\n" +
				"    - description: Add a feature.\n" +
				"      type: enhancement\n" +
				"      link: https://github.com/elastic/integrations/pull/2",
		},
		{
			name:    "colon-space in description",
			version: "1.0.1",
			changes: []changeItem{{Description: "Fix error: timeout in handler", Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/1"}},
			want: "- version: \"1.0.1\"\n" +
				"  changes:\n" +
				"    - description: 'Fix error: timeout in handler'\n" +
				"      type: bugfix\n" +
				"      link: https://github.com/elastic/integrations/pull/1",
		},
		{
			name:    "leading bracket in description",
			version: "1.0.1",
			changes: []changeItem{{Description: "[aws] fix panic on nil", Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/1"}},
			want: "- version: \"1.0.1\"\n" +
				"  changes:\n" +
				"    - description: '[aws] fix panic on nil'\n" +
				"      type: bugfix\n" +
				"      link: https://github.com/elastic/integrations/pull/1",
		},
		{
			name:    "hash in description",
			version: "1.0.1",
			changes: []changeItem{{Description: "remove # legacy field", Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/1"}},
			want: "- version: \"1.0.1\"\n" +
				"  changes:\n" +
				"    - description: 'remove # legacy field'\n" +
				"      type: bugfix\n" +
				"      link: https://github.com/elastic/integrations/pull/1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildEntryBlock(tc.version, tc.changes)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
