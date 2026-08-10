// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package requiresupdate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPRBody(t *testing.T) {
	cases := []struct {
		title        string
		summary      packageSummary
		wantContains []string
		wantExcludes []string
	}{
		{
			title: "applied only",
			summary: packageSummary{
				applied: []proposal{
					{Kind: "input", Package: "apache", Current: "1.2.0", Proposed: "1.3.0"},
				},
			},
			wantContains: []string{"## Applied", "**apache** (`input`): `1.2.0` → `1.3.0`"},
			wantExcludes: []string{"## Skipped"},
		},
		{
			title: "skipped only",
			summary: packageSummary{
				skipped: []proposal{
					{Package: "foo", Warning: "requires kibana >=9.0.0"},
				},
			},
			wantContains: []string{"## Skipped", "⚠️ **foo**: requires kibana >=9.0.0"},
			wantExcludes: []string{"## Applied"},
		},
		{
			title: "applied and skipped",
			summary: packageSummary{
				applied: []proposal{
					{Kind: "input", Package: "apache", Current: "1.2.0", Proposed: "1.3.0"},
				},
				skipped: []proposal{
					{Package: "foo", Warning: "requires kibana >=9.0.0"},
				},
			},
			wantContains: []string{"## Applied", "## Skipped"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			body := prBody(tc.summary)
			for _, want := range tc.wantContains {
				assert.Contains(t, body, want)
			}
			for _, exclude := range tc.wantExcludes {
				assert.NotContains(t, body, exclude)
			}
		})
	}
}

func TestIssueBody(t *testing.T) {
	body := issueBody(packageSummary{
		codeowners: []string{"elastic/some-team"},
		skipped: []proposal{
			{Package: "foo", Warning: "requires kibana >=9.0.0"},
		},
	})

	assert.Contains(t, body, "**foo**: requires kibana >=9.0.0")
	assert.Contains(t, body, "/cc @elastic/some-team")
}

func TestIssueBodyMultipleOwners(t *testing.T) {
	body := issueBody(packageSummary{
		codeowners: []string{"elastic/team-a", "elastic/team-b"},
		skipped: []proposal{
			{Package: "foo", Warning: "requires kibana >=9.0.0"},
		},
	})

	assert.Contains(t, body, "/cc @elastic/team-a @elastic/team-b")
}

func TestIssueBodyOwnerMismatch(t *testing.T) {
	body := issueBody(packageSummary{
		codeowners: []string{"elastic/some-team"},
		ownerMismatch: "CODEOWNERS=elastic/some-team manifest owner.github=elastic/other-team " +
			"(using CODEOWNERS)",
		skipped: []proposal{
			{Package: "foo", Warning: "requires kibana >=9.0.0"},
		},
	})

	assert.Contains(t, body, "codeowner mismatch")
	assert.Contains(t, body, "elastic/other-team")
	assert.Contains(t, body, "/cc @elastic/some-team")
}

func TestReplaceChangelogPlaceholder(t *testing.T) {
	t.Run("replaces placeholder with PR number", func(t *testing.T) {
		dir := t.TempDir()
		cl := filepath.Join(dir, "changelog.yml")
		require.NoError(t, os.WriteFile(cl, []byte("- link: pull/REPLACE_ME\n"), 0644))

		got, err := replaceChangelogPlaceholder([]string{cl}, "42")
		require.NoError(t, err)
		assert.Equal(t, cl, got)

		data, err := os.ReadFile(cl)
		require.NoError(t, err)
		assert.Equal(t, "- link: pull/42\n", string(data))

		info, err := os.Stat(cl)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0644), info.Mode())
	})

	t.Run("error when placeholder missing", func(t *testing.T) {
		dir := t.TempDir()
		cl := filepath.Join(dir, "changelog.yml")
		require.NoError(t, os.WriteFile(cl, []byte("- link: pull/12345\n"), 0644))

		_, err := replaceChangelogPlaceholder([]string{cl}, "42")
		assert.ErrorContains(t, err, "placeholder not found")
	})

	t.Run("error when no changelog.yml in list", func(t *testing.T) {
		_, err := replaceChangelogPlaceholder([]string{"manifest.yml", "data_stream/foo/manifest.yml"}, "42")
		assert.ErrorContains(t, err, "no changelog.yml")
	})

	t.Run("only changelog.yml is modified", func(t *testing.T) {
		dir := t.TempDir()
		cl := filepath.Join(dir, "changelog.yml")
		manifest := filepath.Join(dir, "manifest.yml")
		require.NoError(t, os.WriteFile(cl, []byte("- link: pull/REPLACE_ME\n"), 0644))
		require.NoError(t, os.WriteFile(manifest, []byte("name: mypackage\n"), 0644))

		got, err := replaceChangelogPlaceholder([]string{manifest, cl}, "99")
		require.NoError(t, err)
		assert.Equal(t, cl, got)

		manifestData, err := os.ReadFile(manifest)
		require.NoError(t, err)
		assert.Equal(t, "name: mypackage\n", string(manifestData))

		clData, err := os.ReadFile(cl)
		require.NoError(t, err)
		assert.Contains(t, string(clData), "pull/99")
	})
}

func TestPRBodyOwnerMismatch(t *testing.T) {
	body := prBody(packageSummary{
		applied: []proposal{
			{Kind: "input", Package: "apache", Current: "1.2.0", Proposed: "1.3.0"},
		},
		ownerMismatch: "CODEOWNERS=elastic/some-team manifest owner.github=elastic/other-team " +
			"(using CODEOWNERS)",
	})

	assert.Contains(t, body, "codeowner mismatch")
	assert.Contains(t, body, "elastic/other-team")
}
