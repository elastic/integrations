// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/integrations/dev/gitutil"
)

func TestVersionInContent(t *testing.T) {
	cases := []struct {
		title   string
		content string
		version string
		want    bool
	}{
		{
			title:   "unquoted version matches",
			content: "- version: 1.2.3\n  changes:\n    - description: Fix",
			version: "1.2.3",
			want:    true,
		},
		{
			title:   "double-quoted version matches",
			content: "- version: \"1.2.3\"\n  changes:\n    - description: Fix",
			version: "1.2.3",
			want:    true,
		},
		{
			title:   "single-quoted version matches",
			content: "- version: '1.2.3'\n  changes:\n    - description: Fix",
			version: "1.2.3",
			want:    true,
		},
		{
			title:   "different version does not match",
			content: "- version: \"1.0.0\"\n  changes:",
			version: "1.2.3",
			want:    false,
		},
		{
			title:   "prerelease version matches exactly",
			content: "- version: \"8.15.0-preview-1716438434\"\n  changes:",
			version: "8.15.0-preview-1716438434",
			want:    true,
		},
		{
			title:   "empty content returns false",
			content: "",
			version: "1.0.0",
			want:    false,
		},
		{
			title:   "version appearing only in description does not match",
			content: "- version: \"2.0.0\"\n  changes:\n    - description: Includes fix from 1.2.3",
			version: "1.2.3",
			want:    false,
		},
		{
			title:   "version that is a prefix of a longer version does not match",
			content: "- version: 1.2.30\n  changes:",
			version: "1.2.3",
			want:    false,
		},
		{
			title:   "version that is a prefix of a longer quoted version does not match",
			content: "- version: \"1.2.30\"\n  changes:",
			version: "1.2.3",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			got := versionInContent(tc.content, tc.version)
			assert.Equal(t, tc.want, got)
		})
	}
}

// setupCheckVersionsRepo creates a bare remote and a local clone with:
//   - origin/main at version 1.5.0 for packages/aws/changelog.yml
//   - origin/backport-aws-1.x branched from main (same initial state)
//
// It returns the local clone directory and a run helper. The clone is left
// checked out on the backport branch, ready for the caller to commit PR changes.
func setupCheckVersionsRepo(t *testing.T) (workDir string, run func(...string)) {
	t.Helper()

	run = func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = workDir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}

	remoteDir := t.TempDir()
	cmd := exec.Command("git", "init", "--bare", "-q")
	cmd.Dir = remoteDir
	require.NoError(t, cmd.Run())

	workDir = t.TempDir()
	run("clone", "-q", remoteDir, workDir)
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "Test")
	run("config", "commit.gpgsign", "false")

	pkgDir := filepath.Join(workDir, "packages", "aws")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))

	write := func(rel, content string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(workDir, rel), []byte(content), 0o644))
	}

	write("packages/aws/changelog.yml",
		"- version: \"1.5.0\"\n"+
			"  changes:\n"+
			"    - description: Feature.\n"+
			"      type: enhancement\n"+
			"      link: https://github.com/elastic/integrations/pull/100\n")

	run("add", ".")
	run("commit", "-q", "-m", "initial: aws 1.5.0")
	run("push", "-q", "origin", "HEAD:main")

	run("push", "-q", "origin", "HEAD:backport-aws-1.x")
	run("fetch", "-q", "origin")
	run("checkout", "-q", "-b", "backport-aws-1.x", "--track", "origin/backport-aws-1.x")

	return workDir, run
}

func TestCheckVersionsAgainstMain(t *testing.T) {
	t.Run("no conflict — new version not in main", func(t *testing.T) {
		workDir, run := setupCheckVersionsRepo(t)
		git := gitutil.Git{Dir: workDir}

		require.NoError(t, os.WriteFile(
			filepath.Join(workDir, "packages", "aws", "changelog.yml"),
			[]byte("- version: \"1.4.1\"\n"+
				"  changes:\n"+
				"    - description: Backport patch.\n"+
				"      type: bug fix\n"+
				"      link: https://github.com/elastic/integrations/pull/101\n"+
				"- version: \"1.5.0\"\n"+
				"  changes:\n"+
				"    - description: Feature.\n"+
				"      type: enhancement\n"+
				"      link: https://github.com/elastic/integrations/pull/100\n"),
			0o644))
		run("add", ".")
		run("commit", "-q", "-m", "add 1.4.1")

		conflicts, err := CheckVersionsAgainstMain(git, "origin/backport-aws-1.x", "HEAD")
		require.NoError(t, err)
		assert.Empty(t, conflicts)
	})

	t.Run("conflict — version already present in main", func(t *testing.T) {
		workDir, run := setupCheckVersionsRepo(t)
		git := gitutil.Git{Dir: workDir}

		run("checkout", "-q", "main")
		require.NoError(t, os.WriteFile(
			filepath.Join(workDir, "packages", "aws", "changelog.yml"),
			[]byte("- version: \"1.5.1\"\n"+
				"  changes:\n"+
				"    - description: Sync.\n"+
				"      type: bug fix\n"+
				"      link: https://github.com/elastic/integrations/pull/102\n"+
				"- version: \"1.5.0\"\n"+
				"  changes:\n"+
				"    - description: Feature.\n"+
				"      type: enhancement\n"+
				"      link: https://github.com/elastic/integrations/pull/100\n"),
			0o644))
		run("add", ".")
		run("commit", "-q", "-m", "add 1.5.1 to main")
		run("push", "-q", "origin", "main")
		run("fetch", "-q", "origin")

		run("checkout", "-q", "backport-aws-1.x")
		require.NoError(t, os.WriteFile(
			filepath.Join(workDir, "packages", "aws", "changelog.yml"),
			[]byte("- version: \"1.5.1\"\n"+
				"  changes:\n"+
				"    - description: Backport patch.\n"+
				"      type: bug fix\n"+
				"      link: https://github.com/elastic/integrations/pull/103\n"+
				"- version: \"1.5.0\"\n"+
				"  changes:\n"+
				"    - description: Feature.\n"+
				"      type: enhancement\n"+
				"      link: https://github.com/elastic/integrations/pull/100\n"),
			0o644))
		run("add", ".")
		run("commit", "-q", "-m", "add 1.5.1 on backport")

		conflicts, err := CheckVersionsAgainstMain(git, "origin/backport-aws-1.x", "HEAD")
		require.NoError(t, err)
		require.Len(t, conflicts, 1)
		assert.Contains(t, conflicts[0], "1.5.1")
		assert.Contains(t, conflicts[0], "packages/aws/changelog.yml")
	})

	t.Run("no changelog changes — returns empty", func(t *testing.T) {
		workDir, run := setupCheckVersionsRepo(t)
		git := gitutil.Git{Dir: workDir}

		require.NoError(t, os.WriteFile(filepath.Join(workDir, "README.md"), []byte("hello"), 0o644))
		run("add", ".")
		run("commit", "-q", "-m", "non-changelog change")

		conflicts, err := CheckVersionsAgainstMain(git, "origin/backport-aws-1.x", "HEAD")
		require.NoError(t, err)
		assert.Empty(t, conflicts)
	})
}
