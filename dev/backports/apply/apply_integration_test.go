// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apply

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/integrations/dev/backports/gitutil"
)

// setupIntegrationRepo creates a bare remote and a local clone pre-populated
// with a kubernetes package at version 1.0.0, a matching backport branch on
// the remote, and a single fix commit on main that bumps to 1.0.1. It returns
// the local clone directory and the full SHA of the fix commit.
func setupIntegrationRepo(t *testing.T) (workDir, fixSHA string) {
	t.Helper()

	run := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
		return strings.TrimRight(string(out), "\n")
	}

	remoteDir := t.TempDir()
	run(remoteDir, "init", "--bare", "-q")

	workDir = t.TempDir()
	run(workDir, "clone", "-q", remoteDir, ".")
	run(workDir, "config", "user.email", "test@test.com")
	run(workDir, "config", "user.name", "Test")
	run(workDir, "config", "commit.gpgsign", "false")

	pkgDir := filepath.Join(workDir, "packages", "kubernetes")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))

	write := func(rel, content string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(workDir, rel), []byte(content), 0o644))
	}

	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.0\n")
	write("packages/kubernetes/changelog.yml", "- version: \"1.0.0\"\n"+
		"  changes:\n"+
		"    - description: Initial release.\n"+
		"      type: enhancement\n"+
		"      link: https://github.com/elastic/integrations/pull/1\n")

	// Commit the base state to get a real SHA for base_commit in .backports.yml.
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Initial release")
	baseCommit := run(workDir, "rev-parse", "--short=10", "HEAD")

	write(".backports.yml", "backports:\n"+
		"  - package: kubernetes\n"+
		"    branch: backport-kubernetes-1.x\n"+
		"    base_version: \"1.0.0\"\n"+
		"    base_commit: \""+baseCommit+"\"\n"+
		"    maintained_until: null\n"+
		"    archived: false\n"+
		"    remove_other_packages: false\n")

	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Add backports config")
	run(workDir, "push", "-q", "origin", "HEAD:main")

	// Create the backport branch at the base state and push it to the remote.
	run(workDir, "checkout", "-q", "-b", "backport-kubernetes-1.x")
	run(workDir, "push", "-q", "origin", "backport-kubernetes-1.x")
	run(workDir, "checkout", "-q", "main")

	// Create the fix commit on main — this is the SHA to cherry-pick.
	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.1\n")
	write("packages/kubernetes/changelog.yml", "- version: \"1.0.1\"\n"+
		"  changes:\n"+
		"    - description: Fix timeout in metrics collection.\n"+
		"      type: bugfix\n"+
		"      link: https://github.com/elastic/integrations/pull/999\n"+
		"- version: \"1.0.0\"\n"+
		"  changes:\n"+
		"    - description: Initial release.\n"+
		"      type: enhancement\n"+
		"      link: https://github.com/elastic/integrations/pull/1\n")
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Fix timeout in metrics collection")
	fixSHA = run(workDir, "rev-parse", "HEAD")

	return workDir, fixSHA
}

func TestApplyIntegration_DryRun(t *testing.T) {
	workDir, fixSHA := setupIntegrationRepo(t)

	result, err := Apply(Options{
		SHA:         fixSHA,
		Package:     "kubernetes",
		Target:      "backport-kubernetes-1.x",
		Remote:      "origin",
		DryRun:      true,
		PackagesDir: "packages",
		Repository:  "elastic/integrations",
		WorkDir:     workDir,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "success", result.Status)
	assert.Equal(t, "1.0.1", result.NewVersion)
	assert.Equal(t, "backport-kubernetes-1.x", result.TargetBranch)
	assert.Equal(t, "auto-backport/kubernetes-1.x-"+fixSHA[:8], result.WorkingBranch)

	// Verify manifest was bumped to 1.0.1 on the working branch.
	manifestData, err := os.ReadFile(filepath.Join(workDir, "packages", "kubernetes", "manifest.yml"))
	require.NoError(t, err)
	assert.Contains(t, string(manifestData), "version: 1.0.1")

	// Verify the changelog contains the cherry-picked change description.
	changelogData, err := os.ReadFile(filepath.Join(workDir, "packages", "kubernetes", "changelog.yml"))
	require.NoError(t, err)
	assert.Contains(t, string(changelogData), "Fix timeout in metrics collection")

	// Verify the backport commit was created with the expected message.
	commitMsg, err := gitutil.Git{Dir: workDir}.Output("log", "--format=%B", "-n", "1")
	require.NoError(t, err)
	assert.Contains(t, commitMsg, "Fix timeout in metrics collection")
	assert.Contains(t, commitMsg, "cherry picked from commit")
	assert.Contains(t, commitMsg, "Backport version: 1.0.1")
}
