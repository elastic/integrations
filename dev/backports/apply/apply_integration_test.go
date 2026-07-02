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
// the local clone directory and the full SHA of the fix commit. This models
// the very first backport onto a freshly cut branch: the branch hasn't
// diverged yet, so its version still matches main's parent commit and the
// cherry-pick applies cleanly with no version-line conflict at all.
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

// setupIntegrationRepoWithDivergedManifest is like setupIntegrationRepo, but
// models the typical backport shape: the branch was cut from an elder commit
// and has only advanced through one independent bump of its own (1.0.0 ->
// 1.0.1), while main kept moving and the fix commit being cherry-picked
// carries a much higher version (1.0.0 -> 1.4.0) — main is normally ahead of
// any given backport branch. That gives a genuine version-line conflict
// (base 1.0.0, branch 1.0.1, main's commit 1.4.0, all different). The fix
// commit also adds an unrelated "categories" field that does not overlap
// with anything the branch changed, so it should merge cleanly regardless of
// the version conflict. The expected final version is 1.0.2 — the branch's
// own lineage bumped by one — never anything derived from main's 1.4.0.
func setupIntegrationRepoWithDivergedManifest(t *testing.T) (workDir, fixSHA string) {
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

	// Create the backport branch, cut from the elder "Add backports config"
	// commit, and give it one small independent bump of its own — a much
	// smaller step than main will have taken by the time the fix below lands.
	run(workDir, "checkout", "-q", "-b", "backport-kubernetes-1.x")
	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.1\n")
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Previous backport bump")
	run(workDir, "push", "-q", "origin", "backport-kubernetes-1.x")
	run(workDir, "checkout", "-q", "main")

	// Create the fix commit on main: by now main has advanced well past the
	// branch's own version (1.4.0 vs. the branch's 1.0.1), so the version line
	// conflicts, while the unrelated "categories" field addition should merge
	// cleanly and be preserved regardless.
	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.4.0\ncategories:\n  - kubernetes\n")
	write("packages/kubernetes/changelog.yml", "- version: \"1.4.0\"\n"+
		"  changes:\n"+
		"    - description: Add categories field.\n"+
		"      type: enhancement\n"+
		"      link: https://github.com/elastic/integrations/pull/999\n"+
		"- version: \"1.0.0\"\n"+
		"  changes:\n"+
		"    - description: Initial release.\n"+
		"      type: enhancement\n"+
		"      link: https://github.com/elastic/integrations/pull/1\n")
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Add categories field")
	fixSHA = run(workDir, "rev-parse", "HEAD")

	return workDir, fixSHA
}

func TestApplyIntegration_PreservesUnrelatedManifestChanges(t *testing.T) {
	workDir, fixSHA := setupIntegrationRepoWithDivergedManifest(t)

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

	// The branch's own version (1.0.1) wins the version-line conflict and is
	// bumped from there (to 1.0.2), ignoring main's much further-advanced 1.4.0.
	assert.Equal(t, "success", result.Status)
	assert.Equal(t, "1.0.2", result.NewVersion)

	manifestData, err := os.ReadFile(filepath.Join(workDir, "packages", "kubernetes", "manifest.yml"))
	require.NoError(t, err)
	assert.Contains(t, string(manifestData), "version: 1.0.2")
	// The unrelated "categories" field added by the cherry-picked commit must
	// survive, instead of being discarded along with the version conflict.
	assert.Contains(t, string(manifestData), "categories:\n  - kubernetes\n")
}

// setupIntegrationRepoWithGenuineManifestConflict is like
// setupIntegrationRepoWithDivergedManifest (elder branch at a small bump of
// its own, main's fix commit carrying a much higher version), but both the
// backport branch and the fix commit also change the "description" field
// right next to their respective version bumps. That overlap falls outside
// the version-only auto-resolution and must still be reported as a real
// conflict requiring manual resolution — the final version never matters
// here since the whole cherry-pick gets reset.
func setupIntegrationRepoWithGenuineManifestConflict(t *testing.T) (workDir, fixSHA string) {
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

	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.0\ndescription: Original description.\n")
	write("packages/kubernetes/changelog.yml", "- version: \"1.0.0\"\n"+
		"  changes:\n"+
		"    - description: Initial release.\n"+
		"      type: enhancement\n"+
		"      link: https://github.com/elastic/integrations/pull/1\n")

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

	// Backport branch takes one small independent bump of its own, changing
	// the description field right next to it.
	run(workDir, "checkout", "-q", "-b", "backport-kubernetes-1.x")
	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.1\ndescription: Branch description.\n")
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Previous backport bump")
	run(workDir, "push", "-q", "origin", "backport-kubernetes-1.x")
	run(workDir, "checkout", "-q", "main")

	// Fix commit on main has advanced much further (1.4.0) and also changes the
	// description field, so the description change genuinely conflicts.
	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.4.0\ndescription: Main description.\n")
	write("packages/kubernetes/changelog.yml", "- version: \"1.4.0\"\n"+
		"  changes:\n"+
		"    - description: Update description.\n"+
		"      type: enhancement\n"+
		"      link: https://github.com/elastic/integrations/pull/999\n"+
		"- version: \"1.0.0\"\n"+
		"  changes:\n"+
		"    - description: Initial release.\n"+
		"      type: enhancement\n"+
		"      link: https://github.com/elastic/integrations/pull/1\n")
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Update description")
	fixSHA = run(workDir, "rev-parse", "HEAD")

	return workDir, fixSHA
}

func TestApplyIntegration_ReportsGenuineManifestConflict(t *testing.T) {
	workDir, fixSHA := setupIntegrationRepoWithGenuineManifestConflict(t)

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

	assert.Equal(t, "conflict", result.Status)
	assert.Contains(t, result.ConflictingFiles, "packages/kubernetes/manifest.yml")

	// The working branch must be cleaned up so a retry doesn't fail with
	// "branch already exists".
	branches, err := gitutil.Git{Dir: workDir}.Output("branch", "--list", "auto-backport/*")
	require.NoError(t, err)
	assert.Empty(t, strings.TrimSpace(branches))
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
