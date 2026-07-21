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

	"github.com/elastic/integrations/dev/gitutil"
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

// setupIntegrationRepoWithDeletedManifest is like setupIntegrationRepo, but
// the fix commit being cherry-picked removes the whole kubernetes package
// (including manifest.yml) — modeling a package deprecation/removal on main
// that the branch hasn't caught up with. The branch never touches
// manifest.yml itself, so the deletion applies cleanly during cherry-pick
// (no conflict markers at all, cherryErr == nil) — exactly the gap
// manifestMissingConflict guards: without it, the pipeline would try to
// version-bump a file that no longer exists and crash instead of reporting a
// normal conflict.
func setupIntegrationRepoWithDeletedManifest(t *testing.T) (workDir, fixSHA string) {
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

	// Backport branch never touches the package itself.
	run(workDir, "checkout", "-q", "-b", "backport-kubernetes-1.x")
	run(workDir, "push", "-q", "origin", "backport-kubernetes-1.x")
	run(workDir, "checkout", "-q", "main")

	// Fix commit on main removes the whole package.
	run(workDir, "rm", "-r", "-q", "packages/kubernetes")
	run(workDir, "commit", "-q", "-m", "Remove deprecated kubernetes package")
	fixSHA = run(workDir, "rev-parse", "HEAD")

	// resolvePackage runs against whatever is physically checked out before
	// Apply() switches to its own working branch, so leave the checkout on the
	// backport branch (which still has the package) rather than main
	// (post-deletion) — matching what the other setup helpers do implicitly.
	run(workDir, "checkout", "-q", "backport-kubernetes-1.x")

	return workDir, fixSHA
}

func TestApplyIntegration_ReportsConflictWhenManifestDeleted(t *testing.T) {
	workDir, fixSHA := setupIntegrationRepoWithDeletedManifest(t)

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

// setupIntegrationRepoWithMissingManifestBeforeCherryPick is like
// setupIntegrationRepo, but the backport branch is cut before the kubernetes
// package is ever added to the repo — it never has packages/kubernetes at
// all, let alone a manifest.yml. The package only exists on main, where
// resolvePackage (which runs against whatever is checked out before
// prepareWorkingBranch switches to the backport branch) can find it and
// resolve manifestPath — but that path doesn't exist once cherryPickOrConflict
// actually looks for it on the checked-out backport branch, before any
// cherry-pick has even run. This is the gap the pre-cherry-pick
// manifestMissingConflict call guards: without it, readManifestVersion would
// crash with an opaque os.ReadFile error instead of reporting a normal
// conflict.
func setupIntegrationRepoWithMissingManifestBeforeCherryPick(t *testing.T) (workDir, fixSHA string) {
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

	write := func(rel, content string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(workDir, rel), []byte(content), 0o644))
	}

	// The package doesn't exist yet at all — only .backports.yml does, as if
	// the branch was pre-provisioned ahead of the package's addition.
	write(".backports.yml", "backports:\n"+
		"  - package: kubernetes\n"+
		"    branch: backport-kubernetes-1.x\n"+
		"    base_version: \"1.0.0\"\n"+
		"    base_commit: \"0000000000\"\n"+
		"    maintained_until: null\n"+
		"    archived: false\n"+
		"    remove_other_packages: false\n")
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Add backports config ahead of the package")
	run(workDir, "push", "-q", "origin", "HEAD:main")

	// Cut the backport branch here: it never has packages/kubernetes.
	run(workDir, "checkout", "-q", "-b", "backport-kubernetes-1.x")
	run(workDir, "push", "-q", "origin", "backport-kubernetes-1.x")
	run(workDir, "checkout", "-q", "main")

	// The package is only added afterwards, on main.
	pkgDir := filepath.Join(workDir, "packages", "kubernetes")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.0\n")
	write("packages/kubernetes/changelog.yml", "- version: \"1.0.0\"\n"+
		"  changes:\n"+
		"    - description: Initial release.\n"+
		"      type: enhancement\n"+
		"      link: https://github.com/elastic/integrations/pull/1\n")
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Add kubernetes package")

	// A later fix commit on main — this is the SHA to cherry-pick onto the
	// backport branch, which still has never seen the package.
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

	// Leave the checkout on main: resolvePackage needs the package to be
	// present in whatever is physically checked out before Apply() switches to
	// the backport branch, and main is the only ref that has it.
	return workDir, fixSHA
}

func TestApplyIntegration_ReportsConflictWhenManifestMissingBeforeCherryPick(t *testing.T) {
	workDir, fixSHA := setupIntegrationRepoWithMissingManifestBeforeCherryPick(t)

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

// setupIntegrationRepoWithOwnerDrift is like setupIntegrationRepo, but adds
// a .github/CODEOWNERS entry and a manifest.yml owner.github field for the
// kubernetes package, then changes both on main — after the backport branch
// was cut, but independently of the fix commit being cherry-picked — to
// model ownership changing hands on main over a branch's lifetime.
func setupIntegrationRepoWithOwnerDrift(t *testing.T) (workDir, fixSHA string) {
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
	require.NoError(t, os.MkdirAll(filepath.Join(workDir, ".github"), 0o755))

	write := func(rel, content string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(workDir, rel), []byte(content), 0o644))
	}

	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.0\nowner:\n  github: elastic/obs-old-team\n")
	write("packages/kubernetes/changelog.yml", "- version: \"1.0.0\"\n"+
		"  changes:\n"+
		"    - description: Initial release.\n"+
		"      type: enhancement\n"+
		"      link: https://github.com/elastic/integrations/pull/1\n")
	write(".github/CODEOWNERS", "/packages/kubernetes @elastic/obs-old-team\n")

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

	// Create the backport branch here — ownership still matches main.
	run(workDir, "checkout", "-q", "-b", "backport-kubernetes-1.x")
	run(workDir, "push", "-q", "origin", "backport-kubernetes-1.x")
	run(workDir, "checkout", "-q", "main")

	// Ownership changes hands on main, unrelated to the upcoming fix commit.
	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.0\nowner:\n  github: elastic/obs-new-team\n")
	write(".github/CODEOWNERS", "/packages/kubernetes @elastic/obs-new-team\n")
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Reassign kubernetes ownership")

	// The fix commit to cherry-pick — a normal bugfix, unrelated to ownership.
	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.1\nowner:\n  github: elastic/obs-new-team\n")
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
	run(workDir, "push", "-q", "origin", "HEAD:main")
	run(workDir, "checkout", "-q", "main")

	return workDir, fixSHA
}

func TestApplyIntegration_SyncsOwnersFromMain(t *testing.T) {
	workDir, fixSHA := setupIntegrationRepoWithOwnerDrift(t)

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

	// The backport branch's manifest owner and CODEOWNERS entry must now match
	// main's current owner, even though the cherry-picked fix commit itself
	// never touched ownership.
	manifestData, err := os.ReadFile(filepath.Join(workDir, "packages", "kubernetes", "manifest.yml"))
	require.NoError(t, err)
	assert.Contains(t, string(manifestData), "github: elastic/obs-new-team")

	codeownersData, err := os.ReadFile(filepath.Join(workDir, ".github", "CODEOWNERS"))
	require.NoError(t, err)
	assert.Contains(t, string(codeownersData), "/packages/kubernetes @elastic/obs-new-team")

	// The owner sync must be its own commit, separate from the cherry-pick
	// commit, so both are clearly attributable in review — and it must have
	// been created before the (skipped, DryRun) push, i.e. it's visible in the
	// local log immediately.
	subjects, err := gitutil.Git{Dir: workDir}.Output("log", "--format=%s", "-n", "2")
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(subjects), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "owner")
	assert.Contains(t, lines[1], "Fix timeout in metrics collection")
}

// setupIntegrationRepoWithMatchingOwners is like
// setupIntegrationRepoWithOwnerDrift, but ownership never changes on main —
// the backport branch and main agree throughout. This models the common case
// where sync has nothing to do.
func setupIntegrationRepoWithMatchingOwners(t *testing.T) (workDir, fixSHA string) {
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
	require.NoError(t, os.MkdirAll(filepath.Join(workDir, ".github"), 0o755))

	write := func(rel, content string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(workDir, rel), []byte(content), 0o644))
	}

	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.0\nowner:\n  github: elastic/obs-team\n")
	write("packages/kubernetes/changelog.yml", "- version: \"1.0.0\"\n"+
		"  changes:\n"+
		"    - description: Initial release.\n"+
		"      type: enhancement\n"+
		"      link: https://github.com/elastic/integrations/pull/1\n")
	write(".github/CODEOWNERS", "/packages/kubernetes @elastic/obs-team\n")

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

	run(workDir, "checkout", "-q", "-b", "backport-kubernetes-1.x")
	run(workDir, "push", "-q", "origin", "backport-kubernetes-1.x")
	run(workDir, "checkout", "-q", "main")

	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.1\nowner:\n  github: elastic/obs-team\n")
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
	run(workDir, "push", "-q", "origin", "HEAD:main")
	run(workDir, "checkout", "-q", "main")

	return workDir, fixSHA
}

func TestApplyIntegration_SkipsOwnerSyncCommitWhenOwnersMatch(t *testing.T) {
	workDir, fixSHA := setupIntegrationRepoWithMatchingOwners(t)

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

	// No owner drift, so no separate sync commit — only the cherry-pick commit.
	subjects, err := gitutil.Git{Dir: workDir}.Output("log", "--format=%s", "-n", "2")
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(subjects), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "Fix timeout in metrics collection")
	assert.NotContains(t, lines[0], "owner")
	assert.Contains(t, lines[1], "Add backports config")
}

// setupIntegrationRepoWithUnreadableMainOwner is like
// setupIntegrationRepoWithMatchingOwners, but main clears its manifest.yml
// owner.github value (to "") in a commit ahead of the branch, unrelated to
// the fix commit. The owner.github line itself is present throughout, on
// both sides, and only its value changes — the same clean, value-only-change
// shape as setupIntegrationRepoWithOwnerDrift, so the cherry-pick merges
// without conflict (see the two 3-way-merge cases side by side: a line
// theirs never touches always keeps ours' value, no matter how different
// ours is from base — only a *structural* add/remove adjacent to a line
// theirs does touch is conflict-prone, which this deliberately avoids). This
// models a sync failure that isn't "package removed from main" (which Plan
// already handles by skipping cleanly) but a genuine parse/read failure on
// main's side: an empty owner.github is invalid, not merely absent.
func setupIntegrationRepoWithUnreadableMainOwner(t *testing.T) (workDir, fixSHA string) {
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
	require.NoError(t, os.MkdirAll(filepath.Join(workDir, ".github"), 0o755))

	write := func(rel, content string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(workDir, rel), []byte(content), 0o644))
	}

	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.0\nowner:\n  github: elastic/obs-team\n")
	write("packages/kubernetes/changelog.yml", "- version: \"1.0.0\"\n"+
		"  changes:\n"+
		"    - description: Initial release.\n"+
		"      type: enhancement\n"+
		"      link: https://github.com/elastic/integrations/pull/1\n")
	write(".github/CODEOWNERS", "/packages/kubernetes @elastic/obs-team\n")

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

	run(workDir, "checkout", "-q", "-b", "backport-kubernetes-1.x")
	run(workDir, "push", "-q", "origin", "backport-kubernetes-1.x")
	run(workDir, "checkout", "-q", "main")

	// Main clears the owner value (not the line itself) — unrelated to the fix.
	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.0\nowner:\n  github: \"\"\n")
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Clear kubernetes owner")

	write("packages/kubernetes/manifest.yml", "format_version: \"3.0.0\"\nname: kubernetes\ntype: integration\nversion: 1.0.1\nowner:\n  github: \"\"\n")
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
	run(workDir, "push", "-q", "origin", "HEAD:main")
	run(workDir, "checkout", "-q", "main")

	return workDir, fixSHA
}

func TestApplyIntegration_ContinuesWhenMainOwnerUnreadable(t *testing.T) {
	workDir, fixSHA := setupIntegrationRepoWithUnreadableMainOwner(t)

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
	require.NoError(t, err, "a best-effort sync failure must not fail the whole backport")
	require.NotNil(t, result)
	assert.Equal(t, "success", result.Status)

	// No sync commit was possible, so the branch's own owner is left as-is —
	// and there must be no second commit at all.
	manifestData, err := os.ReadFile(filepath.Join(workDir, "packages", "kubernetes", "manifest.yml"))
	require.NoError(t, err)
	assert.Contains(t, string(manifestData), "github: elastic/obs-team")

	subjects, err := gitutil.Git{Dir: workDir}.Output("log", "--format=%s", "-n", "2")
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(subjects), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "Fix timeout in metrics collection")
	assert.Contains(t, lines[1], "Add backports config")
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
