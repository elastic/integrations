// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// diffPackagesRepo is the fixture built by setupDiffPackagesRepo: a repository
// shaped like a pull request whose branch is behind the base branch.
type diffPackagesRepo struct {
	dir       string // repository root, already the test's working directory
	baseSHA   string // tip of main, i.e. GitHub's base.sha for the PR
	headSHA   string // tip of the PR branch
	mergeBase string // where the PR branch forked from main
}

// setupDiffPackagesRepo builds a repository reproducing the shape reported in
// elastic/integrations#22533:
//
//	o---o  main   (commit touching packages/gcp, landed after the fork)
//	 \
//	  o    feature (commit touching packages/armis)
//
// Only packages/armis is changed by the branch, but a two-dot diff from the
// main tip also reports packages/gcp. The returned repository is the test's
// working directory, since diffPackages shells out to git and reads packages/
// relative to the process working directory.
func setupDiffPackagesRepo(t *testing.T) diffPackagesRepo {
	t.Helper()

	dir := t.TempDir()

	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.Output()
		require.NoError(t, err, "git %v", args)
		return strings.TrimSpace(string(out))
	}

	writeManifest := func(pkg string) {
		t.Helper()
		pkgDir := filepath.Join(dir, "packages", pkg)
		require.NoError(t, os.MkdirAll(pkgDir, 0o755))
		manifest := "format_version: \"1.0.0\"\nname: " + pkg + "\ntype: integration\nversion: \"1.0.0\"\n"
		require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "manifest.yml"), []byte(manifest), 0o644))
	}

	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}

	run("init", "-q", "-b", "main")
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "Test")
	run("config", "commit.gpgsign", "false")

	// Fork point: both packages exist on main.
	writeManifest("armis")
	writeManifest("gcp")
	run("add", ".")
	run("commit", "-q", "-m", "initial")
	mergeBase := run("rev-parse", "HEAD")

	// The PR branch, cut from the fork point, touches only packages/armis.
	run("checkout", "-q", "-b", "feature")
	write("packages/armis/changelog.yml", "- version: \"1.1.0\"\n")
	run("add", ".")
	run("commit", "-q", "-m", "armis: fix")
	headSHA := run("rev-parse", "HEAD")

	// Meanwhile an unrelated PR touching packages/gcp lands on main.
	run("checkout", "-q", "main")
	write("packages/gcp/changelog.yml", "- version: \"2.22.0\"\n")
	run("add", ".")
	run("commit", "-q", "-m", "gcp: unrelated change")
	baseSHA := run("rev-parse", "HEAD")

	t.Chdir(dir)

	return diffPackagesRepo{dir: dir, baseSHA: baseSHA, headSHA: headSHA, mergeBase: mergeBase}
}

func TestDiffPackages(t *testing.T) {
	t.Run("ignores commits that landed on the base branch after the fork", func(t *testing.T) {
		repo := setupDiffPackagesRepo(t)

		// The detect-packages caller (.github/workflows/backport-packages-detect.yml)
		// passes GitHub's base.sha, which is the main tip rather than the fork point.
		pkgs, err := diffPackages(repo.baseSHA, repo.headSHA)
		require.NoError(t, err)
		assert.Equal(t, []string{"armis"}, pkgs,
			"gcp changed on main after the branch was cut and is not part of the PR")
	})

	t.Run("merge base as before gives the same result", func(t *testing.T) {
		repo := setupDiffPackagesRepo(t)

		// The check-owners caller (.buildkite/scripts/check_backport_owners.sh)
		// already resolves the merge base itself, so the switch to three dots
		// must not change what it sees.
		pkgs, err := diffPackages(repo.mergeBase, repo.headSHA)
		require.NoError(t, err)
		assert.Equal(t, []string{"armis"}, pkgs)
	})

	t.Run("no package changes", func(t *testing.T) {
		repo := setupDiffPackagesRepo(t)

		pkgs, err := diffPackages(repo.headSHA, repo.headSHA)
		require.NoError(t, err)
		assert.Empty(t, pkgs)
	})

	t.Run("unresolvable revision returns an error", func(t *testing.T) {
		repo := setupDiffPackagesRepo(t)

		_, err := diffPackages("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", repo.headSHA)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "running git diff")
	})
}
