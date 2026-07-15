// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package owners

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

// setupCheckPackagesRepo creates a bare remote and a local clone with two
// packages: "aws", whose owner changes on main after this local checkout was
// made (modeling a stale backport branch), and "nginx", whose owner never
// changes. It returns the local clone directory, left checked out at the
// pre-reassignment state.
func setupCheckPackagesRepo(t *testing.T) (workDir string) {
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
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(workDir, rel)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(workDir, rel), []byte(content), 0o644))
	}

	write(".github/CODEOWNERS", "/packages/aws @elastic/team-old\n/packages/nginx @elastic/team-nginx\n")
	write("packages/aws/manifest.yml", "name: aws\nowner:\n  github: elastic/team-old\n")
	write("packages/nginx/manifest.yml", "name: nginx\nowner:\n  github: elastic/team-nginx\n")
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Initial state")
	run(workDir, "push", "-q", "origin", "HEAD:main")

	// Ownership changes on main for aws only, after this local checkout was
	// made — this local worktree (standing in for an existing backport
	// branch) still has the old owner.
	write(".github/CODEOWNERS", "/packages/aws @elastic/team-new\n/packages/nginx @elastic/team-nginx\n")
	write("packages/aws/manifest.yml", "name: aws\nowner:\n  github: elastic/team-new\n")
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "Reassign aws ownership")
	run(workDir, "push", "-q", "origin", "HEAD:main")

	// Roll the local checkout back to the pre-reassignment state.
	run(workDir, "reset", "-q", "--hard", "HEAD~1")

	return workDir
}

func TestCheckPackages(t *testing.T) {
	workDir := setupCheckPackagesRepo(t)
	git := gitutil.Git{Dir: workDir}
	require.NoError(t, git.Run("fetch", "origin", "main"))

	pkgDirs := map[string]string{
		"aws":   filepath.Join(workDir, "packages", "aws"),
		"nginx": filepath.Join(workDir, "packages", "nginx"),
	}

	// "removed_pkg" is listed as changed (e.g. by a git diff) but has no
	// entry in pkgDirs — CheckPackages must skip it silently, same as a
	// package Compare itself reports as not found on remoteRef.
	mismatches := CheckPackages(git, workDir, "origin/main", []string{"aws", "nginx", "removed_pkg"}, pkgDirs)

	require.Len(t, mismatches, 1)
	assert.Equal(t, "aws", mismatches[0].Package)
	assert.NoError(t, mismatches[0].Err)
	assert.Equal(t, []string{"@elastic/team-new"}, mismatches[0].Teams)
}

func TestCheckPackages_SkipsPackageRemovedFromMain(t *testing.T) {
	workDir := setupCheckPackagesRepo(t)
	git := gitutil.Git{Dir: workDir}
	require.NoError(t, git.Run("fetch", "origin", "main"))

	// "gone" only exists in this local checkout (standing in for a package
	// still present on a stale backport branch but removed from main) — it
	// has neither a CODEOWNERS entry nor a manifest.yml on origin/main.
	pkgDir := filepath.Join(workDir, "packages", "gone")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "manifest.yml"),
		[]byte("name: gone\nowner:\n  github: elastic/team-old\n"), 0o644))

	mismatches := CheckPackages(git, workDir, "origin/main", []string{"gone"}, map[string]string{"gone": pkgDir})

	assert.Empty(t, mismatches, "a package absent from main's CODEOWNERS must be skipped, not reported as an error")
}
