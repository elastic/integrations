// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package owners

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/elastic/integrations/dev/codeowners"
	"github.com/elastic/integrations/dev/gitutil"
)

// parseCodeowners reads and parses CODEOWNERS from localPath on disk and
// from remoteGitRef (e.g. "origin/main:.github/CODEOWNERS") via git show.
func parseCodeowners(git gitutil.Git, localPath, remoteGitRef string) (current, source *codeowners.Owners, err error) {
	currentData, err := os.ReadFile(localPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", localPath, err)
	}
	sourceData, err := git.Output("show", remoteGitRef)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", remoteGitRef, err)
	}

	current, err = codeowners.ParseOwners(string(currentData))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", localPath, err)
	}
	source, err = codeowners.ParseOwners(sourceData)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", remoteGitRef, err)
	}
	return current, source, nil
}

// parseManifestOwners reads and extracts the owner.github field from
// localPath on disk and from remoteGitRef (e.g.
// "origin/main:packages/aws/manifest.yml") via git show.
func parseManifestOwners(git gitutil.Git, localPath, remoteGitRef string) (current, source string, err error) {
	currentData, err := os.ReadFile(localPath)
	if err != nil {
		return "", "", fmt.Errorf("reading %s: %w", localPath, err)
	}
	sourceData, err := git.Output("show", remoteGitRef)
	if err != nil {
		return "", "", fmt.Errorf("reading %s: %w", remoteGitRef, err)
	}

	current, err = manifestOwner(currentData)
	if err != nil {
		return "", "", fmt.Errorf("parsing manifest owner from %s: %w", localPath, err)
	}
	source, err = manifestOwner([]byte(sourceData))
	if err != nil {
		return "", "", fmt.Errorf("parsing manifest owner from %s: %w", remoteGitRef, err)
	}
	return current, source, nil
}

// existingSubPaths returns the full CODEOWNERS paths nested under pkgPath
// that actually exist in the current worktree checkout — the union of every
// explicit entry current and source declare under pkgPath (data streams, a
// kibana/ directory, or anything else), filtered down to the ones present on
// disk. Plan never touches a sub-path outside this set.
func existingSubPaths(workDir, pkgPath string, current, source *codeowners.Owners) []string {
	candidates := make(map[string]bool)
	for _, p := range current.EntriesUnder(pkgPath) {
		candidates[p] = true
	}
	for _, p := range source.EntriesUnder(pkgPath) {
		candidates[p] = true
	}

	paths := make([]string, 0, len(candidates))
	for p := range candidates {
		if _, err := os.Stat(filepath.Join(workDir, strings.TrimPrefix(p, "/"))); err == nil {
			paths = append(paths, p)
		}
	}
	return paths
}

// Compare reads pkgDir's current CODEOWNERS/manifest.yml owner and
// remoteRef's version of the same, and computes the Plan needed to bring the
// former in line with the latter. relPkgDir is pkgDir relative to workDir
// (both slash-separated) — used to build the git show path for the remote
// side; pkgPath (the CODEOWNERS-style path, e.g. "/packages/aws") is derived
// from it. It's the one place apply.Apply's sync step and the
// backport-branch CI check both call, so they can never see a different
// answer for the same package.
//
// Callers checking multiple packages in one run should prefer compareWith to
// avoid re-reading and re-parsing CODEOWNERS on every call.
func Compare(git gitutil.Git, workDir, pkgDir, relPkgDir, remoteRef string) (plan SyncPlan, found bool, err error) {
	localPath := filepath.Join(workDir, codeowners.DefaultCodeownersPath)
	remoteGitRef := remoteRef + ":" + codeowners.DefaultCodeownersPath
	current, source, err := parseCodeowners(git, localPath, remoteGitRef)
	if err != nil {
		return SyncPlan{}, false, err
	}
	return compareWith(git, workDir, pkgDir, relPkgDir, remoteRef, current, source)
}

// compareWith is like Compare but accepts pre-parsed CODEOWNERS for both the
// current worktree and remoteRef, avoiding a re-read when checking multiple
// packages in the same run. The current and source owners must have been
// produced by parseCodeowners (or equivalent) against the same workDir and
// remoteRef that are passed here.
func compareWith(git gitutil.Git, workDir, pkgDir, relPkgDir, remoteRef string, current, source *codeowners.Owners) (plan SyncPlan, found bool, err error) {
	pkgPath := "/" + relPkgDir

	if _, ok := source.Resolve(pkgPath); !ok {
		// The package no longer resolves to an owner on remoteRef (removed
		// or renamed) — a normal skip, not a failure. Checked before reading
		// manifest.yml, since that file may well not exist there either, and
		// a missing-file error there would otherwise mask this clean case.
		return SyncPlan{}, false, nil
	}

	manifestPath := filepath.Join(pkgDir, "manifest.yml")
	remoteManifestRef := remoteRef + ":" + relPkgDir + "/manifest.yml"
	currentManifestOwner, sourceManifestOwner, err := parseManifestOwners(git, manifestPath, remoteManifestRef)
	if err != nil {
		return SyncPlan{}, false, err
	}

	subPaths := existingSubPaths(workDir, pkgPath, current, source)

	plan, found = Plan(pkgPath, subPaths, current, source, currentManifestOwner, sourceManifestOwner)
	return plan, found, nil
}
