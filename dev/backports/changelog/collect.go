// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cli/go-gh/v2"

	"github.com/elastic/integrations/dev/backports/gitutil"
	"github.com/elastic/integrations/dev/citools"
)

// CollectResult holds the outputs produced by Collect.
type CollectResult struct {
	HasChanges       bool
	EntriesTSV       string // path to the written TSV file
	WorkingBranch    string
	BackportPRNumber string
}

// Collect finds changelog entries introduced between before and after that are
// not yet present on main, writes them to a temp TSV file, and returns a
// CollectResult. Returns HasChanges=false when nothing actionable is found.
func Collect(before, after, repository string) (*CollectResult, error) {
	prNumber, err := backportPRNumber(repository, after)
	if err != nil {
		return nil, fmt.Errorf("resolving backport PR number: %w", err)
	}
	if prNumber == "" {
		return &CollectResult{HasChanges: false}, nil
	}

	workingBranch := "changelog/pr-" + prNumber
	exists, err := syncPRExists(workingBranch)
	if err != nil {
		return nil, fmt.Errorf("checking for existing sync PR: %w", err)
	}
	if exists {
		return &CollectResult{HasChanges: false}, nil
	}

	git := gitutil.Git{}

	changelogs, err := changedChangelogs(git, before, after)
	if err != nil {
		return nil, fmt.Errorf("listing changed changelogs: %w", err)
	}

	var lines []string
	for _, cl := range changelogs {
		line, err := collectChangelogEntry(git, before, after, cl)
		if err != nil {
			return nil, err
		}
		if line != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		return &CollectResult{HasChanges: false}, nil
	}

	tsvFile, err := os.CreateTemp("", "changelog-entries-*.tsv")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer tsvFile.Close()
	for _, line := range lines {
		fmt.Fprintln(tsvFile, line)
	}

	return &CollectResult{
		HasChanges:       true,
		EntriesTSV:       tsvFile.Name(),
		WorkingBranch:    workingBranch,
		BackportPRNumber: prNumber,
	}, nil
}

// collectChangelogEntry processes a single changelog path cl and returns the
// TSV line to record ("pkg\tversion\tentryFilePath"), or "" when there is
// nothing new to sync for that changelog.
func collectChangelogEntry(git gitutil.Git, before, after, cl string) (string, error) {
	pkgDir := filepath.Dir(cl)
	// cl comes from a git diff, so it is a tracked file; its sibling manifest.yml
	// must exist. A missing or unreadable manifest is a real error, not a skip.
	pkgName, err := manifestName(pkgDir)
	if err != nil {
		return "", fmt.Errorf("reading manifest for %s: %w", pkgDir, err)
	}

	diff, err := gitDiff(git, before, after, cl)
	if err != nil {
		return "", fmt.Errorf("diffing %s: %w", cl, err)
	}

	ver, entry, err := ExtractFromDiff(diff)
	if err != nil {
		return "", err
	}
	if ver == "" {
		return "", nil
	}

	alreadyInMain, err := versionInMain(git, cl, ver)
	if err != nil {
		return "", err
	}
	if alreadyInMain {
		return "", nil
	}

	entryFile, err := os.CreateTemp("", "entry-*.yml")
	if err != nil {
		return "", err
	}
	defer entryFile.Close()

	if _, err := fmt.Fprintln(entryFile, entry); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s\t%s\t%s", pkgName, ver, entryFile.Name()), nil
}

// backportPRNumber returns the PR number associated with the given commit SHA,
// or "" if none is found.
func backportPRNumber(repository, sha string) (string, error) {
	stdout, _, err := gh.Exec("api",
		fmt.Sprintf("repos/%s/commits/%s/pulls", repository, sha),
		"--jq", ".[0].number // empty",
	)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

// syncPRExists returns true if a PR (open or closed) already exists with the
// given head branch.
func syncPRExists(workingBranch string) (bool, error) {
	stdout, _, err := gh.Exec("pr", "list",
		"--head", workingBranch,
		"--state", "all",
		"--json", "number",
	)
	if err != nil {
		return false, err
	}
	var prs []struct{ Number int }
	if err := json.Unmarshal(stdout.Bytes(), &prs); err != nil {
		return false, fmt.Errorf("parsing PR list: %w", err)
	}
	return len(prs) > 0, nil
}

// changedChangelogs returns the paths of changelog.yml files that changed
// between before and after.
func changedChangelogs(git gitutil.Git, before, after string) ([]string, error) {
	out, err := git.Output("diff", "--name-only", before+".."+after, "--", "**/changelog.yml")
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			paths = append(paths, line)
		}
	}
	return paths, nil
}

// manifestName reads the manifest.yml in pkgDir and returns the package name.
func manifestName(pkgDir string) (string, error) {
	manifest, err := citools.ReadPackageManifest(filepath.Join(pkgDir, citools.ManifestFileName))
	if err != nil {
		return "", err
	}
	return manifest.Name, nil
}

// gitDiff returns the unified diff for path between before and after.
func gitDiff(git gitutil.Git, before, after, path string) (string, error) {
	out, err := git.Output("diff", before+".."+after, "--", path)
	if err != nil {
		return "", err
	}
	return out, nil
}

// versionInMain checks whether version already appears in the main branch copy
// of changelogPath.
func versionInMain(git gitutil.Git, changelogPath, version string) (bool, error) {
	out, err := git.Output("show", "origin/main:"+changelogPath)
	if err != nil {
		// file may not exist on main yet
		return false, nil
	}
	return versionInContent(out, version), nil
}

// versionInContent reports whether version appears as a version header line
// in content, using the same regex as ExtractFromDiff for consistency.
func versionInContent(content, version string) bool {
	for _, line := range strings.Split(content, "\n") {
		m := versionLineRE.FindStringSubmatch(line)
		if m != nil && m[1] == version {
			return true
		}
	}
	return false
}
