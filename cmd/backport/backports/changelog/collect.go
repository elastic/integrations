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
	"time"

	"github.com/cli/go-gh/v2"

	"github.com/elastic/integrations/cmd/backport/citools"
	"github.com/elastic/integrations/cmd/backport/gitutil"
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
		fmt.Fprintf(os.Stderr, "no backport PR found for commit %s\n", after)
		return &CollectResult{HasChanges: false}, nil
	}

	workingBranch := "changelog/pr-" + prNumber
	exists, err := syncPRExists(workingBranch)
	if err != nil {
		return nil, fmt.Errorf("checking for existing sync PR: %w", err)
	}
	if exists {
		return &CollectResult{HasChanges: false, BackportPRNumber: prNumber, WorkingBranch: workingBranch}, nil
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
		fmt.Fprintf(os.Stderr, "no changelog entry found for backport PR %s or already present in main branch\n", prNumber)
		return &CollectResult{HasChanges: false, BackportPRNumber: prNumber, WorkingBranch: workingBranch}, nil
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

// CheckVersionsAgainstMain finds changelog files that changed between before
// and after and reports any versions that already exist in origin/main.
// Each conflict is returned as a human-readable string "path: version X.Y.Z".
// Intended for use in PR checks to catch duplicate version entries early.
func CheckVersionsAgainstMain(git gitutil.Git, before, after string) ([]string, error) {
	changelogs, err := changedChangelogs(git, before, after)
	if err != nil {
		return nil, err
	}
	var conflicts []string
	for _, cl := range changelogs {
		diff, err := gitDiff(git, before, after, cl)
		if err != nil {
			return nil, fmt.Errorf("diffing %s: %w", cl, err)
		}
		ver, _, err := ExtractFromDiff(diff)
		if err != nil {
			return nil, err
		}
		if ver == "" {
			continue
		}
		inMain, err := versionInMain(git, cl, ver)
		if err != nil {
			return nil, err
		}
		if inMain {
			conflicts = append(conflicts, fmt.Sprintf("%s: version %s", cl, ver))
		}
	}
	return conflicts, nil
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
// or "" if none is found after retries. The GitHub API association between a
// merge commit and its PR may not be immediately available after the push
// event fires, so we retry a few times with exponential backoff.
func backportPRNumber(repository, sha string) (string, error) {
	delays := []time.Duration{0, 5 * time.Second, 15 * time.Second, 30 * time.Second}
	for i, d := range delays {
		if d > 0 {
			fmt.Fprintf(os.Stderr, "backportPRNumber: attempt %d/%d — waiting %s\n", i+1, len(delays), d)
			time.Sleep(d)
		}
		stdout, _, err := gh.Exec("api",
			fmt.Sprintf("repos/%s/commits/%s/pulls", repository, sha),
			"--jq", ".[0].number // empty",
		)
		if err != nil {
			return "", err
		}
		if n := strings.TrimSpace(stdout.String()); n != "" {
			return n, nil
		}
	}
	return "", nil
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

// changedChangelogs returns the paths of changelog.yml files introduced
// between the common ancestor of before/after and after — scoping the result
// to what the PR itself adds, ignoring commits pushed to the base branch
// after the PR was branched.
func changedChangelogs(git gitutil.Git, before, after string) ([]string, error) {
	out, err := git.Output("diff", "--name-only", before+"..."+after, "--", "**/changelog.yml")
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

// gitDiff returns the unified diff for path using the three-dot notation
// (git diff before...after), which diffs against the common ancestor of
// before and after rather than before itself.
func gitDiff(git gitutil.Git, before, after, path string) (string, error) {
	out, err := git.Output("diff", before+"..."+after, "--", path)
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
