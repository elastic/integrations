// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package requiresupdate

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/cli/go-gh/v2"
)

// Publish opens one PR per package with applied changes — creating or
// updating a stable per-package branch — and one GitHub issue per package
// whose proposals were entirely skipped. Deliberately kept simple while
// adoption of `requires:` is low; revisit batching by codeowner once weekly
// volume per team justifies the added complexity.
//
// In preview mode nothing is written to git or GitHub; actions are only
// printed.
func Publish(summaries []packageSummary, preview bool) error {
	sorted := make([]packageSummary, len(summaries))
	copy(sorted, summaries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })

	for _, s := range sorted {
		if len(s.files) == 0 {
			if err := publishIssue(s, preview); err != nil {
				return fmt.Errorf("%s: %w", s.name, err)
			}
			continue
		}
		if err := publishPR(s, preview); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return nil
}

func publishIssue(s packageSummary, preview bool) error {
	title := fmt.Sprintf("[automation] Package version updates blocked for `%s`", s.name)
	body := issueBody(s)

	if preview {
		fmt.Printf("======================================== ISSUE\n"+
			"Package: %s\nOwners:  %s\n\nIssue title: %s\n\nIssue body:\n%s"+
			"========================================\n\n",
			s.name, mentions(s.codeowners), title, body)
		return nil
	}

	number, err := findOpenIssue(title)
	if err != nil {
		return fmt.Errorf("listing existing issues: %w", err)
	}
	if number != "" {
		if _, _, err := gh.Exec("issue", "edit", number, "--body", body); err != nil {
			return fmt.Errorf("updating issue #%s: %w", number, err)
		}
		fmt.Printf("Updated existing issue #%s for %s.\n", number, s.name)
		return nil
	}
	if _, _, err := gh.Exec("issue", "create", "--title", title, "--label", "automation", "--body", body); err != nil {
		return fmt.Errorf("creating issue: %w", err)
	}
	fmt.Printf("Created issue for %s.\n", s.name)
	return nil
}

func publishPR(s packageSummary, preview bool) error {
	branch := "automated/requires-update-" + s.name
	title := fmt.Sprintf("[automation] Update required package versions for `%s`", s.name)
	body := prBody(s)

	if preview {
		fmt.Printf("======================================== PR\n"+
			"Package: %s\nOwners:  %s\nBranch:  %s\nFiles:\n  %s\n\nPR title: %s\n\nPR body:\n%s"+
			"========================================\n\n",
			s.name, mentions(s.codeowners), branch, strings.Join(s.files, "\n  "), title, body)
		return nil
	}

	// Reset HEAD to main without discarding the dirty working tree.
	// "checkout -B" moves HEAD but does not touch untracked/modified files,
	// so other packages' pending changes survive subsequent calls.
	if err := gitExec("checkout", "-B", branch, "origin/main"); err != nil {
		return fmt.Errorf("creating branch: %w", err)
	}
	if err := gitExec(append([]string{"add", "--"}, s.files...)...); err != nil {
		return fmt.Errorf("staging files: %w", err)
	}
	if err := gitExec("commit", "-m", fmt.Sprintf("[automation] Update required package versions for %s", s.name)); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	if err := gitExec("push", "--force-with-lease", "origin", branch); err != nil {
		return fmt.Errorf("pushing: %w", err)
	}

	prNumber, err := createOrUpdatePR(branch, title, body, s.codeowners)
	if err != nil {
		return fmt.Errorf("creating/updating PR: %w", err)
	}

	return fixupChangelogLinks(s, branch, prNumber)
}

// createOrUpdatePR opens a PR for branch, requesting a review from every team
// in codeowners, or updates the body of an existing open one, and returns the
// PR number for changelog link fixup.
func createOrUpdatePR(branch, title, body string, codeowners []string) (string, error) {
	stdout, _, err := gh.Exec("pr", "list", "--head", branch, "--state", "open", "--json", "number,url")
	if err != nil {
		return "", err
	}
	var prs []struct {
		Number int    `json:"number"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &prs); err != nil {
		return "", fmt.Errorf("parsing PR list: %w", err)
	}
	if len(prs) > 0 {
		if _, _, err := gh.Exec("pr", "edit", prs[0].URL, "--body", body); err != nil {
			return "", fmt.Errorf("updating PR: %w", err)
		}
		return fmt.Sprintf("%d", prs[0].Number), nil
	}

	args := []string{
		"pr", "create",
		"--base", "main",
		"--head", branch,
		"--title", title,
		"--label", "automation",
		"--body", body,
	}
	for _, owner := range codeowners {
		args = append(args, "--reviewer", "@"+owner)
	}
	stdout, _, err = gh.Exec(args...)
	if err != nil {
		return "", fmt.Errorf("creating PR: %w", err)
	}
	prURL := strings.TrimSpace(stdout.String())
	return prURL[strings.LastIndex(prURL, "/")+1:], nil
}

// fixupChangelogLinks replaces the pull/REPLACE_ME placeholder in this
// package's changelog file with the real PR number, in a follow-up commit,
// once the PR number is known.
func fixupChangelogLinks(s packageSummary, branch, prNumber string) error {
	if prNumber == "" {
		return nil
	}
	var changed bool
	for _, f := range s.files {
		if !strings.HasSuffix(f, "changelog.yml") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("reading %s: %w", f, err)
		}
		fixed := strings.ReplaceAll(string(data), "pull/REPLACE_ME", "pull/"+prNumber)
		if fixed == string(data) {
			continue
		}
		if err := os.WriteFile(f, []byte(fixed), 0644); err != nil {
			return fmt.Errorf("writing %s: %w", f, err)
		}
		if err := gitExec("add", "--", f); err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return nil
	}
	if err := gitExec("commit", "-m", "Fix changelog PR links"); err != nil {
		return fmt.Errorf("committing changelog fixup: %w", err)
	}
	return gitExec("push", "origin", branch)
}

func findOpenIssue(title string) (string, error) {
	stdout, _, err := gh.Exec("issue", "list",
		"--state", "open",
		"--search", fmt.Sprintf("%s in:title", title),
		"--json", "number,title",
	)
	if err != nil {
		return "", err
	}
	var issues []struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &issues); err != nil {
		return "", fmt.Errorf("parsing issue list: %w", err)
	}
	for _, i := range issues {
		if i.Title == title {
			return fmt.Sprintf("%d", i.Number), nil
		}
	}
	return "", nil
}

func issueBody(s packageSummary) string {
	var b strings.Builder
	b.WriteString("The following dependency updates are available but could not be applied automatically.\n\n")
	for _, p := range s.skipped {
		fmt.Fprintf(&b, "- **%s**: %s\n", p.Package, p.Warning)
	}
	if s.ownerMismatch != "" {
		fmt.Fprintf(&b, "\n> **Note:** codeowner mismatch — %s\n", s.ownerMismatch)
	}
	fmt.Fprintf(&b, "\n/cc %s\n", mentions(s.codeowners))
	return b.String()
}

// mentions formats owners (bare "org/team" entries) as space-separated
// GitHub @mentions, e.g. "@elastic/team-a @elastic/team-b".
func mentions(owners []string) string {
	mentioned := make([]string, len(owners))
	for i, o := range owners {
		mentioned[i] = "@" + o
	}
	return strings.Join(mentioned, " ")
}

func prBody(s packageSummary) string {
	var b strings.Builder
	if len(s.applied) > 0 {
		b.WriteString("## Applied\n\n")
		for _, p := range s.applied {
			fmt.Fprintf(&b, "- **%s** (`%s`): `%s` → `%s`\n", p.Package, p.Kind, p.Current, p.Proposed)
		}
	}
	if len(s.skipped) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("## Skipped\n\n")
		for _, p := range s.skipped {
			fmt.Fprintf(&b, "- ⚠️ **%s**: %s\n", p.Package, p.Warning)
		}
	}
	if s.ownerMismatch != "" {
		fmt.Fprintf(&b, "\n> **Note:** codeowner mismatch — %s\n", s.ownerMismatch)
	}
	return b.String()
}

func gitExec(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
