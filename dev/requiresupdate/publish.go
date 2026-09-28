// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package requiresupdate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cli/go-gh/v2"

	"github.com/elastic/integrations/dev/gitutil"
)

// ghExec runs the gh CLI and folds stderr into the result: on failure it's
// appended to the returned error, since gh's exit error alone typically
// doesn't carry the human-readable reason; on success a non-empty stderr is
// printed as a warning, since gh can report partial problems (e.g. a
// reviewer it couldn't request) without a non-zero exit.
func ghExec(args ...string) (bytes.Buffer, error) {
	stdout, stderr, err := gh.Exec(args...)
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return stdout, fmt.Errorf("%w: %s", err, msg)
		}
		return stdout, err
	}
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		fmt.Printf("gh %s warning: %s\n", strings.Join(args, " "), msg)
	}
	return stdout, nil
}

// publish opens one PR per package with applied changes — creating or
// updating a stable per-package branch — and one GitHub issue per package
// whose proposals were entirely skipped. Deliberately kept simple while
// adoption of `requires:` is low; revisit batching by codeowner once weekly
// volume per team justifies the added complexity.
//
// In preview mode nothing is written to git or GitHub; actions are only
// printed.
func publish(summaries []packageSummary, preview bool) error {
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].name < summaries[j].name })

	for _, s := range summaries {
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
		if _, err := ghExec("issue", "edit", number, "--body", body); err != nil {
			return fmt.Errorf("updating issue #%s: %w", number, err)
		}
		fmt.Printf("Updated existing issue #%s for %s.\n", number, s.name)
		return nil
	}
	if _, err := ghExec("issue", "create", "--title", title, "--label", "automation", "--body", body); err != nil {
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

	git := gitutil.Git{}

	// Reset HEAD to main without discarding the dirty working tree.
	// "checkout -B" moves HEAD but does not touch untracked/modified files,
	// so other packages' pending changes survive subsequent calls.
	if err := git.Run("checkout", "-B", branch, "origin/main"); err != nil {
		return fmt.Errorf("creating branch failed: %w", err)
	}
	if err := git.Run(append([]string{"add", "--"}, s.files...)...); err != nil {
		return fmt.Errorf("staging files failed: %w", err)
	}
	staged, err := git.Output("diff", "--cached", "--name-only")
	if err != nil {
		return fmt.Errorf("checking staged files failed: %w", err)
	}
	if strings.TrimSpace(staged) == "" {
		return fmt.Errorf("nothing staged for %s: files may already be committed or elastic-package produced no changes", s.name)
	}
	if err := git.Run("commit", "-m", fmt.Sprintf("[automation] Update required package versions for %s", s.name)); err != nil {
		return fmt.Errorf("committing failed: %w", err)
	}
	// Force push: each run resets the branch to origin/main and commits fresh
	// changes, so the new commit intentionally diverges from any previous run's
	// commit on the same branch — not a fast-forward.
	if err := git.Run("push", "--force", "origin", branch); err != nil {
		return fmt.Errorf("pushing failed: %w", err)
	}

	prNumber, err := createOrUpdatePR(branch, title, body)
	if err != nil {
		return fmt.Errorf("creating/updating PR failed: %w", err)
	}

	return fixupChangelogLinks(s, branch, prNumber)
}

// createOrUpdatePR opens a PR for branch, or updates the body of an existing
// open one, and returns the PR number for changelog link fixup. Reviewers are
// left to GitHub's automatic CODEOWNERS review request rather than requested
// explicitly here.
func createOrUpdatePR(branch, title, body string) (string, error) {
	stdout, err := ghExec("pr", "list", "--head", branch, "--state", "open", "--json", "number,url")
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
		if _, err := ghExec("pr", "edit", prs[0].URL, "--body", body); err != nil {
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
	if _, err := ghExec(args...); err != nil {
		return "", fmt.Errorf("creating PR: %w", err)
	}
	// gh pr create --json is not available on GitHub-hosted runners yet; pr list
	// supports --json and is already used above for the update path.
	return openPRNumber(branch)
}

func openPRNumber(branch string) (string, error) {
	stdout, err := ghExec("pr", "list", "--head", branch, "--state", "open", "--json", "number")
	if err != nil {
		return "", err
	}
	var prs []struct {
		Number int `json:"number"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &prs); err != nil {
		return "", fmt.Errorf("parsing PR list: %w", err)
	}
	if len(prs) == 0 {
		return "", fmt.Errorf("no open PR found for branch %q after create", branch)
	}
	return fmt.Sprintf("%d", prs[0].Number), nil
}

// fixupChangelogLinks replaces the pull/REPLACE_ME placeholder in this
// package's changelog file with the real PR number, in a follow-up commit,
// once the PR number is known. s.files is only populated (and this function
// only called) when a changelog.yml was written, so a missing file or a
// missing placeholder both indicate elastic-package produced unexpected
// output rather than a normal no-op.
func fixupChangelogLinks(s packageSummary, branch, prNumber string) error {
	if prNumber == "" {
		return nil
	}
	changedPath, err := replaceChangelogPlaceholder(s.files, prNumber)
	if err != nil {
		return err
	}
	git := gitutil.Git{}
	if err := git.Run("add", "--", changedPath); err != nil {
		return err
	}
	if err := git.Run("commit", "-m", "Fix changelog PR links"); err != nil {
		return fmt.Errorf("committing changelog fixup: %w", err)
	}
	return git.Run("push", "origin", branch)
}

// replaceChangelogPlaceholder replaces the pull/REPLACE_ME placeholder in the
// first changelog.yml found in files with the real PR number, preserving file
// permissions. Returns the path of the modified file.
func replaceChangelogPlaceholder(files []string, prNumber string) (string, error) {
	for _, f := range files {
		if !strings.HasSuffix(f, "changelog.yml") {
			continue
		}
		info, err := os.Stat(f)
		if err != nil {
			return "", fmt.Errorf("stat %s: %w", f, err)
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", f, err)
		}
		fixed := strings.ReplaceAll(string(data), "pull/REPLACE_ME", "pull/"+prNumber)
		if fixed == string(data) {
			return "", fmt.Errorf("pull/REPLACE_ME placeholder not found in %s: elastic-package may have changed its changelog output format", f)
		}
		if err := os.WriteFile(f, []byte(fixed), info.Mode()); err != nil {
			return "", fmt.Errorf("writing %s: %w", f, err)
		}
		return f, nil
	}
	return "", fmt.Errorf("no changelog.yml found among written files to fix up PR links")
}

func findOpenIssue(title string) (string, error) {
	stdout, err := ghExec("issue", "list",
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
