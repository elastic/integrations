// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package checklist provides pure functions for building and parsing the
// backport-checklist comment posted on pull requests targeting main.
// No I/O is performed here — callers supply any dynamic data (active branches,
// existing comment body) and receive back a rendered string.
package checklist

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/elastic/integrations/cmd/backport/backports"
)

// marker is the HTML comment embedded at the start of every checklist comment.
// It is used to find and update an existing checklist rather than posting a new one.
const marker = "<!-- backport-checklist -->"

// PackageBranches pairs a package name with its active backport branches.
// Branches are in inventory order.
type PackageBranches struct {
	Package  string
	Branches []backports.ActiveResult
}

// checkedLineRe matches a checked checkbox line: "- [x] `branch-name`..."
var checkedLineRe = regexp.MustCompile("^- \\[[xX]\\] `([^`]+)`")

// checklistItemRe matches any checkbox branch line (checked or unchecked).
// Group 1: checkbox char (' ', 'x', or 'X'). Group 2: branch name.
var checklistItemRe = regexp.MustCompile("^- \\[([xX ])\\] `([^`]+)`")

// packageHeaderRe matches a bold package section header: **package-name**
var packageHeaderRe = regexp.MustCompile(`^\*\*([^*]+)\*\*$`)

// ChecklistItem represents a single branch entry parsed from a checklist comment body.
type ChecklistItem struct {
	Package   string
	Branch    string
	Checked   bool
	Processed bool // true if the line already carries a ✅ or ⚠️ status suffix
}

// ParseChecklistItems scans body for package headers and checkbox branch lines and
// returns one ChecklistItem per branch. An empty or marker-free body returns an
// empty (non-nil) slice so callers never need a nil check.
func ParseChecklistItems(body string) []ChecklistItem {
	items := []ChecklistItem{}
	if !strings.Contains(body, marker) {
		return items
	}
	var currentPkg string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := packageHeaderRe.FindStringSubmatch(line); m != nil {
			currentPkg = m[1]
			continue
		}
		if m := checklistItemRe.FindStringSubmatch(line); m != nil {
			items = append(items, ChecklistItem{
				Package:   currentPkg,
				Branch:    m[2],
				Checked:   m[1] != " ",
				Processed: strings.ContainsRune(line, '✅') || strings.ContainsRune(line, '⚠'),
			})
		}
	}
	return items
}

// UpdateBranchStatus finds the checkbox line for branch in body and appends
// " — <status>" to it. If the line already carries a ✅ or ⚠️ suffix the body
// is returned unchanged (defence-in-depth against workflow self-trigger loops).
// Returns body unchanged when branch is not found.
func UpdateBranchStatus(body, branch, status string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		m := checklistItemRe.FindStringSubmatch(trimmed)
		if m == nil || m[2] != branch {
			continue
		}
		if strings.ContainsRune(trimmed, '✅') || strings.ContainsRune(trimmed, '⚠') {
			return body
		}
		lines[i] = trimmed + " — " + status
		return strings.Join(lines, "\n")
	}
	return body
}

// ParseCheckedBranches scans body for "- [x] `<branch>`" lines and returns the
// set of branch names that are currently ticked. An empty or marker-free body
// returns an empty (non-nil) map so callers never need a nil check.
func ParseCheckedBranches(body string) map[string]bool {
	checked := make(map[string]bool)
	if !strings.Contains(body, marker) {
		return checked
	}
	// strings.SplitSeq requires go1.23; go.mod pins go1.22 for backport compatibility with older base commits.
	for _, line := range strings.Split(body, "\n") {
		if m := checkedLineRe.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			checked[m[1]] = true
		}
	}
	return checked
}

// BuildComment renders the full comment body starting with marker.
// Packages that have no active branches are omitted, so stale sections disappear
// automatically on recompute without any special removal logic.
// Branches in checked are rendered with a filled checkbox; all others are unchecked.
//
// Returns "" when no package has any active branch; callers should skip posting.
func BuildComment(pkgs []PackageBranches, checked map[string]bool) string {
	if !slices.ContainsFunc(pkgs, func(p PackageBranches) bool { return len(p.Branches) > 0 }) {
		return ""
	}

	var b strings.Builder

	fmt.Fprintln(&b, marker)
	fmt.Fprintln(&b, "## Backport branches")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "> [!IMPORTANT]")
	fmt.Fprintln(&b, "> Only branches for packages touched by this PR's current diff are shown.")
	fmt.Fprintln(&b, "> This comment is updated automatically on each push — manual edits will be overwritten.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Tick the branches you want to backport to. PRs will be created automatically on merge, or when you update this checklist after merge.")

	for _, p := range pkgs {
		if len(p.Branches) == 0 {
			continue
		}

		// One blank line before every package header (between intro and first
		// package, and between consecutive packages).
		fmt.Fprintln(&b)
		fmt.Fprintf(&b, "**%s**\n", p.Package)
		for _, r := range p.Branches {
			box := "[ ]"
			if checked[r.Branch] {
				box = "[x]"
			}
			line := fmt.Sprintf("- %s `%s`", box, r.Branch)
			if r.MaintainedUntil != nil {
				line += fmt.Sprintf(" (maintained until %s)", *r.MaintainedUntil)
			}
			fmt.Fprintln(&b, line)
		}
	}

	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "---")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "> [!TIP]")
	fmt.Fprintln(&b, "> If a branch above is no longer required, set `archived: true` in its entry in `.backports.yml` to stop it appearing here.")
	fmt.Fprintln(&b, `> If the branch has a known end-of-life date, prefer `+"`"+`maintained_until: "YYYY-MM-DD"`+"`"+` — it will be excluded automatically once that date passes.`)

	return b.String()
}
