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

	"github.com/elastic/integrations/dev/backports"
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
// The checked parameter is accepted for forward-compatibility but currently has no
// effect on the output — branches are rendered as plain list items until #19214
// (auto-backport PR creation) is implemented, at which point checkboxes will be restored.
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
	fmt.Fprintln(&b, "Active backport branches for the packages touched by this PR:")

	for _, p := range pkgs {
		if len(p.Branches) == 0 {
			continue
		}

		// One blank line before every package header (between intro and first
		// package, and between consecutive packages).
		fmt.Fprintln(&b)
		fmt.Fprintf(&b, "**%s**\n", p.Package)
		for _, r := range p.Branches {
			line := fmt.Sprintf("- `%s`", r.Branch)
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
