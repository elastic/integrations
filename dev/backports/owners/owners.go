// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package owners compares package ownership (CODEOWNERS entries and
// manifest.yml's owner.github field) between a backport branch's worktree and
// another git ref (typically main), and computes the changes needed to bring
// a single package's ownership in line with that ref.
package owners

import (
	"bufio"
	"fmt"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/elastic/integrations/dev/citools"
)

// Owners is a parsed CODEOWNERS file, indexed by path for ownership
// resolution. It does not validate the file, it only extracts path->owners
// rules for use by ResolveOwner.
type Owners struct {
	entries map[string][]string
}

// ParseOwners parses CODEOWNERS content. Lines that are blank, comments, or
// single-field exclusion rules (no owners) are ignored, since they carry no
// information relevant to package/data-stream owner resolution.
func ParseOwners(content string) (*Owners, error) {
	o := &Owners{entries: make(map[string][]string)}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		p, owners, ok := parseEntryLine(scanner.Text())
		if !ok {
			continue
		}
		o.entries[p] = owners
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning CODEOWNERS content: %w", err)
	}

	return o, nil
}

// parseEntryLine parses a single CODEOWNERS line, the same rule ParseOwners
// and ApplyUpdates both use to recognize a real entry: not blank, not a
// comment, and not a single-field exclusion rule (no owners).
func parseEntryLine(line string) (path string, owners []string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil, false
	}

	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", nil, false
	}

	return strings.TrimSuffix(fields[0], "/"), fields[1:], true
}

// ResolveOwner returns the owners that apply to p, walking up parent
// directories until an explicit entry is found (mirrors GitHub's own
// CODEOWNERS resolution and dev/codeowners.findOwnerForFile).
func (o *Owners) ResolveOwner(p string) ([]string, bool) {
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		p = "/"
	}

	for {
		if owners, found := o.entries[p]; found {
			return owners, true
		}
		if p == "/" || p == "." {
			return nil, false
		}
		p = path.Dir(p)
	}
}

// EntriesUnder returns the full paths of every explicit entry nested under
// prefix — e.g. prefix "/packages/aws" matches
// "/packages/aws/data_stream/cloudtrail" and "/packages/aws/kibana", but not
// "/packages/aws" itself or an unrelated "/packages/awsome". Order is
// unspecified.
func (o *Owners) EntriesUnder(prefix string) []string {
	prefix = strings.TrimSuffix(prefix, "/") + "/"
	var paths []string
	for p := range o.entries {
		if strings.HasPrefix(p, prefix) {
			paths = append(paths, p)
		}
	}
	return paths
}

// ManifestOwner extracts the owner.github field from manifest.yml content,
// via dev/citools' shared manifest parser.
func ManifestOwner(manifestYAML []byte) (string, error) {
	manifest, err := citools.ParsePackageManifest(manifestYAML)
	if err != nil {
		return "", fmt.Errorf("parsing manifest.yml: %w", err)
	}
	if manifest.Owner.Github == "" {
		return "", fmt.Errorf("no owner specified in manifest.yml")
	}

	return manifest.Owner.Github, nil
}

// SyncPlan describes the writes needed to bring a package's owners in the
// current worktree in line with another ref. A zero-value SyncPlan means no
// changes are needed.
type SyncPlan struct {
	// ManifestOwner is the new value for manifest.yml's owner.github field.
	// Empty means unchanged.
	ManifestOwner string
	// PackageOwner is the new value for the package's own CODEOWNERS line.
	// Nil means unchanged.
	PackageOwner []string
	// SubPaths maps a full CODEOWNERS path nested under the package — a data
	// stream (".../data_stream/<name>"), a kibana/ directory, or any other
	// overridden subdirectory — to the new explicit line needed for it. Only
	// sub-paths that need an explicit line written (new or updated) are
	// present.
	SubPaths map[string][]string
}

// Empty reports whether the plan requires no changes.
func (p SyncPlan) Empty() bool {
	return p.ManifestOwner == "" && p.PackageOwner == nil && len(p.SubPaths) == 0
}

// Plan computes the changes needed to bring pkgPath's owners (CODEOWNERS
// package line, manifest.yml owner, and any explicit sub-path overrides —
// data streams, a kibana/ directory, or anything else) in line with main's
// resolution. existingSubPaths must be exactly the full CODEOWNERS paths
// nested under pkgPath that actually exist in the current worktree checkout
// for this package (e.g. "/packages/aws/data_stream/cloudtrail",
// "/packages/aws/kibana"): Plan never adds a line for a sub-path absent from
// existingSubPaths, since it may not exist in this backport branch's version
// of the package.
//
// If a package no longer resolves to an owner on main (e.g. it was removed),
// Plan returns (SyncPlan{}, false) so the caller can skip it cleanly.
//
// Plan only ever mirrors what main explicitly says about a given sub-path —
// it never invents a new explicit override for one main leaves implicit,
// even when a sibling sub-path in the same package does gain one.
// Concretely, per sub-path:
//   - if the current worktree already has an explicit line for it, that line
//     is kept explicit and its value is synced to main's resolution (which
//     falls back to the package owner if main consolidated an override back
//     to the package level);
//   - otherwise, a new explicit line is added only if main itself has an
//     explicit entry for that exact sub-path;
//   - if neither side calls it out explicitly, it's left alone, inheriting
//     the package owner on both sides.
//
// This can leave a package's CODEOWNERS only partially split across its
// sub-paths (failing dev/codeowners' all-or-nothing invariant for data
// streams) when main itself hasn't defined owners for every one it shares
// with this branch. That's intentional: deciding an owner for something
// nobody has assigned is a human judgment call, not something to guess a
// default for — codeowners.Check() (or the backport-branch CI check)
// surfaces that gap for a person to resolve instead.
func Plan(pkgPath string, existingSubPaths []string, current, main *Owners, currentManifestOwner, mainManifestOwner string) (SyncPlan, bool) {
	mainPkgOwner, found := main.ResolveOwner(pkgPath)
	if !found {
		return SyncPlan{}, false
	}

	var plan SyncPlan

	if mainManifestOwner != "" && mainManifestOwner != currentManifestOwner {
		plan.ManifestOwner = mainManifestOwner
	}

	currentPkgOwner, _ := current.ResolveOwner(pkgPath)
	if !slices.Equal(currentPkgOwner, mainPkgOwner) {
		plan.PackageOwner = mainPkgOwner
	}

	if len(existingSubPaths) == 0 {
		return plan, true
	}

	subPathPlan := make(map[string][]string, len(existingSubPaths))
	for _, subPath := range existingSubPaths {
		if currentOwner, hasCurrentExplicit := current.entries[subPath]; hasCurrentExplicit {
			mainOwner, _ := main.ResolveOwner(subPath)
			if !slices.Equal(currentOwner, mainOwner) {
				subPathPlan[subPath] = mainOwner
			}
			continue
		}

		mainOwner, hasMainExplicit := main.entries[subPath]
		if !hasMainExplicit {
			continue
		}
		currentOwner, _ := current.ResolveOwner(subPath)
		if !slices.Equal(currentOwner, mainOwner) {
			subPathPlan[subPath] = mainOwner
		}
	}
	if len(subPathPlan) > 0 {
		plan.SubPaths = subPathPlan
	}

	return plan, true
}

// ApplyUpdates rewrites CODEOWNERS content so each path in updates resolves
// to its given owners — updating an existing line in place, or inserting a
// new one (immediately after packagePath's own line, if found; otherwise at
// the end of the file) when none exists yet. It shares parseEntryLine with
// ParseOwners, so a line ApplyUpdates would leave alone is always a line
// ParseOwners would also skip, and vice versa.
func ApplyUpdates(content string, updates map[string][]string, packagePath string) string {
	if len(updates) == 0 {
		return content
	}

	remaining := make(map[string][]string, len(updates))
	maps.Copy(remaining, updates)

	lines := strings.Split(content, "\n")
	packageLineIdx := -1
	for i, line := range lines {
		p, _, ok := parseEntryLine(line)
		if !ok {
			continue
		}
		if p == packagePath {
			packageLineIdx = i
		}
		if newOwners, found := remaining[p]; found {
			lines[i] = p + " " + strings.Join(newOwners, " ")
			delete(remaining, p)
		}
	}

	if len(remaining) > 0 {
		insertAt := len(lines)
		if packageLineIdx != -1 {
			insertAt = packageLineIdx + 1
		} else if len(lines) > 0 && lines[len(lines)-1] == "" {
			// content ends with a trailing newline, represented by a final
			// empty element — insert before it so appended lines land before
			// that newline instead of after it.
			insertAt = len(lines) - 1
		}

		remainingPaths := make([]string, 0, len(remaining))
		for path := range remaining {
			remainingPaths = append(remainingPaths, path)
		}
		sort.Strings(remainingPaths)

		newLines := make([]string, 0, len(remainingPaths))
		for _, path := range remainingPaths {
			newLines = append(newLines, path+" "+strings.Join(remaining[path], " "))
		}
		lines = slices.Insert(lines, insertAt, newLines...)
	}

	return strings.Join(lines, "\n")
}
