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
	"path"
	"slices"
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
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		p := strings.TrimSuffix(fields[0], "/")
		o.entries[p] = fields[1:]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning CODEOWNERS content: %w", err)
	}

	return o, nil
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
	// DataStreams maps data stream name to the new explicit CODEOWNERS line
	// needed for it. Only data streams that need an explicit line written
	// (new or updated) are present.
	DataStreams map[string][]string
}

// Empty reports whether the plan requires no changes.
func (p SyncPlan) Empty() bool {
	return p.ManifestOwner == "" && p.PackageOwner == nil && len(p.DataStreams) == 0
}

// Plan computes the changes needed to bring pkgPath's owners (CODEOWNERS
// package line, manifest.yml owner, and data-stream overrides) in line with
// main's resolution. dataStreamNames must be exactly the data streams that
// exist in the current worktree checkout for this package: Plan never adds a
// line for a data stream absent from dataStreamNames, since it may not exist
// in this backport branch's version of the package.
//
// If a package no longer resolves to an owner on main (e.g. it was removed),
// Plan returns (SyncPlan{}, false) so the caller can skip it cleanly.
//
// When main's resolution requires a per-data-stream split that isn't fully
// explicit in the current worktree yet, Plan includes an entry for every data
// stream in dataStreamNames (not just the one whose owner changed), so
// writing the plan keeps CODEOWNERS' all-or-nothing per-package data-stream
// override invariant satisfied.
func Plan(pkgPath string, dataStreamNames []string, current, main *Owners, currentManifestOwner, mainManifestOwner string) (SyncPlan, bool) {
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

	if len(dataStreamNames) == 0 {
		return plan, true
	}

	resolved := make(map[string][]string, len(dataStreamNames))
	needSplit := false
	for _, ds := range dataStreamNames {
		owner, _ := main.ResolveOwner(dataStreamPath(pkgPath, ds))
		resolved[ds] = owner
		if !slices.Equal(owner, mainPkgOwner) {
			needSplit = true
		}
	}

	dataStreamPlan := make(map[string][]string)
	for _, ds := range dataStreamNames {
		mainOwner := resolved[ds]

		if needSplit {
			dataStreamPlan[ds] = mainOwner
			continue
		}

		_, hasExplicit := current.entries[dataStreamPath(pkgPath, ds)]
		if !hasExplicit {
			continue
		}
		currentOwner, _ := current.ResolveOwner(dataStreamPath(pkgPath, ds))
		if !slices.Equal(currentOwner, mainOwner) {
			dataStreamPlan[ds] = mainOwner
		}
	}
	if len(dataStreamPlan) > 0 {
		plan.DataStreams = dataStreamPlan
	}

	return plan, true
}

func dataStreamPath(pkgPath, dataStream string) string {
	return pkgPath + "/data_stream/" + dataStream
}
