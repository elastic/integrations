// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package owners

import (
	"path/filepath"
	"sort"

	"github.com/elastic/integrations/dev/codeowners"
	"github.com/elastic/integrations/dev/gitutil"
)

// Mismatch is one package's owner-check result against remoteRef. Exactly
// one of Teams or Err is set. A package fully in sync with remoteRef, or no
// longer present there, is neither — CheckPackages omits it entirely.
type Mismatch struct {
	Package string
	// Teams is the resolved, deduped, "@"-prefixed set of owners the package
	// should now have, derived from its SyncPlan.
	Teams []string
	// Err is set instead of Teams when the check itself couldn't run for
	// this package (e.g. a read/parse failure) — no team could be resolved.
	Err error
}

// CheckPackages reports owner mismatches for each named package against
// remoteRef (e.g. "origin/main"). pkgDirs maps package name to its directory
// relative to workDir (e.g. from dev/backports/changelog.BuildPackageIndex);
// a name absent from pkgDirs (the package was removed in this PR) is
// silently skipped, same as a package Compare reports as not found on
// remoteRef.
func CheckPackages(git gitutil.Git, workDir, remoteRef string, pkgNames []string, pkgDirs map[string]string) []Mismatch {
	localPath := filepath.Join(workDir, codeowners.DefaultCodeownersPath)
	remoteGitRef := remoteRef + ":" + codeowners.DefaultCodeownersPath
	current, source, err := parseCodeowners(git, localPath, remoteGitRef)
	if err != nil {
		// Surface as an error on every package rather than silently checking nothing.
		var mismatches []Mismatch
		for _, name := range pkgNames {
			if _, ok := pkgDirs[name]; ok {
				mismatches = append(mismatches, Mismatch{Package: name, Err: err})
			}
		}
		return mismatches
	}

	var mismatches []Mismatch
	for _, name := range pkgNames {
		pkgDir, ok := pkgDirs[name]
		if !ok {
			continue
		}

		relPkgDir := filepath.ToSlash(pkgDir)
		if workDir != "" {
			if rel, err := filepath.Rel(workDir, pkgDir); err == nil {
				relPkgDir = filepath.ToSlash(rel)
			}
		}

		plan, found, err := compareWith(git, workDir, pkgDir, relPkgDir, remoteRef, current, source)
		if err != nil {
			mismatches = append(mismatches, Mismatch{Package: name, Err: err})
			continue
		}
		if !found || plan.Empty() {
			continue
		}
		mismatches = append(mismatches, Mismatch{Package: name, Teams: dedupTeams(plan)})
	}
	return mismatches
}

// dedupTeams collects every distinct owner value named anywhere in plan
// (manifest owner, package owner, and all sub-path owners), "@"-prefixing
// the bare manifest.yml owner so every entry uses the same CODEOWNERS-style
// format, and returns them sorted.
func dedupTeams(plan SyncPlan) []string {
	seen := make(map[string]bool)
	var teams []string
	add := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		teams = append(teams, t)
	}

	if plan.ManifestOwner != "" {
		add("@" + plan.ManifestOwner)
	}
	for _, o := range plan.PackageOwner {
		add(o)
	}
	for _, subOwners := range plan.SubPaths {
		for _, o := range subOwners {
			add(o)
		}
	}

	sort.Strings(teams)
	return teams
}
