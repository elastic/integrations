// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package requiresupdate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/elastic/integrations/dev/citools"
	"github.com/elastic/integrations/dev/codeowners"
)

const packagesDir = "packages"

// elasticPackageBin returns the elastic-package binary to use.
// Override with ELASTIC_PACKAGE_BIN for local builds that carry new commands.
func elasticPackageBin() string {
	if bin := os.Getenv("ELASTIC_PACKAGE_BIN"); bin != "" {
		return bin
	}
	return "elastic-package"
}

type proposal struct {
	Kind             string `json:"kind"`
	Package          string `json:"package"`
	Current          string `json:"current"`
	Proposed         string `json:"proposed"`
	KibanaConstraint string `json:"kibana_constraint"`
	Warning          string `json:"warning"`
}

type updateResult struct {
	Package    string     `json:"package"`
	Codeowner  string     `json:"codeowner"`
	Proposals  []proposal `json:"proposals"`
	NewVersion string     `json:"new_version,omitempty"`
}

// defaultOwner is the catch-all team used when a package has no resolvable
// codeowner (neither CODEOWNERS nor the manifest's owner.github field), so a
// proposal never gets dropped for lack of somewhere to send it.
const defaultOwner = "elastic/ecosystem"

type packageSummary struct {
	path          string
	name          string
	applied       []proposal
	skipped       []proposal
	codeowners    []string // bare "org/team" entries, no leading '@'; every team owning this package
	ownerMismatch string   // non-empty if CODEOWNERS and the manifest fallback disagreed; describes both values
	files         []string // paths written to disk, relative to repo root; empty on dry-run
}

// Run walks all integration packages, runs elastic-package requires update,
// adds changelog entries for packages with actual updates, opens one PR (or,
// if every proposal was skipped, one issue) per package via Publish, and
// prints a summary grouped by codeowner.
//
// Set dryRun to see proposals without applying (this also skips publishing,
// since no files were written). Set preview to print what publish would do
// without touching git or GitHub.
func Run(dryRun, preview bool) error {
	pkgs, err := citools.ListPackagesWithNames(packagesDir)
	if err != nil {
		return fmt.Errorf("listing packages: %w", err)
	}

	owners, err := codeowners.LoadOwners(codeowners.DefaultCodeownersPath)
	if err != nil {
		return fmt.Errorf("loading codeowners: %w", err)
	}

	var summaries []packageSummary
	var errs []string
	eligible := 0

	for _, pkg := range pkgs {
		if pkg.Type != "integration" || !pkg.HasRequires {
			continue
		}
		eligible++

		summary, err := processPackage(pkg.Path, pkg.Name, dryRun, owners)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", pkg.Name, err))
			continue
		}
		if summary != nil {
			summaries = append(summaries, *summary)
		}
	}

	printSummary(summaries, dryRun)
	printScanStats(len(pkgs), eligible, len(summaries), len(errs))

	if dryRun {
		fmt.Println("dry run — skipping PR/issue creation.")
	} else if err := publish(summaries, preview); err != nil {
		errs = append(errs, fmt.Sprintf("publishing: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors in %d package(s):\n  %s", len(errs), strings.Join(errs, "\n  "))
	}
	return nil
}

func processPackage(pkgPath, pkgName string, dryRun bool, owners *codeowners.Owners) (*packageSummary, error) {
	args := []string{"requires", "update", "--changelog", "--format", "json"}
	if dryRun {
		args = append(args, "--dry-run")
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(elasticPackageBin(), args...)
	cmd.Dir = pkgPath
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("elastic-package requires update: %w\nstderr: %s", err, stderr.String())
	}

	if stdout.Len() == 0 {
		return nil, nil
	}

	var result updateResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("parsing JSON output: %w\noutput: %s", err, stdout.String())
	}

	var applied, skipped []proposal
	for _, p := range result.Proposals {
		if p.Proposed != "" {
			applied = append(applied, p)
		} else if p.Warning != "" {
			skipped = append(skipped, p)
		} else {
			fmt.Printf("warning: unrecognised proposal for %s (package=%s kind=%s) — neither proposed nor warning set; skipping\n",
				pkgName, p.Package, p.Kind)
		}
	}

	if len(applied) == 0 && len(skipped) == 0 {
		return nil, nil
	}

	res := resolveOwner(owners, pkgPath, result.Codeowner)

	var writtenFiles []string
	// written files are only populated when proposals are applied, not on dry-run
	if len(applied) > 0 && !dryRun {
		writtenFiles = []string{
			filepath.Join(pkgPath, citools.ManifestFileName),
			filepath.Join(pkgPath, "changelog.yml"),
		}
	}

	return &packageSummary{
		path:          pkgPath,
		name:          pkgName,
		applied:       applied,
		skipped:       skipped,
		codeowners:    res.owners,
		ownerMismatch: res.mismatch,
		files:         writtenFiles,
	}, nil
}

// ownerResolution is the result of reconciling CODEOWNERS against the
// package manifest's own owner.github fallback field.
type ownerResolution struct {
	owners   []string // bare "org/team" entries, no leading '@'; never empty
	mismatch string   // non-empty if CODEOWNERS and the fallback disagreed; describes both values
}

// resolveOwner reconciles the package's codeowner(s), preferring CODEOWNERS
// (which may list more than one owning team) over the JSON fallback field
// (sourced from the package manifest's owner.github, which only ever names
// one team). Falls back to defaultOwner when neither source resolves one, so
// a proposal never gets dropped for lack of somewhere to send it.
func resolveOwner(owners *codeowners.Owners, pkgPath, fallback string) ownerResolution {
	teams, err := owners.PackageOwnersByPath(pkgPath, "")
	if err != nil {
		owner := fallback
		if owner == "" {
			owner = defaultOwner
		}
		return ownerResolution{owners: []string{owner}}
	}
	// CODEOWNERS entries carry a '@' prefix; the JSON fallback field does
	// not — normalize to the bare form so callers get a consistent value
	// regardless of which path resolved it.
	bare := make([]string, len(teams))
	for i, t := range teams {
		bare[i] = strings.TrimPrefix(t, "@")
	}
	res := ownerResolution{owners: bare}
	if fallback != "" && !slices.Contains(bare, fallback) {
		res.mismatch = fmt.Sprintf("CODEOWNERS=%s manifest owner.github=%s (using CODEOWNERS)",
			strings.Join(bare, ","), fallback)
	}
	return res
}

// printScanStats prints a one-line scan summary distinguishing "nothing to do
// because adoption of requires: is low" from "the walk found nothing due to a
// bug" — both currently produce zero proposals. Also appended to
// $GITHUB_STEP_SUMMARY when set, so it's visible without opening the job log.
func printScanStats(total, eligible, withProposals, errored int) {
	line := fmt.Sprintf("Scanned %d packages, %d eligible (requires: present), %d with proposals, %d errored.\n",
		total, eligible, withProposals, errored)
	fmt.Print(line)

	if summaryPath := os.Getenv("GITHUB_STEP_SUMMARY"); summaryPath != "" {
		f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		defer f.Close()
		fmt.Fprint(f, line)
	}
}

func printSummary(summaries []packageSummary, dryRun bool) {
	groups := make(map[string][]packageSummary)
	for _, s := range summaries {
		key := strings.Join(s.codeowners, ", ")
		groups[key] = append(groups[key], s)
	}

	teams := make([]string, 0, len(groups))
	for t := range groups {
		teams = append(teams, t)
	}
	sort.Strings(teams)

	mode := "applied"
	if dryRun {
		mode = "proposed (dry run)"
	}

	fmt.Printf("\n=== Requires Update Summary (%s) ===\n\n", mode)

	for _, team := range teams {
		fmt.Printf("## %s\n", team)
		for _, s := range groups[team] {
			printPackageSummary(s)
		}
		fmt.Println()
	}
}

func printPackageSummary(s packageSummary) {
	fmt.Printf("  %s\n", s.name)
	if s.ownerMismatch != "" {
		fmt.Printf("    [OWNER MISMATCH] %s\n", s.ownerMismatch)
	}
	for _, p := range s.applied {
		fmt.Printf("    [%s] %s: %s → %s\n", p.Kind, p.Package, p.Current, p.Proposed)
	}
	for _, p := range s.skipped {
		fmt.Printf("    [SKIPPED] %s (kibana constraint): %s\n", p.Package, p.Warning)
	}
}
