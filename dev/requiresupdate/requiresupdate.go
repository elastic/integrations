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
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"

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
	Applied    bool       `json:"applied"`
	SkipReason string     `json:"skip_reason,omitempty"`
}

type packageSummary struct {
	path      string
	name      string
	applied   []proposal
	skipped   []proposal
	codeowner string
	files     []string // paths written to disk, relative to repo root; empty on dry-run
}

// teamJSON is the per-team record written by writeJSONReport.
type teamJSON struct {
	Slug     string        `json:"slug"`
	Packages []packageJSON `json:"packages"`
}

type packageJSON struct {
	Name    string     `json:"name"`
	Files   []string   `json:"files"`
	Applied []proposal `json:"applied"`
	Skipped []proposal `json:"skipped"`
}

// Run walks all integration packages, runs elastic-package requires update,
// adds changelog entries for packages with actual updates, and prints a summary
// grouped by codeowner. Set DRY_RUN=true to see proposals without applying.
func Run() error {
	dryRun := os.Getenv("DRY_RUN") == "true"

	paths, err := citools.ListPackages(packagesDir)
	if err != nil {
		return fmt.Errorf("listing packages: %w", err)
	}

	var summaries []packageSummary
	var errs []string

	for _, pkgPath := range paths {
		manifest, err := citools.ReadPackageManifest(filepath.Join(pkgPath, citools.ManifestFileName))
		if err != nil {
			return fmt.Errorf("reading manifest %s: %w", pkgPath, err)
		}
		if manifest.Type != "integration" {
			continue
		}
		if !manifest.HasRequires() {
			continue
		}

		summary, err := processPackage(pkgPath, manifest.Name, manifest.Version, dryRun)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", manifest.Name, err))
			continue
		}
		if summary != nil {
			summaries = append(summaries, *summary)
		}
	}

	printSummary(summaries, dryRun)

	if jsonOut := os.Getenv("REQUIRES_UPDATE_JSON_OUT"); jsonOut != "" {
		if err := writeJSONReport(summaries, jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write JSON report to %s: %v\n", jsonOut, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors in %d package(s):\n  %s", len(errs), strings.Join(errs, "\n  "))
	}
	return nil
}

func processPackage(pkgPath, pkgName, currentVersion string, dryRun bool) (*packageSummary, error) {
	// Always run in dry-run mode to get proposals without letting elastic-package
	// rewrite the whole manifest (which reformats unrelated fields).
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(elasticPackageBin(), "requires", "update", "--format", "json", "--dry-run")
	cmd.Dir = pkgPath
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stdout.Len() == 0 {
			// No output: package likely has no requires section.
			return nil, nil
		}
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
		}
	}

	if len(applied) == 0 && len(skipped) == 0 {
		return nil, nil
	}

	owner, err := resolveOwner(pkgName, result.Codeowner)
	if err != nil {
		return nil, fmt.Errorf("resolving codeowner: %w", err)
	}

	var writtenFiles []string
	if !dryRun && len(applied) > 0 {
		manifestPath := filepath.Join(pkgPath, citools.ManifestFileName)
		if err := patchManifestRequires(manifestPath, applied); err != nil {
			return nil, fmt.Errorf("patching manifest requires: %w", err)
		}
		nextVersion, err := computeNextVersion(currentVersion, applied)
		if err != nil {
			return nil, fmt.Errorf("computing next version: %w", err)
		}
		if err := addChangelog(pkgPath, nextVersion, changelogType(applied)); err != nil {
			return nil, fmt.Errorf("adding changelog: %w", err)
		}
		writtenFiles = []string{
			filepath.Join(pkgPath, citools.ManifestFileName),
			filepath.Join(pkgPath, "changelog.yml"),
		}
	}

	return &packageSummary{
		path:      pkgPath,
		name:      pkgName,
		applied:   applied,
		skipped:   skipped,
		codeowner: owner,
		files:     writtenFiles,
	}, nil
}

// patchManifestRequires updates only the version lines under the requires: block.
// It scans line by line so no other field is touched or reformatted.
func patchManifestRequires(manifestPath string, proposals []proposal) error {
	updates := make(map[string]string, len(proposals))
	for _, p := range proposals {
		updates[p.Package] = p.Proposed
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")

	const (
		stateOutside      = iota
		stateInRequires   // inside requires: block
		stateAfterPackage // just saw "- package: <name>" with a pending update
	)

	state := stateOutside
	requiresIndent := -1
	currentPkg := ""

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		switch state {
		case stateOutside:
			if trimmed == "requires:" {
				state = stateInRequires
				requiresIndent = indent
			}

		case stateInRequires:
			if indent <= requiresIndent {
				// Left the requires block.
				state = stateOutside
				continue
			}
			if strings.HasPrefix(trimmed, "- package:") {
				pkg := strings.TrimSpace(strings.TrimPrefix(trimmed, "- package:"))
				if _, ok := updates[pkg]; ok {
					currentPkg = pkg
					state = stateAfterPackage
				}
			}

		case stateAfterPackage:
			if strings.HasPrefix(trimmed, "version:") {
				leading := line[:indent]
				proposed := updates[currentPkg]
				if strings.Contains(line, `"`) {
					lines[i] = leading + `version: "` + proposed + `"`
				} else {
					lines[i] = leading + "version: " + proposed
				}
				currentPkg = ""
				state = stateInRequires
			} else if strings.HasPrefix(trimmed, "- package:") {
				// Next list entry appeared before a version: line — handle it inline.
				currentPkg = ""
				state = stateInRequires
				pkg := strings.TrimSpace(strings.TrimPrefix(trimmed, "- package:"))
				if _, ok := updates[pkg]; ok {
					currentPkg = pkg
					state = stateAfterPackage
				}
			} else if indent <= requiresIndent {
				// Left the requires block entirely.
				currentPkg = ""
				state = stateOutside
			}
		}
	}

	return os.WriteFile(manifestPath, []byte(strings.Join(lines, "\n")), 0644)
}

func resolveOwner(pkgName, fallback string) (string, error) {
	owners, err := codeowners.PackageOwners(pkgName, "", codeowners.DefaultCodeownersPath)
	if err != nil || len(owners) == 0 {
		if fallback != "" {
			return fallback, nil
		}
		return "", fmt.Errorf("no codeowner found for %s: %w", pkgName, err)
	}
	primary := owners[0]
	// CODEOWNERS entries carry '@' prefix; JSON field does not — strip before comparing.
	if fallback != "" && strings.TrimPrefix(primary, "@") != fallback {
		fmt.Fprintf(os.Stderr, "warning: codeowner mismatch for %s: CODEOWNERS=%s JSON=%s (using CODEOWNERS)\n",
			pkgName, primary, fallback)
	}
	return primary, nil
}

// changelogType returns "breaking-change" if any applied proposal is a major
// dep bump (the integration's public contract may change), "enhancement" otherwise.
func changelogType(applied []proposal) string {
	for _, p := range applied {
		from, err1 := semver.NewVersion(p.Current)
		to, err2 := semver.NewVersion(p.Proposed)
		if err1 != nil || err2 != nil {
			continue
		}
		if bumpTier(from, to) == 2 {
			return "breaking-change"
		}
	}
	return "enhancement"
}

func addChangelog(pkgPath, version, entryType string) error {
	var stderr bytes.Buffer
	cmd := exec.Command(elasticPackageBin(),
		"changelog", "add",
		"--description", "Update required package versions",
		"--type", entryType,
		"--link", "https://github.com/elastic/integrations/pull/0",
		"--version", version,
	)
	cmd.Dir = pkgPath
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("elastic-package changelog add: %w\nstderr: %s", err, stderr.String())
	}
	return nil
}

// computeNextVersion bumps currentVersion by the largest semver tier found across
// all applied dep proposals (major > minor > patch). The rationale: the integration's
// own version must signal the highest severity change introduced by its dependencies.
//
//   - Any dep patch bump  → integration patch bump  (e.g. 1.2.3 → 1.2.4)
//   - Any dep minor bump  → integration minor bump  (e.g. 1.2.3 → 1.3.0)
//   - Any dep major bump  → integration major bump  (e.g. 1.2.3 → 2.0.0)
//
// When multiple deps update at different tiers in the same run, the largest tier
// wins: a mix of patch and minor bumps yields a minor integration bump.
func computeNextVersion(currentVersion string, applied []proposal) (string, error) {
	current, err := semver.NewVersion(currentVersion)
	if err != nil {
		return "", fmt.Errorf("parsing current version %q: %w", currentVersion, err)
	}

	tier := 0 // 0=patch, 1=minor, 2=major
	for _, p := range applied {
		from, err := semver.NewVersion(p.Current)
		if err != nil {
			continue
		}
		to, err := semver.NewVersion(p.Proposed)
		if err != nil {
			continue
		}
		if t := bumpTier(from, to); t > tier {
			tier = t
		}
	}

	var next semver.Version
	switch tier {
	case 2:
		next = current.IncMajor()
	case 1:
		next = current.IncMinor()
	default:
		next = current.IncPatch()
	}
	return next.String(), nil
}

// bumpTier returns the semver tier of a single dep version change:
// 2 = major, 1 = minor, 0 = patch.
func bumpTier(from, to *semver.Version) int {
	if to.Major() > from.Major() {
		return 2
	}
	if to.Minor() > from.Minor() {
		return 1
	}
	return 0
}

func writeJSONReport(summaries []packageSummary, path string) error {
	groups := make(map[string][]packageSummary)
	for _, s := range summaries {
		groups[s.codeowner] = append(groups[s.codeowner], s)
	}

	teams := make([]string, 0, len(groups))
	for t := range groups {
		teams = append(teams, t)
	}
	sort.Strings(teams)

	out := make([]teamJSON, 0, len(teams))
	for _, team := range teams {
		slug := strings.TrimPrefix(team, "@elastic/")
		pkgs := make([]packageJSON, 0, len(groups[team]))
		for _, s := range groups[team] {
			pkgs = append(pkgs, packageJSON{
				Name:    s.name,
				Files:   s.files,
				Applied: s.applied,
				Skipped: s.skipped,
			})
		}
		out = append(out, teamJSON{Slug: slug, Packages: pkgs})
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func printSummary(summaries []packageSummary, dryRun bool) {
	groups := make(map[string][]packageSummary)
	for _, s := range summaries {
		groups[s.codeowner] = append(groups[s.codeowner], s)
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
			fmt.Printf("  %s\n", s.name)
			for _, p := range s.applied {
				fmt.Printf("    [%s] %s: %s → %s\n", p.Kind, p.Package, p.Current, p.Proposed)
			}
			for _, p := range s.skipped {
				fmt.Printf("    [SKIPPED] %s (kibana constraint): %s\n", p.Package, p.Warning)
			}
		}
		fmt.Println()
	}
}
