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
	eligible := 0

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
		eligible++

		summary, err := processPackage(pkgPath, manifest.Name, dryRun)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", manifest.Name, err))
			continue
		}
		if summary != nil {
			summaries = append(summaries, *summary)
		}
	}

	printSummary(summaries, dryRun)
	printScanStats(len(paths), eligible, len(summaries), len(errs))

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

func processPackage(pkgPath, pkgName string, dryRun bool) (*packageSummary, error) {
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
	if result.NewVersion != "" {
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

// printScanStats prints a one-line scan summary distinguishing "nothing to do
// because adoption of requires: is low" from "the walk found nothing due to a
// bug" — both currently produce an empty JSON report. Also appended to
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
