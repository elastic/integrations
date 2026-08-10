// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// backport is the CLI tool for managing backport branches and changelog
// synchronization in the elastic/integrations repository.
//
// Usage:
//
//	backport <subcommand> [args]
//
// Build:
//
//	go build -o backport ./cmd/backport/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/elastic/integrations/cmd/backport/backports"
	"github.com/elastic/integrations/cmd/backport/backports/apply"
	"github.com/elastic/integrations/cmd/backport/backports/changelog"
	bpchecklist "github.com/elastic/integrations/cmd/backport/backports/checklist"
	bpowners "github.com/elastic/integrations/cmd/backport/backports/owners"
	bppackages "github.com/elastic/integrations/cmd/backport/backports/packages"
	"github.com/elastic/integrations/cmd/backport/gitutil"
)

const usageText = `backport — backport branch management tool for elastic/integrations.

Usage:
  backport <subcommand> [args]

Subcommands:
  validate-inventory
        Validate the .backports.yml schema at the repo root.

  validate-branch-name <package> <branch>
        Check that a branch name is valid for the given package.

  add-entry <package> <version>
        Add a new entry to .backports.yml for the given package and base version.

  check-active <branch> [--json]
        Report whether a backport branch is active per .backports.yml.
        Exit codes: 0 = active, 1 = inactive, 2 = error.

  detect-packages <before> <after> [--json]
        List packages changed between two commits (git diff --name-only before..after).

  check-owners <remote> <source-branch> <before> <after>
        Report package owner mismatches between the current worktree and source-branch.

  render-checklist <artifact-path>
        Print the backport-checklist comment body. Reads existing body from stdin.

  parse-checklist <body-file>
        Parse checklist items from a comment body file; print JSON array to stdout.

  update-checklist-status <body-file> <branch> <status>
        Update the status suffix for a branch line in a checklist body file.

  sync-changelog
        Collect changelog entries from a backport push and create a sync PR to main.
        Reads: BEFORE, AFTER, REPOSITORY, BACKPORT_BRANCH env vars.
        Optional: PACKAGES_DIR (default: "packages").

  post-comment
        Post a sync result comment on the originating backport PR.
        Reads: BACKPORT_PR_NUMBER, WORKING_BRANCH, REPOSITORY env vars.
        Optional: NOT_FOUND_PACKAGES, CREATE_OUTCOME, RUN_ID.

  apply [flags] <sha> <package> <target>
        Cherry-pick a commit onto a backport branch, bump the patch version,
        write a changelog entry, and optionally open a PR.
        Flags:
          --open-pr           Create a GitHub PR after pushing.
          --json              Emit structured JSON output.
          --dry-run           Commit locally but skip push and PR creation.
          --remote string     Git remote (default: origin).
          --repository string GitHub repository in org/repo form.
          --packages-dir string  Path to packages directory (default: packages).

  check-changelog-versions <base-branch>
        Verify that changelog versions introduced in the current PR do not
        already exist in origin/main.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error

	switch cmd {
	case "validate-inventory":
		err = runValidateInventory(args)
	case "validate-branch-name":
		err = runValidateBranchName(args)
	case "add-entry":
		err = runAddEntry(args)
	case "check-active":
		runCheckActive(args) // handles its own exit codes; never returns
		return
	case "detect-packages":
		err = runDetectPackages(args)
	case "check-owners":
		err = runCheckOwners(args)
	case "render-checklist":
		err = runRenderChecklist(args)
	case "parse-checklist":
		err = runParseChecklist(args)
	case "update-checklist-status":
		err = runUpdateChecklistStatus(args)
	case "sync-changelog":
		err = runSyncChangelog(args)
	case "post-comment":
		err = runPostComment(args)
	case "apply":
		err = runApply(args)
	case "check-changelog-versions":
		err = runCheckChangelogVersions(args)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "backport: unknown subcommand %q\n\n", cmd)
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// ── Inventory subcommands ────────────────────────────────────────────────────

func runValidateInventory(args []string) error {
	fs := flag.NewFlagSet("validate-inventory", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	return backports.ValidateInventory(".backports.yml", "packages")
}

func runValidateBranchName(args []string) error {
	fs := flag.NewFlagSet("validate-branch-name", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("validate-branch-name: requires <package> <branch>")
	}
	packageName := fs.Arg(0)
	branch := fs.Arg(1)
	if err := backports.ValidateBranchName(packageName, branch); err != nil {
		return err
	}
	fmt.Printf("Branch name %q is valid for package %q.\n", branch, packageName)
	return nil
}

func runAddEntry(args []string) error {
	fs := flag.NewFlagSet("add-entry", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("add-entry: requires <package> <version>")
	}
	packageName := fs.Arg(0)
	baseVersion := fs.Arg(1)

	baseCommit, err := cmdOutput("bash", "dev/scripts/get_release_commit.sh", "-p", packageName, "-v", baseVersion)
	if err != nil {
		return fmt.Errorf("resolving base commit for %s@%s: %w", packageName, baseVersion, err)
	}
	commit := strings.TrimSpace(baseCommit)

	branch, err := backports.AddEntry(".backports.yml", packageName, baseVersion, commit, "packages")
	if err != nil {
		return err
	}
	fmt.Printf("Added: branch=%s base_commit=%s\n", branch, commit)
	fmt.Printf("Tip: if you need a custom branch name, edit the 'branch' field in .backports.yml before opening the PR (must start with \"backport-%s-\").\n", packageName)
	return nil
}

// runCheckActive never returns: it always calls os.Exit.
// Exit codes: 0 = active, 1 = inactive, 2 = error.
func runCheckActive(args []string) {
	fs := flag.NewFlagSet("check-active", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "check-active: requires <branch>")
		os.Exit(2)
	}
	branch := fs.Arg(0)

	result, err := backports.CheckActive(".backports.yml", branch, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	if *asJSON {
		data, _ := json.Marshal(result)
		fmt.Println(string(data))
	} else {
		if result.Active {
			fmt.Printf("%s: active\n", branch)
		} else {
			reason := "archived"
			if !result.Archived && result.MaintainedUntil != nil {
				reason = fmt.Sprintf("maintained_until=%s is past", *result.MaintainedUntil)
			}
			fmt.Printf("%s: inactive (%s)\n", branch, reason)
		}
	}

	if !result.Active {
		os.Exit(1)
	}
	os.Exit(0)
}

// ── Packages subcommands ─────────────────────────────────────────────────────

// diffPackages runs git diff --name-only before..after and maps changed files
// to package names. Shared between detect-packages and check-owners.
func diffPackages(before, after string) ([]string, error) {
	out, err := cmdOutput("git", "diff", "--name-only", before+".."+after)
	if err != nil {
		return nil, fmt.Errorf("running git diff: %w", err)
	}
	var files []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			files = append(files, line)
		}
	}
	return bppackages.DetectPackages(files, "packages")
}

func runDetectPackages(args []string) error {
	fs := flag.NewFlagSet("detect-packages", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output as JSON array")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("detect-packages: requires <before> <after>")
	}
	before := fs.Arg(0)
	after := fs.Arg(1)

	pkgs, err := diffPackages(before, after)
	if err != nil {
		return err
	}

	if *asJSON {
		data, err := json.Marshal(pkgs)
		if err != nil {
			return fmt.Errorf("marshalling packages: %w", err)
		}
		fmt.Println(string(data))
	} else {
		for _, p := range pkgs {
			fmt.Println(p)
		}
	}
	return nil
}

func runCheckOwners(args []string) error {
	fs := flag.NewFlagSet("check-owners", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 4 {
		return fmt.Errorf("check-owners: requires <remote> <source-branch> <before> <after>")
	}
	remote := fs.Arg(0)
	sourceBranch := fs.Arg(1)
	before := fs.Arg(2)
	after := fs.Arg(3)

	if err := cmdRun("git", "fetch", remote, sourceBranch); err != nil {
		return fmt.Errorf("fetching %s: %w", sourceBranch, err)
	}
	remoteRef := remote + "/" + sourceBranch

	pkgs, err := diffPackages(before, after)
	if err != nil {
		return fmt.Errorf("detecting packages: %w", err)
	}

	pkgIndex, err := changelog.BuildPackageIndex("packages")
	if err != nil {
		return fmt.Errorf("building package index: %w", err)
	}

	mismatches := bpowners.CheckPackages(gitutil.Git{}, "", remoteRef, pkgs, pkgIndex)

	type mismatchJSON struct {
		Package string   `json:"package"`
		Teams   []string `json:"teams,omitempty"`
		Error   string   `json:"error,omitempty"`
	}
	results := make([]mismatchJSON, 0, len(mismatches))
	for _, m := range mismatches {
		entry := mismatchJSON{Package: m.Package, Teams: m.Teams}
		if m.Err != nil {
			entry.Error = m.Err.Error()
		}
		results = append(results, entry)
	}

	data, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("marshalling results: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// ── Checklist subcommands ────────────────────────────────────────────────────

func runRenderChecklist(args []string) error {
	fs := flag.NewFlagSet("render-checklist", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("render-checklist: requires <artifact-path>")
	}
	artifactPath := fs.Arg(0)

	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("reading artifact: %w", err)
	}

	var artifact struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		return fmt.Errorf("parsing artifact: %w", err)
	}

	existingBody, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	checked := bpchecklist.ParseCheckedBranches(string(existingBody))

	skipPkgs, err := backports.ListSkipChecklistPackages(".backports.yml")
	if err != nil {
		return fmt.Errorf("loading skip checklist packages: %w", err)
	}
	skipSet := make(map[string]struct{}, len(skipPkgs))
	for _, p := range skipPkgs {
		skipSet[p] = struct{}{}
	}

	checklistPkgs := make([]string, 0, len(artifact.Packages))
	for _, pkg := range artifact.Packages {
		if _, skip := skipSet[pkg]; !skip {
			checklistPkgs = append(checklistPkgs, pkg)
		}
	}

	branchesByPkg, err := backports.ListAllActiveBackportBranches(".backports.yml", checklistPkgs, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("listing active backport branches: %w", err)
	}

	pkgs := make([]bpchecklist.PackageBranches, 0, len(checklistPkgs))
	for _, pkg := range checklistPkgs {
		pkgs = append(pkgs, bpchecklist.PackageBranches{
			Package:  pkg,
			Branches: branchesByPkg[pkg],
		})
	}

	body := bpchecklist.BuildComment(pkgs, checked)
	if body != "" {
		fmt.Print(body)
	}
	return nil
}

func runParseChecklist(args []string) error {
	fs := flag.NewFlagSet("parse-checklist", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("parse-checklist: requires <body-file>")
	}
	bodyFile := fs.Arg(0)

	data, err := os.ReadFile(bodyFile)
	if err != nil {
		return fmt.Errorf("reading body file: %w", err)
	}
	items := bpchecklist.ParseChecklistItems(string(data))
	out, err := json.Marshal(items)
	if err != nil {
		return fmt.Errorf("marshalling checklist items: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

func runUpdateChecklistStatus(args []string) error {
	fs := flag.NewFlagSet("update-checklist-status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 3 {
		return fmt.Errorf("update-checklist-status: requires <body-file> <branch> <status>")
	}
	bodyFile := fs.Arg(0)
	branch := fs.Arg(1)
	status := fs.Arg(2)

	data, err := os.ReadFile(bodyFile)
	if err != nil {
		return fmt.Errorf("reading body file: %w", err)
	}
	fmt.Print(bpchecklist.UpdateBranchStatus(string(data), branch, status))
	return nil
}

// ── Changelog subcommands ────────────────────────────────────────────────────

func runSyncChangelog(_ []string) error {
	before := os.Getenv("BEFORE")
	after := os.Getenv("AFTER")
	repository := os.Getenv("REPOSITORY")
	backportBranch := os.Getenv("BACKPORT_BRANCH")
	if before == "" || after == "" || repository == "" || backportBranch == "" {
		return fmt.Errorf("BEFORE, AFTER, REPOSITORY, and BACKPORT_BRANCH must be set")
	}
	packagesDir := os.Getenv("PACKAGES_DIR")
	if packagesDir == "" {
		packagesDir = "packages"
	}

	collectResult, err := changelog.Collect(before, after, repository)
	if err != nil {
		return err
	}

	if !collectResult.HasChanges {
		return writeGitHubOutputs(map[string]string{
			"backport_pr_number": collectResult.BackportPRNumber,
			"working_branch":     collectResult.WorkingBranch,
			"not_found_packages": "",
			"create_outcome":     "skipped",
		})
	}

	syncResult, err := changelog.CreateSyncPR(
		"",
		collectResult.EntriesTSV,
		collectResult.WorkingBranch,
		collectResult.BackportPRNumber,
		backportBranch,
		packagesDir,
		repository,
	)
	if err != nil {
		return err
	}
	return writeGitHubOutputs(map[string]string{
		"backport_pr_number": collectResult.BackportPRNumber,
		"working_branch":     collectResult.WorkingBranch,
		"not_found_packages": strings.Join(syncResult.NotFoundPackages, ","),
		"create_outcome":     syncResult.Outcome,
	})
}

func runPostComment(_ []string) error {
	backportPRNumber := os.Getenv("BACKPORT_PR_NUMBER")
	workingBranch := os.Getenv("WORKING_BRANCH")
	repository := os.Getenv("REPOSITORY")
	if repository == "" {
		return fmt.Errorf("REPOSITORY must be set")
	}
	return changelog.PostComment(
		backportPRNumber,
		workingBranch,
		os.Getenv("NOT_FOUND_PACKAGES"),
		os.Getenv("CREATE_OUTCOME"),
		os.Getenv("RUN_ID"),
		repository,
	)
}

func runCheckChangelogVersions(args []string) error {
	fs := flag.NewFlagSet("check-changelog-versions", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("check-changelog-versions: requires <base-branch>")
	}
	baseBranch := fs.Arg(0)
	before := "origin/" + baseBranch

	git := gitutil.Git{}
	conflicts, err := changelog.CheckVersionsAgainstMain(git, before, "HEAD")
	if err != nil {
		return err
	}
	if len(conflicts) > 0 {
		fmt.Fprintln(os.Stderr, "ERROR: the following changelog versions are already present in main:")
		for _, c := range conflicts {
			fmt.Fprintf(os.Stderr, "  - %s\n", c)
		}
		return fmt.Errorf("found %d changelog version(s) already in main", len(conflicts))
	}
	fmt.Println("All changelog versions are new — no conflicts with main.")
	return nil
}

// ── Apply subcommand ─────────────────────────────────────────────────────────

func runApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	openPR := fs.Bool("open-pr", false, "create a GitHub PR after pushing the working branch")
	asJSON := fs.Bool("json", false, "emit JSON output (success/conflict schema)")
	dryRun := fs.Bool("dry-run", false, "commit locally but skip push and PR creation")
	remote := fs.String("remote", "", "git remote to fetch from and push to (default: origin)")
	repository := fs.String("repository", "", "GitHub repository in org/repo form")
	packagesDir := fs.String("packages-dir", "", "path to packages directory (default: packages)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 3 {
		return fmt.Errorf("apply: requires <sha> <package> <target>")
	}
	sha := fs.Arg(0)
	pkg := fs.Arg(1)
	target := fs.Arg(2)

	opts := apply.Options{
		SHA:         sha,
		Package:     pkg,
		Target:      target,
		OpenPR:      *openPR,
		AsJSON:      *asJSON,
		DryRun:      *dryRun,
		Remote:      *remote,
		Repository:  *repository,
		PackagesDir: *packagesDir,
	}

	result, err := apply.Apply(opts)
	if err != nil {
		return err
	}

	if opts.AsJSON {
		data, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("marshalling result: %w", err)
		}
		fmt.Println(string(data))
		if result.Status == "conflict" {
			return fmt.Errorf("cherry-pick conflict on %s", strings.Join(result.ConflictingFiles, ", "))
		}
	} else if result.Status == "conflict" {
		fmt.Fprintf(os.Stderr, "conflict: cherry-pick of %s onto %s failed\n", result.SHA, result.TargetBranch)
		fmt.Fprintln(os.Stderr, "conflicting files:")
		for _, f := range result.ConflictingFiles {
			fmt.Fprintf(os.Stderr, "  %s\n", f)
		}
		fmt.Fprintf(os.Stderr, "suggested command: %s\n", result.SuggestedCommand)
		return fmt.Errorf("cherry-pick conflict on %s", strings.Join(result.ConflictingFiles, ", "))
	} else if result.WorkingBranch != "" {
		fmt.Printf("dry run: branch %q created locally with version %s — review with: git checkout %s\n",
			result.WorkingBranch, result.NewVersion, result.WorkingBranch)
	} else {
		fmt.Printf("backport success: %s %s", result.TargetBranch, result.NewVersion)
		if result.PRURL != "" {
			fmt.Printf(", PR: %s", result.PRURL)
		}
		fmt.Println()
	}
	return nil
}

// ── Utilities ────────────────────────────────────────────────────────────────

// cmdOutput runs a command and returns its combined stdout as a string.
func cmdOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// cmdRun runs a command, forwarding stdout and stderr to the terminal.
func cmdRun(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// writeGitHubOutputs appends key=value pairs to the file named by $GITHUB_OUTPUT.
// When GITHUB_OUTPUT is unset (local runs), it prints to stdout instead.
func writeGitHubOutputs(outputs map[string]string) error {
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile == "" {
		for k, v := range outputs {
			fmt.Printf("%s=%s\n", k, v)
		}
		return nil
	}
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("opening GITHUB_OUTPUT: %w", err)
	}
	defer f.Close()
	for k, v := range outputs {
		if _, err := fmt.Fprintf(f, "%s=%s\n", k, v); err != nil {
			return err
		}
	}
	return nil
}
