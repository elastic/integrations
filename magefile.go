// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"

	"github.com/elastic/integrations/dev/backports"
	"github.com/elastic/integrations/dev/backports/apply"
	"github.com/elastic/integrations/dev/backports/changelog"
	bpchecklist "github.com/elastic/integrations/dev/backports/checklist"
	bpowners "github.com/elastic/integrations/dev/backports/owners"
	bppackages "github.com/elastic/integrations/dev/backports/packages"
	"github.com/elastic/integrations/dev/citools"
	"github.com/elastic/integrations/dev/codeowners"
	"github.com/elastic/integrations/dev/coverage"
	"github.com/elastic/integrations/dev/gitutil"
	"github.com/elastic/integrations/dev/packagenames"
	"github.com/elastic/integrations/dev/requiresupdate"
	"github.com/elastic/integrations/dev/testsreporter"
)

const (
	defaultResultsPath           = "build/test-results/"
	defaultPreviousLinksNumber   = 5
	defaultMaximumTestsReported  = 20
	defaultServerlessProjectType = "observability"

	elasticPackageModulePath = "github.com/elastic/elastic-package"
)

var (
	// GoImportsLocalPrefix is a string prefix matching imports that should be
	// grouped after third-party packages.
	GoImportsLocalPrefix = "github.com/elastic"

	buildDir = "./build"
)

func Check() error {
	mg.Deps(build)
	mg.Deps(format)
	mg.Deps(ModTidy)
	mg.Deps(goTest)
	mg.Deps(codeowners.Check)
	mg.Deps(packagenames.Check)
	return nil
}

func Clean() error {
	return os.RemoveAll(buildDir)
}

func ImportBeats() error {
	args := []string{"run", "./dev/import-beats/"}
	if os.Getenv("SKIP_KIBANA") == "true" {
		args = append(args, "-skipKibana")
	}
	if os.Getenv("PACKAGES") != "" {
		args = append(args, "-packages", os.Getenv("PACKAGES"))
	}
	args = append(args, "*.go")
	return sh.Run("go", args...)
}

func MergeCoverage() error {
	coverageFiles, err := filepath.Glob("build/test-coverage/coverage-*.xml")
	if err != nil {
		return fmt.Errorf("glob failed: %w", err)
	}
	return coverage.MergeGenericCoverageFiles(coverageFiles, "build/test-coverage/coverage_merged.xml")
}

func build() error {
	mg.Deps(buildImportBeats)
	return nil
}

func buildImportBeats() error {
	err := sh.Run("go", "build", "-o", "/dev/null", "./dev/import-beats")
	if err != nil {
		return errors.Wrap(err, "building import-beats failed")
	}
	return nil
}

func format() {
	mg.Deps(addLicenseHeaders)
	mg.Deps(goImports)
}

func addLicenseHeaders() error {
	return sh.RunV("go", "run", "github.com/elastic/go-licenser", "-license", "Elastic")
}

func goImports() error {
	goFiles, err := findFilesRecursive(func(path string, _ os.FileInfo) bool {
		return filepath.Ext(path) == ".go"
	})
	if err != nil {
		return err
	}
	if len(goFiles) == 0 {
		return nil
	}

	args := append(
		[]string{"run", "golang.org/x/tools/cmd/goimports", "-local", GoImportsLocalPrefix, "-l", "-w"},
		goFiles...,
	)
	return sh.RunV("go", args...)
}

func goTest() error {
	args := []string{"run", "gotest.tools/gotestsum", "--format", "testname", "--junitfile", "tests-report.xml"}
	stdout := io.Discard
	stderr := io.Discard
	if mg.Verbose() {
		stdout = os.Stdout
		stderr = os.Stderr
	}
	args = append(args, "./dev/...")
	_, err := sh.Exec(nil, stdout, stderr, "go", args...)
	return err
}

func findFilesRecursive(match func(path string, info os.FileInfo) bool) ([]string, error) {
	var matches []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			// continue
			return nil
		}

		if match(filepath.ToSlash(path), info) {
			matches = append(matches, path)
		}
		return nil
	})
	return matches, err
}

func ModTidy() error {
	return sh.RunV("go", "mod", "tidy")
}

func ReportFailedTests(ctx context.Context, testResultsFolder string) error {
	stackVersion := os.Getenv("STACK_VERSION")
	serverlessEnv := os.Getenv("SERVERLESS")
	dryRunEnv := os.Getenv("DRY_RUN")
	serverlessProjectEnv := os.Getenv("SERVERLESS_PROJECT")
	buildURL := os.Getenv("BUILDKITE_BUILD_URL")
	subscription := os.Getenv("ELASTIC_SUBSCRIPTION")

	serverless := false
	if serverlessEnv != "" {
		var err error
		serverless, err = strconv.ParseBool(serverlessEnv)
		if err != nil {
			return fmt.Errorf("failed to parse SERVERLESS value: %w", err)
		}
		if serverlessProjectEnv == "" {
			serverlessProjectEnv = defaultServerlessProjectType
		}
	}

	logsDBEnabled := false
	if v, found := os.LookupEnv("STACK_LOGSDB_ENABLED"); found && v == "true" {
		logsDBEnabled = true
	}

	verboseMode := false
	if v, found := os.LookupEnv("VERBOSE_MODE_ENABLED"); found && v == "true" {
		verboseMode = true
	}

	maxIssuesString := os.Getenv("CI_MAX_TESTS_REPORTED")
	maxIssues := defaultMaximumTestsReported
	if maxIssuesString != "" {
		var err error
		maxIssues, err = strconv.Atoi(maxIssuesString)
		if err != nil {
			return fmt.Errorf("failed to convert env. variable CI_MAX_TESTS_REPORTED to int (%s): %w", maxIssuesString, err)
		}
	}

	dryRun := false
	if dryRunEnv != "" {
		var err error
		dryRun, err = strconv.ParseBool(dryRunEnv)
		if err != nil {
			return fmt.Errorf("failed to parse DRY_RUN value: %w", err)
		}
	}

	options := testsreporter.CheckOptions{
		Serverless:        serverless,
		ServerlessProject: serverlessProjectEnv,
		LogsDB:            logsDBEnabled,
		StackVersion:      stackVersion,
		Subscription:      subscription,
		BuildURL:          buildURL,
		MaxPreviousLinks:  defaultPreviousLinksNumber,
		MaxTestsReported:  maxIssues,
		DryRun:            dryRun,
		Verbose:           verboseMode,
	}
	return testsreporter.Check(ctx, testResultsFolder, options)
}

// ValidateBackportsInventory validates the schema of .backports.yml at the repo root.
func ValidateBackportsInventory() error {
	return backports.ValidateInventory(".backports.yml", "packages")
}

// ValidateBackportBranchName checks that the given branch name is valid for the given package.
// The branch must match backport-<package>-<suffix> and start with "backport-<packageName>-".
func ValidateBackportBranchName(packageName, branch string) error {
	if err := backports.ValidateBranchName(packageName, branch); err != nil {
		return err
	}
	fmt.Printf("Branch name %q is valid for package %q.\n", branch, packageName)
	return nil
}

// ListPackages lists all packages found under the packages directory.
func ListPackages() error {
	const packagesDir = "packages"
	packages, err := citools.ListPackages(packagesDir)
	if err != nil {
		return fmt.Errorf("failed to list packages: %w", err)
	}
	for _, p := range packages {
		fmt.Println(p)
	}
	return nil
}

// IsSubscriptionCompatible checks whether or not the package in the current directory allows to run with the given subscription (ELASTIC_SUBSCRIPTION env var).
func IsSubscriptionCompatible() error {
	subscription := os.Getenv("ELASTIC_SUBSCRIPTION")
	if subscription == "" {
		fmt.Println("true")
		return nil
	}

	supported, err := citools.IsSubscriptionCompatible(subscription, "manifest.yml")
	if err != nil {
		return err
	}
	if supported {
		fmt.Println("true")
		return nil
	}
	fmt.Println("false")
	return nil
}

// KibanaConstraintPackage returns the Kibana version constraint defined in the package manifest
func KibanaConstraintPackage() error {
	constraint, err := citools.KibanaConstraintPackage("manifest.yml")
	if err != nil {
		return fmt.Errorf("failed to get Kibana constraint: %w", err)
	}
	if constraint == nil {
		fmt.Println("null")
		return nil
	}
	fmt.Println(constraint)
	return nil
}

// IsSupportedStack checks whether or not the package in the current directory is allowed to be installed in the given stack version
func IsSupportedStack(stackVersion string) error {
	if stackVersion == "" {
		fmt.Println("true")
		return nil
	}

	supported, err := citools.IsPackageSupportedInStackVersion(stackVersion, "manifest.yml")
	if err != nil {
		return err
	}

	if supported {
		fmt.Println("true")
		return nil
	}
	fmt.Println("false")
	return nil
}

// IsLogsDBSupportedInPackage checks whether or not the package in the current directory supports LogsDB
func IsLogsDBSupportedInPackage() error {
	supported, err := citools.IsLogsDBSupportedInPackage("manifest.yml")
	if err != nil {
		return err
	}
	if !supported {
		fmt.Println("false")
		return nil
	}
	fmt.Println("true")
	return nil
}

// IsVersionLessThanLogsDBGA checks whether or not the given version supports LogsDB. Minimum version that supports LogsDB as GA 8.17.0.
func IsVersionLessThanLogsDBGA(version string) error {
	stackVersion, err := semver.NewVersion(version)
	if err != nil {
		return fmt.Errorf("failed to parse version %q: %w", version, err)
	}
	lessThan := citools.IsVersionLessThanLogsDBGA(stackVersion)
	if lessThan {
		fmt.Println("true")
		return nil
	}
	fmt.Println("false")
	return nil
}

// AddBackportEntry adds a new entry to .backports.yml for the given package and
// base version. The branch name is derived as backport-<package>-<major>.<minor>,
// archived is set to false, and maintained_until to null. The base commit is
// resolved via dev/scripts/get_release_commit.sh. The entry is inserted in
// sorted order (by package name ascending, then by version descending — newest first).
func AddBackportEntry(packageName, baseVersion string) error {
	baseCommit, err := sh.Output("bash", "dev/scripts/get_release_commit.sh", "-p", packageName, "-v", baseVersion)
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

// CheckBackportBranchActive reports whether a backport branch is active per .backports.yml.
// Prints "<branch>: active" or "<branch>: inactive (<reason>)".
// Pass -json for JSON output: mage CheckBackportBranchActive <branch> -json
// Exit codes: 0 = active, 1 = inactive, 2 = error (branch not found, parse error, etc.).
func CheckBackportBranchActive(branch string, asJSON *bool) error {
	result, err := backports.CheckActive(".backports.yml", branch, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	if asJSON != nil && *asJSON {
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
	return nil
}

// diffPackages runs git diff --name-only before..after and maps the changed
// files to package names. Shared by DetectBackportPackages and
// CheckBackportOwners so the diff-to-package logic lives in one place.
func diffPackages(before, after string) ([]string, error) {
	out, err := sh.Output("git", "diff", "--name-only", before+".."+after)
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

// DetectBackportPackages lists the packages touched by commits between before and after.
// Runs git diff --name-only before..after and maps the changed files to package names
// using the packages/ directory as the root.
// Plain output: one package name per line. Pass -asJSON for a JSON array.
func DetectBackportPackages(before, after string, asJSON *bool) error {
	pkgs, err := diffPackages(before, after)
	if err != nil {
		return err
	}

	if asJSON != nil && *asJSON {
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

// CheckBackportOwners reports package owner mismatches between the current
// worktree and remote/sourceBranch (the ownership source of truth, normally
// "main"), for every package changed between before and after — before..after,
// following DetectBackportPackages's convention: before is normally the PR's
// merge-base with sourceBranch, after is the PR's own commit.
// Prints a JSON array to stdout; see check_backport_owners.sh's
// build_owner_check_comment for the exact shape it expects. A package fully
// in sync, or no longer present on sourceBranch, is omitted entirely.
func CheckBackportOwners(remote, sourceBranch, before, after string) error {
	if err := sh.Run("git", "fetch", remote, sourceBranch); err != nil {
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

// RenderBackportChecklist prints the backport-checklist comment body for a PR.
// It reads the list of packages from artifactPath (a JSON file with shape
// {"pr_number": N, "packages": [...]}) and the existing comment body (if any) from
// stdin. Active branches for each package are looked up in .backports.yml using the
// current UTC time. Previously checked boxes are preserved: any branch that appeared
// as "- [x] `branch`" in the existing body is rendered ticked in the new body.
// Prints nothing when no package has any active branch; callers should skip posting.
func RenderBackportChecklist(artifactPath string) error {
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

	branchesByPkg, err := backports.ListAllActiveBackportBranches(".backports.yml", artifact.Packages, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("listing active backport branches: %w", err)
	}

	pkgs := make([]bpchecklist.PackageBranches, 0, len(artifact.Packages))
	for _, pkg := range artifact.Packages {
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

// IsElasticPackageDependencyLessThan checks whether or not the elastic-package version set in go.mod is less than the given version
func IsElasticPackageDependencyLessThan(version string) error {
	foundVersion, err := citools.PackageVersionGoMod("go.mod", elasticPackageModulePath)
	if err != nil {
		return fmt.Errorf("failed to get elastic-package version from go.mod: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Found elastic-package %s\n", foundVersion)

	desiredVersion, err := semver.NewVersion(version)
	if err != nil {
		return fmt.Errorf("failed to parse version %q: %w", version, err)
	}

	value := "false"
	if foundVersion.LessThan(desiredVersion) {
		value = "true"
	}

	fmt.Println(value)
	return nil
}

// SyncBackportChangelog collects changelog entries introduced by a backport push
// and creates a sync PR targeting main. Outputs are written to $GITHUB_OUTPUT for
// use by the PostBackportComment step.
//
// Required env vars: BEFORE, AFTER, REPOSITORY, BACKPORT_BRANCH.
// Optional env vars: PACKAGES_DIR (defaults to "packages").
func SyncBackportChangelog() error {
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

// PostBackportComment posts a result comment on the originating backport PR.
//
// Required env vars: BACKPORT_PR_NUMBER, WORKING_BRANCH, REPOSITORY.
// Optional env vars: NOT_FOUND_PACKAGES, CREATE_OUTCOME, RUN_ID.
func PostBackportComment() error {
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

// ApplyBackport cherry-picks a fix commit onto a backport branch, bumps the patch
// version, writes a correct changelog entry, and optionally opens a PR.
//
// Usage: mage ApplyBackport <sha> <package> <target> [-openPR] [-asJSON] [-dryRun] \
//
//	[repository] [packagesDir]
//
// sha, pkg, target are required. All remaining parameters are optional (nil = unset).
// *bool flags may be passed as -openPR / -asJSON / -dryRun on the command line.
func ApplyBackport(sha, pkg, target string, openPR, asJSON, dryRun *bool, remote, repository, packagesDir *string) error {
	opts := apply.Options{
		SHA:         sha,
		Package:     pkg,
		Target:      target,
		OpenPR:      openPR != nil && *openPR,
		AsJSON:      asJSON != nil && *asJSON,
		DryRun:      dryRun != nil && *dryRun,
		Remote:      deref(remote),
		Repository:  deref(repository),
		PackagesDir: deref(packagesDir),
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
		fmt.Fprintf(os.Stderr, "conflicting files:\n")
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

// deref returns the string pointed to by s, or "" if s is nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// writeGitHubOutputs appends key=value pairs to the file named by $GITHUB_OUTPUT.
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

// RequiresUpdate updates required package versions for all integration packages,
// adds a changelog entry per modified package, and opens one PR (or issue) per
// package.
//
// Usage: mage RequiresUpdate [-dryRun] [-preview]
//
// Pass -dryRun to preview proposals without applying changes (also skips
// publishing, since no files would be written); pass -preview to print what
// would be published without touching git or GitHub.
func RequiresUpdate(dryRun, preview *bool) error {
	return requiresupdate.Run(dryRun != nil && *dryRun, preview != nil && *preview)
}
