// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apply

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/cli/go-gh/v2"
	"gopkg.in/yaml.v3"

	"github.com/elastic/integrations/dev/backports"
	"github.com/elastic/integrations/dev/backports/changelog"
	"github.com/elastic/integrations/dev/backports/gitutil"
)

// Options controls the behaviour of Apply.
type Options struct {
	SHA         string // commit to cherry-pick (required)
	Package     string // package name as in manifest.yml (required)
	Target      string // "6.14", "6.x", or full "backport-aws-6.14" (required)
	OpenPR      bool   // create a GitHub PR when true
	Description string // overrides description extracted from cherry-pick diff
	Type        string // overrides type extracted from cherry-pick diff
	Link        string // overrides placeholder link (original PR URL) extracted from cherry-pick diff
	AsJSON      bool   // emit JSON output instead of human-readable text
	PackagesDir string // path to packages dir; default "packages"
	Repository  string // "org/repo" e.g. "elastic/integrations"
}

// Result is the structured output of Apply.
type Result struct {
	Status           string   `json:"status"` // "success" or "conflict"
	SHA              string   `json:"sha"`
	TargetBranch     string   `json:"target_branch"`
	NewVersion       string   `json:"new_version,omitempty"`
	PRURL            string   `json:"pr_url,omitempty"`
	ConflictingFiles []string `json:"conflicting_files,omitempty"`
	SuggestedCommand string   `json:"suggested_command,omitempty"`
}

// branchRE matches valid backport branch names (mirrors dev/backports/inventory.go).
var branchRE = regexp.MustCompile(`^backport-[a-zA-Z0-9_]+-[0-9][0-9.]*x?$`)

// Apply cherry-picks SHA onto the resolved backport branch, bumps the package's
// patch version, writes a new changelog entry, and optionally opens a GitHub PR.
// It uses the current working directory as the repository root.
func Apply(opts Options) (*Result, error) {
	if opts.SHA == "" || opts.Package == "" || opts.Target == "" {
		return nil, fmt.Errorf("SHA, Package, and Target are all required")
	}
	if len(opts.SHA) < 8 {
		return nil, fmt.Errorf("SHA must be at least 8 characters, got %q", opts.SHA)
	}

	packagesDir := opts.PackagesDir
	if packagesDir == "" {
		packagesDir = "packages"
	}
	sha8 := opts.SHA[:8]

	pkgDir, err := resolvePackage(packagesDir, opts.Package)
	if err != nil {
		return nil, err
	}

	branchName, err := ResolveBranchName(opts.Target, opts.Package)
	if err != nil {
		return nil, err
	}
	if err := checkBranchReady(branchName, opts.AsJSON); err != nil {
		return nil, err
	}

	workingBranch := workingBranchName(opts.Package, branchName, sha8)
	if err := prepareWorkingBranch(branchName, workingBranch); err != nil {
		return nil, err
	}

	// Clean up the working branch if any subsequent step fails, so that a retry
	// with the same SHA does not fail with "branch already exists".
	success := false
	defer func() {
		if !success {
			_ = gitutil.Run("checkout", "-")
			_ = gitutil.Run("branch", "-D", workingBranch)
		}
	}()

	if conflict := cherryPickOrConflict(opts.SHA, branchName, workingBranch, opts.Package); conflict != nil {
		return conflict, nil
	}

	changelogPath := filepath.Join(pkgDir, "changelog.yml")
	manifestPath := filepath.Join(pkgDir, "manifest.yml")

	description, changeType, link, err := extractChangelogFields(changelogPath, opts)
	if err != nil {
		return nil, err
	}

	newVersion, err := resetAndWriteChanges(manifestPath, changelogPath, description, changeType, link)
	if err != nil {
		return nil, err
	}

	if err := commitAndPush(pkgDir, opts.Package, sha8, description, newVersion); err != nil {
		return nil, err
	}

	prURL, err := maybeOpenPR(opts.OpenPR, workingBranch, branchName, opts.Package, description, newVersion, opts.SHA, opts.Repository)
	if err != nil {
		return nil, err
	}

	success = true
	return &Result{
		Status:       "success",
		SHA:          opts.SHA,
		TargetBranch: branchName,
		NewVersion:   newVersion,
		PRURL:        prURL,
	}, nil
}

// resolvePackage looks up the package directory for the given package name.
func resolvePackage(packagesDir, pkg string) (string, error) {
	pkgIndex, err := changelog.BuildPackageIndex(packagesDir)
	if err != nil {
		return "", fmt.Errorf("building package index: %w", err)
	}
	dir, ok := pkgIndex[pkg]
	if !ok {
		return "", fmt.Errorf("package %q not found under %s", pkg, packagesDir)
	}
	return dir, nil
}

// checkBranchReady verifies the branch is in .backports.yml.
// An inactive branch is a warning in human mode and an error in JSON mode.
func checkBranchReady(branchName string, asJSON bool) error {
	result, err := backports.CheckActive(".backports.yml", branchName, time.Now().UTC())
	if err != nil {
		return fmt.Errorf(
			"branch %q not found in .backports.yml — add an entry and open a PR to have it created first: %w",
			branchName, err,
		)
	}
	if !result.Active {
		msg := fmt.Sprintf("branch %q is inactive (archived or past maintained_until)", branchName)
		if asJSON {
			return fmt.Errorf("%s", msg)
		}
		fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
	}
	return nil
}

// workingBranchName derives the local working branch name for this backport.
func workingBranchName(pkg, branchName, sha8 string) string {
	versionSuffix := strings.TrimPrefix(branchName, "backport-"+pkg+"-")
	return fmt.Sprintf("auto-backport/%s-%s-%s", pkg, versionSuffix, sha8)
}

// prepareWorkingBranch fetches the backport branch and creates a local working branch off it.
func prepareWorkingBranch(branchName, workingBranch string) error {
	if err := gitutil.Run("fetch", "origin", branchName); err != nil {
		return fmt.Errorf(
			"fetching %q from remote failed — verify that the .backports.yml PR was merged and the creation pipeline succeeded: %w",
			branchName, err,
		)
	}
	if err := gitutil.Run("checkout", "-b", workingBranch, "origin/"+branchName); err != nil {
		return fmt.Errorf("creating working branch %s: %w", workingBranch, err)
	}
	return nil
}

// cherryPickOrConflict attempts the cherry-pick. On conflict it cleans up and
// returns a populated conflict Result; on success it returns nil.
func cherryPickOrConflict(sha, branchName, workingBranch, pkg string) *Result {
	if err := gitutil.Run("cherry-pick", "-n", sha); err == nil {
		return nil
	}
	files, _ := conflictingFiles()
	// reset --hard instead of cherry-pick --abort: with -n, git does not always
	// write CHERRY_PICK_HEAD, so --abort may fail and leave the index dirty.
	_ = gitutil.Run("reset", "--hard", "HEAD")
	_ = gitutil.Run("checkout", "-")
	_ = gitutil.Run("branch", "-D", workingBranch)
	return &Result{
		Status:           "conflict",
		SHA:              sha,
		TargetBranch:     branchName,
		ConflictingFiles: files,
		SuggestedCommand: fmt.Sprintf(
			"dev/scripts/backport_apply.sh --sha %s --package %s --target %s --open-pr",
			sha, pkg, branchName,
		),
	}
}

// extractChangelogFields reads the staged diff of changelogPath, extracts the
// description / type / link from the cherry-picked entry, and applies any
// overrides from opts.
func extractChangelogFields(changelogPath string, opts Options) (description, changeType, link string, err error) {
	diff, err := gitutil.Output("diff", "--cached", "--", changelogPath)
	if err != nil {
		return "", "", "", fmt.Errorf("reading staged changelog diff: %w", err)
	}
	_, entryBlock, err := changelog.ExtractFromDiff(diff)
	if err != nil {
		return "", "", "", fmt.Errorf("extracting changelog entry from diff: %w", err)
	}
	description, changeType, link = ParseEntryFields(entryBlock)
	if opts.Description != "" {
		description = opts.Description
	}
	if opts.Type != "" {
		changeType = opts.Type
	}
	if opts.Link != "" {
		link = opts.Link
	}
	if description == "" || changeType == "" {
		return "", "", "", fmt.Errorf(
			"could not extract description/type from cherry-pick diff; use --description and --type to provide them explicitly",
		)
	}
	return description, changeType, link, nil
}

// resetAndWriteChanges resets changelog.yml and manifest.yml to the backport-branch
// state (discarding the cherry-picked version bump and entry), bumps the patch
// version, and inserts a fresh changelog entry. Returns the new version string.
func resetAndWriteChanges(manifestPath, changelogPath, description, changeType, link string) (string, error) {
	if err := gitutil.Run("checkout", "HEAD", "--", changelogPath, manifestPath); err != nil {
		return "", fmt.Errorf("resetting changelog and manifest: %w", err)
	}
	newVersion, err := BumpPatchVersion(manifestPath)
	if err != nil {
		return "", fmt.Errorf("bumping version in %s: %w", manifestPath, err)
	}
	if err := changelog.InsertEntry(changelogPath, newVersion, BuildEntryBlock(newVersion, description, changeType, link)); err != nil {
		return "", fmt.Errorf("inserting changelog entry: %w", err)
	}
	return newVersion, nil
}

// commitAndPush stages all package changes, commits, and pushes the working branch.
func commitAndPush(pkgDir, pkg, sha8, description, newVersion string) error {
	commitMsg := fmt.Sprintf("[%s] Backport %s: %s (%s)", pkg, sha8, description, newVersion)
	if err := gitutil.Run("add", pkgDir); err != nil {
		return fmt.Errorf("staging changes: %w", err)
	}
	if err := gitutil.Run("commit", "-m", commitMsg); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	if err := gitutil.Run("push", "origin", "HEAD"); err != nil {
		return fmt.Errorf("pushing: %w", err)
	}
	return nil
}

// maybeOpenPR creates a GitHub PR if openPR is true, returning the PR URL.
func maybeOpenPR(openPR bool, workingBranch, branchName, pkg, description, newVersion, sha, repository string) (string, error) {
	if !openPR {
		return "", nil
	}
	title := fmt.Sprintf("[%s] Backport %s (%s)", pkg, description, newVersion)
	body := fmt.Sprintf("Automated backport of commit `%s` onto `%s`.", sha, branchName)
	if repository != "" {
		body += fmt.Sprintf("\n\nOriginal commit: https://github.com/%s/commit/%s", repository, sha)
	}
	stdout, _, err := gh.Exec("pr", "create",
		"--base", branchName,
		"--head", workingBranch,
		"--title", title,
		"--body", body,
	)
	if err != nil {
		return "", fmt.Errorf("creating PR: %w", err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// ResolveBranchName derives the full backport branch name from target.
// If target already matches the branch pattern it is returned as-is.
// Otherwise "backport-<packageName>-<target>" is constructed and validated.
func ResolveBranchName(target, packageName string) (string, error) {
	if branchRE.MatchString(target) {
		return target, nil
	}
	branch := "backport-" + packageName + "-" + target
	if !branchRE.MatchString(branch) {
		return "", fmt.Errorf(
			"cannot derive a valid branch name from package %q and target %q: "+
				"constructed %q does not match backport-<package>-<version>",
			packageName, target, branch,
		)
	}
	return branch, nil
}

// manifestVersionRE matches the version scalar in manifest.yml, capturing:
//
//	group 1: "version: " prefix (including any opening quote)
//	group 2: the raw version digits (stops at whitespace or a quote character)
var manifestVersionRE = regexp.MustCompile(`(?m)^(version:\s*["']?)([0-9]+\.[0-9]+\.[0-9][^\s"']*)`)

// BumpPatchVersion reads manifestPath, increments the patch version by one,
// writes the file back preserving existing formatting, and returns the new version.
func BumpPatchVersion(manifestPath string) (string, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", manifestPath, err)
	}
	info, err := os.Stat(manifestPath)
	if err != nil {
		return "", err
	}
	idx := manifestVersionRE.FindSubmatchIndex(data)
	if idx == nil {
		return "", fmt.Errorf("version field not found in %s", manifestPath)
	}
	versionStr := string(data[idx[4]:idx[5]])
	ver, err := semver.StrictNewVersion(versionStr)
	if err != nil {
		return "", fmt.Errorf("parsing version %q from %s: %w", versionStr, manifestPath, err)
	}
	newVersion := fmt.Sprintf("%d.%d.%d", ver.Major(), ver.Minor(), ver.Patch()+1)

	var buf bytes.Buffer
	buf.Write(data[:idx[4]])
	buf.WriteString(newVersion)
	buf.Write(data[idx[5]:])
	if err := os.WriteFile(manifestPath, buf.Bytes(), info.Mode()); err != nil {
		return "", fmt.Errorf("writing %s: %w", manifestPath, err)
	}
	return newVersion, nil
}

type changelogEntryYAML struct {
	Version string `yaml:"version"`
	Changes []struct {
		Description string `yaml:"description"`
		Type        string `yaml:"type"`
		Link        string `yaml:"link"`
	} `yaml:"changes"`
}

// ParseEntryFields extracts description, type, and link from a changelog entry
// block as returned by changelog.ExtractFromDiff. Returns empty strings when
// the block cannot be parsed or contains no change items.
func ParseEntryFields(entryBlock string) (description, changeType, link string) {
	if entryBlock == "" {
		return "", "", ""
	}
	var entries []changelogEntryYAML
	if err := yaml.Unmarshal([]byte(entryBlock), &entries); err != nil || len(entries) == 0 {
		return "", "", ""
	}
	if len(entries[0].Changes) == 0 {
		return "", "", ""
	}
	c := entries[0].Changes[0]
	return c.Description, c.Type, c.Link
}

// BuildEntryBlock constructs the YAML changelog entry block for the given fields.
// The version is double-quoted to match the format used by elastic-package.
// All other fields are encoded via yaml.Marshal so that special characters
// (e.g. ": " in a description) are quoted rather than written as raw scalars.
func BuildEntryBlock(version, description, changeType, link string) string {
	n := &yaml.Node{
		Kind: yaml.SequenceNode,
		Content: []*yaml.Node{{
			Kind: yaml.MappingNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "version"},
				{Kind: yaml.ScalarNode, Value: version, Style: yaml.DoubleQuotedStyle},
				{Kind: yaml.ScalarNode, Value: "changes"},
				{Kind: yaml.SequenceNode, Content: []*yaml.Node{{
					Kind: yaml.MappingNode,
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Value: "description"},
						{Kind: yaml.ScalarNode, Value: description},
						{Kind: yaml.ScalarNode, Value: "type"},
						{Kind: yaml.ScalarNode, Value: changeType},
						{Kind: yaml.ScalarNode, Value: "link"},
						{Kind: yaml.ScalarNode, Value: link},
					},
				}}},
			},
		}},
	}
	out, _ := yaml.Marshal(n)
	return strings.TrimRight(string(out), "\n")
}

// conflictingFiles returns files in a conflict state after a failed cherry-pick.
func conflictingFiles() ([]string, error) {
	out, err := exec.Command("git", "status", "--porcelain").Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for line := range strings.SplitSeq(string(out), "\n") {
		if len(line) < 3 {
			continue
		}
		xy := line[:2]
		if strings.ContainsRune(xy, 'U') || xy == "AA" || xy == "DD" {
			files = append(files, strings.TrimSpace(line[3:]))
		}
	}
	return files, nil
}
