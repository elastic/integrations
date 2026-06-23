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
	DryRun      bool   // commit locally but skip push and PR creation
	AsJSON      bool   // emit JSON output instead of human-readable text
	Remote      string // git remote to fetch from and push to; default "origin"
	PackagesDir string // path to packages dir; default "packages"
	Repository  string // "org/repo" e.g. "elastic/integrations"
}

// Result is the structured output of Apply.
type Result struct {
	Status           string   `json:"status"` // "success" or "conflict"
	SHA              string   `json:"sha"`
	TargetBranch     string   `json:"target_branch"`
	NewVersion       string   `json:"new_version,omitempty"`
	WorkingBranch    string   `json:"working_branch,omitempty"` // populated on dry run
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
	remote := opts.Remote
	if remote == "" {
		remote = "origin"
	}
	sha8 := opts.SHA[:8]

	pkgDir, err := resolvePackage(packagesDir, opts.Package)
	if err != nil {
		return nil, err
	}

	branchName, err := resolveBranchName(opts.Target, opts.Package)
	if err != nil {
		return nil, err
	}
	if err := checkBranchReady(branchName, opts.AsJSON); err != nil {
		return nil, err
	}

	workingBranch := workingBranchName(opts.Package, branchName, sha8)
	if err := prepareWorkingBranch(remote, branchName, workingBranch); err != nil {
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

	changelogPath := filepath.Join(pkgDir, "changelog.yml")
	manifestPath := filepath.Join(pkgDir, "manifest.yml")

	if conflict := cherryPickOrConflict(opts.SHA, branchName, workingBranch, opts.Package, changelogPath, manifestPath); conflict != nil {
		return conflict, nil
	}

	changes, err := extractChangelogFields(opts.SHA, changelogPath)
	if err != nil {
		return nil, err
	}

	newVersion, err := resetAndWriteChanges(manifestPath, changelogPath, changes)
	if err != nil {
		return nil, err
	}

	if err := commitChanges(pkgDir, opts.SHA, newVersion); err != nil {
		return nil, err
	}

	if opts.DryRun {
		success = true
		return &Result{
			Status:        "success",
			SHA:           opts.SHA,
			TargetBranch:  branchName,
			NewVersion:    newVersion,
			WorkingBranch: workingBranch,
		}, nil
	}

	if err := gitutil.Run("push", remote, "HEAD"); err != nil {
		return nil, fmt.Errorf("pushing: %w", err)
	}

	prURL, err := maybeOpenPR(opts.OpenPR, workingBranch, branchName, opts.Package, changes[0].Description, newVersion, opts.SHA, opts.Repository)
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

// prepareWorkingBranch fetches the backport branch from remote and creates a
// local working branch off it.
func prepareWorkingBranch(remote, branchName, workingBranch string) error {
	if err := gitutil.Run("fetch", remote, branchName); err != nil {
		fmt.Println("fetching", branchName, "from remote", remote, "failed — verify that the .backports.yml PR was merged and the creation pipeline succeeded: %w", err)
		// return fmt.Errorf(
		// 	"fetching %q from remote %q failed — verify that the .backports.yml PR was merged and the creation pipeline succeeded: %w",
		// 	branchName, remote, err,
		// )
	}
	if err := gitutil.Run("checkout", "-b", workingBranch, branchName); err != nil {
		return fmt.Errorf("creating working branch %s: %w", workingBranch, err)
	}
	return nil
}

// cherryPickOrConflict attempts the cherry-pick. manifest.yml and changelog.yml
// are always restored to HEAD afterwards — we manage those files ourselves, so
// conflicts in them should never block the backport. If other files still
// conflict after that, it cleans up and returns a populated conflict Result;
// on success it returns nil.
func cherryPickOrConflict(sha, branchName, workingBranch, pkg, changelogPath, manifestPath string) *Result {
	cherryErr := gitutil.Run("cherry-pick", "-n", sha)

	// Always restore manifest and changelog to HEAD. They are the most likely
	// source of spurious conflicts (version bump and entry differ per branch) and
	// we overwrite them ourselves in resetAndWriteChanges anyway.
	_ = gitutil.Run("checkout", "HEAD", "--", changelogPath, manifestPath)

	if cherryErr == nil {
		return nil
	}

	// cherry-pick failed; check whether non-manifest/changelog conflicts remain.
	files, _ := conflictingFiles()
	if len(files) == 0 {
		// Only manifest/changelog conflicted — we resolved them above; continue.
		return nil
	}

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

// extractChangelogFields reads changelog.yml directly from the source commit
// and returns the change items from its first (newest) entry.
func extractChangelogFields(sha, changelogPath string) ([]changeItem, error) {
	content, err := gitutil.Output("show", sha+":"+changelogPath)
	if err != nil {
		return nil, fmt.Errorf("reading changelog from commit %s: %w", sha, err)
	}
	var entries []changelogEntryYAML
	if err := yaml.Unmarshal([]byte(content), &entries); err != nil || len(entries) == 0 {
		return nil, fmt.Errorf("parsing changelog from commit %s: %w", sha, err)
	}
	changes := make([]changeItem, 0, len(entries[0].Changes))
	for _, c := range entries[0].Changes {
		changes = append(changes, changeItem{Description: c.Description, Type: c.Type, Link: c.Link})
	}
	if len(changes) == 0 || changes[0].Description == "" || changes[0].Type == "" {
		return nil, fmt.Errorf("no valid changelog entry found in commit %s", sha)
	}
	return changes, nil
}

// resetAndWriteChanges resets changelog.yml and manifest.yml to the backport-branch
// state (discarding the cherry-picked version bump and entry), bumps the patch
// version, and inserts a fresh changelog entry. Returns the new version string.
func resetAndWriteChanges(manifestPath, changelogPath string, changes []changeItem) (string, error) {
	if err := gitutil.Run("checkout", "HEAD", "--", changelogPath, manifestPath); err != nil {
		return "", fmt.Errorf("resetting changelog and manifest: %w", err)
	}
	newVersion, err := bumpPatchVersion(manifestPath)
	if err != nil {
		return "", fmt.Errorf("bumping version in %s: %w", manifestPath, err)
	}
	if err := changelog.InsertEntry(changelogPath, newVersion, buildEntryBlock(newVersion, changes)); err != nil {
		return "", fmt.Errorf("inserting changelog entry: %w", err)
	}
	return newVersion, nil
}

// commitChanges stages all package changes and commits with the original commit
// message plus a cherry-pick annotation.
func commitChanges(pkgDir, sha, newVersion string) error {
	originalMsg, err := gitutil.Output("log", "--format=%B", "-n", "1", sha)
	if err != nil {
		return fmt.Errorf("reading original commit message for %s: %w", sha, err)
	}
	commitMsg := strings.TrimRight(originalMsg, "\n") +
		fmt.Sprintf("\n\n(cherry picked from commit %s)\n\nBackport version: %s", sha, newVersion)
	if err := gitutil.Run("add", pkgDir); err != nil {
		return fmt.Errorf("staging changes: %w", err)
	}
	if err := gitutil.Run("commit", "-m", commitMsg); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}

// maybeOpenPR creates a GitHub PR if openPR is true, returning the PR URL.
func maybeOpenPR(openPR bool, workingBranch, branchName, pkg, description, newVersion, sha, repository string) (string, error) {
	if !openPR {
		return "", nil
	}
	title := fmt.Sprintf("[%s] Backport %s (%s)", pkg, description, newVersion)
	body := buildPRBody(sha, branchName, repository)
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

// buildPRBody constructs the PR description, including origin links and an
// author checklist.
func buildPRBody(sha, branchName, repository string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Automated backport of commit `%s` onto `%s`.\n", sha, branchName)

	if repository != "" {
		fmt.Fprintf(&b, "\n## Origin\n\n")
		fmt.Fprintf(&b, "- Commit: https://github.com/%s/commit/%s\n", repository, sha)
		if prURL := findOriginPR(sha, repository); prURL != "" {
			fmt.Fprintf(&b, "- Source PR: %s\n", prURL)
		}
	}

	b.WriteString("\n## Author's checklist\n\n")
	b.WriteString("- [ ] Review the version set in `manifest.yml` and `changelog.yml`\n")
	b.WriteString("- [ ] Review the links set in `changelog.yml`\n")

	return b.String()
}

// findOriginPR returns the HTML URL of the first PR associated with sha in
// repository (e.g. "elastic/integrations"). Returns an empty string when the
// PR cannot be determined (no repository given, API error, or no associated PR).
func findOriginPR(sha, repository string) string {
	if repository == "" {
		return ""
	}
	stdout, _, err := gh.Exec("api",
		fmt.Sprintf("repos/%s/commits/%s/pulls", repository, sha),
		"--jq", ".[0].html_url",
	)
	if err != nil {
		return ""
	}
	url := strings.TrimSpace(stdout.String())
	if url == "null" {
		return ""
	}
	return url
}

// resolveBranchName derives the full backport branch name from target.
// If target already matches the branch pattern it is returned as-is.
// Otherwise "backport-<packageName>-<target>" is constructed and validated.
func resolveBranchName(target, packageName string) (string, error) {
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

// bumpPatchVersion reads manifestPath, increments the patch version by one,
// writes the file back preserving existing formatting, and returns the new version.
func bumpPatchVersion(manifestPath string) (string, error) {
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

// changeItem represents a single entry in a changelog changes list.
type changeItem struct {
	Description string
	Type        string
	Link        string
}

type changelogEntryYAML struct {
	Version string `yaml:"version"`
	Changes []struct {
		Description string `yaml:"description"`
		Type        string `yaml:"type"`
		Link        string `yaml:"link"`
	} `yaml:"changes"`
}

// parseEntryFields extracts all change items from a changelog entry block.
// Returns nil when the block cannot be parsed or contains no change items.
func parseEntryFields(entryBlock string) []changeItem {
	if entryBlock == "" {
		return nil
	}
	var entries []changelogEntryYAML
	if err := yaml.Unmarshal([]byte(entryBlock), &entries); err != nil || len(entries) == 0 {
		return nil
	}
	changes := make([]changeItem, 0, len(entries[0].Changes))
	for _, c := range entries[0].Changes {
		changes = append(changes, changeItem{Description: c.Description, Type: c.Type, Link: c.Link})
	}
	return changes
}

// buildEntryBlock constructs the YAML changelog entry block for the given
// version and change items. The version is double-quoted to match the format
// used by elastic-package. All string fields are encoded via yaml.Marshal so
// that special characters (e.g. ": " in a description) are quoted correctly.
func buildEntryBlock(version string, changes []changeItem) string {
	changeNodes := make([]*yaml.Node, 0, len(changes))
	for _, c := range changes {
		changeNodes = append(changeNodes, &yaml.Node{
			Kind: yaml.MappingNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "description"},
				{Kind: yaml.ScalarNode, Value: c.Description},
				{Kind: yaml.ScalarNode, Value: "type"},
				{Kind: yaml.ScalarNode, Value: c.Type},
				{Kind: yaml.ScalarNode, Value: "link"},
				{Kind: yaml.ScalarNode, Value: c.Link},
			},
		})
	}
	n := &yaml.Node{
		Kind: yaml.SequenceNode,
		Content: []*yaml.Node{{
			Kind: yaml.MappingNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "version"},
				{Kind: yaml.ScalarNode, Value: version, Style: yaml.DoubleQuotedStyle},
				{Kind: yaml.ScalarNode, Value: "changes"},
				{Kind: yaml.SequenceNode, Content: changeNodes},
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
