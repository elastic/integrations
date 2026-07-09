// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apply

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/cli/go-gh/v2"
	"gopkg.in/yaml.v3"

	"github.com/elastic/integrations/dev/backports"
	"github.com/elastic/integrations/dev/backports/changelog"
	"github.com/elastic/integrations/dev/backports/gitutil"
	"github.com/elastic/integrations/dev/citools"
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
	WorkDir     string // absolute path to the repository root; defaults to the current working directory
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

// applier holds the shared git context used by the apply pipeline steps.
type applier struct {
	git     gitutil.Git
	workDir string
}

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

	workDir := opts.WorkDir
	if workDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("getting working directory: %w", err)
		}
		workDir = wd
	}
	workDir, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("resolving work dir: %w", err)
	}
	a := applier{git: gitutil.Git{Dir: workDir}, workDir: workDir}

	packagesDir := opts.PackagesDir
	if packagesDir == "" {
		packagesDir = "packages"
	}
	if !filepath.IsAbs(packagesDir) {
		packagesDir = filepath.Join(workDir, packagesDir)
	}
	packagesDir = filepath.Clean(packagesDir)
	remote := opts.Remote
	if remote == "" {
		remote = "origin"
	}
	repository := opts.Repository
	if repository == "" {
		repository = "elastic/integrations"
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
	if err := checkBranchReady(filepath.Join(workDir, ".backports.yml"), branchName, opts.AsJSON); err != nil {
		return nil, err
	}

	workingBranch := workingBranchName(opts.Package, branchName, sha8)
	if err := a.prepareWorkingBranch(remote, branchName, workingBranch); err != nil {
		return nil, err
	}

	// Clean up the working branch if any subsequent step fails, so that a retry
	// with the same SHA does not fail with "branch already exists".
	success := false
	defer func() {
		if !success {
			_ = a.git.Run("checkout", "-")
			_ = a.git.Run("branch", "-D", workingBranch)
		}
	}()

	changelogPath := filepath.Join(pkgDir, "changelog.yml")
	manifestPath := filepath.Join(pkgDir, "manifest.yml")

	conflict, err := a.cherryPickOrConflict(opts.SHA, branchName, opts.Package, changelogPath, manifestPath)
	if err != nil {
		return nil, err
	}
	if conflict != nil {
		return conflict, nil
	}

	changes, err := a.extractChangelogFields(opts.SHA, changelogPath)
	if err != nil {
		return nil, err
	}

	newVersion, err := a.resetAndWriteChanges(manifestPath, changelogPath, changes)
	if err != nil {
		return nil, err
	}

	if err := a.commitChanges(pkgDir, opts.SHA, newVersion); err != nil {
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

	if err := a.git.Run("push", remote, "HEAD"); err != nil {
		return nil, fmt.Errorf("pushing: %w", err)
	}

	prURL, err := maybeOpenPR(opts.OpenPR, workingBranch, branchName, opts.Package, changes[0].Description, newVersion, opts.SHA, repository)
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

// checkBranchReady verifies the branch is in the backports inventory file.
// An inactive branch is a warning in human mode and an error in JSON mode.
func checkBranchReady(backportsFile, branchName string, asJSON bool) error {
	result, err := backports.CheckActive(backportsFile, branchName, time.Now().UTC())
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
func (a applier) prepareWorkingBranch(remote, branchName, workingBranch string) error {
	if err := a.git.Run("fetch", remote, branchName); err != nil {
		return fmt.Errorf(
			"fetching %q from remote %q failed — verify that the .backports.yml PR was merged and the creation pipeline succeeded: %w",
			branchName, remote, err,
		)
	}
	if err := a.git.Run("checkout", "-b", workingBranch, remote+"/"+branchName); err != nil {
		return fmt.Errorf("creating working branch %s: %w", workingBranch, err)
	}
	return nil
}

// cherryPickOrConflict attempts the cherry-pick. changelog.yml is always
// restored to HEAD afterwards — its entries are fully regenerated by this
// pipeline (see extractChangelogFields/InsertEntry), so cherry-picked changes
// to it are redundant. manifest.yml is left as cherry-pick merges it: any
// legitimate, non-version content change is preserved, and a conflict that is
// purely a "version:" line difference (expected, since each backport branch
// bumps its own version independently) is auto-resolved in favor of the
// current branch — bumpPatchVersion recomputes the version afterwards. A
// manifest.yml conflict block containing anything else is left as a genuine
// conflict, as is manifest.yml going missing entirely — whether it was
// already missing before the cherry-pick started, or a delete/modify
// conflict, or the cherry-picked commit cleanly removing/renaming the
// package — either way there's no manifest left to version-bump, so it's
// reported the same way as any other unresolved conflict. If conflicts
// remain in any file after this, it resets the index and returns a populated
// conflict Result; the caller's defer is responsible for branch cleanup. On
// success it returns (nil, nil).
func (a applier) cherryPickOrConflict(sha, branchName, pkg, changelogPath, manifestPath string) (*Result, error) {
	if conflict := a.manifestMissingConflict(sha, branchName, pkg, manifestPath); conflict != nil {
		return conflict, nil
	}

	baseVersion, err := readManifestVersion(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading current version from %s: %w", manifestPath, err)
	}

	// Force the default 2-way conflict marker style regardless of the caller's
	// git config: resolveManifestVersionConflict below parses "<<<<<<<"/"======="/
	// ">>>>>>>" text directly, and a diff3/zdiff3 style would make every block
	// look unresolvable.
	cherryErr := a.git.Run("-c", "merge.conflictStyle=merge", "cherry-pick", "-n", sha)

	if err := a.git.Run("checkout", "HEAD", "--", changelogPath); err != nil {
		a.abortCherryPick()
		return nil, fmt.Errorf("restoring changelog after cherry-pick: %w", err)
	}

	if conflict := a.manifestMissingConflict(sha, branchName, pkg, manifestPath); conflict != nil {
		return conflict, nil
	}

	if cherryErr != nil {
		manifestHadConflict, manifestResolved, err := resolveManifestVersionConflict(manifestPath)
		if err != nil {
			a.abortCherryPick()
			return nil, fmt.Errorf("resolving manifest.yml conflict: %w", err)
		}
		if manifestResolved {
			if err := a.git.Run("add", manifestPath); err != nil {
				a.abortCherryPick()
				return nil, fmt.Errorf("staging resolved manifest.yml: %w", err)
			}
			if manifestHadConflict {
				fmt.Fprintf(os.Stderr, "note: %s had a version-only conflict, auto-resolved by keeping the incoming change\n", manifestPath)
			}
		} else {
			fmt.Fprintf(os.Stderr, "note: %s has conflicts beyond the version line — manual resolution required\n", manifestPath)
		}

		// cherry-pick failed; check whether conflicts remain.
		files, err := a.conflictingFiles()
		if err != nil {
			a.abortCherryPick()
			return nil, fmt.Errorf("checking conflict state after cherry-pick: %w", err)
		}
		if len(files) > 0 {
			// Branch checkout and deletion are left to the caller's defer.
			a.abortCherryPick()
			return buildConflictResult(sha, branchName, pkg, files), nil
		}
	}

	// The backport pipeline owns package versioning independently of the source
	// branch: force manifest.yml's version back to what it was before the
	// cherry-pick, so bumpPatchVersion below increments the target branch's own
	// version rather than whatever the cherry-picked commit set it to.
	if err := setManifestVersion(manifestPath, baseVersion); err != nil {
		a.abortCherryPick()
		return nil, fmt.Errorf("restoring manifest.yml version: %w", err)
	}
	return nil, nil
}

// abortCherryPick resets the working tree and index back to HEAD, discarding
// any in-progress cherry-pick state. Used instead of "cherry-pick --abort":
// with -n, git does not always write CHERRY_PICK_HEAD, so --abort may fail
// and leave the index dirty.
func (a applier) abortCherryPick() {
	_ = a.git.Run("reset", "--hard", "HEAD")
}

// manifestMissingConflict reports a conflict Result if manifestPath does not
// exist in the working tree. Called both before the cherry-pick (the
// package doesn't exist on the target backport branch at all yet) and after
// (a delete/modify conflict, or the cherry-picked commit cleanly
// deletes/renames the package). Either way there's no manifest.yml left to
// version-bump, so this needs a human decision rather than a downstream
// os.ReadFile failing with an opaque error. Returns nil if manifestPath is
// present, or if statting it fails for some other reason (that error
// surfaces naturally from the next operation that reads the file instead).
func (a applier) manifestMissingConflict(sha, branchName, pkg, manifestPath string) *Result {
	_, err := os.Stat(manifestPath)
	if !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	a.abortCherryPick()
	relPath, relErr := filepath.Rel(a.workDir, manifestPath)
	if relErr != nil {
		relPath = manifestPath
	}
	return buildConflictResult(sha, branchName, pkg, []string{relPath})
}

// buildConflictResult constructs the conflict Result returned by
// cherryPickOrConflict when one or more files remain conflicted.
func buildConflictResult(sha, branchName, pkg string, files []string) *Result {
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

// resolveManifestVersionConflict looks for cherry-pick conflict markers in
// manifestPath and auto-resolves any conflict block where the current
// branch's side ("ours") is purely a "version:" line difference. Such a block
// keeps the incoming ("theirs") side instead of ours: git groups a changed
// line together with any content the source commit inserted right next to it
// (e.g. a new field added directly below the version bump) into the same
// conflict block, so discarding "theirs" here would silently drop that
// content. The version field itself doesn't need to be ours at this point —
// cherryPickOrConflict normalizes it back to the target branch's own version
// afterwards regardless of which side's value ends up on disk. A block where
// "ours" contains anything other than a single version line is left
// untouched so it still surfaces as a real conflict.
// It assumes the default (non-diff3) conflict marker style; cherryPickOrConflict
// forces this via "-c merge.conflictStyle=merge" on the cherry-pick itself, so
// this is independent of the caller's own git config.
// version is a mandatory, singular manifest.yml field: since "ours" is a
// valid, existing file, it has exactly one line matching "version:", so at
// most one conflict block can ever match the auto-resolve condition above.
// After resolving, the merged content is required to still contain exactly
// one such line before it's accepted; otherwise the whole file is left
// untouched and reported as a conflict instead. This isn't expected to
// trigger from two legitimately-committed manifest.yml states — a valid
// "theirs" can't drop or duplicate a mandatory field either — but guards
// against writing an invalid manifest.yml if that assumption is ever wrong.
// hadConflict reports whether manifestPath contained any conflict markers at
// all (false if the cherry-pick failed for an unrelated file and manifest.yml
// merged cleanly on its own). resolved reports whether the file has no
// remaining conflict markers (either none were present, or all were
// resolved) — the caller uses this, not hadConflict, to decide whether to
// stage the file.
func resolveManifestVersionConflict(manifestPath string) (hadConflict, resolved bool, err error) {
	const (
		conflictStartPrefix = "<<<<<<<"
		conflictMidPrefix   = "======="
		conflictEndPrefix   = ">>>>>>>"
	)

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return false, false, fmt.Errorf("reading %s: %w", manifestPath, err)
	}
	lines := strings.Split(string(data), "\n")
	if !slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, conflictStartPrefix) }) {
		return false, true, nil
	}

	info, err := os.Stat(manifestPath)
	if err != nil {
		return true, false, err
	}

	var out []string
	fullyResolved := true
	for i := 0; i < len(lines); {
		line := lines[i]
		if !strings.HasPrefix(line, conflictStartPrefix) {
			out = append(out, line)
			i++
			continue
		}
		startLine := line
		i++
		oursStart := i
		for i < len(lines) && !strings.HasPrefix(lines[i], conflictMidPrefix) {
			i++
		}
		if i >= len(lines) {
			return true, false, fmt.Errorf("malformed conflict markers in %s: missing %q", manifestPath, conflictMidPrefix)
		}
		ours := lines[oursStart:i]
		midLine := lines[i]
		i++
		theirsStart := i
		for i < len(lines) && !strings.HasPrefix(lines[i], conflictEndPrefix) {
			i++
		}
		if i >= len(lines) {
			return true, false, fmt.Errorf("malformed conflict markers in %s: missing %q", manifestPath, conflictEndPrefix)
		}
		theirs := lines[theirsStart:i]
		endLine := lines[i]
		i++

		if len(ours) == 1 && strings.HasPrefix(ours[0], "version:") {
			out = append(out, theirs...)
			continue
		}
		fullyResolved = false
		out = append(out, startLine)
		out = append(out, ours...)
		out = append(out, midLine)
		out = append(out, theirs...)
		out = append(out, endLine)
	}

	if !fullyResolved {
		return true, false, nil
	}

	versionLines := 0
	for _, l := range out {
		if strings.HasPrefix(l, "version:") {
			versionLines++
		}
	}
	if versionLines != 1 {
		return true, false, nil
	}

	if err := os.WriteFile(manifestPath, []byte(strings.Join(out, "\n")), info.Mode()); err != nil {
		return true, false, fmt.Errorf("writing resolved %s: %w", manifestPath, err)
	}
	return true, true, nil
}

// extractChangelogFields reads changelog.yml directly from the source commit
// and returns the change items from its first (newest) entry.
func (a applier) extractChangelogFields(sha, changelogPath string) ([]changeItem, error) {
	relPath, err := filepath.Rel(a.workDir, changelogPath)
	if err != nil {
		return nil, fmt.Errorf("computing repo-relative path for %s: %w", changelogPath, err)
	}
	content, err := a.git.Output("show", sha+":"+relPath)
	if err != nil {
		return nil, fmt.Errorf("reading changelog from commit %s: %w", sha, err)
	}
	changes := parseEntryFields(content)
	if len(changes) == 0 {
		return nil, fmt.Errorf("no changelog entries found in commit %s", sha)
	}
	if changes[0].Description == "" || changes[0].Type == "" || changes[0].Link == "" {
		return nil, fmt.Errorf("no valid changelog entry found in commit %s", sha)
	}
	return changes, nil
}

// resetAndWriteChanges resets changelog.yml to the backport-branch state
// (discarding the cherry-picked entry), bumps manifest.yml's patch version,
// and inserts a fresh changelog entry. Returns the new version string.
// manifest.yml is intentionally left as cherryPickOrConflict prepared it: any
// legitimate cherry-picked content is preserved, and its version field was
// already restored to the target branch's own version.
func (a applier) resetAndWriteChanges(manifestPath, changelogPath string, changes []changeItem) (string, error) {
	// cherryPickOrConflict already restores changelog.yml on the success path, so
	// this checkout is redundant in normal flow. It is kept here so this function
	// remains self-contained and correct if ever called from a different context.
	if err := a.git.Run("checkout", "HEAD", "--", changelogPath); err != nil {
		return "", fmt.Errorf("resetting changelog: %w", err)
	}
	newVersion, err := bumpPatchVersion(manifestPath)
	if err != nil {
		return "", fmt.Errorf("bumping version in %s: %w", manifestPath, err)
	}
	entryBlock, err := buildEntryBlock(newVersion, changes)
	if err != nil {
		return "", err
	}
	if err := changelog.InsertEntry(changelogPath, newVersion, entryBlock); err != nil {
		return "", fmt.Errorf("inserting changelog entry: %w", err)
	}
	return newVersion, nil
}

// commitChanges stages all package changes and commits with the original commit
// message plus a cherry-pick annotation.
func (a applier) commitChanges(pkgDir, sha, newVersion string) error {
	originalMsg, err := a.git.Output("log", "--format=%B", "-n", "1", sha)
	if err != nil {
		return fmt.Errorf("reading original commit message for %s: %w", sha, err)
	}
	commitMsg := strings.TrimRight(originalMsg, "\n") +
		fmt.Sprintf("\n\n(cherry picked from commit %s)\n\nBackport version: %s", sha, newVersion)
	if err := a.git.Run("add", pkgDir); err != nil {
		return fmt.Errorf("staging changes: %w", err)
	}
	if err := a.git.Run("commit", "-m", commitMsg); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}

// conflictingFiles returns files in a conflict state after a failed cherry-pick.
func (a applier) conflictingFiles() ([]string, error) {
	out, err := a.git.Output("status", "--porcelain")
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
	b.WriteString("- [ ] Compare the `manifest.yml` changes here against the original PR (linked above under Origin) and confirm they match — a conflict limited to the version line is auto-resolved by keeping the incoming change as-is, with no compatibility check against this branch\n")
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

// bumpPatchVersion reads manifestPath, increments the patch version by one,
// writes the file back preserving existing formatting, and returns the new version.
func bumpPatchVersion(manifestPath string) (string, error) {
	current, err := readManifestVersion(manifestPath)
	if err != nil {
		return "", err
	}
	ver, err := semver.StrictNewVersion(current)
	if err != nil {
		return "", fmt.Errorf("parsing version %q from %s: %w", current, manifestPath, err)
	}
	newVersion := fmt.Sprintf("%d.%d.%d", ver.Major(), ver.Minor(), ver.Patch()+1)
	if err := setManifestVersion(manifestPath, newVersion); err != nil {
		return "", fmt.Errorf("bumping version in %s: %w", manifestPath, err)
	}
	return newVersion, nil
}

// readManifestVersion returns the value of the "version" field in manifestPath.
func readManifestVersion(manifestPath string) (string, error) {
	m, err := citools.ReadPackageManifest(manifestPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", manifestPath, err)
	}
	if m.Version == "" {
		return "", fmt.Errorf("version field not found in %s", manifestPath)
	}
	return m.Version, nil
}

// setManifestVersion rewrites the line starting with "version:" in manifestPath
// to version, preserving quoting and the rest of the file's formatting.
func setManifestVersion(manifestPath, version string) error {
	current, err := readManifestVersion(manifestPath)
	if err != nil {
		return err
	}
	if current == version {
		return nil
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", manifestPath, err)
	}
	info, err := os.Stat(manifestPath)
	if err != nil {
		return err
	}

	// Replace the version digits only on the line that starts with "version:",
	// preserving quotes and surrounding fields.
	lines := bytes.Split(data, []byte("\n"))
	idx := slices.IndexFunc(lines, func(l []byte) bool {
		return bytes.HasPrefix(l, []byte("version:"))
	})
	if idx == -1 {
		return fmt.Errorf("version line not found in %s", manifestPath)
	}
	lines[idx] = bytes.Replace(lines[idx], []byte(current), []byte(version), 1)
	updated := bytes.Join(lines, []byte("\n"))
	if err := os.WriteFile(manifestPath, updated, info.Mode()); err != nil {
		return fmt.Errorf("writing %s: %w", manifestPath, err)
	}
	return nil
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
func buildEntryBlock(version string, changes []changeItem) (string, error) {
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
	out, err := yaml.Marshal(n)
	if err != nil {
		return "", fmt.Errorf("marshalling changelog entry: %w", err)
	}
	return strings.TrimRight(string(out), "\n"), nil
}
