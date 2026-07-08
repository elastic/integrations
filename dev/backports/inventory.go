// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package backports

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"

	"github.com/elastic/integrations/dev/citools"
)

type inventory struct {
	Backports []entry `yaml:"backports"`
}

type entry struct {
	Package             string  `yaml:"package"`
	Branch              string  `yaml:"branch"`
	BaseVersion         string  `yaml:"base_version"`
	BaseCommit          string  `yaml:"base_commit"`
	MaintainedUntil     *string `yaml:"maintained_until"`      // null → nil; "YYYY-MM-DD" → &string
	Archived            *bool   `yaml:"archived"`              // nil when field is absent
	RemoveOtherPackages *bool   `yaml:"remove_other_packages"` // nil when field is absent
}

const maintainedUntilLayout = "2006-01-02"

// shaRE matches a lowercase hexadecimal git SHA (short or full, 7–40 chars).
var shaRE = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// duplicatePackageVersionExceptions lists package@version pairs that are
// intentionally allowed to appear more than once in the inventory.
// Each entry must include a comment explaining why the exception exists.
var duplicatePackageVersionExceptions = map[string]struct{}{
	// backport-security_detection_engine-8.17 and -8.18 share the same base
	// release (8.17.7) because the 8.18 branch was cut from the same tag.
	"security_detection_engine@8.17.7": {},
}

// branchRE matches a valid backport branch name:
//
//	backport-<package>-<suffix>
//
// where <package> is one or more letters, digits, or underscores, and
// <suffix> starts with a letter or digit and may contain letters, digits,
// dots, underscores, or hyphens (e.g. "3.17", "6.x", "7.15.0", "2024-hotfix").
// Whitespace, quotes, colons, semicolons, dollar signs, backticks, and all
// other special characters are not permitted.
var branchRE = regexp.MustCompile(`^backport-[a-zA-Z0-9_]+-[a-zA-Z0-9][a-zA-Z0-9_.\-]*$`)

// ActiveResult is the result of a CheckActive call.
type ActiveResult struct {
	Branch          string  `json:"branch"`
	Active          bool    `json:"active"`
	Archived        bool    `json:"archived"`
	MaintainedUntil *string `json:"maintained_until"`
}

// CheckActive looks up branch in the inventory at path and reports whether it
// is currently active. now is injected so callers can test with a fixed date.
// Returns an error if the inventory cannot be read, parsed, or the branch is not found.
func CheckActive(path, branch string, now time.Time) (ActiveResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ActiveResult{}, fmt.Errorf("reading inventory: %w", err)
	}
	var inv inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return ActiveResult{}, fmt.Errorf("parsing inventory: %w", err)
	}
	for _, e := range inv.Backports {
		if e.Branch == branch {
			return e.activeResult(now), nil
		}
	}
	return ActiveResult{}, fmt.Errorf("branch %q not found in %s", branch, path)
}

// activeResult applies the active-branch rules for a single entry.
//
// A branch is inactive when:
//   - archived == true, OR
//   - maintained_until is set and is strictly before today (UTC).
func (e entry) activeResult(now time.Time) ActiveResult {
	archived := e.Archived != nil && *e.Archived
	result := ActiveResult{
		Branch:          e.Branch,
		Active:          true,
		Archived:        archived,
		MaintainedUntil: e.MaintainedUntil,
	}
	if archived {
		result.Active = false
		return result
	}
	if e.MaintainedUntil != nil {
		t, err := time.Parse(maintainedUntilLayout, *e.MaintainedUntil)
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		if err == nil && t.Before(today) {
			result.Active = false
		}
	}
	return result
}

// validateBranchFormat checks that branch matches the required backport branch format:
// backport-<package>-<suffix>, where package is letters/digits/underscores and suffix
// starts with a letter or digit and may contain letters, digits, dots, underscores, or hyphens.
// Whitespace, quotes, colons, semicolons, dollar signs, backticks, and other special characters
// are not permitted.
func validateBranchFormat(branch string) error {
	if !branchRE.MatchString(branch) {
		return fmt.Errorf("invalid branch %q: must match backport-<package>-<suffix> "+
			"(package: letters/digits/underscores; suffix: letters/digits/dots/underscores/hyphens; "+
			"no whitespace, quotes, colons, semicolons, dollar signs, backticks or other special characters)", branch)
	}
	return nil
}

// ValidateBranchName checks that branch is a valid backport branch name for the given package:
// it must pass ValidateBranchFormat and start with "backport-<packageName>-".
func ValidateBranchName(packageName, branch string) error {
	if err := validateBranchFormat(branch); err != nil {
		return err
	}
	if !strings.HasPrefix(branch, "backport-"+packageName+"-") {
		return fmt.Errorf("branch %q must start with \"backport-%s-\"", branch, packageName)
	}
	return nil
}

// AddEntry inserts a new backport entry into the inventory at path.
// The branch name is derived as backport-<packageName>-<major>.<minor>.
// archived is set to false and maintained_until to null.
// The entry is placed in sorted order: package name ascending, then version descending (newest first).
// packagesDir is the path to the packages/ directory used to verify that packageName names a real
// package. Pass an empty string to skip this check.
// Returns the derived branch name.
func AddEntry(path, packageName, baseVersion, baseCommit, packagesDir string) (string, error) {
	v, err := semver.StrictNewVersion(baseVersion)
	if err != nil {
		return "", fmt.Errorf("invalid base_version %q: %w", baseVersion, err)
	}
	branch := fmt.Sprintf("backport-%s-%d.%d", packageName, v.Major(), v.Minor())

	knownPackages, err := buildKnownPackages(packagesDir)
	if err != nil {
		return "", fmt.Errorf("loading packages from %s: %w", packagesDir, err)
	}
	if knownPackages != nil {
		if _, ok := knownPackages[packageName]; !ok {
			return "", fmt.Errorf("unknown package %q: not found under %s", packageName, packagesDir)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading inventory: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("parsing inventory: %w", err)
	}

	seq, err := backportsSequenceNode(&doc)
	if err != nil {
		return "", err
	}

	pos := entryInsertPos(seq, packageName, v)
	newNode := newEntryNode(packageName, branch, baseVersion, baseCommit)

	updated := make([]*yaml.Node, len(seq.Content)+1)
	copy(updated, seq.Content[:pos])
	updated[pos] = newNode
	copy(updated[pos+1:], seq.Content[pos:])
	seq.Content = updated

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", fmt.Errorf("marshaling inventory: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return "", fmt.Errorf("writing inventory: %w", err)
	}
	return branch, nil
}

// backportsSequenceNode navigates from the document root to the sequence node
// under the "backports" key.
func backportsSequenceNode(doc *yaml.Node) (*yaml.Node, error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("unexpected document structure")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping at document root")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "backports" {
			seq := root.Content[i+1]
			if seq.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("'backports' is not a sequence")
			}
			return seq, nil
		}
	}
	return nil, fmt.Errorf("'backports' key not found in inventory")
}

// entryInsertPos returns the index at which a new entry with the given package
// and version should be inserted to keep the sequence sorted (package ascending,
// then version descending within the same package — newest first).
func entryInsertPos(seq *yaml.Node, newPkg string, newVer *semver.Version) int {
	for i, node := range seq.Content {
		pkg := mappingFieldValue(node, "package")
		if pkg > newPkg {
			return i
		}
		if pkg == newPkg {
			ver, err := semver.StrictNewVersion(mappingFieldValue(node, "base_version"))
			if err == nil && ver.LessThan(newVer) {
				return i
			}
		}
	}
	return len(seq.Content)
}

// mappingFieldValue returns the scalar value for the given key in a YAML mapping node.
func mappingFieldValue(node *yaml.Node, key string) string {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1].Value
		}
	}
	return ""
}

// newEntryNode builds a YAML mapping node for a new backport entry.
// base_version and base_commit are double-quoted to match the existing file style.
func newEntryNode(pkg, branch, baseVersion, baseCommit string) *yaml.Node {
	scalar := func(value, tag string, style yaml.Style) *yaml.Node {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value, Style: style}
	}
	key := func(k string) *yaml.Node { return scalar(k, "!!str", 0) }
	str := func(v string) *yaml.Node { return scalar(v, "!!str", 0) }
	quoted := func(v string) *yaml.Node { return scalar(v, "!!str", yaml.DoubleQuotedStyle) }

	return &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
		Content: []*yaml.Node{
			key("package"), str(pkg),
			key("branch"), str(branch),
			key("base_version"), quoted(baseVersion),
			key("base_commit"), quoted(baseCommit),
			key("maintained_until"), scalar("null", "!!null", 0),
			key("archived"), scalar("false", "!!bool", 0),
			key("remove_other_packages"), scalar("true", "!!bool", 0),
		},
	}
}

// ValidateInventory reads the .backports.yml inventory at path and returns a
// combined error listing every schema violation found across all entries.
//
// packagesDir is the path to the packages/ directory used to verify that each
// entry's package field names a real package. Pass an empty string to skip
// this check (useful in unit tests that do not have a full checkout).
func ValidateInventory(path, packagesDir string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading inventory: %w", err)
	}

	var inv inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return fmt.Errorf("parsing inventory: %w", err)
	}

	knownPackages, err := buildKnownPackages(packagesDir)
	if err != nil {
		return fmt.Errorf("loading packages from %s: %w", packagesDir, err)
	}

	var errs []error
	for i, e := range inv.Backports {
		errs = append(errs, validateEntryFields(i, e, knownPackages, packagesDir)...)
	}
	errs = append(errs, validateDuplicates(inv.Backports)...)

	return errors.Join(errs...)
}

// validateEntryFields checks that all required fields of a single entry are
// present and contain valid values.
func validateEntryFields(i int, e entry, knownPackages map[string]struct{}, packagesDir string) []error {
	id := fmt.Sprintf("entry[%d]", i)
	if e.Branch != "" {
		id = fmt.Sprintf("branch %q", e.Branch)
	}

	var errs []error

	if e.Package == "" {
		errs = append(errs, fmt.Errorf("%s: missing required field 'package'", id))
	} else if knownPackages != nil {
		if _, ok := knownPackages[e.Package]; !ok {
			errs = append(errs, fmt.Errorf("%s: unknown package %q: not found under %s", id, e.Package, packagesDir))
		}
	}

	if e.Branch == "" {
		errs = append(errs, fmt.Errorf("%s: missing required field 'branch'", id))
	} else if e.Package != "" {
		if err := ValidateBranchName(e.Package, e.Branch); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
		}
	} else if err := validateBranchFormat(e.Branch); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", id, err))
	}

	if e.BaseVersion == "" {
		errs = append(errs, fmt.Errorf("%s: missing required field 'base_version'", id))
	} else if _, parseErr := semver.StrictNewVersion(e.BaseVersion); parseErr != nil {
		errs = append(errs, fmt.Errorf("%s: invalid base_version %q: must be a valid semantic version", id, e.BaseVersion))
	}

	if e.BaseCommit == "" {
		errs = append(errs, fmt.Errorf("%s: missing required field 'base_commit'", id))
	} else if !shaRE.MatchString(e.BaseCommit) {
		errs = append(errs, fmt.Errorf("%s: invalid base_commit %q: must be a lowercase hex SHA (7–40 chars)", id, e.BaseCommit))
	}

	if e.Archived == nil {
		errs = append(errs, fmt.Errorf("%s: missing required field 'archived'", id))
	}

	if e.RemoveOtherPackages == nil {
		errs = append(errs, fmt.Errorf("%s: missing required field 'remove_other_packages'", id))
	}

	if e.MaintainedUntil != nil {
		if _, parseErr := time.Parse(maintainedUntilLayout, *e.MaintainedUntil); parseErr != nil {
			errs = append(errs, fmt.Errorf("%s: invalid maintained_until %q: must be YYYY-MM-DD", id, *e.MaintainedUntil))
		}
	}

	return errs
}

// validateDuplicates checks for duplicate branch names and duplicate
// package/version pairs across all entries.
func validateDuplicates(entries []entry) []error {
	seenBranches := make(map[string]struct{})
	seenPackageVersions := make(map[string]struct{})

	var errs []error
	for i, e := range entries {
		id := fmt.Sprintf("entry[%d]", i)
		if e.Branch != "" {
			id = fmt.Sprintf("branch %q", e.Branch)
		}

		if e.Branch != "" {
			if _, seen := seenBranches[e.Branch]; seen {
				errs = append(errs, fmt.Errorf("%s: duplicate branch %q", id, e.Branch))
			} else {
				seenBranches[e.Branch] = struct{}{}
			}
		}

		if e.Package != "" && e.BaseVersion != "" {
			key := e.Package + "@" + e.BaseVersion
			if _, isException := duplicatePackageVersionExceptions[key]; !isException {
				if _, seen := seenPackageVersions[key]; seen {
					errs = append(errs, fmt.Errorf("%s: duplicate package/version %q/%q", id, e.Package, e.BaseVersion))
				} else {
					seenPackageVersions[key] = struct{}{}
				}
			}
		}
	}

	return errs
}

// buildKnownPackages scans packagesDir and returns a set of valid package names.
// Returns nil (no error) when packagesDir is empty, skipping package validation.
func buildKnownPackages(packagesDir string) (map[string]struct{}, error) {
	if packagesDir == "" {
		return nil, nil
	}
	paths, err := citools.ListPackages(packagesDir)
	if err != nil {
		return nil, err
	}
	known := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		manifest, err := citools.ReadPackageManifest(filepath.Join(p, citools.ManifestFileName))
		if err != nil {
			return nil, fmt.Errorf("reading manifest at %s: %w", p, err)
		}
		known[manifest.Name] = struct{}{}
	}
	return known, nil
}
