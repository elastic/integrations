// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package backports

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"

	"github.com/elastic/integrations/dev/citools"
)

type inventory struct {
	Backports []entry `yaml:"backports"`
}

type entry struct {
	Package         string  `yaml:"package"`
	Branch          string  `yaml:"branch"`
	BaseVersion     string  `yaml:"base_version"`
	BaseCommit      string  `yaml:"base_commit"`
	MaintainedUntil *string `yaml:"maintained_until"` // null → nil; "YYYY-MM-DD" → &string
	Archived        *bool   `yaml:"archived"`         // nil when field is absent
}

const maintainedUntilLayout = "2006-01-02"

// shaRE matches a lowercase hexadecimal git SHA (short or full, 7–40 chars).
var shaRE = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// branchRE matches a valid backport branch name:
//
//	backport-<package>-<version>
//
// where <package> is one or more letters, digits, or underscores, and
// <version> starts with a digit followed by digits, dots, and an optional
// trailing 'x' wildcard (e.g. "6.x" or "6.14.x").
// Whitespace, quotes, colons, semicolons, and all other special characters
// are not permitted.
var branchRE = regexp.MustCompile(`^backport-[a-zA-Z0-9_]+-[0-9][0-9.]*x?$`)

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
		id := fmt.Sprintf("entry[%d]", i)
		if e.Branch != "" {
			id = fmt.Sprintf("branch %q", e.Branch)
		}

		if e.Package == "" {
			errs = append(errs, fmt.Errorf("%s: missing required field 'package'", id))
		} else if knownPackages != nil {
			if _, ok := knownPackages[e.Package]; !ok {
				errs = append(errs, fmt.Errorf("%s: unknown package %q: not found under %s", id, e.Package, packagesDir))
			}
		}

		if e.Branch == "" {
			errs = append(errs, fmt.Errorf("%s: missing required field 'branch'", id))
		} else if !branchRE.MatchString(e.Branch) {
			errs = append(errs, fmt.Errorf("%s: invalid branch %q: must match backport-<package>-<version> "+
				"(letters/digits/underscores in package name, version starts with a digit; "+
				"no whitespace, quotes, colons, semicolons or other special characters)", id, e.Branch))
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
		if e.MaintainedUntil != nil {
			if _, parseErr := time.Parse(maintainedUntilLayout, *e.MaintainedUntil); parseErr != nil {
				errs = append(errs, fmt.Errorf("%s: invalid maintained_until %q: must be YYYY-MM-DD", id, *e.MaintainedUntil))
			}
		}
	}

	return errors.Join(errs...)
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
