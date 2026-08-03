// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package packagenames

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/elastic/integrations/dev/citools"
)

const packagesDir = "packages"

// Check validates that no two packages share the same name under the default packages directory.
func Check() error {
	if err := checkPackageNames(packagesDir); err != nil {
		return fmt.Errorf("error validating package names in directory '%s': %w", packagesDir, err)
	}
	return nil
}

func checkPackageNames(dir string) error {
	paths, err := citools.ListPackages(dir)
	if err != nil {
		return fmt.Errorf("error finding packages: %w", err)
	}
	return checkDuplicateNames(paths)
}

func checkDuplicateNames(paths []string) error {
	seen := make(map[string][]string)
	for _, path := range paths {
		manifest, err := citools.ReadPackageManifest(filepath.Join(path, citools.ManifestFileName))
		if err != nil {
			return fmt.Errorf("error reading manifest in %s: %w", path, err)
		}
		seen[manifest.Name] = append(seen[manifest.Name], path)
	}

	var duplicates []string
	for name, dirs := range seen {
		if len(dirs) > 1 {
			duplicates = append(duplicates, fmt.Sprintf("duplicate package name %q found in: %s", name, strings.Join(dirs, ", ")))
		}
	}

	if len(duplicates) > 0 {
		slices.Sort(duplicates)
		return fmt.Errorf("found duplicate package names:\n%s", strings.Join(duplicates, "\n"))
	}
	return nil
}
