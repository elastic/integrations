// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package packagenames

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
)

const (
	packagesDir      = "packages"
	manifestFileName = "manifest.yml"
)

// Check validates that no two packages share the same name under the default packages directory.
func Check() error {
	if err := checkPackageNames(packagesDir); err != nil {
		return fmt.Errorf("error validating package names in directory '%s': %w", packagesDir, err)
	}
	return nil
}

func checkPackageNames(dir string) error {
	paths, err := walkPackagePaths(dir)
	if err != nil {
		return fmt.Errorf("error finding packages: %w", err)
	}
	return checkDuplicateNames(paths)
}

func walkPackagePaths(dir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		manifestPath := filepath.Join(path, manifestFileName)
		manifest, err := readManifest(manifestPath)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		} else if err != nil {
			return fmt.Errorf("error reading manifest %s: %w", manifestPath, err)
		}
		if !manifest.isValid() {
			return nil
		}
		paths = append(paths, path)
		// No need to look deeper, we already found a package.
		return filepath.SkipDir
	})
	return paths, err
}

func checkDuplicateNames(paths []string) error {
	seen := make(map[string][]string)
	for _, path := range paths {
		manifest, err := readManifest(filepath.Join(path, manifestFileName))
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
