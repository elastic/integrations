// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package packagenames

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/elastic/integrations/dev/citools"
)

const (
	packagesDir                  = "packages"
	elasticPackageModulePath     = "github.com/elastic/elastic-package"
	elasticPackageFindMinVersion = "0.118.0"
	goModPath                    = "go.mod"
	elasticPackageBinaryName     = "elastic-package"
	elasticPackageCIPath         = "build/elastic-package"
)

// Check validates that no two packages share the same name under the default packages directory.
func Check() error {
	if err := checkPackageNames(packagesDir); err != nil {
		return fmt.Errorf("error validating package names in directory '%s': %w", packagesDir, err)
	}
	return nil
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
		manifestPath := filepath.Join(path, "manifest.yml")
		manifest, err := readManifest(manifestPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("error reading manifest %s: %w", manifestPath, err)
		}
		if !manifest.isValid() {
			return nil
		}
		paths = append(paths, path)
		return filepath.SkipDir
	})
	return paths, err
}

func elasticPackageBinaryPath() (string, bool) {
	if workspace := os.Getenv("WORKSPACE"); workspace != "" {
		ciPath := filepath.Join(workspace, elasticPackageCIPath)
		if _, err := os.Stat(ciPath); err == nil {
			return ciPath, true
		}
	}
	if path, err := exec.LookPath(elasticPackageBinaryName); err == nil {
		return path, true
	}
	return "", false
}

func findPackagePaths(dir string) ([]string, error) {
	binaryPath, found := elasticPackageBinaryPath()
	if !found {
		return walkPackagePaths(dir)
	}

	version, err := citools.PackageVersionGoMod(goModPath, elasticPackageModulePath)
	if err != nil {
		return nil, fmt.Errorf("error reading elastic-package version from go.mod: %w", err)
	}

	minVersion := semver.MustParse(elasticPackageFindMinVersion)
	if !version.LessThan(minVersion) {
		return elasticPackageFind(binaryPath, dir)
	}
	return walkPackagePaths(dir)
}

func elasticPackageFind(binaryPath, dir string) ([]string, error) {
	cmd := exec.Command(binaryPath, "-C", dir, "find")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running elastic-package find: %w", err)
	}

	var paths []string
	scanner := bufio.NewScanner(strings.NewReader(string(stdout)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			paths = append(paths, line)
		}
	}
	return paths, scanner.Err()
}

func checkDuplicateNames(paths []string) error {
	seen := make(map[string][]string)
	for _, path := range paths {
		manifest, err := readManifest(filepath.Join(path, "manifest.yml"))
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

func checkPackageNames(dir string) error {
	paths, err := findPackagePaths(dir)
	if err != nil {
		return fmt.Errorf("error finding packages: %w", err)
	}
	return checkDuplicateNames(paths)
}
