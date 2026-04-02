// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package packagenames

import (
	"bufio"
	"bytes"
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
	manifestFileName             = "manifest.yml"
)

// Check validates that no two packages share the same name under the default packages directory.
func Check() error {
	if err := checkPackageNames(packagesDir); err != nil {
		return fmt.Errorf("error validating package names in directory '%s': %w", packagesDir, err)
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

func findPackagePaths(dir string) ([]string, error) {
	// Assumption, the elastic-package binary found in PATH or via ELASTIC_PACKAGE_BIN is the same version as the one used in go.mod, if it exists.
	// If the binary is not found or the version is less than 0.118.0, we will fall back to a recursive walk to find packages.
	binaryPath, found := elasticPackageBinaryPath()
	if !found {
		fmt.Println("elastic-package binary not found, using recursive walk to find packages")
		return walkPackagePaths(dir)
	}

	version, err := citools.PackageVersionGoMod(goModPath, elasticPackageModulePath)
	if err != nil {
		fmt.Printf("could not determine elastic-package version from go.mod (%v), using recursive walk to find packages\n", err)
		return walkPackagePaths(dir)
	}

	minVersion := semver.MustParse(elasticPackageFindMinVersion)
	if version.LessThan(minVersion) {
		fmt.Printf("elastic-package %s < %s, using recursive walk to find packages\n", version, elasticPackageFindMinVersion)
		return walkPackagePaths(dir)
	}
	fmt.Printf("elastic-package %s >= %s, using \"elastic-package find\" to find packages\n", version, elasticPackageFindMinVersion)
	return elasticPackageFind(binaryPath, dir)
}

func elasticPackageBinaryPath() (string, bool) {
	// ELASTIC_PACKAGE_BIN is set by CI and points to the elastic-package binary.
	if ciPath := os.Getenv("ELASTIC_PACKAGE_BIN"); ciPath != "" {
		if _, err := os.Stat(ciPath); err == nil {
			return ciPath, true
		}
	}
	if path, err := exec.LookPath(elasticPackageBinaryName); err == nil {
		return path, true
	}
	return "", false
}

func elasticPackageFind(binaryPath, dir string) ([]string, error) {
	cmd := exec.Command(binaryPath, "-C", dir, "find")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running elastic-package find: %w", err)
	}

	var paths []string
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			paths = append(paths, line)
		}
	}
	return paths, scanner.Err()
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
