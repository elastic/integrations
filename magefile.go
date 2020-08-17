// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build mage

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"
)

var (
	// GoImportsLocalPrefix is a string prefix matching imports that should be
	// grouped after third-party packages.
	GoImportsLocalPrefix = "github.com/elastic"

	buildDir        = "./build"
	integrationsDir = "./packages"
)

func Build() error {
	err := buildIntegrations()
	if err != nil {
		return err
	}

	err = dryRunPackageRegistry()
	if err != nil {
		return err
	}

	err = buildImportBeats()
	if err != nil {
		return err
	}
	return nil
}

func buildIntegrations() error {
	return runElasticPackageOnAllIntegrations("build")
}

func findIntegrations() ([]string, error) {
	var matches []string

	err := filepath.Walk(integrationsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		f, err := os.Stat(path)
		if err != nil {
			return err
		}

		if !f.IsDir() {
			return nil // skip as the path is not a directory
		}

		manifestPath := filepath.Join(path, "manifest.yml")
		_, err = os.Stat(manifestPath)
		if os.IsNotExist(err) {
			return nil
		}
		matches = append(matches, path)
		return filepath.SkipDir
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}

func dryRunPackageRegistry() error {
	err := sh.Run("go", "run", "github.com/elastic/package-registry", "-dry-run=true")
	if err != nil {
		return errors.Wrap(err, "package-registry dry-run failed")
	}
	return nil
}

func buildImportBeats() error {
	err := sh.Run("go", "build", "-o", "/dev/null", "./dev/import-beats")
	if err != nil {
		return errors.Wrap(err, "building import-beats failed")
	}
	return nil
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

func UpdatePackageStorage() error {
	err := Build()
	if err != nil {
		return err
	}

	args := []string{"run", "./dev/update-package-storage/"}
	if os.Getenv("SKIP_PULL_REQUEST") == "true" {
		args = append(args, "-skipPullRequest")
	}
	if os.Getenv("PACKAGES_SOURCE_DIR") != "" {
		args = append(args, "-packagesSourceDir", os.Getenv("PACKAGES_SOURCE_DIR"))
	}
	args = append(args, "*.go")
	return sh.Run("go", args...)
}

func GenerateDocs() error {
	args := []string{"run", "./dev/generate-docs/"}
	if os.Getenv("PACKAGES") != "" {
		args = append(args, "-packages", os.Getenv("PACKAGES"))
	}
	args = append(args, "*.go")
	return sh.Run("go", args...)
}

func Check() error {
	if err := Lint(); err != nil {
		return err
	}

	Format()

	err := Build()
	if err != nil {
		return err
	}

	err = GenerateDocs()
	if err != nil {
		return err
	}

	err = ModTidy()
	if err != nil {
		return err
	}

	// Check if no changes are shown
	err = sh.RunV("git", "update-index", "--refresh")
	if err != nil {
		return err
	}
	return sh.RunV("git", "diff-index", "--exit-code", "HEAD", "--")
}

func Reload() error {
	err := Build()
	if err != nil {
		return err
	}

	err = sh.RunV("docker-compose", "-f", "testing/environments/snapshot.yml", "build", "package-registry")
	if err != nil {
		return err
	}
	return sh.RunV("docker-compose", "-f", "testing/environments/snapshot.yml", "up", "-d", "package-registry")
}

// Format adds license headers, formats .go files with goimports, and formats
// .py files with autopep8.
func Format() {
	// Don't run AddLicenseHeaders and GoImports concurrently because they
	// both can modify the same files.
	mg.Deps(AddLicenseHeaders)
	mg.Deps(GoImports)
}

// Lint lint checks every package.
func Lint() error {
	return runElasticPackageOnAllIntegrations("lint")
}

// GoImports executes goimports against all .go files in and below the CWD. It
// ignores vendor/ directories.
func GoImports() error {
	goFiles, err := FindFilesRecursive(func(path string, _ os.FileInfo) bool {
		return filepath.Ext(path) == ".go" && !strings.Contains(path, "vendor/")
	})
	if err != nil {
		return err
	}
	if len(goFiles) == 0 {
		return nil
	}

	fmt.Println(">> fmt - goimports: Formatting Go code")
	args := append(
		[]string{"-local", GoImportsLocalPrefix, "-l", "-w"},
		goFiles...,
	)

	return sh.RunV("goimports", args...)
}

// AddLicenseHeaders adds license headers to .go files. It applies the
// appropriate license header based on the value of mage.BeatLicense.
func AddLicenseHeaders() error {
	fmt.Println(">> fmt - go-licenser: Adding missing headers")
	return sh.RunV("go-licenser", "-license", "Elastic")
}

// FindFilesRecursive recursively traverses from the CWD and invokes the given
// match function on each regular file to determine if the given path should be
// returned as a match.
func FindFilesRecursive(match func(path string, info os.FileInfo) bool) ([]string, error) {
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

func Clean() error {
	return os.RemoveAll(buildDir)
}

func ModTidy() error {
	fmt.Println(">> mod - updating vendor directory")

	err := sh.RunV("go", "mod", "tidy")
	if err != nil {
		return err
	}
	return nil
}

func runElasticPackageOnAllIntegrations(subcommand string) error {
	packagePaths, err := findIntegrations()
	if err != nil {
		return err
	}

	workDir, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "getwd failed")
	}

	for _, packagePath := range packagePaths {
		err := os.Chdir(filepath.Join(workDir, packagePath))
		if err != nil {
			return errors.Wrapf(err, "chdir failed (path: %s)", packagePath)
		}

		fmt.Printf("%s: elastic-package %s\n", packagePath, subcommand)
		err = sh.Run("go", "run", "github.com/elastic/elastic-package", subcommand)
		if err != nil {
			return errors.Wrapf(err, "elastic-package %s failed (path: %s)", subcommand, packagePath)
		}
	}

	err = os.Chdir(workDir)
	if err != nil {
		return errors.Wrapf(err, "chdir failed (path: %s)", workDir)
	}
	return nil
}