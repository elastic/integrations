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

func Check() error {
	mg.Deps(Format)
	mg.Deps(Lint)
	mg.Deps(Build)
	mg.Deps(GenerateDocs)
	mg.Deps(ModTidy)
	mg.Deps(Test)

	// Check if no changes are shown
	err := sh.RunV("git", "update-index", "--refresh")
	if err != nil {
		return err
	}
	return sh.RunV("git", "diff-index", "--exit-code", "HEAD", "--")
}

// Lint lint checks every package.
func Lint() error {
	return runElasticPackageOnAllIntegrations(true, "lint")
}

// Format adds license headers, formats .go files with goimports, and formats
// .py files with autopep8.
func Format() {
	// Don't run AddLicenseHeaders and GoImports concurrently because they
	// both can modify the same files.
	mg.Deps(addLicenseHeaders)
	mg.Deps(goImports)
	mg.Deps(formatIntegrations)
}

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
	return runElasticPackageOnAllIntegrations(true, "build")
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

func GenerateDocs() error {
	args := []string{"run", "./dev/generate-docs/"}
	if os.Getenv("PACKAGES") != "" {
		args = append(args, "-packages", os.Getenv("PACKAGES"))
	}
	args = append(args, "*.go")
	return sh.Run("go", args...)
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

// Format method formats integrations.
func formatIntegrations() error {
	return runElasticPackageOnAllIntegrations(true, "format")
}

// GoImports executes goimports against all .go files in and below the CWD. It
// ignores vendor/ directories.
func goImports() error {
	goFiles, err := findFilesRecursive(func(path string, _ os.FileInfo) bool {
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
func addLicenseHeaders() error {
	fmt.Println(">> fmt - go-licenser: Adding missing headers")
	return sh.RunV("go-licenser", "-license", "Elastic")
}

// findFilesRecursive recursively traverses from the CWD and invokes the given
// match function on each regular file to determine if the given path should be
// returned as a match.
func findFilesRecursive(match func(path string, info os.FileInfo) bool) ([]string, error) {
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

func Test() {
	mg.Deps(bootUpStack)
	defer tearDownStack()

	var failed bool
	err := testPipeline()
	if err != nil {
		failed = true
	}

	err = testSystem()
	if err != nil {
		failed = true
	}

	if failed {
		panic("testing failed")
	}
}

func testPipeline() error {
	cmdArgs := []string{"test", "pipeline"}
	cmdArgs = append(cmdArgs, strings.Split(os.Getenv("TEST_RUNNER_CMD_ARGS"), " ")...)
	return runElasticPackageOnAllIntegrations(false, cmdArgs...)
}

func testSystem() error {
	cmdArgs := []string{"test", "system"}
	cmdArgs = append(cmdArgs, strings.Split(os.Getenv("TEST_RUNNER_CMD_ARGS"), " ")...)
	return runElasticPackageOnAllIntegrations(false, cmdArgs...)
}

func bootUpStack() error {
	err := runElasticPackage("stack", "up", "-d")
	if err != nil {
		return err
	}
	return loadStackEnvs()
}

func loadStackEnvs() error {
	mg.Deps(buildElasticPackageBinary)

	workDir, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "getwd failed")
	}

	exports, err := sh.Output(filepath.Join(workDir, "build", "elastic-package"), "stack", "shellinit")
	if err != nil {
		return errors.Wrap(err, "shellinit failed")
	}

	exports = strings.ReplaceAll(exports, "export ", "")
	exportPerLine := strings.Split(exports, "\n")
	for _, record := range exportPerLine {
		keyValue := strings.Split(record, "=")
		if len(keyValue) != 2 {
			return fmt.Errorf("invalid export line: %s", record)
		}

		err = os.Setenv(keyValue[0], keyValue[1])
		if err != nil {
			return errors.Wrap(err, "can't set env variable")
		}
	}
	return nil
}

func tearDownStack() error {
	return runElasticPackage("stack", "down")
}

// runElasticPackageOnAllIntegrations runs the `elastic-package <subCommand>` tool on all
// packages with the given subCommand.
func runElasticPackageOnAllIntegrations(failFast bool, subCommandWithArgs ...string) error {
	packagePaths, err := findIntegrations()
	if err != nil {
		return err
	}

	workDir, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "getwd failed")
	}

	var failed bool
	for _, packagePath := range packagePaths {
		fmt.Printf("%s:\n", packagePath)
		err = runElasticPackageInWorkDir(filepath.Join(workDir, packagePath), subCommandWithArgs...)
		if err != nil && failFast {
			return err
		}
		if err != nil {
			failed = true
		}
	}
	if failed {
		return fmt.Errorf("command failed: elastic-package %s", strings.TrimSpace(strings.Join(subCommandWithArgs, " ")))
	}
	return nil
}

func runElasticPackage(subCommandWithArgs ...string) error {
	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "getwd failed")
	}
	return runElasticPackageInWorkDir(currentDir, subCommandWithArgs...)
}

func runElasticPackageInWorkDir(workDir string, subCommandWithArgs ...string) error {
	mg.Deps(buildElasticPackageBinary)

	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "getwd failed")
	}
	defer os.Chdir(currentDir)

	err = os.Chdir(workDir)
	if err != nil {
		return errors.Wrapf(err, "chdir failed (path: %s)", workDir)
	}

	fmt.Printf("elastic-package %s\n", strings.Join(subCommandWithArgs, " "))
	err = sh.RunV(filepath.Join(currentDir, "build", "elastic-package"), subCommandWithArgs...)
	if err != nil {
		return errors.Wrapf(err, "running elastic-package failed")
	}
	return nil
}

func buildElasticPackageBinary() error {
	err := sh.Run("go", "build", "-o", "./build/elastic-package", "github.com/elastic/elastic-package")
	if err != nil {
		return errors.Wrapf(err, "building elastic-package failed")
	}
	return nil
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
