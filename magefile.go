// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"

	"github.com/elastic/integrations/dev/codeowners"
	"github.com/elastic/integrations/dev/coverage"
	"github.com/elastic/integrations/dev/testsreporter"
)

const (
	defaultResultsPath           = "build/test-results/"
	defaultPreviousLinksNumber   = 5
	defaultMaximumTestsReported  = 20
	defaultServerlessProjectType = "observability"
)

var (
	// GoImportsLocalPrefix is a string prefix matching imports that should be
	// grouped after third-party packages.
	GoImportsLocalPrefix = "github.com/elastic"

	buildDir = "./build"
)

func Check() error {
	mg.Deps(build)
	mg.Deps(format)
	mg.Deps(ModTidy)
	mg.Deps(goTest)
	mg.Deps(codeowners.Check)
	return nil
}

func Clean() error {
	return os.RemoveAll(buildDir)
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

func MergeCoverage() error {
	coverageFiles, err := filepath.Glob("build/test-coverage/coverage-*.xml")
	if err != nil {
		return fmt.Errorf("glob failed: %w", err)
	}
	return coverage.MergeGenericCoverageFiles(coverageFiles, "build/test-coverage/coverage_merged.xml")
}

func build() error {
	mg.Deps(buildImportBeats)
	return nil
}

func buildImportBeats() error {
	err := sh.Run("go", "build", "-o", "/dev/null", "./dev/import-beats")
	if err != nil {
		return errors.Wrap(err, "building import-beats failed")
	}
	return nil
}

func format() {
	mg.Deps(addLicenseHeaders)
	mg.Deps(goImports)
}

func addLicenseHeaders() error {
	return sh.RunV("go", "run", "github.com/elastic/go-licenser", "-license", "Elastic")
}

func goImports() error {
	goFiles, err := findFilesRecursive(func(path string, _ os.FileInfo) bool {
		return filepath.Ext(path) == ".go"
	})
	if err != nil {
		return err
	}
	if len(goFiles) == 0 {
		return nil
	}

	args := append(
		[]string{"run", "golang.org/x/tools/cmd/goimports", "-local", GoImportsLocalPrefix, "-l", "-w"},
		goFiles...,
	)
	return sh.RunV("go", args...)
}

func goTest() error {
	args := []string{"test"}
	stdout := io.Discard
	stderr := io.Discard
	if mg.Verbose() {
		args = append(args, "-v")
		stdout = os.Stdout
		stderr = os.Stderr
	}
	args = append(args, "./dev/...")
	_, err := sh.Exec(nil, stdout, stderr, "go", args...)
	return err
}

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

func ModTidy() error {
	return sh.RunV("go", "mod", "tidy")
}

func ReportFailedTests(testResultsFolder string) error {
	stackVersion := os.Getenv("STACK_VERSION")
	serverlessEnv := os.Getenv("SERVERLESS")
	serverlessProjectEnv := os.Getenv("SERVERLESS_PROJECT")
	buildURL := os.Getenv("BUILDKITE_BUILD_URL")

	serverless := false
	if serverlessEnv != "" {
		var err error
		serverless, err = strconv.ParseBool(serverlessEnv)
		if err != err {
			return fmt.Errorf("failed to parse SERVERLESS value: %w", err)
		}
		if serverlessProjectEnv == "" {
			serverlessProjectEnv = defaultServerlessProjectType
		}
	}

	maxIssuesString := os.Getenv("CI_MAX_TESTS_REPORTED")
	maxIssues := defaultMaximumTestsReported
	if maxIssuesString != "" {
		var err error
		maxIssues, err = strconv.Atoi(maxIssuesString)
		if err != nil {
			return fmt.Errorf("failed to convert to int env. variable CI_MAX_TESTS_REPORTED %s: %w", maxIssuesString, err)
		}
	}

	mg.Deps(mg.F(testsreporter.Check, testResultsFolder, buildURL, stackVersion, serverless, serverlessProjectEnv, defaultPreviousLinksNumber, maxIssues))
	return nil
}
