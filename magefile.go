// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Masterminds/semver/v3"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"

	"github.com/elastic/integrations/dev/citools"
	"github.com/elastic/integrations/dev/codeowners"
	"github.com/elastic/integrations/dev/coverage"
	"github.com/elastic/integrations/dev/testsreporter"
)

const (
	defaultResultsPath           = "build/test-results/"
	defaultPreviousLinksNumber   = 5
	defaultMaximumTestsReported  = 20
	defaultServerlessProjectType = "observability"

	elasticPackageModulePath = "github.com/elastic/elastic-package"
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
	args := []string{"run", "gotest.tools/gotestsum", "--format", "testname", "--junitfile", "tests-report.xml"}
	stdout := io.Discard
	stderr := io.Discard
	if mg.Verbose() {
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

func ReportFailedTests(ctx context.Context, testResultsFolder string) error {
	stackVersion := os.Getenv("STACK_VERSION")
	serverlessEnv := os.Getenv("SERVERLESS")
	dryRunEnv := os.Getenv("DRY_RUN")
	serverlessProjectEnv := os.Getenv("SERVERLESS_PROJECT")
	buildURL := os.Getenv("BUILDKITE_BUILD_URL")
	subscription := os.Getenv("ELASTIC_SUBSCRIPTION")

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

	logsDBEnabled := false
	if v, found := os.LookupEnv("STACK_LOGSDB_ENABLED"); found && v == "true" {
		logsDBEnabled = true
	}

	verboseMode := false
	if v, found := os.LookupEnv("VERBOSE_MODE_ENABLED"); found && v == "true" {
		verboseMode = true
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

	dryRun := false
	if dryRunEnv != "" {
		var err error
		dryRun, err = strconv.ParseBool(dryRunEnv)
		if err != err {
			return fmt.Errorf("failed to parse DRY_RUN value: %w", err)
		}
	}

	options := testsreporter.CheckOptions{
		Serverless:        serverless,
		ServerlessProject: serverlessProjectEnv,
		LogsDB:            logsDBEnabled,
		StackVersion:      stackVersion,
		Subscription:      subscription,
		BuildURL:          buildURL,
		MaxPreviousLinks:  defaultPreviousLinksNumber,
		MaxTestsReported:  maxIssues,
		DryRun:            dryRun,
		Verbose:           verboseMode,
	}
	return testsreporter.Check(ctx, testResultsFolder, options)
}

// IsSubscriptionCompatible checks whether or not the package in the current directory allows to run with the given subscription (ELASTIC_SUBSCRIPTION env var).
func IsSubscriptionCompatible() error {
	subscription := os.Getenv("ELASTIC_SUBSCRIPTION")
	if subscription == "" {
		fmt.Println("true")
		return nil
	}

	supported, err := citools.IsSubscriptionCompatible(subscription, "manifest.yml")
	if err != nil {
		return err
	}
	if supported {
		fmt.Println("true")
		return nil
	}
	fmt.Println("false")
	return nil
}

// KibanaConstraintPackage returns the Kibana version constraint defined in the package manifest
func KibanaConstraintPackage() error {
	constraint, err := citools.KibanaConstraintPackage("manifest.yml")
	if err != nil {
		return fmt.Errorf("faile")
	}
	if constraint == nil {
		fmt.Println("null")
		return nil
	}
	fmt.Println(constraint)
	return nil
}

// IsSupportedStack checks whether or not the package in the current directory is allowed to be installed in the given stack version
func IsSupportedStack(stackVersion string) error {
	if stackVersion == "" {
		fmt.Println("true")
		return nil
	}

	supported, err := citools.IsPackageSupportedInStackVersion(stackVersion, "manifest.yml")
	if err != nil {
		return err
	}

	if supported {
		fmt.Println("true")
		return nil
	}
	fmt.Println("false")
	return nil
}

// IsLogsDBSupportedInPackage checks whether or not the package in the current directory supports LogsDB
func IsLogsDBSupportedInPackage() error {
	supported, err := citools.IsLogsDBSupportedInPackage("manifest.yml")
	if err != nil {
		return err
	}
	if !supported {
		fmt.Println("false")
		return nil
	}
	fmt.Println("true")
	return nil
}

// IsVersionLessThanLogsDBGA checks whether or not the given version supports LogsDB. Minimum version that supports LogsDB as GA 8.17.0.
func IsVersionLessThanLogsDBGA(version string) error {
	stackVersion, err := semver.NewVersion(version)
	if err != nil {
		return fmt.Errorf("failed to parse version %q: %w", version, err)
	}
	lessThan := citools.IsVersionLessThanLogsDBGA(stackVersion)
	if lessThan {
		fmt.Println("true")
		return nil
	}
	fmt.Println("false")
	return nil
}

// IsElasticPackageDependencyLessThan checks whether or not the elastic-package version set in go.mod is less than the given version
func IsElasticPackageDependencyLessThan(version string) error {
	foundVersion, err := citools.PackageVersionGoMod("go.mod", elasticPackageModulePath)
	if err != nil {
		return fmt.Errorf("failed to get elastic-package version from go.mod: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Found elastic-package %s\n", foundVersion)

	desiredVersion, err := semver.NewVersion(version)
	if err != nil {
		return fmt.Errorf("failed to parse version %q: %w", version, err)
	}

	value := "false"
	if foundVersion.LessThan(desiredVersion) {
		value = "true"
	}

	fmt.Println(value)
	return nil
}
