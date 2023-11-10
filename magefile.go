// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"

	"github.com/elastic/integrations/dev/codeowners"
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

// func (Prepare) Env() {
// 	mg.Deps(Mkdir("build"), Build.GenerateConfig)
// 	RunGo("version")
// 	RunGo("env")
// }

// func (Build) GenerateConfig() error {
// 	mg.Deps(Mkdir(buildDir))
// 	return sh.Copy(filepath.Join(buildDir, configFile), filepath.Join(metaDir, configFile))
// }

// func (Build) TestBinaries() error {
// 	wd, _ := os.Getwd()
// 	testBinaryPkgs := []string{
// 		filepath.Join(wd, "pkg", "component", "fake", "component"),
// 		filepath.Join(wd, "pkg", "component", "fake", "shipper"),
// 		filepath.Join(wd, "internal", "pkg", "agent", "install", "testblocking"),
// 	}
// 	for _, pkg := range testBinaryPkgs {
// 		binary := filepath.Base(pkg)
// 		if runtime.GOOS == "windows" {
// 			binary += ".exe"
// 		}

// 		outputName := filepath.Join(pkg, binary)
// 		err := RunGo("build", "-o", outputName, filepath.Join(pkg))
// 		if err != nil {
// 			return err
// 		}
// 		err = os.Chmod(outputName, 0755)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

// // UnitTest performs unit test on agent.
// func UnitTest() {
// 	mg.Deps(Test.All)
// }

// // RunGo runs go command and output the feedback to the stdout and the stderr.
// func RunGo(args ...string) error {
// 	return sh.RunV(mg.GoCmd(), args...)
// }

// // All runs all the tests.
// func (Test) All() {
// 	mg.SerialDeps(Test.Unit)
// }

// // Unit runs all the unit tests.
// func (Test) Unit(ctx context.Context) error {
// 	mg.Deps(Prepare.Env, Build.TestBinaries)
// 	params := devtools.DefaultGoTestUnitArgs()
// 	return devtools.GoTest(ctx, params)
// }

// // Coverage takes the coverages report from running all the tests and display the results in the browser.
// func (Test) Coverage() error {
// 	mg.Deps(Prepare.Env, Build.TestBinaries)
// 	return RunGo("tool", "cover", "-html="+filepath.Join(buildDir, "coverage.out"))
// }
