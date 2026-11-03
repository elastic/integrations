// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const binaryName = "backport"

// binPath returns the output path for the binary: ../../build/backport relative
// to cmd/backport/, which resolves to the repo root's build/ directory.
// build/ is gitignored, matching the elastic-package convention.
func binPath() string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	return filepath.Join("..", "..", "build", binaryName+ext)
}

// Build compiles the backport binary into the repo root's build/ directory.
func Build() error {
	out := binPath()
	fmt.Printf("Building %s → %s\n", binaryName, out)
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return fmt.Errorf("creating build dir: %w", err)
	}
	return sh.Run("go", "build", "-o", out, ".")
}

// Install installs the backport binary to $GOBIN (or $GOPATH/bin).
func Install() error {
	fmt.Printf("Installing %s...\n", binaryName)
	return sh.Run("go", "install", ".")
}

// Test runs the unit tests for the backport tool.
func Test() error {
	return sh.Run("go", "test", "./...")
}

// Tidy runs go mod tidy for the backport sub-module.
func Tidy() error {
	return sh.Run("go", "mod", "tidy")
}

// Clean removes the compiled binary from build/.
func Clean() error {
	bin := binPath()
	if err := os.Remove(bin); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", bin, err)
	}
	return nil
}

// BuildPath compiles the backport binary and prints its absolute path.
// Useful for CI steps that need to know the binary location.
func BuildPath() error {
	if err := Build(); err != nil {
		return err
	}
	abs, err := filepath.Abs(binPath())
	if err != nil {
		return err
	}
	fmt.Println(abs)
	return nil
}

// Format runs goimports and ensures Elastic license headers are present.
func Format() {
	mg.Deps(addLicenseHeaders, goImports)
}

func addLicenseHeaders() error {
	return sh.RunV("go", "run", "github.com/elastic/go-licenser", "-license", "Elastic")
}

func goImports() error {
	goFiles, err := findGoFiles()
	if err != nil {
		return err
	}
	if len(goFiles) == 0 {
		return nil
	}
	args := append([]string{"run", "golang.org/x/tools/cmd/goimports", "-local", "github.com/elastic", "-l", "-w"}, goFiles...)
	return sh.RunV("go", args...)
}

func findGoFiles() ([]string, error) {
	var files []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && filepath.Ext(path) == ".go" {
			files = append(files, filepath.ToSlash(path))
		}
		return nil
	})
	return files, err
}

// Check runs Build, Format, Tidy, and Test — the full pre-push validation suite.
func Check() error {
	mg.Deps(Build)
	mg.Deps(Format)
	mg.Deps(Tidy)
	mg.Deps(Test)
	return nil
}
