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
