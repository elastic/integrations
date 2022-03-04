// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"bufio"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var (
	// GoImportsLocalPrefix is a string prefix matching imports that should be
	// grouped after third-party packages.
	GoImportsLocalPrefix = "github.com/elastic"
)

const (
	buildDir = "./build"

	codeownersPath = ".github/CODEOWNERS"
)

func Check() error {
	mg.Deps(build)
	mg.Deps(format)
	mg.Deps(modTidy)
	mg.Deps(checkPackageOwners)
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
	return sh.RunV("go-licenser", "-license", "Elastic")
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
		[]string{"-local", GoImportsLocalPrefix, "-l", "-w"},
		goFiles...,
	)
	return sh.RunV("goimports", args...)
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

func modTidy() error {
	return sh.RunV("go", "mod", "tidy")
}

func checkPackageOwners() error {
	codeowners, err := readGithubOwners()
	if err != nil {
		return err
	}

	const packagesDir = "packages"
	return filepath.WalkDir(packagesDir, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			if path != packagesDir && filepath.Dir(path) != packagesDir {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "manifest.yml" {
			return nil
		}

		return codeowners.checkManifest(path)
	})
}

type githubOwners map[string][]string

func readGithubOwners() (githubOwners, error) {
	f, err := os.Open(codeownersPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %q", codeownersPath)
	}
	defer f.Close()

	codeowners := make(githubOwners)

	scanner := bufio.NewScanner(f)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, errors.Errorf("invalid line %d in %q: %q", lineNumber, codeownersPath, line)
		}
		path, owners := fields[0], fields[1:]

		// It is ok to overwrite because latter lines have precedence in these files.
		codeowners[path] = owners
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrapf(err, "scanner error")
	}

	return codeowners, nil
}

func (codeowners githubOwners) checkManifest(path string) error {
	pkgDir := filepath.Dir(path)
	owners, found := codeowners["/"+pkgDir]
	if !found {
		return errors.Errorf("there is no owner for %q in %q", pkgDir, codeownersPath)
	}

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	var manifest struct {
		Owner struct {
			Github string `yaml:"github"`
		} `yaml:"owner"`
	}
	err = yaml.Unmarshal(content, &manifest)
	if err != nil {
		return err
	}

	if manifest.Owner.Github == "" {
		return errors.Errorf("no owner specified in %q", path)
	}

	found = false
	for _, owner := range owners {
		if owner == "@"+manifest.Owner.Github {
			found = true
			break
		}
	}
	if !found {
		return errors.Errorf("owner %q defined in %q is not in %q", manifest.Owner.Github, path, codeownersPath)
	}
	return nil
}
