// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build mage

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"

	"github.com/elastic/package-registry/util"
)

var (
	// GoImportsImportPath controls the import path used to install goimports.
	GoImportsImportPath = "golang.org/x/tools/cmd/goimports"

	// GoImportsLocalPrefix is a string prefix matching imports that should be
	// grouped after third-party packages.
	GoImportsLocalPrefix = "github.com/elastic"

	// GoLicenserImportPath controls the import path used to install go-licenser.
	GoLicenserImportPath = "github.com/elastic/go-licenser"

	buildDir           = "./build"
	publicDir          = filepath.Join(buildDir, "public")
	storageRepoDir     = filepath.Join(buildDir, "package-storage")
	storagePackagesDir = filepath.Join(buildDir, "package-storage-packages")
	packagePaths       = []string{storagePackagesDir, "./packages"}

	fieldsToEncode = []string{
		"attributes.kibanaSavedObjectMeta.searchSourceJSON",
		"attributes.layerListJSON",
		"attributes.mapStateJSON",
		"attributes.optionsJSON",
		"attributes.panelsJSON",
		"attributes.uiStateJSON",
		"attributes.visState",
	}
)

type fieldEntry struct {
	name  string
	aType string
}

func Build() error {
	err := buildPublicDirectory()
	if err != nil {
		return err
	}

	err = fetchPackageStorage()
	if err != nil {
		return err
	}

	err = buildPackages()
	if err != nil {
		return err
	}

	err = dryRunPackageRegistry()
	if err != nil {
		return err
	}
	return nil
}

func buildPublicDirectory() error {
	err := os.MkdirAll(publicDir, 0755)
	if err != nil {
		return err
	}

	err = os.RemoveAll(filepath.Join(publicDir, "package"))
	if err != nil {
		return err
	}
	return nil
}

func fetchPackageStorage() error {
	_, err := os.Stat(storagePackagesDir)
	if err == nil {
		return nil // package storage has been already fetched
	}

	err = sh.Run("git", "clone", "https://github.com/elastic/package-storage.git", storageRepoDir)
	if err != nil {
		return err
	}

	packageStorageRevision := os.Getenv("PACKAGE_STORAGE_REVISION")
	if packageStorageRevision == "" {
		packageStorageRevision = "master"
	}

	err = sh.Run("git",
		"--git-dir", filepath.Join(storageRepoDir, ".git"),
		"--work-tree", storageRepoDir,
		"checkout",
		packageStorageRevision)
	if err != nil {
		return err
	}

	err = os.MkdirAll(storagePackagesDir, 0755)
	if err != nil {
		return err
	}

	err = sh.Run("rsync", "-a",
		filepath.Join(storageRepoDir, "packages", "base")+"/",
		filepath.Join(storagePackagesDir, "base"))
	if err != nil {
		return err
	}
	return sh.Run("rsync", "-a",
		filepath.Join(storageRepoDir, "packages", "endpoint")+"/",
		filepath.Join(storagePackagesDir, "endpoint"))
}

func buildPackages() error {
	packagePaths, err := findPackages()
	if err != nil {
		return err
	}

	for _, packagePath := range packagePaths {
		srcDir := packagePath + "/"
		p, err := util.NewPackage(srcDir)
		if err != nil {
			return err
		}
		dstDir := filepath.Join(publicDir, "package", p.Name, p.Version)

		err = copyPackageFromSource(srcDir, dstDir)
		if err != nil {
			return err
		}

		err = encodeDashboards(dstDir)
		if err != nil {
			return err
		}
	}
	return nil
}

func findPackages() ([]string, error) {
	var matches []string
	for _, sourceDir := range packagePaths {
		err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
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
	}
	return matches, nil
}

func copyPackageFromSource(src, dst string) error {
	err := os.MkdirAll(dst, 0755)
	if err != nil {
		return err
	}
	err = sh.RunV("rsync", "-a", src, dst)
	if err != nil {
		return err
	}

	return nil
}

func encodeDashboards(dstDir string) error {
	savedObjects, err := filepath.Glob(filepath.Join(dstDir, "kibana", "*", "*"))
	if err != nil {
		return err
	}
	for _, file := range savedObjects {

		data, err := ioutil.ReadFile(file)
		if err != nil {
			return err
		}
		output, changed, err := encodedSavedObject(data)
		if err != nil {
			return err
		}

		if changed {
			err = ioutil.WriteFile(file, output, 0644)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// encodeSavedObject encodes all the fields inside a saved object
// which are stored in encoded JSON in Kibana.
// The reason is that for versioning it is much nicer to have the full
// json so only on packaging this is changed.
func encodedSavedObject(data []byte) ([]byte, bool, error) {
	savedObject := MapStr{}
	err := json.Unmarshal(data, &savedObject)
	if err != nil {
		return nil, false, errors.Wrapf(err, "unmarshalling saved object failed")
	}

	var changed bool
	for _, v := range fieldsToEncode {
		out, err := savedObject.GetValue(v)
		// This means the key did not exists, no conversion needed.
		if err != nil {
			continue
		}

		// It may happen that some objects existing in example directory might be already encoded.
		// In this case skip encoding the field and move to the next one.
		_, isString := out.(string)
		if isString {
			continue
		}

		// Marshal the value to encode it properly.
		r, err := json.Marshal(&out)
		if err != nil {
			return nil, false, err
		}
		_, err = savedObject.Put(v, string(r))
		if err != nil {
			return nil, false, errors.Wrapf(err, "can't put value to the saved object")
		}
		changed = true
	}
	return []byte(savedObject.StringToPrint()), changed, nil
}

func dryRunPackageRegistry() error {
	currentDir, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "reading current directory failed")
	}
	defer os.Chdir(currentDir)

	err = os.Chdir(buildDir)
	if err != nil {
		return errors.Wrapf(err, "can't change directory to %s", buildDir)
	}

	err = sh.Run("go", "run", "github.com/elastic/package-registry", "-dry-run=true")
	if err != nil {
		return errors.Wrap(err, "package-registry dry-run failed")
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

func Check() error {
	Format()

	err := Build()
	if err != nil {
		return err
	}

	err = Vendor()
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

// Format adds license headers, formats .go files with goimports, and formats
// .py files with autopep8.
func Format() {
	// Don't run AddLicenseHeaders and GoImports concurrently because they
	// both can modify the same files.
	mg.Deps(AddLicenseHeaders)
	mg.Deps(GoImports)
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

func Vendor() error {
	fmt.Println(">> mod - updating vendor directory")

	err := sh.RunV("go", "mod", "tidy")
	if err != nil {
		return err
	}

	err = sh.RunV("go", "mod", "vendor")
	if err != nil {
		return err
	}

	err = sh.RunV("go", "mod", "verify")
	if err != nil {
		return err
	}
	return nil
}
