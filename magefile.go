// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build mage

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"gopkg.in/yaml.v2"
)

func Export() error {

	err := os.RemoveAll("./build")
	if err != nil {
		return err
	}

	integrations, _ := filepath.Glob("./tools/exporter/integrations/*")

	for _, i := range integrations {
		err = sh.RunV("go", "run", "./tools/exporter/main.go", "--path="+i)
		if err != nil {
			return err
		}
	}

	err = sh.RunV("go", "run", "./tools/exporter/main.go", "--path=./tools/exporter/integrations/envoyproxy-logs.yml")
	if err != nil {
		return err
	}

	return nil
}

func Package() error {

	integrations, err := filepath.Glob("integration/*")
	if err != nil {
		return err
	}

	for _, i := range integrations {
		info, err := os.Stat(i)
		if err != nil {
			return err
		}

		if info.IsDir() {
			err = packageIntegration(filepath.Base(i))
			if err != nil {
				return err
			}
		}
	}
	fmt.Println(">> Packaging completed")

	return nil
}

func packageIntegration(p string) error {

	err := os.MkdirAll("build/packages", 0755)
	if err != nil {
		return err
	}

	// TODO: Make version dynamic
	path := "integration/" + p
	m := &Manifest{}

	f, err := ioutil.ReadFile(path + "/manifest.yml")
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(f, m)
	if err != nil {
		return err
	}

	if m.Package != nil && !*m.Package {
		return nil
	}

	// Create package directory
	packagePath := "build/packages/" + p + "-" + m.Version
	err = os.MkdirAll(packagePath, 0755)
	if err != nil {
		return err
	}

	localDatasets, err := filepath.Glob(path + "/dataset/*")
	if err != nil {
		return err
	}

	for _, dataset := range localDatasets {
		info, _ := os.Stat(dataset)
		// Skip non directories
		if !info.IsDir() {
			continue
		}
		copyDataset(dataset, packagePath)
	}

	for _, ds := range m.DataSets {
		// Copy external datasets
		parts := strings.Split(ds["name"], ":")
		if len(parts) != 2 {
			return fmt.Errorf("Definition of the dataset dependencies wrong. Make sure it is {integration}:{dataset}: %s", ds)
		}
		path := "integration/" + parts[0] + "/dataset/" + parts[1]

		_, err := os.Stat(path)
		if err != nil {
			return err
		}

		copyDataset(path, packagePath)
	}

	// Copy manifest
	err = copyFile(path+"/manifest.yml", packagePath+"/manifest.yml")
	if err != nil {
		return err
	}

	// Collect config options from

	// Read a module manifest for the version and dataset
	// Collect all dataset assets into 1 single directory
	// Do renaming where needed?

	// Create zip file
	return nil
}

// Clean removes the build directory
func Clean() error {
	return os.RemoveAll("build")
}

func copyDataset(dataset, dest string) error {

	files, _ := filepath.Glob(dataset + "/*/*/*")

	for _, f := range files {
		// Skips tests files
		if strings.Contains(f, "/tests/") {
			continue
		}
		fileName := renameFile(f, dest)
		err := os.MkdirAll(filepath.Dir(fileName), 0755)
		if err != nil {
			return err
		}

		// Each asset must be prefixed by the integration.dataset to make sure it's unique
		err = copyFile(f, fileName)
		if err != nil {
			return err
		}
	}

	d, _ := filepath.Glob(dataset + "/fields/fields.yml")

	for _, g := range d {
		newName := renameFile2(g, dest)
		err := os.MkdirAll(filepath.Dir(newName), 0755)
		if err != nil {
			return err
		}

		// Each asset must be prefixed by the integration.dataset to make sure it's unique
		err = copyFile(g, newName)
		if err != nil {
			return err
		}
	}

	// TODO create template based on fields.yml files

	return nil
}

func renameFile(source, dest string) string {
	parts := strings.Split(source, "/")

	// Read out parts from the old path to create the new one with version potentially
	// An example path looks as following:
	//   integration/uptime/dataset/uptime.http/kibana/visualization/091c3a90-eb1e-11e6-be20-559646f8b9ba.json
	l := len(parts)
	integration, dataset, service, typ, name := parts[l-6], parts[l-4], parts[l-3], parts[l-2], parts[l-1]

	return fmt.Sprintf("%s/%s/%s/%s.%s-%s", dest, service, typ, integration, dataset, name)
}

func renameFile2(source, dest string) string {
	parts := strings.Split(source, "/")

	// Read out parts from the old path to create the new one with version potentially
	// An example path looks as following:
	//   integration/uptime/dataset/uptime.http/kibana/visualization/091c3a90-eb1e-11e6-be20-559646f8b9ba.json
	l := len(parts)
	integration, dataset, name := parts[l-5], parts[l-3], parts[l-1]

	return fmt.Sprintf("%s/fields/%s.%s-%s", dest, integration, dataset, name)
}

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

type Manifest struct {
	Version  string
	DataSets []map[string]string `yaml:datasets`
	Package  *bool
}

var (
	// GoImportsImportPath controls the import path used to install goimports.
	GoImportsImportPath = "golang.org/x/tools/cmd/goimports"

	// GoImportsLocalPrefix is a string prefix matching imports that should be
	// grouped after third-party packages.
	GoImportsLocalPrefix = "github.com/elastic"

	// GoLicenserImportPath controls the import path used to install go-licenser.
	GoLicenserImportPath = "github.com/elastic/go-licenser"
)

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

func LintJSON() error {

	files, err := filepath.Glob("integration/*/dataset/*/*/*/*.json")
	if err != nil {
		return err
	}

	for _, f := range files {
		if strings.Contains(f, "/tests") {
			continue
		}

		var data = map[string]interface{}{}

		content, err := ioutil.ReadFile(f)
		if err != nil {
			return err
		}

		err = json.Unmarshal(content, &data)
		if err != nil {
			return err
		}

		newContent, err := json.MarshalIndent(data, "", "    ")
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(f, newContent, 0644)
		if err != nil {
			return err
		}
	}

	return nil
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
