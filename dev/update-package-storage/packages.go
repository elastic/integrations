// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/blang/semver"
	"github.com/magefile/mage/sh"
	"gopkg.in/yaml.v2"
)

type manifest struct {
	Version string `yaml:"version"`
}

func listPackages(err error, options updateOptions) ([]string, error) {
	if err != nil {
		return nil, err
	}

	var folders []string
	fileInfos, err := ioutil.ReadDir(options.packagesSourceDir)
	for _, fileInfo := range fileInfos {
		if fileInfo.IsDir() {
			folders = append(folders, fileInfo.Name())
		}
	}
	return folders, nil
}

func reviewPackages(err error, options updateOptions, packageNames []string, handlePackageChanges func(error, updateOptions, string) error) error {
	if err != nil {
		return err
	}

	for _, packageName := range packageNames {
		err = handlePackageChanges(err, options, packageName)
	}
	return err
}

func detectPackageVersion(err error, options updateOptions, packageName string) (string, error) {
	if err != nil {
		return "", err
	}

	m, err := loadManifestFile(packageName, options)
	if err != nil {
		return "", err
	}
	return m.Version, nil
}

func loadManifestFile(packageName string, options updateOptions) (*manifest, error) {
	body, err := ioutil.ReadFile(filepath.Join(options.packagesSourceDir, packageName, "manifest.yml"))
	if err != nil {
		return nil, err
	}

	var m manifest
	err = yaml.Unmarshal(body, &m)
	return &m, err
}

func checkIfPackageReleased(err error, options updateOptions, packageName, packageVersion string) (bool, error) {
	if err != nil {
		return false, err
	}

	packagePath := filepath.Join(options.packageStorageDir, "packages", packageName, packageVersion)
	return checkIfPackageManifestExists(packagePath)
}

func detectLastReleasedPackageVersion(err error, options updateOptions, packageName string) (string, error) {
	if err != nil {
		return "", err
	}

	var versions []semver.Version
	packagePath := filepath.Join(options.packageStorageDir, "packages", packageName)
	fileInfos, err := ioutil.ReadDir(packagePath)
	for _, fileInfo := range fileInfos {
		if fileInfo.IsDir() {
			v, err := semver.Parse(fileInfo.Name())
			if err != nil {
				return "", err
			}

			ok, err := checkIfPackageManifestExists(filepath.Join(packagePath, fileInfo.Name()))
			if err != nil {
				return "", err
			}

			if ok {
				versions = append(versions, v)
			}
		}
	}

	if len(versions) == 0 {
		return "0", nil
	}

	semver.Sort(versions)
	return versions[len(versions)-1].String(), nil
}

func checkIfPackageManifestExists(packagePath string) (bool, error) {
	_, err := os.Stat(filepath.Join(packagePath, "manifest.yml"))
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func copyLastPackageRevisionToPackageStorage(err error, options updateOptions, packageName, sourcePackageVersion, destinationPackageVersion string) error {
	if err != nil {
		return err
	}

	if sourcePackageVersion == "0" {
		return nil // this is the package first revision
	}

	sourcePath := filepath.Join(options.packageStorageDir, "packages", packageName, sourcePackageVersion)
	destinationPath := filepath.Join(options.packageStorageDir, "packages", packageName, destinationPackageVersion)
	return copyPackageContents(sourcePath, destinationPath)
}

func copyIntegrationToPackageStorage(err error, options updateOptions, packageName, packageVersion string) error {
	if err != nil {
		return err
	}

	sourcePath := filepath.Join(options.packagesSourceDir, packageName)
	destinationPath := filepath.Join(options.packageStorageDir, "packages", packageName, packageVersion)
	return copyPackageContents(sourcePath, destinationPath)
}

func copyPackageContents(sourcePath, destinationPath string) error {
	err := os.MkdirAll(destinationPath, 0755)
	if err != nil {
		return err
	}

	return filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relativePath, err := filepath.Rel(sourcePath, path)
		if err != nil {
			return err
		}

		if relativePath == "." {
			return nil
		}

		if info.IsDir() {
			return os.MkdirAll(filepath.Join(destinationPath, relativePath), 0755)
		}

		return sh.Copy(
			filepath.Join(destinationPath, relativePath),
			filepath.Join(sourcePath, relativePath))
	})
}
