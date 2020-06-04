// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"

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

	destinationPath := filepath.Join(options.packageStorageDir, "packages", packageName, packageVersion)
	_, err = os.Stat(destinationPath)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func copyIntegrationToPackageStorage(err error, options updateOptions, packageName, packageVersion string) error {
	if err != nil {
		return err
	}

	sourcePath := filepath.Join(options.packagesSourceDir, packageName)
	destinationPath := filepath.Join(options.packageStorageDir, "packages", packageName, packageVersion)
	err = os.MkdirAll(destinationPath, 0755)
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
