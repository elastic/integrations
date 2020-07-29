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
	"github.com/pkg/errors"
)

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

func checkIfPackageReleased(err error, options updateOptions, packageName, packageVersion string) (bool, error) {
	if err != nil {
		return false, err
	}

	var released bool
	packagePath := filepath.Join(options.packageStorageDir, "packages", packageName, packageVersion)
	for _, releaseBranch := range releaseBranches {
		err = checkoutReleaseBranch(err, options, releaseBranch)
		released, err = checkIfPackageManifestExists(packagePath)
		if released {
			return released, err
		}
	}
	return released, err
}

func detectGreatestBuiltPackageVersion(err error, options updateOptions, packageName string) (string, error) {
	if err != nil {
		return "", err
	}
	packagePath := filepath.Join(options.packagesSourceDir, packageName)
	return detectGreatestPackageVersion(packagePath)
}

func detectGreatestReleasedPackageVersion(err error, options updateOptions, packageName string) (string, string, error) {
	if err != nil {
		return "", "", err
	}
	packagePath := filepath.Join(options.packageStorageDir, "packages", packageName)

	greatestVersion := "0.0.0"
	semverGreatestVersion := semver.MustParse(greatestVersion)
	var stage string

	var pv string
	for _, releaseBranch := range releaseBranches {
		err = checkoutReleaseBranch(err, options, releaseBranch)
		pv, err = detectGreatestPackageVersion(packagePath)

		semverPackageVersion := semver.MustParse(pv)
		if semverGreatestVersion.LT(semverPackageVersion) {
			semverGreatestVersion = semverPackageVersion
			greatestVersion = pv
			stage = releaseBranch
		}
	}
	return greatestVersion, stage, err
}

func detectGreatestPackageVersion(packagePath string) (string, error) {
	var versions []semver.Version
	fileInfos, err := ioutil.ReadDir(packagePath)
	if os.IsNotExist(err) {
		return "0.0.0", nil // no release here
	}
	if err != nil {
		return "", errors.Wrapf(err, "reading directory failed (path: %s)", packagePath)
	}

	for _, fileInfo := range fileInfos {
		if fileInfo.IsDir() {
			v, err := semver.Parse(fileInfo.Name())
			if err != nil {
				return "", errors.Wrapf(err, "parsing semver failed (filename: %s)", fileInfo.Name())
			}

			ok, err := checkIfPackageManifestExists(filepath.Join(packagePath, fileInfo.Name()))
			if err != nil {
				return "", errors.Wrapf(err, "checking if package manifest exists failed (packagePath: %s, filename: %s)",
					packagePath, fileInfo.Name())
			}

			if ok {
				versions = append(versions, v)
			}
		}
	}
	if len(versions) == 0 {
		return "0.0.0", nil
	}

	semver.Sort(versions)
	return versions[len(versions)-1].String(), nil
}

func checkIfPackageManifestExists(packagePath string) (bool, error) {
	path := filepath.Join(packagePath, "manifest.yml")
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, errors.Wrapf(err, "stat file failed (path: %s)", path)
	}
	return true, nil
}

func copyLastPackageRevisionToPackageStorage(err error, options updateOptions, packageName, sourcePackageVersion, releaseBranch, destinationPackageVersion string) error {
	if err != nil {
		return err
	}

	if sourcePackageVersion == "0.0.0" {
		return nil // this is the package first revision
	}

	sourcePath := filepath.Join(options.packageStorageDir, "packages", packageName, sourcePackageVersion)
	destinationPath := filepath.Join(options.packageStorageDir, "packages", packageName, destinationPackageVersion)
	err = checkoutReleaseBranch(err, options, releaseBranch)
	if err != nil {
		return err
	}
	err = copyPackageContents(sourcePath, destinationPath)
	if err != nil {
		return err
	}

	return checkoutReleaseBranch(err, options, "snapshot")
}

func copyIntegrationToPackageStorage(err error, options updateOptions, packageName, packageVersion string) error {
	if err != nil {
		return err
	}

	sourcePath := filepath.Join(options.packagesSourceDir, packageName, packageVersion)
	destinationPath := filepath.Join(options.packageStorageDir, "packages", packageName, packageVersion)
	return copyPackageContents(sourcePath, destinationPath)
}

func copyPackageContents(sourcePath, destinationPath string) error {
	err := os.MkdirAll(destinationPath, 0755)
	if err != nil {
		return errors.Wrapf(err, "creating directories failed (path: %s)", destinationPath)
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
