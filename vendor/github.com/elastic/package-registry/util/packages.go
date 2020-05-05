// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package util

import (
	"os"
	"path/filepath"
)

var packageList []Package

// GetPackages returns a slice with all existing packages.
// The list is stored in memory and on the second request directly
// served from memory. This assumes chnages to packages only happen on restart.
// Caching the packages request many file reads every time this method is called.
func GetPackages(packagesBasePath string) ([]Package, error) {
	if packageList != nil {
		return packageList, nil
	}

	packagePaths, err := getPackagePaths(packagesBasePath)
	if err != nil {
		return nil, err
	}

	for _, path := range packagePaths {
		p, err := NewPackage(path)
		if err != nil {
			return nil, err
		}
		packageList = append(packageList, *p)
	}

	return packageList, nil
}

// getPackagePaths returns list of available packages, one for each version.
func getPackagePaths(packagesPath string) ([]string, error) {

	allPaths, err := filepath.Glob(packagesPath + "/*/*")
	if err != nil {
		return nil, err
	}

	var packagePaths []string
	for _, path := range allPaths {
		p, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !p.IsDir() {
			continue
		}

		packagePaths = append(packagePaths, path)
	}

	return packagePaths, nil
}
