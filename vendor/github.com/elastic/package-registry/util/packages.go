// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package util

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
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
			return nil, errors.Wrapf(err, "loading package failed (path: %s)", path)
		}

		err = p.Validate()
		if err != nil {
			return nil, errors.Wrapf(err, "validating package failed (path: %s)", path)
		}
		packageList = append(packageList, *p)
	}

	return packageList, nil
}

// getPackagePaths returns list of available packages, one for each version.
func getPackagePaths(packagesPath string) ([]string, error) {
	log.Printf("List packages in %s", packagesPath)

	var foundPaths []string
	return foundPaths, filepath.Walk(packagesPath, func(path string, info os.FileInfo, err error) error {
		relativePath, err := filepath.Rel(packagesPath, path)
		if err != nil {
			return err
		}

		dirs := strings.Split(relativePath, string(filepath.Separator))
		if len(dirs) < 2 {
			return nil // need to go to the package version level
		}

		p, err := os.Stat(path)
		if err != nil {
			return err
		}

		if p.IsDir() {
			log.Printf("%-20s\t%10s\t%s", dirs[0], dirs[1], path)
			foundPaths = append(foundPaths, path)
		}
		return filepath.SkipDir // don't need to go deeper
	})
}
