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
// The list is stored in memory and on the second request directly served from memory.
// This assumes changes to packages only happen on restart (unless development mode is enabled).
// Caching the packages request many file reads every time this method is called.
func GetPackages(packagesBasePaths []string) ([]Package, error) {
	if packageList != nil {
		return packageList, nil
	}

	var err error
	packageList, err = getPackagesFromFilesystem(packagesBasePaths)
	if err != nil {
		return nil, errors.Wrapf(err, "reading packages from filesystem failed")
	}
	return packageList, nil
}

func getPackagesFromFilesystem(packagesBasePaths []string) ([]Package, error) {
	packagePaths, err := getPackagePaths(packagesBasePaths)
	if err != nil {
		return nil, err
	}

	var pList []Package
	for _, path := range packagePaths {
		p, err := NewPackage(path)
		if err != nil {
			return nil, errors.Wrapf(err, "loading package failed (path: %s)", path)
		}

		pList = append(pList, *p)
	}
	return pList, nil
}

// getPackagePaths returns list of available packages, one for each version.
func getPackagePaths(allPaths []string) ([]string, error) {
	var foundPaths []string
	for _, packagesPath := range allPaths {
		log.Printf("Packages in %s:", packagesPath)
		err := filepath.Walk(packagesPath, func(path string, info os.FileInfo, err error) error {
			relativePath, err := filepath.Rel(packagesPath, path)
			if err != nil {
				return err
			}

			dirs := strings.Split(relativePath, string(filepath.Separator))
			if len(dirs) < 2 {
				return nil // need to go to the package version level
			}

			if info.IsDir() {
				log.Printf("%-20s\t%10s\t%s", dirs[0], dirs[1], path)
				foundPaths = append(foundPaths, path)
			}
			return filepath.SkipDir // don't need to go deeper
		})
		if err != nil {
			return nil, errors.Wrapf(err, "listing packages failed (path: %s)", packagesPath)
		}
	}
	return foundPaths, nil
}
