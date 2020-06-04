// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"flag"
	"log"
	"os"

	"github.com/pkg/errors"
)

type updateOptions struct {
	packagesSourceDir string
	packageStorageDir string
	skipPullRequest   bool
}

func (uo *updateOptions) validate() error {
	_, err := os.Stat(uo.packageStorageDir)
	if err != nil {
		return errors.Wrapf(err, "stat file failed (path: %s)", uo.packageStorageDir)
	}
	return nil
}

func main() {
	var options updateOptions
	flag.StringVar(&options.packagesSourceDir, "sourceDir", "./packages", "Path to the packages directory")
	flag.StringVar(&options.packageStorageDir, "packageStorageDir", "../package-storage", "Path to the package-storage repository")
	flag.BoolVar(&options.skipPullRequest, "skipPullRequest", false, "Skip opening pull requests")
	flag.Parse()

	err := options.validate()
	if err != nil {
		log.Fatal(errors.Wrap(err, "command options validation failed"))
	}

	err = fetchUpstream(err, options)
	err = checkoutMasterBranch(err, options)
	err = rebaseUpstreamMaster(err, options)
	packageNames, err := listPackages(err, options)
	err = reviewPackages(err, options, packageNames, handlePackageChanges)
}

func handlePackageChanges(err error, options updateOptions, packageName string) error {
	if err != nil {
		return err
	}

	packageVersion, err := detectPackageVersion(err, options, packageName)
	err = checkoutMasterBranch(err, options)
	released, err := checkIfPackageReleased(err, options, packageName, packageVersion)
	if released {
		return nil
	}

	err = copyIntegrationToPackageStorage(err, options, packageName, packageVersion)
	err = addToIndex(err, options, packageName, packageVersion)
	empty, err := checkIfEmptyIndex(err, options)
	if empty {
		return nil
	}

	branchName, err := createBranch(err, options, packageName, packageVersion)
	err = commitChanges(err, options, packageName, packageVersion)
	err = pushChanges(err, options, branchName)

	// TODO Create a pull-request using Github API
	return err
}
