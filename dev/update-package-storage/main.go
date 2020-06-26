// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"flag"
	"fmt"
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
	flag.StringVar(&options.packagesSourceDir, "sourceDir", "./build/public/package", "Path to the packages directory")
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
	if err != nil {
		log.Fatal(errors.Wrap(err, "reviewing packages failed"))
	}
}

func handlePackageChanges(err error, options updateOptions, packageName string) error {
	if err != nil {
		return err
	}

	packageVersion, err := detectGreatestBuiltPackageVersion(err, options, packageName)
	err = checkoutMasterBranch(err, options)
	released, err := checkIfPackageReleased(err, options, packageName, packageVersion)
	if released {
		return nil
	}
	lastRelease, err := detectGreatestReleasedPackageVersion(err, options, packageName)
	err = copyLastPackageRevisionToPackageStorage(err, options, packageName, lastRelease, packageVersion)
	err = addToIndex(err, options, packageName, packageVersion)
	branchName, err := createBranch(err, options, packageName, packageVersion)
	err = commitChanges(err, options, "Copy contents of last package revision")
	err = copyIntegrationToPackageStorage(err, options, packageName, packageVersion)
	err = addToIndex(err, options, packageName, packageVersion)
	err = commitChanges(err, options, fmt.Sprintf(`Update "%s" integration (version: %s)`, packageName, packageVersion))
	err = pushChanges(err, options, branchName)
	username, err := getUsername(err, options)
	lastCommit, err := getLastCommit(err, options)
	err = openPullRequest(err, options, packageName, packageVersion, username, branchName, lastCommit)
	return err
}
