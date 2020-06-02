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

	err = checkoutMasterBranch(err, options)
	version, err := detectPackageVersion(err, options, packageName)
	// copy to package/version
	// add to index
	// check index
	// checkout new branch

	// commit
	// push

	// pull request

	return nil
}
