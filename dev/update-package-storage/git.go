// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/magefile/mage/sh"
)

func fetchUpstream(err error, options updateOptions) error {
	if err != nil {
		return err
	}
	return runGitCommand(options, "fetch", "upstream")
}

func checkoutMasterBranch(err error, options updateOptions) error {
	if err != nil {
		return err
	}
	return runGitCommand(options, "checkout", "master")
}

func rebaseUpstreamMaster(err error, options updateOptions) error {
	if err != nil {
		return err
	}
	return runGitCommand(options, "rebase", "upstream/master")
}

func createBranch(err error, options updateOptions) (string, error) {
	if err != nil {
		return "", err
	}

	branchName := fmt.Sprintf("sync-integrations-%d", time.Now().Unix())
	err = runGitCommand(options, "checkout", "-b", branchName)
	return branchName, err
}

func runGitCommand(options updateOptions, args ...string) error {
	var commandArgs []string
	commandArgs = append(commandArgs,
		"--git-dir", filepath.Join(options.packageStorageDir, ".git"),
		"--work-tree", options.packageStorageDir)
	commandArgs = append(commandArgs, args...)
	return sh.RunV("git", commandArgs...)
}
