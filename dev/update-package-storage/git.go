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

func addToIndex(err error, options updateOptions, packageName, packageVersion string) error {
	if err != nil {
		return err
	}

	return runGitCommand(options, "add", "--all", filepath.Join("packages", packageName, packageVersion))
}

func checkIfEmptyIndex(err error, options updateOptions) (bool, error) {
	if err != nil {
		return false, err
	}

	exitCode := runGitCommand(options, "diff", "--cached", "--exit-code")
	return sh.ExitStatus(exitCode) != 1, nil
}

func createBranch(err error, options updateOptions, packageName, packageVersion string) (string, error) {
	if err != nil {
		return "", err
	}

	branchName := fmt.Sprintf("update-%s-%s-%d", packageName, packageVersion, time.Now().Unix())
	err = runGitCommand(options, "checkout", "-b", branchName)
	return branchName, err
}

func commitChanges(err error, options updateOptions, packageName, packageVersion string) error {
	if err != nil {
		return err
	}

	return runGitCommand(options, "commit", "-m", fmt.Sprintf(`Update "%s" integration (version: %s)`, packageName, packageVersion))
}

func pushChanges(err error, options updateOptions, branchName string) error {
	if err != nil {
		return err
	}

	return runGitCommand(options, "push", "origin", branchName)
}

func runGitCommand(options updateOptions, args ...string) error {
	var commandArgs []string
	commandArgs = append(commandArgs,
		"--git-dir", filepath.Join(options.packageStorageDir, ".git"),
		"--work-tree", options.packageStorageDir)
	commandArgs = append(commandArgs, args...)
	return sh.Run("git", commandArgs...)
}
