// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"time"

	"github.com/magefile/mage/sh"
)

func fetchUpstream(err error, options updateOptions) error {
	if err != nil {
		return err
	}
	return runGitCommand(options, "fetch", "upstream")
}

func checkoutProductionBranch(err error, options updateOptions) error {
	if err != nil {
		return err
	}
	return runGitCommand(options, "checkout", "production")
}

func rebaseUpstreamProduction(err error, options updateOptions) error {
	if err != nil {
		return err
	}
	return runGitCommand(options, "rebase", "upstream/production")
}

func addToIndex(err error, options updateOptions, packageName, packageVersion string) error {
	if err != nil {
		return err
	}
	return runGitCommand(options, "add", "--all", filepath.Join("packages", packageName, packageVersion))
}

func createBranch(err error, options updateOptions, packageName, packageVersion string) (string, error) {
	if err != nil {
		return "", err
	}

	branchName := fmt.Sprintf("update-%s-%s-%d", packageName, packageVersion, time.Now().Unix())
	err = runGitCommand(options, "checkout", "-b", branchName)
	return branchName, err
}

func commitChanges(err error, options updateOptions, message string) error {
	if err != nil {
		return err
	}
	return runGitCommand(options, "commit", "-m", message)
}

func getLastCommit(err error, options updateOptions) (string, error) {
	if err != nil {
		return "", err
	}
	return outputGitCommand(options, "rev-parse", "HEAD")
}

func getUsername(err error, options updateOptions) (string, error) {
	if err != nil {
		return "", err
	}
	remoteURL, err := outputGitCommand(options, "remote", "get-url", "origin")
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`github.com[:/](.+)/package-storage`)
	matches := re.FindStringSubmatch(remoteURL)
	if len(matches) < 2 {
		return "", fmt.Errorf("No remote user found in %s", remoteURL)
	}

	return matches[1], nil
}

func pushChanges(err error, options updateOptions, branchName string) error {
	if err != nil {
		return err
	}
	return runGitCommand(options, "push", "origin", branchName)
}

func runGitCommand(options updateOptions, args ...string) error {
	return sh.Run("git", append(buildRequiredGitCommandArgs(options), args...)...)
}

func outputGitCommand(options updateOptions, args ...string) (string, error) {
	return sh.Output("git", append(buildRequiredGitCommandArgs(options), args...)...)
}

func buildRequiredGitCommandArgs(options updateOptions) []string {
	var commandArgs []string
	commandArgs = append(commandArgs,
		"--git-dir", filepath.Join(options.packageStorageDir, ".git"),
		"--work-tree", options.packageStorageDir)
	return commandArgs
}
