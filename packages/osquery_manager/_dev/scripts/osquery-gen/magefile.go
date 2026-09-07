// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build mage

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Update regenerates osquery_manager schemas for the latest stable osquery
// release. Set OSQUERY_VERSION to select a specific release and BEATS_PATH to
// read extension specs from an unreleased local Beats checkout.
// KIBANA_VERSION is required when the resolved osquery version is new (not yet
// in the changelog); it must list only stack releases that contain the upgraded
// runtime. CHANGELOG_LINK is also required for that bump.
func Update() error {
	toolDir, err := osqueryGenDir()
	if err != nil {
		return err
	}

	version := os.Getenv("OSQUERY_VERSION")
	if version == "" {
		version = "latest"
	}
	args := []string{"run", ".", "-config", "./config.yml", "-osquery-version", version, "-update-config", "-update-package"}
	if changelogLink := os.Getenv("CHANGELOG_LINK"); changelogLink != "" {
		args = append(args, "-changelog-link", changelogLink)
	}
	if kibanaVersion := os.Getenv("KIBANA_VERSION"); kibanaVersion != "" {
		args = append(args, "-kibana-version", kibanaVersion)
	}
	if beatsPath := os.Getenv("BEATS_PATH"); beatsPath != "" {
		absolutePath, err := filepath.Abs(beatsPath)
		if err != nil {
			return fmt.Errorf("resolve BEATS_PATH: %w", err)
		}
		args = append(args, "-beats-path", absolutePath)
	}

	cmd := exec.Command("go", args...)
	cmd.Dir = toolDir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func osqueryGenDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if isOsqueryGenDir(dir) {
			return dir, nil
		}
		candidate := filepath.Join(dir, "packages", "osquery_manager", "_dev", "scripts", "osquery-gen")
		if isOsqueryGenDir(candidate) {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("could not find osquery-gen; run mage from the integrations repo or from packages/osquery_manager/_dev/scripts/osquery-gen")
}

func isOsqueryGenDir(dir string) bool {
	for _, name := range []string{"config.yml", "magefile.go"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.IsDir() {
			return false
		}
	}
	return true
}
