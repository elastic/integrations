// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package codeowners

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckManifest(t *testing.T) {
	cases := []struct {
		codeownersPath string
		manifestPath   string
		valid          bool
	}{
		{
			codeownersPath: "testdata/CODEOWNERS-valid",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-valid",
			manifestPath:   "testdata/noowner/manifest.yml",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-multiple-owners",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-no-owner",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-empty",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-wrong-devexp",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-precedence",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-wrong-precedence",
			manifestPath:   "testdata/devexp/manifest.yml",
			valid:          false,
		},
	}

	for _, c := range cases {
		t.Run(c.codeownersPath+"_"+c.manifestPath, func(t *testing.T) {
			owners, err := readGithubOwners(c.codeownersPath)
			require.NoError(t, err)

			err = owners.checkManifest(c.manifestPath)
			if c.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidatePackages(t *testing.T) {
	cases := []struct {
		codeownersPath string
		packageDir     string
		valid          bool
	}{
		{
			codeownersPath: "testdata/CODEOWNERS-streams-missing-owners",
			packageDir:     "testdata/test_packages",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-streams-multiple-owners",
			packageDir:     "testdata/test_packages",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-streams-valid",
			packageDir:     "testdata/test_packages",
			valid:          true,
		},
	}

	for _, c := range cases {
		t.Run(c.codeownersPath, func(t *testing.T) {
			owners, err := readGithubOwners(c.codeownersPath)
			require.NoError(t, err)

			err = validatePackages(owners, c.packageDir)
			if c.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestReadGithubOwners(t *testing.T) {
	cases := []struct {
		codeownersPath string
		valid          bool
	}{
		{
			codeownersPath: "testdata/CODEOWNERS-valid",
			valid:          true,
		},
		{
			codeownersPath: "notexsists",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-no-owner",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-multiple-owners",
			valid:          true,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-invalid-override",
			valid:          false,
		},
		{
			codeownersPath: "testdata/CODEOWNERS-invalid-override-wildcard",
			valid:          false,
		},
	}

	for _, c := range cases {
		t.Run(c.codeownersPath, func(t *testing.T) {
			_, err := readGithubOwners(c.codeownersPath)
			if c.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
