// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package packagenames

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoDuplicates(t *testing.T) {
	paths, err := walkPackagePaths("testdata/no_duplicates")
	require.NoError(t, err)
	assert.Len(t, paths, 2)

	err = checkDuplicateNames(paths)
	assert.NoError(t, err)
}

func TestDuplicates(t *testing.T) {
	paths, err := walkPackagePaths("testdata/duplicates")
	require.NoError(t, err)
	assert.Len(t, paths, 2)

	err = checkDuplicateNames(paths)
	assert.EqualError(t, err, "found duplicate package names:\nduplicate package name \"pkg_a\" found in: testdata/duplicates/p1, testdata/duplicates/p2")
}

func TestInvalidManifestsIgnored(t *testing.T) {
	paths, err := walkPackagePaths("testdata/invalid_manifests")
	require.NoError(t, err)
	// p2 has no type field and must be ignored
	assert.Len(t, paths, 1)

	err = checkDuplicateNames(paths)
	assert.NoError(t, err)
}

func TestNestedNoDuplicates(t *testing.T) {
	paths, err := walkPackagePaths("testdata/nested/no_duplicates")
	require.NoError(t, err)
	// p3 at first level + technology/p1 and technology/p2 at second level
	assert.Len(t, paths, 3)

	err = checkDuplicateNames(paths)
	assert.NoError(t, err)
}

func TestNestedDuplicates(t *testing.T) {
	paths, err := walkPackagePaths("testdata/nested/duplicates")
	require.NoError(t, err)
	// p3 at first level + technology/p1 and technology/p2 at second level
	assert.Len(t, paths, 3)

	err = checkDuplicateNames(paths)
	assert.EqualError(t, err, "found duplicate package names:\nduplicate package name \"pkg_e\" found in: testdata/nested/duplicates/p3, testdata/nested/duplicates/technology/p1, testdata/nested/duplicates/technology/p2")
}
