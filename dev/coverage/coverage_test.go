// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coverage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeCoverage(t *testing.T) {
	coverageFiles, err := filepath.Glob("testdata/test-coverage-*.xml")
	require.NoError(t, err)

	expectedCoverage, err := ReadGenericCoverage("testdata/expected-test-coverage.xml")
	require.NoError(t, err)

	output := filepath.Join(t.TempDir(), "coverage-merged.xml")

	err = MergeGenericCoverageFiles(coverageFiles, output)
	require.NoError(t, err)

	mergedCoverage, err := ReadGenericCoverage(output)
	require.NoError(t, err)

	assert.EqualValues(t, expectedCoverage, mergedCoverage)
}
