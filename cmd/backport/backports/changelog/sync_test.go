// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTSV(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "entries-*.tsv")
	require.NoError(t, err)
	_, err = fmt.Fprint(f, content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestReadEntriesTSV(t *testing.T) {
	t.Run("valid file with multiple entries", func(t *testing.T) {
		path := writeTSV(t, "aws\t1.2.3\t/tmp/e1.yml\nazure\t2.0.0\t/tmp/e2.yml\n")
		entries, err := readEntriesTSV(path)
		require.NoError(t, err)
		require.Len(t, entries, 2)
		assert.Equal(t, tsvEntry{"aws", "1.2.3", "/tmp/e1.yml"}, entries[0])
		assert.Equal(t, tsvEntry{"azure", "2.0.0", "/tmp/e2.yml"}, entries[1])
	})

	t.Run("empty file returns empty slice", func(t *testing.T) {
		path := writeTSV(t, "")
		entries, err := readEntriesTSV(path)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("lines with wrong field count are skipped", func(t *testing.T) {
		path := writeTSV(t, "only-one-field\naws\t1.2.3\t/tmp/e.yml\n")
		entries, err := readEntriesTSV(path)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "aws", entries[0].pkg)
	})

	t.Run("entry file path may contain tabs via SplitN limit", func(t *testing.T) {
		// entryFile path should not be split even if it contained a tab
		path := writeTSV(t, "aws\t1.2.3\t/tmp/entry file.yml\n")
		entries, err := readEntriesTSV(path)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "/tmp/entry file.yml", entries[0].entryFile)
	})

	t.Run("file not found returns error", func(t *testing.T) {
		_, err := readEntriesTSV("/no/such/file.tsv")
		assert.Error(t, err)
	})
}

func TestBuildCommitMessage(t *testing.T) {
	t.Run("single entry names package and version", func(t *testing.T) {
		entries := []tsvEntry{{pkg: "aws", version: "1.2.3", entryFile: "/tmp/e.yml"}}
		msg := buildCommitMessage(entries, "42")
		assert.Equal(t, "changelog: aws 1.2.3 (backport sync from PR #42)", msg)
	})

	t.Run("multiple entries uses generic message", func(t *testing.T) {
		entries := []tsvEntry{
			{pkg: "aws", version: "1.2.3", entryFile: "/tmp/e1.yml"},
			{pkg: "azure", version: "2.0.0", entryFile: "/tmp/e2.yml"},
		}
		msg := buildCommitMessage(entries, "42")
		assert.Equal(t, "changelog: backport sync from PR #42", msg)
	})
}

func TestBuildPRTitle(t *testing.T) {
	entries := []tsvEntry{{pkg: "gcp", version: "3.1.0", entryFile: "/tmp/e.yml"}}
	assert.Equal(t, buildCommitMessage(entries, "99"), buildPRTitle(entries, "99"))
}
