// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeChangelog(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "changelog.yml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func TestInsertEntry(t *testing.T) {
	newEntry := "- version: \"1.5.0\"\n  changes:\n    - description: New feature\n      type: enhancement\n      link: https://example.com/100"

	t.Run("inserts between versions in correct order", func(t *testing.T) {
		path := writeChangelog(t, `- version: "2.0.0"
  changes:
    - description: Major release
- version: "1.0.0"
  changes:
    - description: Initial release
`)
		require.NoError(t, InsertEntry(path, "1.5.0", newEntry))
		got, _ := os.ReadFile(path)
		content := string(got)
		assert.Contains(t, content, "1.5.0")
		v2 := indexOfVersion(content, "2.0.0")
		v15 := indexOfVersion(content, "1.5.0")
		v1 := indexOfVersion(content, "1.0.0")
		assert.True(t, v2 < v15 && v15 < v1, "order should be 2.0.0 > 1.5.0 > 1.0.0")
	})

	t.Run("inserts at top when higher than all existing", func(t *testing.T) {
		path := writeChangelog(t, `- version: "1.0.0"
  changes:
    - description: Initial release
`)
		entry := "- version: \"9.9.9\"\n  changes:\n    - description: Future"
		require.NoError(t, InsertEntry(path, "9.9.9", entry))
		got, _ := os.ReadFile(path)
		assert.True(t, indexOfVersion(string(got), "9.9.9") < indexOfVersion(string(got), "1.0.0"))
	})

	t.Run("inserts at bottom when lower than all existing", func(t *testing.T) {
		path := writeChangelog(t, `- version: "2.0.0"
  changes:
    - description: Latest
`)
		entry := "- version: \"0.1.0\"\n  changes:\n    - description: Oldest"
		require.NoError(t, InsertEntry(path, "0.1.0", entry))
		got, _ := os.ReadFile(path)
		assert.True(t, indexOfVersion(string(got), "2.0.0") < indexOfVersion(string(got), "0.1.0"))
	})

	t.Run("idempotent — existing version not duplicated", func(t *testing.T) {
		original := "- version: \"1.0.0\"\n  changes:\n    - description: Only entry\n"
		path := writeChangelog(t, original)
		require.NoError(t, InsertEntry(path, "1.0.0", newEntry))
		got, _ := os.ReadFile(path)
		assert.Equal(t, original, string(got))
	})

	t.Run("missing file returns error", func(t *testing.T) {
		err := InsertEntry("/no/such/changelog.yml", "1.0.0", newEntry)
		assert.Error(t, err)
	})

	t.Run("header comment preserved", func(t *testing.T) {
		path := writeChangelog(t, `# Changelog
- version: "1.0.0"
  changes:
    - description: Initial
`)
		require.NoError(t, InsertEntry(path, "1.5.0", newEntry))
		got, _ := os.ReadFile(path)
		assert.Contains(t, string(got), "# Changelog")
	})
}

func indexOfVersion(content, version string) int {
	return strings.Index(content, "- version: \""+version+"\"")
}
