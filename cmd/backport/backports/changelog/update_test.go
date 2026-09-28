// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateEntryLinks(t *testing.T) {
	const newURL = "https://github.com/elastic/integrations/pull/9999"

	t.Run("replaces link in matching version entry", func(t *testing.T) {
		path := writeChangelog(t, `- version: "1.5.0"
  changes:
    - description: New feature
      type: enhancement
      link: https://github.com/elastic/integrations/pull/REPLACE_ME
`)
		require.NoError(t, UpdateEntryLinks(path, "1.5.0", newURL))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Contains(t, string(got), newURL)
		assert.NotContains(t, string(got), "REPLACE_ME")
	})

	t.Run("replaces all links when entry has multiple change items", func(t *testing.T) {
		path := writeChangelog(t, `- version: "1.5.0"
  changes:
    - description: Fix A
      type: bugfix
      link: https://github.com/elastic/integrations/pull/REPLACE_ME
    - description: Fix B
      type: bugfix
      link: https://github.com/elastic/integrations/pull/REPLACE_ME
`)
		require.NoError(t, UpdateEntryLinks(path, "1.5.0", newURL))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		content := string(got)
		assert.NotContains(t, content, "REPLACE_ME")
		// Both link lines now contain the new URL.
		count := 0
		for _, line := range splitLines(content) {
			if line == "      link: "+newURL {
				count++
			}
		}
		assert.Equal(t, 2, count, "expected both link fields to be updated")
	})

	t.Run("leaves other version entries untouched", func(t *testing.T) {
		const oldURL = "https://github.com/elastic/integrations/pull/1234"
		path := writeChangelog(t, `- version: "1.5.0"
  changes:
    - description: New feature
      type: enhancement
      link: https://github.com/elastic/integrations/pull/REPLACE_ME
- version: "1.4.0"
  changes:
    - description: Old fix
      type: bugfix
      link: `+oldURL+`
`)
		require.NoError(t, UpdateEntryLinks(path, "1.5.0", newURL))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		content := string(got)
		assert.Contains(t, content, newURL)
		assert.Contains(t, content, oldURL, "unrelated entry must not be modified")
		assert.NotContains(t, content, "REPLACE_ME")
	})

	t.Run("version not found — file unchanged, no error", func(t *testing.T) {
		original := `- version: "1.0.0"
  changes:
    - description: Only entry
      type: bugfix
      link: https://github.com/elastic/integrations/pull/42
`
		path := writeChangelog(t, original)
		require.NoError(t, UpdateEntryLinks(path, "9.9.9", newURL))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, original, string(got))
	})

	t.Run("missing file returns error", func(t *testing.T) {
		err := UpdateEntryLinks("/no/such/changelog.yml", "1.0.0", newURL)
		assert.Error(t, err)
	})
}

// splitLines splits content into lines without the trailing newline element
// that strings.Split produces for a newline-terminated string.
func splitLines(content string) []string {
	lines := make([]string, 0)
	start := 0
	for i, c := range content {
		if c == '\n' {
			lines = append(lines, content[start:i])
			start = i + 1
		}
	}
	if start < len(content) {
		lines = append(lines, content[start:])
	}
	return lines
}
