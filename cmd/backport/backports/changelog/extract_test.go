// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractFromDiff(t *testing.T) {
	cases := []struct {
		title        string
		diff         string
		wantVersion  string
		wantContains string
		wantEmpty    bool
	}{
		{
			title: "single version entry extracted",
			diff: `--- a/changelog.yml
+++ b/changelog.yml
@@ -1,3 +1,8 @@
+- version: "1.5.0"
+  changes:
+    - description: Added new field
+      type: enhancement
+      link: https://github.com/elastic/integrations/pull/100
 - version: "1.4.0"
   changes:`,
			wantVersion:  "1.5.0",
			wantContains: "Added new field",
		},
		{
			title: "two version entries — only first is extracted",
			diff: `--- a/changelog.yml
+++ b/changelog.yml
@@ -1,3 +1,10 @@
+- version: "2.0.0"
+  changes:
+    - description: Breaking change
+      type: breaking-change
+      link: https://github.com/elastic/integrations/pull/200
+- version: "1.9.0"
+  changes:
+    - description: Minor fix
 - version: "1.8.0"`,
			wantVersion:  "2.0.0",
			wantContains: "Breaking change",
		},
		{
			title: "single version with multiple change entries",
			diff: `--- a/changelog.yml
+++ b/changelog.yml
@@ -1,3 +1,13 @@
+- version: "2.1.0"
+  changes:
+    - description: First enhancement
+      type: enhancement
+      link: https://github.com/elastic/integrations/pull/300
+    - description: Second bugfix
+      type: bugfix
+      link: https://github.com/elastic/integrations/pull/301
 - version: "2.0.0"
   changes:`,
			wantVersion:  "2.1.0",
			wantContains: "Second bugfix",
		},
		{
			title: "unquoted version line",
			diff: `+- version: 3.1.0
+  changes:
+    - description: Unquoted version`,
			wantVersion:  "3.1.0",
			wantContains: "Unquoted version",
		},
		{
			title: "prerelease version",
			diff: `+- version: "8.15.0-preview-1716438434"
+  changes:
+    - description: Preview release`,
			wantVersion:  "8.15.0-preview-1716438434",
			wantContains: "Preview release",
		},
		{
			title:     "no added lines — returns empty",
			diff:      " - version: \"1.0.0\"\n   changes:",
			wantEmpty: true,
		},
		{
			title:     "added lines but no version header — returns empty",
			diff:      "+  - description: orphan change\n+    type: enhancement",
			wantEmpty: true,
		},
		{
			title:     "empty diff — returns empty",
			diff:      "",
			wantEmpty: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			ver, entry, err := ExtractFromDiff(tc.diff)
			require.NoError(t, err)
			if tc.wantEmpty {
				assert.Empty(t, ver)
				assert.Empty(t, entry)
				return
			}
			assert.Equal(t, tc.wantVersion, ver)
			assert.Contains(t, entry, tc.wantContains)
		})
	}
}
