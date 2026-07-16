// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionInContent(t *testing.T) {
	cases := []struct {
		title   string
		content string
		version string
		want    bool
	}{
		{
			title:   "unquoted version matches",
			content: "- version: 1.2.3\n  changes:\n    - description: Fix",
			version: "1.2.3",
			want:    true,
		},
		{
			title:   "double-quoted version matches",
			content: "- version: \"1.2.3\"\n  changes:\n    - description: Fix",
			version: "1.2.3",
			want:    true,
		},
		{
			title:   "single-quoted version matches",
			content: "- version: '1.2.3'\n  changes:\n    - description: Fix",
			version: "1.2.3",
			want:    true,
		},
		{
			title:   "different version does not match",
			content: "- version: \"1.0.0\"\n  changes:",
			version: "1.2.3",
			want:    false,
		},
		{
			title:   "prerelease version matches exactly",
			content: "- version: \"8.15.0-preview-1716438434\"\n  changes:",
			version: "8.15.0-preview-1716438434",
			want:    true,
		},
		{
			title:   "empty content returns false",
			content: "",
			version: "1.0.0",
			want:    false,
		},
		{
			title:   "version appearing only in description does not match",
			content: "- version: \"2.0.0\"\n  changes:\n    - description: Includes fix from 1.2.3",
			version: "1.2.3",
			want:    false,
		},
		{
			title:   "version that is a prefix of a longer version does not match",
			content: "- version: 1.2.30\n  changes:",
			version: "1.2.3",
			want:    false,
		},
		{
			title:   "version that is a prefix of a longer quoted version does not match",
			content: "- version: \"1.2.30\"\n  changes:",
			version: "1.2.3",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			got := versionInContent(tc.content, tc.version)
			assert.Equal(t, tc.want, got)
		})
	}
}
