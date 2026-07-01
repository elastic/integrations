// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package requiresupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPRBody(t *testing.T) {
	cases := []struct {
		title        string
		summary      packageSummary
		wantContains []string
		wantExcludes []string
	}{
		{
			title: "applied only",
			summary: packageSummary{
				applied: []proposal{
					{Kind: "input", Package: "apache", Current: "1.2.0", Proposed: "1.3.0"},
				},
			},
			wantContains: []string{"## Applied", "**apache** (`input`): `1.2.0` → `1.3.0`"},
			wantExcludes: []string{"## Skipped"},
		},
		{
			title: "skipped only",
			summary: packageSummary{
				skipped: []proposal{
					{Package: "foo", Warning: "requires kibana >=9.0.0"},
				},
			},
			wantContains: []string{"## Skipped", "⚠️ **foo**: requires kibana >=9.0.0"},
			wantExcludes: []string{"## Applied"},
		},
		{
			title: "applied and skipped",
			summary: packageSummary{
				applied: []proposal{
					{Kind: "input", Package: "apache", Current: "1.2.0", Proposed: "1.3.0"},
				},
				skipped: []proposal{
					{Package: "foo", Warning: "requires kibana >=9.0.0"},
				},
			},
			wantContains: []string{"## Applied", "## Skipped"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			body := prBody(tc.summary)
			for _, want := range tc.wantContains {
				assert.Contains(t, body, want)
			}
			for _, exclude := range tc.wantExcludes {
				assert.NotContains(t, body, exclude)
			}
		})
	}
}

func TestIssueBody(t *testing.T) {
	body := issueBody(packageSummary{
		codeowner: "elastic/some-team",
		skipped: []proposal{
			{Package: "foo", Warning: "requires kibana >=9.0.0"},
		},
	})

	assert.Contains(t, body, "**foo**: requires kibana >=9.0.0")
	assert.Contains(t, body, "/cc @elastic/some-team")
}
