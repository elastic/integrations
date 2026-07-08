// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package checklist

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/integrations/dev/backports"
)

// ptr returns a pointer to s, for constructing MaintainedUntil values inline.
func ptr(s string) *string { return &s }

// awsBranch returns an ActiveResult for the aws package with the given branch.
func awsBranch(branch string) backports.ActiveResult {
	return backports.ActiveResult{Branch: branch, Active: true}
}

func awsBranchUntil(branch, until string) backports.ActiveResult {
	return backports.ActiveResult{Branch: branch, Active: true, MaintainedUntil: ptr(until)}
}

func TestBuildComment(t *testing.T) {
	cases := []struct {
		title        string
		pkgs         []PackageBranches
		checked      map[string]bool
		wantEmpty    bool
		wantContains []string
		wantMissing  []string
	}{
		{
			title:     "empty pkgs returns empty string",
			pkgs:      nil,
			wantEmpty: true,
		},
		{
			title: "pkgs with no active branches returns empty string",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: nil},
			},
			wantEmpty: true,
		},
		{
			title: "marker is present in output",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranch("backport-aws-6.14")}},
			},
			checked:      map[string]bool{},
			wantContains: []string{marker},
		},
		{
			title: "package header and branch line rendered",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranch("backport-aws-6.14")}},
			},
			checked:      map[string]bool{},
			wantContains: []string{"**aws**", "- `backport-aws-6.14`"},
		},
		{
			title: "maintained_until appended when set",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranchUntil("backport-aws-6.14", "2027-01-15")}},
			},
			checked:      map[string]bool{},
			wantContains: []string{"(maintained until 2027-01-15)"},
		},
		{
			title: "maintained_until omitted when nil",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranch("backport-aws-6.15")}},
			},
			checked:     map[string]bool{},
			wantMissing: []string{"maintained until"},
		},
		{
			title: "branch rendered as plain list item regardless of checked state",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranch("backport-aws-6.14")}},
			},
			checked:      map[string]bool{"backport-aws-6.14": true},
			wantContains: []string{"- `backport-aws-6.14`"},
			wantMissing:  []string{"- [x] `backport-aws-6.14`", "- [ ] `backport-aws-6.14`"},
		},
		{
			title: "multiple packages both rendered",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranch("backport-aws-6.14")}},
				{Package: "kubernetes", Branches: []backports.ActiveResult{awsBranch("backport-kubernetes-1.28")}},
			},
			checked:      map[string]bool{},
			wantContains: []string{"**aws**", "backport-aws-6.14", "**kubernetes**", "backport-kubernetes-1.28"},
		},
		{
			title: "package with no branches omitted from output",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranch("backport-aws-6.14")}},
				{Package: "nginx", Branches: nil},
			},
			checked:      map[string]bool{},
			wantContains: []string{"**aws**"},
			wantMissing:  []string{"**nginx**"},
		},
		{
			title: "tip footer always present",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranch("backport-aws-6.14")}},
			},
			checked:      map[string]bool{},
			wantContains: []string{"[!TIP]", "archived: true", ".backports.yml"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			got := BuildComment(tc.pkgs, tc.checked)

			if tc.wantEmpty {
				assert.Empty(t, got)
				return
			}

			for _, want := range tc.wantContains {
				assert.Contains(t, got, want)
			}
			for _, missing := range tc.wantMissing {
				assert.NotContains(t, got, missing)
			}
		})
	}
}

func TestParseCheckedBranches(t *testing.T) {
	cases := []struct {
		title string
		body  string
		want  map[string]bool
	}{
		{
			title: "empty body returns empty map",
			body:  "",
			want:  map[string]bool{},
		},
		{
			title: "body without marker returns empty map",
			body:  "- [x] `backport-aws-6.14`\nsome text",
			want:  map[string]bool{},
		},
		{
			title: "single checked branch",
			body:  marker + "\n- [x] `backport-aws-6.14`\n",
			want:  map[string]bool{"backport-aws-6.14": true},
		},
		{
			title: "unchecked branch not collected",
			body:  marker + "\n- [ ] `backport-aws-6.14`\n",
			want:  map[string]bool{},
		},
		{
			title: "mix of checked and unchecked",
			body:  marker + "\n- [x] `backport-aws-6.14`\n- [ ] `backport-aws-6.15`\n",
			want:  map[string]bool{"backport-aws-6.14": true},
		},
		{
			title: "multiple checked branches across packages",
			body: marker + "\n**aws**\n- [x] `backport-aws-6.14`\n- [ ] `backport-aws-6.15`\n\n" +
				"**kubernetes**\n- [x] `backport-kubernetes-1.28`\n",
			want: map[string]bool{"backport-aws-6.14": true, "backport-kubernetes-1.28": true},
		},
		{
			title: "branch with maintained_until suffix still parsed",
			body:  marker + "\n- [x] `backport-aws-6.14` (maintained until 2027-01-15)\n",
			want:  map[string]bool{"backport-aws-6.14": true},
		},
		{
			title: "uppercase [X] checkbox is treated as checked",
			body:  marker + "\n- [X] `backport-aws-6.14`\n",
			want:  map[string]bool{"backport-aws-6.14": true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			got := ParseCheckedBranches(tc.body)
			assert.Equal(t, tc.want, got)
		})
	}
}
