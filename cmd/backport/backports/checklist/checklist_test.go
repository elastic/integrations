// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package checklist

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/integrations/cmd/backport/backports"
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
			wantContains: []string{"**aws**", "- [ ] `backport-aws-6.14`"},
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
			title: "unchecked branch renders with empty checkbox",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranch("backport-aws-6.14")}},
			},
			checked:      map[string]bool{},
			wantContains: []string{"- [ ] `backport-aws-6.14`"},
			wantMissing:  []string{"- [x] `backport-aws-6.14`"},
		},
		{
			title: "checked branch renders with filled checkbox",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranch("backport-aws-6.14")}},
			},
			checked:      map[string]bool{"backport-aws-6.14": true},
			wantContains: []string{"- [x] `backport-aws-6.14`"},
			wantMissing:  []string{"- [ ] `backport-aws-6.14`"},
		},
		{
			title: "intro text mentions PRs will be created automatically for checked branches",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranch("backport-aws-6.14")}},
			},
			checked:      map[string]bool{},
			wantContains: []string{"PRs will be created automatically on merge, or when you update this checklist after merge."},
		},
		{
			title: "intro links to the backport guidance wiki",
			pkgs: []PackageBranches{
				{Package: "aws", Branches: []backports.ActiveResult{awsBranch("backport-aws-6.14")}},
			},
			checked: map[string]bool{},
			wantContains: []string{
				"Backport a change when it fixes behavior a branch already has",
				"https://github.com/elastic/integrations/wiki/Package-Backports",
			},
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

func TestParseChecklistItems(t *testing.T) {
	cases := []struct {
		title string
		body  string
		want  []ChecklistItem
	}{
		{
			title: "empty body returns empty slice",
			body:  "",
			want:  []ChecklistItem{},
		},
		{
			title: "body without marker returns empty slice",
			body:  "**aws**\n- [x] `backport-aws-6.14`\n",
			want:  []ChecklistItem{},
		},
		{
			title: "single unchecked branch",
			body:  marker + "\n**aws**\n- [ ] `backport-aws-6.14`\n",
			want: []ChecklistItem{
				{Package: "aws", Branch: "backport-aws-6.14", Checked: false, Processed: false},
			},
		},
		{
			title: "single checked branch",
			body:  marker + "\n**aws**\n- [x] `backport-aws-6.14`\n",
			want: []ChecklistItem{
				{Package: "aws", Branch: "backport-aws-6.14", Checked: true, Processed: false},
			},
		},
		{
			title: "checked branch with success status is Processed",
			body:  marker + "\n**aws**\n- [x] `backport-aws-6.14` — ✅ #1234\n",
			want: []ChecklistItem{
				{Package: "aws", Branch: "backport-aws-6.14", Checked: true, Processed: true},
			},
		},
		{
			title: "checked branch with conflict status is Processed",
			body:  marker + "\n**aws**\n- [x] `backport-aws-6.14` — ⚠️ conflict: please run manually\n",
			want: []ChecklistItem{
				{Package: "aws", Branch: "backport-aws-6.14", Checked: true, Processed: true},
			},
		},
		{
			title: "multiple packages with multiple branches each",
			body: marker + "\n**aws**\n- [x] `backport-aws-6.14`\n- [ ] `backport-aws-6.15`\n\n" +
				"**kubernetes**\n- [x] `backport-kubernetes-1.28` — ✅ #5678\n- [ ] `backport-kubernetes-1.29`\n",
			want: []ChecklistItem{
				{Package: "aws", Branch: "backport-aws-6.14", Checked: true, Processed: false},
				{Package: "aws", Branch: "backport-aws-6.15", Checked: false, Processed: false},
				{Package: "kubernetes", Branch: "backport-kubernetes-1.28", Checked: true, Processed: true},
				{Package: "kubernetes", Branch: "backport-kubernetes-1.29", Checked: false, Processed: false},
			},
		},
		{
			title: "branch with maintained_until suffix is parsed correctly",
			body:  marker + "\n**aws**\n- [ ] `backport-aws-6.14` (maintained until 2027-01-15)\n",
			want: []ChecklistItem{
				{Package: "aws", Branch: "backport-aws-6.14", Checked: false, Processed: false},
			},
		},
		{
			title: "branch with maintained_until suffix and success status is Processed",
			body:  marker + "\n**aws**\n- [x] `backport-aws-6.14` (maintained until 2027-01-15) — ✅ #1234\n",
			want: []ChecklistItem{
				{Package: "aws", Branch: "backport-aws-6.14", Checked: true, Processed: true},
			},
		},
		{
			title: "branch with maintained_until suffix and conflict status is Processed",
			body:  marker + "\n**aws**\n- [x] `backport-aws-6.14` (maintained until 2027-01-15) — ⚠️ conflict: please run manually\n",
			want: []ChecklistItem{
				{Package: "aws", Branch: "backport-aws-6.14", Checked: true, Processed: true},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			got := ParseChecklistItems(tc.body)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestUpdateBranchStatus(t *testing.T) {
	cases := []struct {
		title  string
		body   string
		branch string
		status string
		want   string
	}{
		{
			title:  "appends success status to matching checked branch line",
			body:   marker + "\n**aws**\n- [x] `backport-aws-6.14`\n",
			branch: "backport-aws-6.14",
			status: "✅ #1234",
			want:   marker + "\n**aws**\n- [x] `backport-aws-6.14` — ✅ #1234\n",
		},
		{
			title:  "appends conflict status to matching checked branch line",
			body:   marker + "\n**aws**\n- [x] `backport-aws-6.14`\n",
			branch: "backport-aws-6.14",
			status: "⚠️ conflict: please run manually",
			want:   marker + "\n**aws**\n- [x] `backport-aws-6.14` — ⚠️ conflict: please run manually\n",
		},
		{
			title:  "line already has success suffix is a no-op",
			body:   marker + "\n**aws**\n- [x] `backport-aws-6.14` — ✅ #1234\n",
			branch: "backport-aws-6.14",
			status: "✅ #9999",
			want:   marker + "\n**aws**\n- [x] `backport-aws-6.14` — ✅ #1234\n",
		},
		{
			title:  "line already has conflict suffix is a no-op",
			body:   marker + "\n**aws**\n- [x] `backport-aws-6.14` — ⚠️ conflict: please run manually\n",
			branch: "backport-aws-6.14",
			status: "✅ #9999",
			want:   marker + "\n**aws**\n- [x] `backport-aws-6.14` — ⚠️ conflict: please run manually\n",
		},
		{
			title:  "branch not found leaves body unchanged",
			body:   marker + "\n**aws**\n- [x] `backport-aws-6.14`\n",
			branch: "backport-aws-6.15",
			status: "✅ #1234",
			want:   marker + "\n**aws**\n- [x] `backport-aws-6.14`\n",
		},
		{
			title:  "only the matching branch line is updated, others untouched",
			body:   marker + "\n**aws**\n- [x] `backport-aws-6.14`\n- [ ] `backport-aws-6.15`\n",
			branch: "backport-aws-6.14",
			status: "✅ #1234",
			want:   marker + "\n**aws**\n- [x] `backport-aws-6.14` — ✅ #1234\n- [ ] `backport-aws-6.15`\n",
		},
		{
			title:  "branch with maintained_until suffix gets status appended",
			body:   marker + "\n**aws**\n- [x] `backport-aws-6.14` (maintained until 2027-01-15)\n",
			branch: "backport-aws-6.14",
			status: "✅ #1234",
			want:   marker + "\n**aws**\n- [x] `backport-aws-6.14` (maintained until 2027-01-15) — ✅ #1234\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			got := UpdateBranchStatus(tc.body, tc.branch, tc.status)
			assert.Equal(t, tc.want, got)
		})
	}
}
