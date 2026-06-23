// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestResolveBranchName(t *testing.T) {
	tests := []struct {
		target  string
		pkg     string
		want    string
		wantErr bool
	}{
		{target: "6.14", pkg: "aws", want: "backport-aws-6.14"},
		{target: "6.x", pkg: "aws", want: "backport-aws-6.x"},
		{target: "backport-aws-6.14", pkg: "aws", want: "backport-aws-6.14"},
		{target: "backport-prometheus-1.24", pkg: "prometheus", want: "backport-prometheus-1.24"},
		{target: "bad version!", pkg: "aws", wantErr: true},
		{target: "6.14", pkg: "bad pkg!", wantErr: true},
	}
	for _, tc := range tests {
		got, err := ResolveBranchName(tc.target, tc.pkg)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ResolveBranchName(%q, %q): expected error, got %q", tc.target, tc.pkg, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveBranchName(%q, %q): unexpected error: %v", tc.target, tc.pkg, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ResolveBranchName(%q, %q) = %q, want %q", tc.target, tc.pkg, got, tc.want)
		}
	}
}

func TestWorkingBranchName(t *testing.T) {
	tests := []struct {
		pkg, branch, sha8, want string
	}{
		{"aws", "backport-aws-6.14", "abc12345", "auto-backport/aws-6.14-abc12345"},
		{"prometheus", "backport-prometheus-1.24", "deadbeef", "auto-backport/prometheus-1.24-deadbeef"},
	}
	for _, tc := range tests {
		got := workingBranchName(tc.pkg, tc.branch, tc.sha8)
		if got != tc.want {
			t.Errorf("workingBranchName(%q, %q, %q) = %q, want %q", tc.pkg, tc.branch, tc.sha8, got, tc.want)
		}
	}
}

func TestBumpPatchVersion(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "unquoted",
			content: "name: aws\nversion: 6.14.2\nformat_version: 3.0.0\n",
			want:    "6.14.3",
		},
		{
			name:    "double-quoted",
			content: "name: zscaler\nversion: \"1.23.3\"\nformat_version: 3.0.0\n",
			want:    "1.23.4",
		},
		{
			name:    "single-quoted",
			content: "name: prom\nversion: '2.0.1'\nformat_version: 3.0.0\n",
			want:    "2.0.2",
		},
		{
			name:    "patch zero",
			content: "version: 1.0.0\n",
			want:    "1.0.1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "manifest-*.yml")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(tc.content); err != nil {
				t.Fatal(err)
			}
			f.Close()

			got, err := BumpPatchVersion(f.Name())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}

			// Verify the file was actually updated.
			updated, _ := os.ReadFile(f.Name())
			if !strings.Contains(string(updated), tc.want) {
				t.Errorf("file does not contain new version %q:\n%s", tc.want, updated)
			}
		})
	}
}

func TestBumpPatchVersionMissingField(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "manifest-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("name: pkg\nformat_version: 3.0.0\n")
	f.Close()

	if _, err := BumpPatchVersion(f.Name()); err == nil {
		t.Error("expected error for manifest without version field")
	}
}

func TestParseEntryFields(t *testing.T) {
	tests := []struct {
		name       string
		entryBlock string
		wantDesc   string
		wantType   string
		wantLink   string
	}{
		{
			name: "full entry",
			entryBlock: `- version: "1.2.3"
  changes:
    - description: Fix a bug in the ingestion pipeline.
      type: bugfix
      link: https://github.com/elastic/integrations/pull/123`,
			wantDesc: "Fix a bug in the ingestion pipeline.",
			wantType: "bugfix",
			wantLink: "https://github.com/elastic/integrations/pull/123",
		},
		{
			name: "missing link",
			entryBlock: `- version: "1.2.3"
  changes:
    - description: Some enhancement.
      type: enhancement`,
			wantDesc: "Some enhancement.",
			wantType: "enhancement",
			wantLink: "",
		},
		{
			name:       "empty block",
			entryBlock: "",
			wantDesc:   "",
			wantType:   "",
			wantLink:   "",
		},
		{
			name:       "invalid yaml",
			entryBlock: "not: [valid yaml: {",
			wantDesc:   "",
			wantType:   "",
			wantLink:   "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			desc, changeType, link := ParseEntryFields(tc.entryBlock)
			if desc != tc.wantDesc || changeType != tc.wantType || link != tc.wantLink {
				t.Errorf("ParseEntryFields() = (%q, %q, %q), want (%q, %q, %q)",
					desc, changeType, link, tc.wantDesc, tc.wantType, tc.wantLink)
			}
		})
	}
}

func TestBuildEntryBlock(t *testing.T) {
	got := BuildEntryBlock("1.2.4", "Fix the thing.", "bugfix", "https://github.com/elastic/integrations/pull/999")
	want := "- version: \"1.2.4\"\n  changes:\n    - description: Fix the thing.\n      type: bugfix\n      link: https://github.com/elastic/integrations/pull/999"
	if got != want {
		t.Errorf("BuildEntryBlock() =\n%s\nwant:\n%s", got, want)
	}
}

func TestBuildEntryBlockSpecialChars(t *testing.T) {
	tests := []struct {
		name        string
		description string
	}{
		{"colon-space", "Fix error: timeout in handler"},
		{"leading bracket", "[aws] fix panic on nil"},
		{"hash", "remove # legacy field"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			block := BuildEntryBlock("1.0.1", tc.description, "bugfix", "https://github.com/elastic/integrations/pull/1")
			var entries []changelogEntryYAML
			if err := yaml.Unmarshal([]byte(block), &entries); err != nil {
				t.Fatalf("output is not valid YAML: %v\noutput:\n%s", err, block)
			}
			if len(entries) == 0 || len(entries[0].Changes) == 0 {
				t.Fatalf("unexpected structure after Unmarshal: %+v", entries)
			}
			if got := entries[0].Changes[0].Description; got != tc.description {
				t.Errorf("round-trip description = %q, want %q", got, tc.description)
			}
		})
	}
}

func TestBumpPatchVersionPreservesRestOfFile(t *testing.T) {
	content := "name: mypackage\nformat_version: 3.0.0\nversion: 2.5.9\ndescription: A package.\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.yml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := BumpPatchVersion(path); err != nil {
		t.Fatal(err)
	}
	updated, _ := os.ReadFile(path)
	want := "name: mypackage\nformat_version: 3.0.0\nversion: 2.5.10\ndescription: A package.\n"
	if string(updated) != want {
		t.Errorf("file content after bump:\n%s\nwant:\n%s", updated, want)
	}
}
