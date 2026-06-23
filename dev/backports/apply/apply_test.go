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
		got, err := resolveBranchName(tc.target, tc.pkg)
		if tc.wantErr {
			if err == nil {
				t.Errorf("resolveBranchName(%q, %q): expected error, got %q", tc.target, tc.pkg, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveBranchName(%q, %q): unexpected error: %v", tc.target, tc.pkg, err)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveBranchName(%q, %q) = %q, want %q", tc.target, tc.pkg, got, tc.want)
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

			got, err := bumpPatchVersion(f.Name())
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

	if _, err := bumpPatchVersion(f.Name()); err == nil {
		t.Error("expected error for manifest without version field")
	}
}

func TestParseEntryFields(t *testing.T) {
	tests := []struct {
		name    string
		block   string
		want    []changeItem
	}{
		{
			name: "single item",
			block: `- version: "1.2.3"
  changes:
    - description: Fix a bug in the ingestion pipeline.
      type: bugfix
      link: https://github.com/elastic/integrations/pull/123`,
			want: []changeItem{
				{Description: "Fix a bug in the ingestion pipeline.", Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/123"},
			},
		},
		{
			name: "multiple items",
			block: `- version: "1.2.3"
  changes:
    - description: Fix a bug.
      type: bugfix
      link: https://github.com/elastic/integrations/pull/1
    - description: Add a feature.
      type: enhancement
      link: https://github.com/elastic/integrations/pull/2`,
			want: []changeItem{
				{Description: "Fix a bug.", Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/1"},
				{Description: "Add a feature.", Type: "enhancement", Link: "https://github.com/elastic/integrations/pull/2"},
			},
		},
		{
			name:  "missing link",
			block: `- version: "1.2.3"
  changes:
    - description: Some enhancement.
      type: enhancement`,
			want: []changeItem{{Description: "Some enhancement.", Type: "enhancement"}},
		},
		{
			name:  "empty block",
			block: "",
			want:  nil,
		},
		{
			name:  "invalid yaml",
			block: "not: [valid yaml: {",
			want:  nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseEntryFields(tc.block)
			if len(got) != len(tc.want) {
				t.Fatalf("parseEntryFields() returned %d items, want %d: %+v", len(got), len(tc.want), got)
			}
			for i, item := range got {
				if item != tc.want[i] {
					t.Errorf("item[%d] = %+v, want %+v", i, item, tc.want[i])
				}
			}
		})
	}
}

func TestBuildEntryBlock(t *testing.T) {
	changes := []changeItem{{Description: "Fix the thing.", Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/999"}}
	got := buildEntryBlock("1.2.4", changes)
	want := "- version: \"1.2.4\"\n  changes:\n    - description: Fix the thing.\n      type: bugfix\n      link: https://github.com/elastic/integrations/pull/999"
	if got != want {
		t.Errorf("buildEntryBlock() =\n%s\nwant:\n%s", got, want)
	}
}

func TestBuildEntryBlockMultipleItems(t *testing.T) {
	changes := []changeItem{
		{Description: "Fix a bug.", Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/1"},
		{Description: "Add a feature.", Type: "enhancement", Link: "https://github.com/elastic/integrations/pull/2"},
	}
	block := buildEntryBlock("1.2.4", changes)
	var entries []changelogEntryYAML
	if err := yaml.Unmarshal([]byte(block), &entries); err != nil {
		t.Fatalf("output is not valid YAML: %v\noutput:\n%s", err, block)
	}
	if len(entries) == 0 || len(entries[0].Changes) != 2 {
		t.Fatalf("expected 2 change items, got %d", len(entries[0].Changes))
	}
	if entries[0].Changes[0].Description != "Fix a bug." || entries[0].Changes[1].Description != "Add a feature." {
		t.Errorf("unexpected change items: %+v", entries[0].Changes)
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
			changes := []changeItem{{Description: tc.description, Type: "bugfix", Link: "https://github.com/elastic/integrations/pull/1"}}
			block := buildEntryBlock("1.0.1", changes)
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

	if _, err := bumpPatchVersion(path); err != nil {
		t.Fatal(err)
	}
	updated, _ := os.ReadFile(path)
	want := "name: mypackage\nformat_version: 3.0.0\nversion: 2.5.10\ndescription: A package.\n"
	if string(updated) != want {
		t.Errorf("file content after bump:\n%s\nwant:\n%s", updated, want)
	}
}
