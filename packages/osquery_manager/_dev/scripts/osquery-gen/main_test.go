// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateConfigOsqueryVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	input := "osquery:\n  # Keep this comment.\n  version: \"5.23.0\"\nbeats:\n  version: \"9.4.0\"\n"
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := updateConfigOsqueryVersion(path, "5.23.1"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "# Keep this comment.") || !strings.Contains(string(b), `version: "5.23.1"`) || !strings.Contains(string(b), `version: "9.4.0"`) {
		t.Fatalf("unexpected config:\n%s", b)
	}
}

func TestLoadLocalBeatsExtensionSpecs(t *testing.T) {
	root := t.TempDir()
	specsDir := filepath.Join(root, "x-pack", "osquerybeat", "ext", "osquery-extension", "specs")
	if err := os.MkdirAll(specsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := "type: table\nname: local_table\ndescription: Local table\nplatforms: [linux]\ncolumns:\n  - name: value\n    type: TEXT\n    description: Value\n"
	if err := os.WriteFile(filepath.Join(specsDir, "local.table.yml"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	tables, err := loadLocalBeatsExtensionSpecs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) != 1 || tables[0].Name != "local_table" {
		t.Fatalf("unexpected tables: %#v", tables)
	}
}

func TestUpdatePackageMetadata(t *testing.T) {
	root := t.TempDir()
	packageDir := filepath.Join(root, "packages", "osquery_manager")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "manifest.yml"), []byte("name: osquery_manager\nversion: 1.33.2\nconditions:\n  kibana:\n    version: \"^9.4.2\"\n  agent:\n    version: \"^9.4.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "changelog.yml"), []byte("# newer versions go on top\n- version: \"1.33.2\"\n  changes: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := updatePackageMetadata(root, "5.23.1", "https://github.com/elastic/integrations/issues/123", "~9.4.6 || ^9.5.2"); err != nil {
		t.Fatal(err)
	}
	manifest, _ := os.ReadFile(filepath.Join(packageDir, "manifest.yml"))
	changelog, _ := os.ReadFile(filepath.Join(packageDir, "changelog.yml"))
	if !strings.Contains(string(manifest), "version: 1.34.0") || !strings.Contains(string(manifest), `version: "~9.4.6 || ^9.5.2"`) || !strings.Contains(string(manifest), `version: "^9.4.0"`) || !strings.Contains(string(changelog), `version: "1.34.0"`) || !strings.Contains(string(changelog), "5.23.1") || strings.Contains(string(changelog), "security-fixed") {
		t.Fatalf("unexpected metadata:\n%s\n%s", manifest, changelog)
	}
	if err := updatePackageMetadata(root, "5.23.1", "", "~9.4.6 || ^9.5.2"); err != nil {
		t.Fatalf("idempotent update failed: %v", err)
	}
	changelog, _ = os.ReadFile(filepath.Join(packageDir, "changelog.yml"))
	if strings.Count(string(changelog), "Upgrade osquery schema artifacts to version 5.23.1") != 1 {
		t.Fatalf("duplicate changelog entry:\n%s", changelog)
	}
}

func TestUpdatePackageMetadataQuotedVersion(t *testing.T) {
	root := t.TempDir()
	packageDir := filepath.Join(root, "packages", "osquery_manager")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "manifest.yml"), []byte("name: osquery_manager\nversion: \"1.33.2\"\nconditions:\n  kibana:\n    version: \"^9.4.2\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "changelog.yml"), []byte("# newer versions go on top\n- version: \"1.33.2\"\n  changes: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := updatePackageMetadata(root, "5.23.1", "https://github.com/elastic/integrations/pull/1", "~9.4.6 || ^9.5.2"); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(packageDir, "manifest.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), "version: 1.34.0") {
		t.Fatalf("quoted package version not updated:\n%s", manifest)
	}
}

func TestChangelogHasOsquerySchemaVersion(t *testing.T) {
	root := t.TempDir()
	packageDir := filepath.Join(root, "packages", "osquery_manager")
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	changelog := "# newer versions go on top\n- version: \"1.34.0\"\n  changes:\n    - description: Upgrade osquery schema artifacts to version 5.23.1; require Kibana ~9.4.6 || ^9.5.2 so the upgraded runtime is available\n      type: enhancement\n      link: https://github.com/elastic/integrations/pull/1\n"
	if err := os.WriteFile(filepath.Join(packageDir, "changelog.yml"), []byte(changelog), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := changelogHasOsquerySchemaVersion(root, "5.23.1")
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("expected changelog to report schema version 5.23.1 as released")
	}
	got, err = changelogHasOsquerySchemaVersion(root, "5.24.0")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("expected changelog not to report schema version 5.24.0 as released")
	}
}

func TestUpdatePackageMetadataKibanaVersionFormats(t *testing.T) {
	cases := []struct {
		name   string
		kibana string
	}{
		{name: "double-quoted", kibana: "conditions:\n  kibana:\n    version: \"^9.4.2\"\n"},
		{name: "single-quoted", kibana: "conditions:\n  kibana:\n    version: '^9.4.2'\n"},
		{name: "unquoted-tabs", kibana: "conditions:\n\tkibana:\n\t\tversion: ^9.4.2\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			packageDir := filepath.Join(root, "packages", "osquery_manager")
			if err := os.MkdirAll(packageDir, 0o755); err != nil {
				t.Fatal(err)
			}
			manifest := "name: osquery_manager\nversion: 1.33.2\n" + tc.kibana
			if err := os.WriteFile(filepath.Join(packageDir, "manifest.yml"), []byte(manifest), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(packageDir, "changelog.yml"), []byte("# newer versions go on top\n- version: \"1.33.2\"\n  changes: []\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := updatePackageMetadata(root, "5.23.1", "https://github.com/elastic/integrations/pull/1", "~9.4.6 || ^9.5.2"); err != nil {
				t.Fatal(err)
			}
			updated, err := os.ReadFile(filepath.Join(packageDir, "manifest.yml"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(updated), `version: "~9.4.6 || ^9.5.2"`) {
				t.Fatalf("kibana version not updated:\n%s", updated)
			}
		})
	}
}
