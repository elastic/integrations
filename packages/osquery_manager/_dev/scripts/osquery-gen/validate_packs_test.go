// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"strings"
	"testing"
)

func TestValidateShadowAIPacks(t *testing.T) {
	repoRoot := findRepoRoot()
	if repoRoot == "." {
		t.Fatal("failed to detect integrations repo root")
	}

	errs := ValidateShadowAIPacks(repoRoot)
	if len(errs) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString("Shadow AI pack contract violations:\n")
	for _, err := range errs {
		b.WriteString("  - ")
		b.WriteString(err.Error())
		b.WriteByte('\n')
	}
	t.Fatal(b.String())
}

func TestExpectedEventActionContract(t *testing.T) {
	tests := []struct {
		queryID string
		want    string
	}{
		{queryID: "ai_llm_processes", want: "osquery.ai_llm_processes"},
		{queryID: "ai_config_file_changes_linux", want: "osquery.ai_config_file_changes"},
		{queryID: "ai_sensitive_file_proximity_windows", want: "osquery.ai_sensitive_file_colocation"},
		{queryID: "ai_sensitive_file_proximity_macos", want: "osquery.ai_sensitive_file_access"},
	}
	for _, tc := range tests {
		if got := expectedEventAction(tc.queryID); got != tc.want {
			t.Fatalf("expectedEventAction(%q) = %q, want %q", tc.queryID, got, tc.want)
		}
	}
}

func TestExtractOutputColumns(t *testing.T) {
	sql := `SELECT
    p.name,
    p.path,
    datetime(p.start_time, 'unixepoch') AS start_time,
    p.parent AS ppid,
    CASE WHEN p.name IN ('copilot-agent') THEN 'developer' ELSE NULL END AS copilot_variant
FROM processes p`

	cols := extractOutputColumns(sql)
	for _, want := range []string{"name", "path", "start_time", "ppid", "copilot_variant"} {
		if _, ok := cols[want]; !ok {
			t.Fatalf("expected output column %q, got %v", want, cols)
		}
	}
}

func TestValidateDuplicateOrPredicates(t *testing.T) {
	sql := `SELECT p.name FROM processes p
WHERE p.name = 'cursor'
    OR p.cmdline LIKE '%copilot-agent%'
    OR p.cmdline LIKE '%copilot-agent%'`

	errs := validateDuplicateOrPredicates("test", sql)
	if len(errs) != 1 {
		t.Fatalf("expected 1 duplicate OR error, got %d: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Error(), "copilot-agent") {
		t.Fatalf("expected actionable duplicate predicate message, got %q", errs[0].Error())
	}
}

func TestValidateFleetSafeSQL(t *testing.T) {
	badSQL := `SELECT name FROM processes
-- Fleet flattens this query before delivery
WHERE name = 'cursor'`
	errs := validateFleetSafeSQL("test", badSQL)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "Fleet removes query newlines") {
		t.Fatalf("expected Fleet line-comment violation, got %v", errs)
	}

	safeSQL := `SELECT name FROM processes WHERE cmdline LIKE '%--verbose%'`
	if errs := validateFleetSafeSQL("test", safeSQL); len(errs) != 0 {
		t.Fatalf("expected SQL string literal containing dashes to be valid, got %v", errs)
	}
}

func TestValidateStaticArrayMapping(t *testing.T) {
	query := packQuery{
		ID: "ai_llm_processes",
		ECSMapping: []ecsMappingEntry{
			{Key: "event.category", Value: map[string]any{"value": []any{"process"}}},
			{Key: "event.type", Value: map[string]any{"value": []any{"info"}}},
			{Key: "event.action", Value: map[string]any{"value": "osquery.ai_llm_processes"}},
			{Key: "tags", Value: map[string]any{"value": []any{"osquery", "shadow_ai"}}},
		},
	}

	errs := validateQueryReviewMappings("test", query)
	for _, err := range errs {
		if strings.Contains(err.Error(), "event.category") || strings.Contains(err.Error(), "event.type") || strings.Contains(err.Error(), "tags") {
			t.Fatalf("unexpected static array validation error: %v", err)
		}
	}

	bad := packQuery{
		ID: "bad",
		ECSMapping: []ecsMappingEntry{
			{Key: "event.category", Value: map[string]any{"value": "process"}},
			{Key: "event.type", Value: map[string]any{"value": []any{"info"}}},
			{Key: "event.action", Value: map[string]any{"value": "osquery.bad"}},
			{Key: "tags", Value: map[string]any{"value": []any{"osquery"}}},
		},
	}
	errs = validateQueryReviewMappings("test", bad)
	if len(errs) == 0 {
		t.Fatal("expected event.category string violation")
	}
}

func TestValidateOpenClawListeningPortContracts(t *testing.T) {
	exposureSQL := `SELECT l.port FROM listening_ports l JOIN processes p ON l.pid = p.pid
WHERE (
    l.port IN (11434)
    OR (
        l.port = 18789
        AND (
            p.cmdline LIKE '%openclaw%'
            OR p.cmdline LIKE '%moltbot%'
            OR p.cmdline LIKE '%clawdbot%'
            OR p.name LIKE '%openclaw%'
        )
    )
)
    AND l.address != '127.0.0.1'
    AND l.address != '::1';`

	localSQL := `SELECT l.port FROM listening_ports l JOIN processes p ON l.pid = p.pid
WHERE (
    l.port IN (11434)
    OR (
        l.port = 18789
        AND (
            l.address = '127.0.0.1'
            OR l.address = '::1'
        )
        AND (
            p.cmdline LIKE '%openclaw%'
            OR p.cmdline LIKE '%moltbot%'
            OR p.cmdline LIKE '%clawdbot%'
            OR p.name LIKE '%openclaw%'
        )
    )
);`

	if errs := validateOpenClawExposureListeningPorts("test-pack", exposureSQL); len(errs) != 0 {
		t.Fatalf("expected valid exposure SQL, got %v", errs)
	}
	if errs := validateOpenClawLocalListeningPorts("test-pack", localSQL); len(errs) != 0 {
		t.Fatalf("expected valid local SQL, got %v", errs)
	}

	badExposure := strings.Replace(exposureSQL, "p.cmdline LIKE '%openclaw%'", "", 1)
	if errs := validateOpenClawExposureListeningPorts("test-pack", badExposure); len(errs) == 0 {
		t.Fatal("expected missing openclaw corroboration to fail")
	}

	badLocal := strings.Replace(localSQL, "l.address = '127.0.0.1'", "", 1)
	if errs := validateOpenClawLocalListeningPorts("test-pack", badLocal); len(errs) == 0 {
		t.Fatal("expected missing loopback predicate to fail")
	}
}

func TestRejectsGenAIMapping(t *testing.T) {
	query := packQuery{
		ID: "bad",
		ECSMapping: []ecsMappingEntry{
			{Key: "event.category", Value: map[string]any{"value": []any{"process"}}},
			{Key: "event.type", Value: map[string]any{"value": []any{"info"}}},
			{Key: "event.action", Value: map[string]any{"value": "osquery.bad"}},
			{Key: "tags", Value: map[string]any{"value": []any{"osquery"}}},
			{Key: "gen_ai.provider.name", Value: map[string]any{"value": "openai"}},
		},
	}
	errs := validateQueryReviewMappings("test", query)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "gen_ai.") {
		t.Fatalf("expected gen_ai rejection, got %v", errs)
	}
}
