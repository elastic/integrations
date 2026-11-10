// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMergeOsqueryFields(t *testing.T) {
	norms := false
	text := osqueryMultiField{Name: "text", Type: "text", Norms: &norms}
	long := osqueryMultiField{Name: "number", Type: "long"}
	double := osqueryMultiField{Name: "number", Type: "double"}

	previous := []osqueryField{
		{Name: "channel", Description: "old", Type: "keyword", IgnoreAbove: 1024},
		{Name: "cid", Description: "bpf_process_events.cid - Cgroup ID", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{long}},
		{Name: "count", Description: "old", Type: "keyword", IgnoreAbove: 1024},
		{Name: "exit_code", Description: "old", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{text}},
		{Name: "fd", Description: "old", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{text}},
		{Name: "size", Description: "old", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{long}},
	}
	generated := []osqueryField{
		{Name: "channel", Description: "new", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{text}},
		{Name: "count", Description: "new", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{long}},
		{Name: "exit_code", Description: "new", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{long}},
		{Name: "fd", Description: "new", Type: "keyword", IgnoreAbove: 1024},
		{Name: "gpu", Description: "new", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{text}},
		{Name: "size", Description: "new", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{double}},
	}

	got := mergeOsqueryFields(generated, previous, "5.24.0")
	want := []osqueryField{
		// An existing field gains a text multi-field.
		{Name: "channel", Description: "new", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{text}},
		{Name: "cid", Description: "Removed in osquery 5.24.0; mapping kept for results from older agents.\nbpf_process_events.cid - Cgroup ID", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{long}},
		// An existing field never gains a numeric multi-field.
		{Name: "count", Description: "new", Type: "keyword", IgnoreAbove: 1024},
		{Name: "exit_code", Description: "new", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{text}},
		{Name: "fd", Description: "new", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{text}},
		// A new field gets its generated multi-fields.
		{Name: "gpu", Description: "new", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{text}},
		{Name: "size", Description: "new", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{long}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected merge:\ngot:  %#v\nwant: %#v", got, want)
	}

	// A later upgrade must not stack another note or change the result.
	again := mergeOsqueryFields(generated, got, "5.25.0")
	if !reflect.DeepEqual(again, want) {
		t.Fatalf("merge is not stable on re-run:\ngot:  %#v\nwant: %#v", again, want)
	}
}

func TestOsqueryFieldsYAMLRoundTrip(t *testing.T) {
	norms := false
	fields := []osqueryField{
		{Name: "a", Description: "a.a - A", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{{Name: "text", Type: "text", Norms: &norms}}},
		{Name: "b", Description: "b.b - B", Type: "keyword", IgnoreAbove: 1024, Multifields: []osqueryMultiField{{Name: "number", Type: "long"}}},
		{Name: "c", Description: "c.c - C", Type: "keyword", IgnoreAbove: 1024},
	}
	b, err := generateOsqueryFieldsYAML(fields)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"        - name: text\n          type: text\n          norms: false\n          default_field: false\n",
		"        - name: number\n          type: long\n          default_field: false\n",
	} {
		if !strings.Contains(string(b), s) {
			t.Fatalf("missing %q in:\n%s", s, b)
		}
	}

	path := filepath.Join(t.TempDir(), "osquery.yml")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readOsqueryFieldsYAML(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, fields) {
		t.Fatalf("round trip mismatch:\ngot:  %#v\nwant: %#v", got, fields)
	}
}

func TestReadOsqueryFieldsYAMLMissingFile(t *testing.T) {
	got, err := readOsqueryFieldsYAML(filepath.Join(t.TempDir(), "osquery.yml"))
	if err != nil || got != nil {
		t.Fatalf("got %v, %v; want nil, nil", got, err)
	}
}
