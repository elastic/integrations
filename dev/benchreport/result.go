// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package benchreport

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func listAllDirResults(path string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("reading directory failed (path: %s): %w", path, err)
	}

	// only keep results, scan is not recursive
	var filtered []os.DirEntry
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != reportExt {
			continue
		}
		filtered = append(filtered, e)
	}

	return filtered, nil
}

func listAllDirResultsAsMap(path string) (map[string]map[string]fs.DirEntry, error) {
	entries, err := listAllDirResults(path)
	if err != nil {
		return nil, err
	}

	m := map[string]map[string]fs.DirEntry{}
	for _, entry := range entries {
		res, err := readResult(path, entry)
		if err != nil {
			return nil, fmt.Errorf("reading result: %w", err)
		}
		pkg, ds := res.getPackageAndDatastream()
		if m[pkg] == nil {
			m[pkg] = map[string]fs.DirEntry{}
		}
		m[pkg][ds] = entry
	}

	return m, nil
}

func readResult(path string, e fs.DirEntry) (BenchmarkResult, error) {
	fi, err := e.Info()
	if err != nil {
		return BenchmarkResult{}, fmt.Errorf("getting file info failed (file: %s): %w", e.Name(), err)
	}

	b, err := os.ReadFile(path + string(os.PathSeparator) + fi.Name())
	if err != nil {
		return BenchmarkResult{}, fmt.Errorf("reading result contents (file: %s): %w", fi.Name(), err)
	}

	var br BenchmarkResult
	if err := xml.Unmarshal(b, &br); err != nil {
		return BenchmarkResult{}, fmt.Errorf("decoding xml (file: %s): %w", fi.Name(), err)
	}

	return br, nil
}
