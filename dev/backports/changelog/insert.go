// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// versionEntryRE matches a changelog version header and captures the version string.
var versionEntryRE = regexp.MustCompile(`^- version:\s*["']?([^\s"']+)["']?\s*$`)

// InsertEntry inserts entryBlock into the changelog at changelogPath, placing
// it before the first existing entry whose version is lower than newVersion,
// preserving semver-descending order. It is idempotent: if newVersion is
// already present the file is left unchanged.
func InsertEntry(changelogPath, newVersion, entryBlock string) error {
	info, err := os.Stat(changelogPath)
	if err != nil {
		return fmt.Errorf("reading changelog %s: %w", changelogPath, err)
	}
	data, err := os.ReadFile(changelogPath)
	if err != nil {
		return fmt.Errorf("reading changelog %s: %w", changelogPath, err)
	}

	newVer, err := semver.NewVersion(newVersion)
	if err != nil {
		return fmt.Errorf("parsing version %q: %w", newVersion, err)
	}

	lines := strings.Split(string(data), "\n")
	insertAt := len(lines)

	for i, line := range lines {
		m := versionEntryRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		existing := m[1]
		if existing == newVersion {
			return nil // already present — idempotent
		}
		existingVer, err := semver.NewVersion(existing)
		if err != nil {
			continue
		}
		if newVer.GreaterThan(existingVer) {
			insertAt = i
			break
		}
	}

	entryLines := strings.Split(entryBlock, "\n")
	result := make([]string, 0, len(lines)+len(entryLines))
	result = append(result, lines[:insertAt]...)
	result = append(result, entryLines...)
	result = append(result, lines[insertAt:]...)

	return os.WriteFile(changelogPath, []byte(strings.Join(result, "\n")), info.Mode())
}
