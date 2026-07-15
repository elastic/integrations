// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// linkLineRE matches a changelog link field line and captures the leading
// whitespace + key prefix so the URL value can be replaced without touching
// indentation.
var linkLineRE = regexp.MustCompile(`^(\s+link:\s+)\S.*$`)

// UpdateEntryLinks replaces every link: value inside the changelog entry for
// version with newURL. Entries for other versions are left untouched. If
// version is not present the file is left unchanged and no error is returned.
func UpdateEntryLinks(changelogPath, version, newURL string) error {
	info, err := os.Stat(changelogPath)
	if err != nil {
		return fmt.Errorf("reading changelog %s: %w", changelogPath, err)
	}
	data, err := os.ReadFile(changelogPath)
	if err != nil {
		return fmt.Errorf("reading changelog %s: %w", changelogPath, err)
	}

	lines := strings.Split(string(data), "\n")
	inTarget := false
	changed := false

	for i, line := range lines {
		if m := versionEntryRE.FindStringSubmatch(line); m != nil {
			inTarget = m[1] == version
			continue
		}
		if !inTarget {
			continue
		}
		if loc := linkLineRE.FindStringSubmatchIndex(line); loc != nil {
			// loc[2]:loc[3] is the span of group 1: the "  link: " prefix.
			lines[i] = line[loc[2]:loc[3]] + newURL
			changed = true
		}
	}

	if !changed {
		return nil
	}
	return os.WriteFile(changelogPath, []byte(strings.Join(lines, "\n")), info.Mode())
}
