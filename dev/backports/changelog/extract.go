// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"regexp"
	"strings"
)

// versionLineRE matches a changelog version header line with optional quoting:
//
//   - version: 1.2.3
//   - version: "1.2.3-preview"
var versionLineRE = regexp.MustCompile(`^- version:\s*["']?([0-9]+\.[0-9]+\.[0-9][^\s"']*)["']?\s*$`)

// ExtractFromDiff parses a unified diff of a changelog.yml and returns the
// first newly-added version string and its full entry block (the lines from
// that version header up to, but not including, the next version header).
//
// Returns ("", "", nil) when the diff contains no added version entry.
func ExtractFromDiff(diffText string) (version, entryBlock string, err error) {
	var added []string
	for _, line := range strings.Split(diffText, "\n") {
		if strings.HasPrefix(line, "+++ ") {
			continue
		}
		if strings.HasPrefix(line, "+") {
			added = append(added, line[1:])
		}
	}

	start := -1
	end := len(added)

	for i, line := range added {
		m := versionLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if start == -1 {
			start = i
			version = m[1]
		} else {
			end = i
			break
		}
	}

	if start == -1 {
		return "", "", nil
	}

	entryBlock = strings.Join(added[start:end], "\n")
	return version, entryBlock, nil
}
