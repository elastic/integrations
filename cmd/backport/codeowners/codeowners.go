// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Copied from dev/codeowners/codeowners.go. Kept as a local copy so that
// cmd/backport remains a self-contained sub-module that can be synced onto
// backport branches without carrying dev/codeowners and its dependencies.

package codeowners

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
)

const DefaultCodeownersPath = ".github/CODEOWNERS"

// Owners holds a parsed CODEOWNERS file for repeated lookups without re-reading disk.
// Obtain one via ParseOwners.
type Owners struct {
	inner *githubOwners
}

// ParseOwners parses CODEOWNERS content from a string, applying the same
// single-field exclusion-rule validation that readGithubOwners does when
// reading from disk. A file that passes mage check never triggers this error.
func ParseOwners(content string) (*Owners, error) {
	o, err := scanGithubOwners(strings.NewReader(content), "<in-memory>")
	if err != nil {
		return nil, err
	}
	return &Owners{inner: o}, nil
}

// Resolve returns the owners that apply to p, walking up parent directories
// until an explicit CODEOWNERS entry is found. p must be a CODEOWNERS-style
// slash-prefixed path (e.g. "/packages/aws/data_stream/cloudtrail"). Returns
// (nil, false) when no entry exists for p or any of its ancestors.
func (o *Owners) Resolve(p string) ([]string, bool) {
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		p = "/"
	}
	for {
		if owners, ok := o.inner.owners[p]; ok {
			return owners, true
		}
		if p == "/" || p == "." {
			return nil, false
		}
		p = path.Dir(p)
	}
}

// EntriesUnder returns the full CODEOWNERS paths of every explicit entry
// nested under prefix (e.g. "/packages/aws" returns
// "/packages/aws/data_stream/cloudtrail" and "/packages/aws/kibana", but not
// "/packages/aws" itself or the unrelated "/packages/awsome"). Order is
// unspecified.
func (o *Owners) EntriesUnder(prefix string) []string {
	prefix = strings.TrimSuffix(prefix, "/") + "/"
	var paths []string
	for p := range o.inner.owners {
		if strings.HasPrefix(p, prefix) {
			paths = append(paths, p)
		}
	}
	return paths
}

// ExplicitEntry returns the owners explicitly defined for exactly this
// CODEOWNERS path — no walk-up/fallback resolution. Returns (nil, false) if
// no explicit entry exists for this exact path.
func (o *Owners) ExplicitEntry(p string) ([]string, bool) {
	p = strings.TrimSuffix(p, "/")
	owners, ok := o.inner.owners[p]
	return owners, ok
}

type githubOwners struct {
	owners map[string][]string
	path   string
}

func scanGithubOwners(r io.Reader, sourcePath string) (*githubOwners, error) {
	codeowners := githubOwners{
		owners: make(map[string][]string),
		path:   sourcePath,
	}

	scanner := bufio.NewScanner(r)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 1 {
			err := codeowners.checkSingleField(fields[0])
			if err != nil {
				return nil, fmt.Errorf("invalid line %d in %q: %w", lineNumber, sourcePath, err)
			}
			continue
		}
		ownerPath, owners := fields[0], fields[1:]

		// remove trailing slash from path
		ownerPath = strings.TrimSuffix(ownerPath, "/")
		codeowners.owners[ownerPath] = owners
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return &codeowners, nil
}

// checkSingleField checks if a single field in a CODEOWNERS file is valid.
// We allow single fields to add files for which we don't need to have owners.
func (codeowners *githubOwners) checkSingleField(field string) error {
	switch field[0] {
	case '/':
		// Allow only rules that wouldn't remove owners for previously
		// defined rules.
		for path := range codeowners.owners {
			matches, err := filepath.Match(field, path)
			if err != nil {
				return err
			}
			if matches || strings.HasPrefix(field, path) {
				return fmt.Errorf("%q would remove owners for %q", field, path)
			}

			if strings.HasPrefix(path, field) {
				_, err := filepath.Rel(field, path)
				if err == nil {
					return fmt.Errorf("%q would remove owners for %q", field, path)
				}
			}
		}

		// Excluding other files is fine.
		return nil
	case '@':
		return fmt.Errorf("rule with owner without path: %q", field)
	default:
		return fmt.Errorf("unexpected field found: %q", field)
	}
}
