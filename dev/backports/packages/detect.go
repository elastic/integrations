// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package packages

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/elastic/integrations/dev/citools"
)

// DetectPackages maps a list of changed file paths to the package names they belong to.
// packagesDir is the path to the packages/ directory (e.g. "packages").
//
// It first calls citools.ListPackagesWithNames to discover all package roots, then checks
// each changed file against those roots. This handles both flat structures
// (packages/<name>/) and nested structures (packages/<technology>/<name>/) without
// any custom tree-walking logic. Files not under any known package root are silently
// skipped.
//
// Returns a deduplicated list of package names in the order they are first encountered.
func DetectPackages(files []string, packagesDir string) ([]string, error) {
	pkgs, err := citools.ListPackagesWithNames(packagesDir)
	if err != nil {
		return nil, fmt.Errorf("listing packages in %s: %w", packagesDir, err)
	}

	// Pre-append the separator once per package to avoid a string allocation on every
	// (file, package) pair in the inner loop below.
	sep := string(filepath.Separator)
	for i := range pkgs {
		pkgs[i].Path += sep
	}

	seen := make(map[string]struct{})
	result := make([]string, 0) // non-nil so json.Marshal produces [] not null
	for _, f := range files {
		for _, p := range pkgs {
			if strings.HasPrefix(f, p.Path) {
				if _, ok := seen[p.Name]; !ok {
					seen[p.Name] = struct{}{}
					result = append(result, p.Name)
				}
				break
			}
		}
	}
	return result, nil
}
