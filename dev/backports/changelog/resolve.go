// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"fmt"

	"github.com/elastic/integrations/dev/citools"
)

// BuildPackageIndex returns a map of package name → directory for every
// package found under packagesDir.
func BuildPackageIndex(packagesDir string) (map[string]string, error) {
	pkgs, err := citools.ListPackagesWithNames(packagesDir)
	if err != nil {
		return nil, fmt.Errorf("listing packages under %s: %w", packagesDir, err)
	}

	index := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		index[p.Name] = p.Path
	}

	return index, nil
}
