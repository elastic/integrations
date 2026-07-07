// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"fmt"
	"path/filepath"

	"github.com/elastic/integrations/dev/citools"
)

// BuildPackageIndex returns a map of package name → directory for every
// package found under packagesDir.
func BuildPackageIndex(packagesDir string) (map[string]string, error) {
	paths, err := citools.ListPackages(packagesDir)
	if err != nil {
		return nil, fmt.Errorf("listing packages under %s: %w", packagesDir, err)
	}

	index := make(map[string]string, len(paths))
	for _, p := range paths {
		manifest, err := citools.ReadPackageManifest(filepath.Join(p, citools.ManifestFileName))
		if err != nil {
			return nil, fmt.Errorf("reading manifest at %s: %w", p, err)
		}
		index[manifest.Name] = p
	}

	return index, nil
}
