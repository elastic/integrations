// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package citools

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

const ManifestFileName = "manifest.yml"

// ListPackages returns the sorted paths of all packages found under dir.
func ListPackages(dir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		manifestPath := filepath.Join(path, ManifestFileName)
		_, statErr := os.Stat(manifestPath)
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		} else if statErr != nil {
			return fmt.Errorf("error statting manifest %s: %w", manifestPath, statErr)
		}
		manifest, err := ReadPackageManifest(manifestPath)
		if err != nil {
			return fmt.Errorf("error reading manifest %s: %w", manifestPath, err)
		}
		if !manifest.IsValid() {
			return nil
		}
		paths = append(paths, path)
		// No need to look deeper once a package is found.
		return filepath.SkipDir
	})
	if err != nil {
		return nil, fmt.Errorf("error listing packages in %s: %w", dir, err)
	}
	slices.Sort(paths)
	return paths, nil
}
