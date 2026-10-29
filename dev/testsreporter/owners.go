// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testsreporter

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/elastic/integrations/dev/citools"
	"github.com/elastic/integrations/dev/codeowners"
)

// ownersResolver finds the owners of the packages reported in the tests results.
//
// The package name in the results is the name defined in the manifest of the package for recent
// versions of elastic-package, and the name of the package folder for older versions. Both are
// supported: the name in the manifest is looked up first, and then the name of the folder.
type ownersResolver struct {
	owners   *codeowners.Owners
	packages []citools.PackageInfo
}

// newOwnersResolver creates a resolver for the packages found in packagesPath, that must be relative
// to the root of the repository, as the paths in the CODEOWNERS file are.
func newOwnersResolver(codeownersPath, packagesPath string) (*ownersResolver, error) {
	owners, err := codeowners.LoadOwners(codeownersPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CODEOWNERS file: %w", err)
	}

	packages, err := citools.ListPackagesWithNames(packagesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list packages: %w", err)
	}

	return &ownersResolver{owners: owners, packages: packages}, nil
}

// packageDetails are the details found for a package reported in the tests results.
type packageDetails struct {
	// path of the package, relative to the root of the repository.
	path string
	// owners of the package, or of its data stream if the data stream has owners.
	owners []string
}

// lookup finds the path and the owners of a package. The path is returned even if the owners
// are not found.
func (r *ownersResolver) lookup(packageName, dataStream string) (packageDetails, error) {
	pkg, err := r.findPackage(packageName)
	if err != nil {
		return packageDetails{}, err
	}

	details := packageDetails{path: pkg.Path}
	details.owners, err = r.owners.PackageOwnersByPath(pkg.Path, dataStream)
	if err != nil {
		return details, fmt.Errorf("failed to find owners for package %s: %w", packageName, err)
	}
	return details, nil
}

func (r *ownersResolver) findPackage(name string) (citools.PackageInfo, error) {
	var byName, byFolder []citools.PackageInfo
	for _, pkg := range r.packages {
		if pkg.Name == name {
			byName = append(byName, pkg)
		}
		if filepath.Base(pkg.Path) == name {
			byFolder = append(byFolder, pkg)
		}
	}

	if len(byName) > 0 {
		return uniquePackage(name, "name", byName)
	}
	if len(byFolder) > 0 {
		return uniquePackage(name, "folder", byFolder)
	}
	return citools.PackageInfo{}, fmt.Errorf("no package found with name or folder %q", name)
}

func uniquePackage(name, kind string, candidates []citools.PackageInfo) (citools.PackageInfo, error) {
	if len(candidates) == 1 {
		return candidates[0], nil
	}

	paths := make([]string, len(candidates))
	for i, pkg := range candidates {
		paths[i] = pkg.Path
	}
	return citools.PackageInfo{}, fmt.Errorf("package %s %q is ambiguous, found in: %s", kind, name, strings.Join(paths, ", "))
}
