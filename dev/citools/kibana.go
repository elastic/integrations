// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package citools

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

func KibanaConstraintPackage(path string) (*semver.Constraints, error) {
	manifest, err := readPackageManifest(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read package manifest: %w", err)
	}

	kibanaVersion := manifest.Conditions.Kibana.Version
	if kibanaVersion == "" {
		return nil, nil
	}

	constraint, err := semver.NewConstraint(kibanaVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kibana constraint: %w", err)
	}
	return constraint, nil
}

func IsPackageSupportedInStackVersion(stackVersion string, path string) (bool, error) {
	stackVersion = strings.TrimSuffix(stackVersion, "-SNAPSHOT")

	stackSemVersion, err := semver.NewVersion(stackVersion)
	if err != nil {
		return false, fmt.Errorf("failed to parse stack version: %w", err)
	}

	packageConstraint, err := KibanaConstraintPackage(path)
	if err != nil {
		return false, err
	}

	if packageConstraint == nil {
		return true, nil
	}

	return packageConstraint.Check(stackSemVersion), nil
}
