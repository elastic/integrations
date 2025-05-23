// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package citools

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
)

var (
	semver8_17_0  = semver.MustParse("8.17.0")
	semver8_19_99 = semver.MustParse("8.19.99")
	semver9_99_99 = semver.MustParse("9.99.99")
)

func IsVersionLessThanLogsDBGA(version *semver.Version) bool {
	return version.LessThan(semver8_17_0)
}

func packageKibanaConstraint(path string) (*semver.Constraints, error) {
	manifest, err := readPackageManifest(path)
	if err != nil {
		return nil, err
	}

	kibanaConstraint := manifest.Conditions.Kibana.Version
	if kibanaConstraint == "" {
		return nil, nil
	}

	constraints, err := semver.NewConstraint(kibanaConstraint)
	if err != nil {
		return nil, err
	}

	return constraints, nil
}

func IsLogsDBSupportedInPackage(path string) (bool, error) {
	constraint, err := packageKibanaConstraint(path)
	if err != nil {
		return false, fmt.Errorf("failed to read kibana.constraint fro mmanifest: %w", err)
	}

	if constraint == nil {
		// Package does not contain any kibana.version
		return true, nil
	}

	// Ensure that the package supports LogsDB mode
	// It is not used here "semver8_17_0" since a constraint like "^8.18.0 || ^9.0.0" would return false
	if constraint.Check(semver8_19_99) || constraint.Check(semver9_99_99) {
		return true, nil
	}
	return false, nil
}
