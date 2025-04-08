package citools

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
)

var (
	semver_8_17_0 = semver.MustParse("8.17.0")
	semver_8_19_0 = semver.MustParse("8.19.0")
	semver_9_1_0  = semver.MustParse("9.1.0")
)

func IsVersionLessThanLogsDBGA(version *semver.Version) bool {
	if version.LessThan(semver_8_17_0) {
		return true
	}
	return false
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

	if constraint.Check(semver_8_19_0) || constraint.Check(semver_9_1_0) {
		return true, nil
	}
	return false, nil
}
