// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package util

const (
	ReleaseExperimental = "experimental"
	ReleaseBeta         = "beta"
	ReleaseGa           = "ga"

	// Default release if no release is configured
	DefaultRelease = ReleaseExperimental
)

var ReleaseTypes = map[string]interface{}{
	ReleaseExperimental: nil,
	ReleaseBeta:         nil,
	ReleaseGa:           nil,
}

func IsValidRelase(release string) bool {
	_, exists := ReleaseTypes[release]
	return exists
}
