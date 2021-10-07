// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"github.com/blang/semver"

	"github.com/elastic/package-registry/packages"
)

var zeroVersion = semver.MustParse("0.0.0")

func createConditions() *packages.Conditions {
	return &packages.Conditions{
		Kibana: &packages.KibanaConditions{Version: "^7.15.0"},
	}
}
