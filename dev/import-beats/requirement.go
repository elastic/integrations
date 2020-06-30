// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/blang/semver"
	"github.com/pkg/errors"

	"github.com/elastic/package-registry/util"
)

var zeroVersion = semver.MustParse("0.0.0")

func createRequirement(kibanaContent kibanaContent, datasetContent []datasetContent) (util.Requirement, error) {
	// TODO: Update requirement
	// Proposal: Have ^7.9 as default instead of reading it from module?
	kibanaRequirement, err := findRequiredKibanaVersion(kibanaContent)
	if err != nil {
		return util.Requirement{}, errors.Wrapf(err, "finding required Kibana version failed")
	}
	return util.Requirement{
		Kibana: kibanaRequirement,
	}, nil
}

func findRequiredKibanaVersion(kibanaContent kibanaContent) (util.ProductRequirement, error) {
	dashboards, ok := kibanaContent.files["dashboard"]
	if !ok {
		return util.ProductRequirement{}, nil // no dashboards available, no version requirement
	}

	currentVersion := zeroVersion

	for _, dashboardFile := range dashboards {
		var dashboard mapStr
		err := json.Unmarshal(dashboardFile, &dashboard)
		if err != nil {
			return util.ProductRequirement{}, errors.Wrap(err, "unmarshalling dashboard filed")
		}

		panels, err := dashboard.getValue("attributes.panelsJSON")
		if err == errKeyNotFound {
			continue // panelsJSON is missing, skip this dashboard
		}
		if err != nil {
			return util.ProductRequirement{}, errors.Wrap(err, "retrieving key 'attributes.panelsJSON' failed")
		}

		panelsValue := panels.([]interface{})
		if len(panelsValue) == 0 {
			continue // panelsJSON is present, but empty, skip this dashboard
		}

		for _, panel := range panelsValue {
			panelValue, err := toMapStr(panel)
			if err != nil {
				return util.ProductRequirement{}, errors.Wrap(err, "converting to mapstr failed")
			}

			version, err := panelValue.getValue("version")
			if err == errKeyNotFound {
				continue // no version tag, skip this panel
			}
			if err != nil {
				return util.ProductRequirement{}, errors.Wrap(err, "retrieving key 'version' failed")
			}
			versionValue := version.(string)
			parsed, err := semver.Parse(versionValue)
			if err != nil {
				return util.ProductRequirement{}, errors.Wrapf(err, "parsing version failed (value: %s)", versionValue)
			}

			if currentVersion.LT(parsed) {
				currentVersion = parsed
			}
		}
	}

	if currentVersion.EQ(zeroVersion) {
		return util.ProductRequirement{}, nil // no version requirement found, even if all files were visited.
	}

	return util.ProductRequirement{
		Versions: fmt.Sprintf("~%s", currentVersion),
	}, nil
}
