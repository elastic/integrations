// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package citools

import (
	"fmt"
)

func packageSubscription(path string) (string, error) {
	manifest, err := readPackageManifest(path)
	if err != nil {
		return "", err
	}

	packageSubscription := manifest.Conditions.Elastic.Subscription
	if packageSubscription == "" {
		packageSubscription = manifest.License
	}
	if packageSubscription == "" {
		packageSubscription = "basic"
	}

	return packageSubscription, nil
}

func IsSubscriptionCompatible(stackSubscription, path string) (bool, error) {
	pkgSubscription, err := packageSubscription(path)
	if err != nil {
		return false, fmt.Errorf("failed to read subscription from manifest: %w", err)
	}

	if stackSubscription == "trial" {
		// All subscriptions supported
		return true, nil
	}

	if stackSubscription == "basic" {
		if pkgSubscription != "basic" {
			return false, nil
		}
		return true, nil
	}

	return false, fmt.Errorf("unknown subscription %s", stackSubscription)
}
