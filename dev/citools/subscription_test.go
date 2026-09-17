// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package citools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageSubscription(t *testing.T) {
	cases := []struct {
		title    string
		contents string
		expected string
	}{
		{
			title: "Subscription field",
			contents: `name: "subscription"
conditions:
  elastic:
    subscription: foo
`,
			expected: "foo",
		},
		{
			title: "Dotted Subscription field",
			contents: `name: "subscription"
conditions:
  elastic.subscription: dotted
`,
			expected: "dotted",
		},
		{
			title: "Deprecated Subscription field",
			contents: `name: "subscription"
license: deprecated
`,
			expected: "deprecated",
		},
		{
			title: "No Subscription field",
			contents: `name: "subscription"
`,
			expected: "basic",
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			directory := t.TempDir()
			pkgManifestPath := filepath.Join(directory, "manifest.yml")
			err := os.WriteFile(pkgManifestPath, []byte(c.contents), 0o644)
			require.NoError(t, err)
			pkgSubscription, err := packageSubscription(pkgManifestPath)
			require.NoError(t, err)
			assert.Equal(t, c.expected, pkgSubscription)
		})
	}
}

func TestIsSubscriptionCompatible(t *testing.T) {
	cases := []struct {
		title             string
		contents          string
		stackSubscription string
		expectedError     bool
		supported         bool
	}{
		{
			title:             "Trial with Basic Subscription field",
			stackSubscription: "trial",
			contents: `name: "subscription"
conditions:
  elastic:
    subscription: basic
`,
			expectedError: false,
			supported:     true,
		},
		{
			title:             "Trial with Enterprise Subscription",
			stackSubscription: "trial",
			contents: `name: "subscription"
conditions:
  elastic:
    subscription: enterprise
`,
			expectedError: false,
			supported:     true,
		},
		{
			title:             "Trial with Platinum Subscription",
			stackSubscription: "trial",
			contents: `name: "subscription"
conditions:
  elastic:
    subscription: platinum
`,
			expectedError: false,
			supported:     true,
		},
		{
			title:             "Trial with Platinum Subscription",
			stackSubscription: "trial",
			contents: `name: "subscription"
conditions:
  elastic:
    subscription: platinum
`,
			expectedError: false,
			supported:     true,
		},
		{
			title:             "Basic with Basic Subscription field",
			stackSubscription: "basic",
			contents: `name: "subscription"
conditions:
  elastic:
    subscription: basic
`,
			expectedError: false,
			supported:     true,
		},
		{
			title:             "Basic with Enterprise Subscription",
			stackSubscription: "basic",
			contents: `name: "subscription"
conditions:
  elastic:
    subscription: enterprise
`,
			expectedError: false,
			supported:     false,
		},
		{
			title:             "Basic with Platinum Subscription",
			stackSubscription: "basic",
			contents: `name: "subscription"
conditions:
  elastic:
    subscription: platinum
`,
			expectedError: false,
			supported:     false,
		},
		{
			title:             "Unknown Stack Subscription",
			stackSubscription: "other",
			contents: `name: "subscription"
conditions:
  elastic:
    subscription: platinum
`,
			expectedError: true,
			supported:     false,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			directory := t.TempDir()
			pkgManifestPath := filepath.Join(directory, "manifest.yml")
			err := os.WriteFile(pkgManifestPath, []byte(c.contents), 0o644)
			require.NoError(t, err)
			supported, err := IsSubscriptionCompatible(c.stackSubscription, pkgManifestPath)
			if c.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.supported, supported)
			}
		})
	}
}
