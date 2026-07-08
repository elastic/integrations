// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package owners

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveOwner(t *testing.T) {
	const codeowners = `
/packages/aws @elastic/obs-infraobs-integrations
/packages/aws/data_stream/cloudtrail @elastic/security-service-integrations
/packages/nested/foo @elastic/ecosystem
`

	cases := []struct {
		name     string
		path     string
		expected []string
		found    bool
	}{
		{
			name:     "package root",
			path:     "/packages/aws",
			expected: []string{"@elastic/obs-infraobs-integrations"},
			found:    true,
		},
		{
			name:     "explicit data stream override",
			path:     "/packages/aws/data_stream/cloudtrail",
			expected: []string{"@elastic/security-service-integrations"},
			found:    true,
		},
		{
			name:     "data stream without override falls back to package owner",
			path:     "/packages/aws/data_stream/vpcflow",
			expected: []string{"@elastic/obs-infraobs-integrations"},
			found:    true,
		},
		{
			name:     "nested category package",
			path:     "/packages/nested/foo",
			expected: []string{"@elastic/ecosystem"},
			found:    true,
		},
		{
			name:  "unknown path",
			path:  "/packages/does-not-exist",
			found: false,
		},
	}

	owners, err := ParseOwners(codeowners)
	require.NoError(t, err)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, found := owners.ResolveOwner(c.path)
			assert.Equal(t, c.found, found)
			if c.found {
				assert.Equal(t, c.expected, got)
			}
		})
	}
}

func TestManifestOwner(t *testing.T) {
	cases := []struct {
		name          string
		manifest      string
		expected      string
		expectedError bool
	}{
		{
			name:     "owner present",
			manifest: "name: aws\nowner:\n  github: elastic/obs-infraobs-integrations\n",
			expected: "elastic/obs-infraobs-integrations",
		},
		{
			name:          "owner missing",
			manifest:      "name: aws\n",
			expectedError: true,
		},
		{
			name:          "invalid yaml",
			manifest:      "not: [valid",
			expectedError: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ManifestOwner([]byte(c.manifest))
			if c.expectedError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.expected, got)
		})
	}
}

func TestPlan(t *testing.T) {
	cases := []struct {
		name            string
		current         string
		main            string
		pkgPath         string
		dataStreams     []string
		currentManifest string
		mainManifest    string
		expectedPlan    SyncPlan
		expectedFound   bool
	}{
		{
			name:            "matched: owners already in sync, no-op",
			current:         "/packages/aws @elastic/obs-infraobs-integrations\n",
			main:            "/packages/aws @elastic/obs-infraobs-integrations\n",
			pkgPath:         "/packages/aws",
			dataStreams:     []string{"cloudtrail"},
			currentManifest: "elastic/obs-infraobs-integrations",
			mainManifest:    "elastic/obs-infraobs-integrations",
			expectedPlan:    SyncPlan{},
			expectedFound:   true,
		},
		{
			name:            "mismatched: package owner changed on main",
			current:         "/packages/aws @elastic/obs-infraobs-integrations\n",
			main:            "/packages/aws @elastic/obs-ds-hosted-services\n",
			pkgPath:         "/packages/aws",
			dataStreams:     []string{"cloudtrail"},
			currentManifest: "elastic/obs-infraobs-integrations",
			mainManifest:    "elastic/obs-ds-hosted-services",
			expectedPlan: SyncPlan{
				ManifestOwner: "elastic/obs-ds-hosted-services",
				PackageOwner:  []string{"@elastic/obs-ds-hosted-services"},
			},
			expectedFound: true,
		},
		{
			name:            "missing on main: package removed, plan skips cleanly",
			current:         "/packages/aws @elastic/obs-infraobs-integrations\n",
			main:            "/packages/other @elastic/obs-ds-hosted-services\n",
			pkgPath:         "/packages/aws",
			dataStreams:     []string{"cloudtrail"},
			currentManifest: "elastic/obs-infraobs-integrations",
			mainManifest:    "elastic/obs-infraobs-integrations",
			expectedPlan:    SyncPlan{},
			expectedFound:   false,
		},
		{
			name:    "nested category package owner changed on main",
			current: "/packages/aws/foo @elastic/team-a\n",
			main:    "/packages/aws/foo @elastic/team-b\n",
			pkgPath: "/packages/aws/foo",
			expectedPlan: SyncPlan{
				PackageOwner: []string{"@elastic/team-b"},
			},
			expectedFound: true,
		},
		{
			name:        "all-or-nothing: main introduces a per-data-stream split not yet present here",
			current:     "/packages/aws @elastic/obs-infraobs-integrations\n",
			main:        "/packages/aws @elastic/obs-infraobs-integrations\n/packages/aws/data_stream/cloudtrail @elastic/security-service-integrations\n",
			pkgPath:     "/packages/aws",
			dataStreams: []string{"cloudtrail", "vpcflow"},
			expectedPlan: SyncPlan{
				DataStreams: map[string][]string{
					"cloudtrail": {"@elastic/security-service-integrations"},
					"vpcflow":    {"@elastic/obs-infraobs-integrations"},
				},
			},
			expectedFound: true,
		},
		{
			name: "all-or-nothing: main consolidates a previously-split override back to the package level",
			current: "/packages/aws @elastic/obs-infraobs-integrations\n" +
				"/packages/aws/data_stream/cloudtrail @elastic/security-service-integrations\n",
			main:        "/packages/aws @elastic/obs-infraobs-integrations\n",
			pkgPath:     "/packages/aws",
			dataStreams: []string{"cloudtrail"},
			expectedPlan: SyncPlan{
				DataStreams: map[string][]string{
					"cloudtrail": {"@elastic/obs-infraobs-integrations"},
				},
			},
			expectedFound: true,
		},
		{
			name:          "data stream absent from this worktree is never touched",
			current:       "/packages/aws @elastic/obs-infraobs-integrations\n",
			main:          "/packages/aws @elastic/obs-infraobs-integrations\n/packages/aws/data_stream/newly_added @elastic/security-service-integrations\n",
			pkgPath:       "/packages/aws",
			dataStreams:   []string{"cloudtrail"},
			expectedPlan:  SyncPlan{},
			expectedFound: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			current, err := ParseOwners(c.current)
			require.NoError(t, err)
			main, err := ParseOwners(c.main)
			require.NoError(t, err)

			plan, found := Plan(c.pkgPath, c.dataStreams, current, main, c.currentManifest, c.mainManifest)
			assert.Equal(t, c.expectedFound, found)
			assert.Equal(t, c.expectedPlan, plan)
		})
	}
}

func TestSyncPlanEmpty(t *testing.T) {
	assert.True(t, SyncPlan{}.Empty())
	assert.False(t, SyncPlan{ManifestOwner: "elastic/ecosystem"}.Empty())
	assert.False(t, SyncPlan{PackageOwner: []string{"@elastic/ecosystem"}}.Empty())
	assert.False(t, SyncPlan{DataStreams: map[string][]string{"cloudtrail": {"@elastic/ecosystem"}}}.Empty())
}
