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
		name             string
		current          string
		main             string
		pkgPath          string
		existingSubPaths []string
		currentManifest  string
		mainManifest     string
		expectedPlan     SyncPlan
		expectedFound    bool
	}{
		{
			name:             "matched: owners already in sync, no-op",
			current:          "/packages/aws @elastic/obs-infraobs-integrations\n",
			main:             "/packages/aws @elastic/obs-infraobs-integrations\n",
			pkgPath:          "/packages/aws",
			existingSubPaths: []string{"/packages/aws/data_stream/cloudtrail"},
			currentManifest:  "elastic/obs-infraobs-integrations",
			mainManifest:     "elastic/obs-infraobs-integrations",
			expectedPlan:     SyncPlan{},
			expectedFound:    true,
		},
		{
			name:             "mismatched: package owner changed on main",
			current:          "/packages/aws @elastic/obs-infraobs-integrations\n",
			main:             "/packages/aws @elastic/obs-ds-hosted-services\n",
			pkgPath:          "/packages/aws",
			existingSubPaths: []string{"/packages/aws/data_stream/cloudtrail"},
			currentManifest:  "elastic/obs-infraobs-integrations",
			mainManifest:     "elastic/obs-ds-hosted-services",
			expectedPlan: SyncPlan{
				ManifestOwner: "elastic/obs-ds-hosted-services",
				PackageOwner:  []string{"@elastic/obs-ds-hosted-services"},
			},
			expectedFound: true,
		},
		{
			name:             "missing on main: package removed, plan skips cleanly",
			current:          "/packages/aws @elastic/obs-infraobs-integrations\n",
			main:             "/packages/other @elastic/obs-ds-hosted-services\n",
			pkgPath:          "/packages/aws",
			existingSubPaths: []string{"/packages/aws/data_stream/cloudtrail"},
			currentManifest:  "elastic/obs-infraobs-integrations",
			mainManifest:     "elastic/obs-infraobs-integrations",
			expectedPlan:     SyncPlan{},
			expectedFound:    false,
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
			// Regression case: a package with several data streams, where
			// main assigns an explicit owner to just one of them. Sibling
			// data streams that main leaves implicit must NOT get a
			// synthesized owner — even though this can leave the branch's
			// CODEOWNERS only partially split (failing the all-or-nothing
			// invariant), inventing an owner for something nobody assigned
			// is worse than surfacing the gap for a human to resolve.
			name:    "main introduces an explicit override for one data stream; sibling data streams are left untouched",
			current: "/packages/aws @elastic/obs-infraobs-integrations\n",
			main:    "/packages/aws @elastic/obs-infraobs-integrations\n/packages/aws/data_stream/cloudtrail @elastic/security-service-integrations\n",
			pkgPath: "/packages/aws",
			existingSubPaths: []string{
				"/packages/aws/data_stream/cloudtrail",
				"/packages/aws/data_stream/vpcflow",
				"/packages/aws/data_stream/apigateway_logs",
			},
			expectedPlan: SyncPlan{
				SubPaths: map[string][]string{
					"/packages/aws/data_stream/cloudtrail": {"@elastic/security-service-integrations"},
				},
			},
			expectedFound: true,
		},
		{
			name: "main consolidates a previously-split override back to the package level",
			current: "/packages/aws @elastic/obs-infraobs-integrations\n" +
				"/packages/aws/data_stream/cloudtrail @elastic/security-service-integrations\n",
			main:             "/packages/aws @elastic/obs-infraobs-integrations\n",
			pkgPath:          "/packages/aws",
			existingSubPaths: []string{"/packages/aws/data_stream/cloudtrail"},
			expectedPlan: SyncPlan{
				SubPaths: map[string][]string{
					"/packages/aws/data_stream/cloudtrail": {"@elastic/obs-infraobs-integrations"},
				},
			},
			expectedFound: true,
		},
		{
			name:             "sub-path absent from this worktree is never touched",
			current:          "/packages/aws @elastic/obs-infraobs-integrations\n",
			main:             "/packages/aws @elastic/obs-infraobs-integrations\n/packages/aws/data_stream/newly_added @elastic/security-service-integrations\n",
			pkgPath:          "/packages/aws",
			existingSubPaths: []string{"/packages/aws/data_stream/cloudtrail"},
			expectedPlan:     SyncPlan{},
			expectedFound:    true,
		},
		{
			// A non-data-stream sub-path (e.g. a package's kibana/ assets
			// directory) must be handled exactly the same way as a data
			// stream — Plan has no special-cased notion of "data_stream/".
			name:             "non-data-stream sub-path (kibana/) owner changed on main",
			current:          "/packages/kubernetes @elastic/obs-ds-hosted-services\n/packages/kubernetes/kibana @elastic/obs-ds-hosted-services-old\n",
			main:             "/packages/kubernetes @elastic/obs-ds-hosted-services\n/packages/kubernetes/kibana @elastic/obs-ds-hosted-services-new\n",
			pkgPath:          "/packages/kubernetes",
			existingSubPaths: []string{"/packages/kubernetes/kibana"},
			expectedPlan: SyncPlan{
				SubPaths: map[string][]string{
					"/packages/kubernetes/kibana": {"@elastic/obs-ds-hosted-services-new"},
				},
			},
			expectedFound: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			current, err := ParseOwners(c.current)
			require.NoError(t, err)
			main, err := ParseOwners(c.main)
			require.NoError(t, err)

			plan, found := Plan(c.pkgPath, c.existingSubPaths, current, main, c.currentManifest, c.mainManifest)
			assert.Equal(t, c.expectedFound, found)
			assert.Equal(t, c.expectedPlan, plan)
		})
	}
}

func TestSyncPlanEmpty(t *testing.T) {
	assert.True(t, SyncPlan{}.Empty())
	assert.False(t, SyncPlan{ManifestOwner: "elastic/ecosystem"}.Empty())
	assert.False(t, SyncPlan{PackageOwner: []string{"@elastic/ecosystem"}}.Empty())
	assert.False(t, SyncPlan{SubPaths: map[string][]string{"/packages/aws/data_stream/cloudtrail": {"@elastic/ecosystem"}}}.Empty())
}

func TestEntriesUnder(t *testing.T) {
	const codeowners = `
/packages/aws @elastic/obs-infraobs-integrations
/packages/aws/data_stream/cloudtrail @elastic/security-service-integrations
/packages/aws/kibana @elastic/obs-infraobs-integrations
/packages/awsome @elastic/unrelated-team
`
	owners, err := ParseOwners(codeowners)
	require.NoError(t, err)

	got := owners.EntriesUnder("/packages/aws")
	assert.ElementsMatch(t, []string{
		"/packages/aws/data_stream/cloudtrail",
		"/packages/aws/kibana",
	}, got)
}
