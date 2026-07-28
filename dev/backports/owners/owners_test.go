// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package owners

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/integrations/dev/codeowners"
)

func TestManifestOwnerFn(t *testing.T) {
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
			got, err := manifestOwner([]byte(c.manifest))
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
			current, err := codeowners.ParseOwners(c.current)
			require.NoError(t, err)
			main, err := codeowners.ParseOwners(c.main)
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

func TestApplyUpdates(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		updates     map[string][]string
		packagePath string
		wantContent string
	}{
		{
			name:        "no-op when there are no updates",
			content:     "/packages/aws @elastic/obs-team\n",
			updates:     nil,
			packagePath: "/packages/aws",
			wantContent: "/packages/aws @elastic/obs-team\n",
		},
		{
			name:        "updates an existing line in place, preserving unrelated lines",
			content:     "/packages/aws @elastic/obs-old-team\n/packages/other @elastic/other-team\n",
			updates:     map[string][]string{"/packages/aws": {"@elastic/obs-new-team"}},
			packagePath: "/packages/aws",
			wantContent: "/packages/aws @elastic/obs-new-team\n/packages/other @elastic/other-team\n",
		},
		{
			name:    "inserts a new data-stream line right after the package's own line",
			content: "/packages/aws @elastic/obs-team\n/packages/other @elastic/other-team\n",
			updates: map[string][]string{
				"/packages/aws/data_stream/cloudtrail": {"@elastic/security-team"},
			},
			packagePath: "/packages/aws",
			wantContent: "/packages/aws @elastic/obs-team\n/packages/aws/data_stream/cloudtrail @elastic/security-team\n" +
				"/packages/other @elastic/other-team\n",
		},
		{
			name:        "appends at end of file when the package line isn't found",
			content:     "/packages/other @elastic/other-team\n",
			updates:     map[string][]string{"/packages/aws": {"@elastic/obs-team"}},
			packagePath: "/packages/aws",
			wantContent: "/packages/other @elastic/other-team\n/packages/aws @elastic/obs-team\n",
		},
		{
			// Comments and exclusion-only rules must survive untouched.
			name: "preserves comments and unrelated rules",
			content: "# top-level comment\n/packages/aws @elastic/obs-old-team\n" +
				"/packages/aws/README.md\n/packages/other @elastic/other-team\n",
			updates:     map[string][]string{"/packages/aws": {"@elastic/obs-new-team"}},
			packagePath: "/packages/aws",
			wantContent: "# top-level comment\n/packages/aws @elastic/obs-new-team\n" +
				"/packages/aws/README.md\n/packages/other @elastic/other-team\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ApplyUpdates(tc.content, tc.updates, tc.packagePath)
			assert.Equal(t, tc.wantContent, got)
		})
	}
}
