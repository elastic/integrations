// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package owners

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDedupTeams(t *testing.T) {
	tests := []struct {
		name string
		plan SyncPlan
		want []string
	}{
		{
			name: "empty plan yields no teams",
			plan: SyncPlan{},
			want: nil,
		},
		{
			name: "manifest owner is @-prefixed",
			plan: SyncPlan{ManifestOwner: "elastic/team-a"},
			want: []string{"@elastic/team-a"},
		},
		{
			name: "package owner is used as-is (already @-prefixed)",
			plan: SyncPlan{PackageOwner: []string{"@elastic/team-a"}},
			want: []string{"@elastic/team-a"},
		},
		{
			name: "duplicate across manifest, package, and sub-paths is deduped",
			plan: SyncPlan{
				ManifestOwner: "elastic/team-a",
				PackageOwner:  []string{"@elastic/team-a"},
				SubPaths: map[string][]string{
					"/packages/aws/data_stream/cloudtrail": {"@elastic/team-a"},
				},
			},
			want: []string{"@elastic/team-a"},
		},
		{
			name: "distinct teams across fields are all included, sorted",
			plan: SyncPlan{
				ManifestOwner: "elastic/team-c",
				PackageOwner:  []string{"@elastic/team-a"},
				SubPaths: map[string][]string{
					"/packages/aws/data_stream/cloudtrail": {"@elastic/team-b"},
				},
			},
			want: []string{"@elastic/team-a", "@elastic/team-b", "@elastic/team-c"},
		},
		{
			name: "multiple owners on one sub-path all included",
			plan: SyncPlan{
				SubPaths: map[string][]string{
					"/packages/aws/data_stream/cloudtrail": {"@elastic/team-a", "@elastic/team-b"},
				},
			},
			want: []string{"@elastic/team-a", "@elastic/team-b"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, dedupTeams(tc.plan))
		})
	}
}
