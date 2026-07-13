// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package requiresupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/integrations/dev/codeowners"
)

func TestResolveOwner(t *testing.T) {
	owners, err := codeowners.LoadOwners("testdata/CODEOWNERS")
	require.NoError(t, err)

	cases := []struct {
		title        string
		pkgPath      string
		fallback     string
		wantOwners   []string
		wantMismatch bool
	}{
		{
			title:      "CODEOWNERS only",
			pkgPath:    "packages/aws",
			fallback:   "",
			wantOwners: []string{"elastic/obs-infraobs-integrations"},
		},
		{
			title:      "CODEOWNERS agrees with manifest fallback",
			pkgPath:    "packages/aws",
			fallback:   "elastic/obs-infraobs-integrations",
			wantOwners: []string{"elastic/obs-infraobs-integrations"},
		},
		{
			title:        "CODEOWNERS disagrees with manifest fallback",
			pkgPath:      "packages/aws",
			fallback:     "elastic/other-team",
			wantOwners:   []string{"elastic/obs-infraobs-integrations"},
			wantMismatch: true,
		},
		{
			title:      "no CODEOWNERS entry, manifest fallback used",
			pkgPath:    "packages/unknown-package",
			fallback:   "elastic/fallback-team",
			wantOwners: []string{"elastic/fallback-team"},
		},
		{
			title:      "no CODEOWNERS entry and no fallback falls back to the default owner",
			pkgPath:    "packages/unknown-package",
			fallback:   "",
			wantOwners: []string{defaultOwner},
		},
		{
			title:      "CODEOWNERS lists multiple teams, all are kept",
			pkgPath:    "packages/multi_owner",
			fallback:   "",
			wantOwners: []string{"elastic/team-a", "elastic/team-b"},
		},
		{
			title:      "CODEOWNERS lists multiple teams, fallback matches one of them",
			pkgPath:    "packages/multi_owner",
			fallback:   "elastic/team-b",
			wantOwners: []string{"elastic/team-a", "elastic/team-b"},
		},
		{
			title:        "CODEOWNERS lists multiple teams, fallback matches none of them",
			pkgPath:      "packages/multi_owner",
			fallback:     "elastic/other-team",
			wantOwners:   []string{"elastic/team-a", "elastic/team-b"},
			wantMismatch: true,
		},
		{
			title:      "nested package path where folder name differs from manifest name",
			pkgPath:    "testdata/nested_packages/technology/p1",
			fallback:   "",
			wantOwners: []string{"elastic/nested-team"},
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			res := resolveOwner(owners, c.pkgPath, c.fallback)
			assert.Equal(t, c.wantOwners, res.owners)
			if c.wantMismatch {
				assert.NotEmpty(t, res.mismatch)
				assert.Contains(t, res.mismatch, c.fallback)
			} else {
				assert.Empty(t, res.mismatch)
			}
		})
	}
}
