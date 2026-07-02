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
		pkgName      string
		fallback     string
		wantOwners   []string
		wantMismatch bool
	}{
		{
			title:      "CODEOWNERS only",
			pkgName:    "aws",
			fallback:   "",
			wantOwners: []string{"elastic/obs-infraobs-integrations"},
		},
		{
			title:      "CODEOWNERS agrees with manifest fallback",
			pkgName:    "aws",
			fallback:   "elastic/obs-infraobs-integrations",
			wantOwners: []string{"elastic/obs-infraobs-integrations"},
		},
		{
			title:        "CODEOWNERS disagrees with manifest fallback",
			pkgName:      "aws",
			fallback:     "elastic/other-team",
			wantOwners:   []string{"elastic/obs-infraobs-integrations"},
			wantMismatch: true,
		},
		{
			title:      "no CODEOWNERS entry, manifest fallback used",
			pkgName:    "unknown-package",
			fallback:   "elastic/fallback-team",
			wantOwners: []string{"elastic/fallback-team"},
		},
		{
			title:      "no CODEOWNERS entry and no fallback falls back to the default owner",
			pkgName:    "unknown-package",
			fallback:   "",
			wantOwners: []string{defaultOwner},
		},
		{
			title:      "CODEOWNERS lists multiple teams, all are kept",
			pkgName:    "multi_owner",
			fallback:   "",
			wantOwners: []string{"elastic/team-a", "elastic/team-b"},
		},
		{
			title:      "CODEOWNERS lists multiple teams, fallback matches one of them",
			pkgName:    "multi_owner",
			fallback:   "elastic/team-b",
			wantOwners: []string{"elastic/team-a", "elastic/team-b"},
		},
		{
			title:        "CODEOWNERS lists multiple teams, fallback matches none of them",
			pkgName:      "multi_owner",
			fallback:     "elastic/other-team",
			wantOwners:   []string{"elastic/team-a", "elastic/team-b"},
			wantMismatch: true,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			res := resolveOwner(owners, c.pkgName, c.fallback)
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
