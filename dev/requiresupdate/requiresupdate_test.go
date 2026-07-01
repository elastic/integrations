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
		wantOwner    string
		wantMismatch bool
	}{
		{
			title:     "CODEOWNERS only",
			pkgName:   "aws",
			fallback:  "",
			wantOwner: "elastic/obs-infraobs-integrations",
		},
		{
			title:     "CODEOWNERS agrees with manifest fallback",
			pkgName:   "aws",
			fallback:  "elastic/obs-infraobs-integrations",
			wantOwner: "elastic/obs-infraobs-integrations",
		},
		{
			title:        "CODEOWNERS disagrees with manifest fallback",
			pkgName:      "aws",
			fallback:     "elastic/other-team",
			wantOwner:    "elastic/obs-infraobs-integrations",
			wantMismatch: true,
		},
		{
			title:     "no CODEOWNERS entry, manifest fallback used",
			pkgName:   "unknown-package",
			fallback:  "elastic/fallback-team",
			wantOwner: "elastic/fallback-team",
		},
		{
			title:     "no CODEOWNERS entry and no fallback falls back to the default owner",
			pkgName:   "unknown-package",
			fallback:  "",
			wantOwner: defaultOwner,
		},
	}

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			res := resolveOwner(owners, c.pkgName, c.fallback)
			assert.Equal(t, c.wantOwner, res.owner)
			if c.wantMismatch {
				assert.NotEmpty(t, res.mismatch)
				assert.Contains(t, res.mismatch, c.fallback)
			} else {
				assert.Empty(t, res.mismatch)
			}
		})
	}
}
