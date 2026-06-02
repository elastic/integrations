// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package backports

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "backports.yml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

const validEntry = `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`

func TestValidateInventory(t *testing.T) {
	cases := []struct {
		title      string
		contents   string
		wantErr    bool
		errContains []string
	}{
		{
			title:    "valid entry with null maintained_until",
			contents: validEntry,
		},
		{
			title: "valid entry with date maintained_until",
			contents: `backports:
  - package: security_detection_engine
    branch: backport-security_detection_engine-8.19
    base_version: "8.19.0"
    base_commit: "abcdef1234"
    maintained_until: "2027-01-15"
    archived: false
`,
		},
		{
			title:    "empty backports list",
			contents: "backports: []\n",
		},
		{
			title: "missing package field",
			contents: `backports:
  - branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"missing required field 'package'"},
		},
		{
			title: "missing branch field",
			contents: `backports:
  - package: aws
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"missing required field 'branch'"},
		},
		{
			title: "missing base_version field",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"missing required field 'base_version'"},
		},
		{
			title: "missing base_commit field",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    maintained_until: null
    archived: false
`,
			wantErr:     true,
			errContains: []string{"missing required field 'base_commit'"},
		},
		{
			title: "missing archived field",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
`,
			wantErr:     true,
			errContains: []string{"missing required field 'archived'"},
		},
		{
			title: "invalid maintained_until format",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: "01/15/2027"
    archived: false
`,
			wantErr:     true,
			errContains: []string{"invalid maintained_until", "must be YYYY-MM-DD"},
		},
		{
			title: "multiple entries with errors are all reported",
			contents: `backports:
  - package: aws
    branch: backport-aws-3.17
    base_version: "3.17.0"
    base_commit: "5b593f6681"
    maintained_until: null
    archived: false
  - branch: backport-aws-1.51
    base_version: "1.51.2"
    base_commit: "88ad4b8432"
    maintained_until: "not-a-date"
    archived: true
`,
			wantErr:     true,
			errContains: []string{"missing required field 'package'", "invalid maintained_until"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			path := writeTemp(t, tc.contents)
			err := ValidateInventory(path)
			if tc.wantErr {
				require.Error(t, err)
				for _, substr := range tc.errContains {
					assert.True(t, strings.Contains(err.Error(), substr),
						"expected error to contain %q, got: %s", substr, err.Error())
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateInventoryFileNotFound(t *testing.T) {
	err := ValidateInventory("/no/such/file.yml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading inventory")
}
