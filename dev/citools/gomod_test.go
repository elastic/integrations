// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package citools

import (
	"os"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"
)

func TestPackageVersionGoMod(t *testing.T) {
	cases := []struct {
		name         string
		gomodContent string
		modulePath   string
		expectedVer  string
		expectErr    bool
	}{
		{
			name: "elastic-package version found",
			gomodContent: `module example.com/test

go 1.24.2

require (
	github.com/elastic/elastic-package v1.2.3
	github.com/elastic/package-spec v0.1.0
)

require (
	github.com/elastic/elastic-package v0.1.0 // indirect
)
`,
			modulePath:  "github.com/elastic/elastic-package",
			expectedVer: "1.2.3",
			expectErr:   false,
		},
		{
			name: "other version found",
			gomodContent: `module example.com/test

go 1.24.2

require (
	github.com/elastic/elastic-package v1.2.3
	github.com/elastic/package-spec v0.1.0
)

require (
	github.com/elastic/elastic-package v0.1.0 // indirect
)
`,
			modulePath:  "github.com/elastic/package-spec",
			expectedVer: "0.1.0",
			expectErr:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gomodPath := tmpDir + "/go.mod"
			err := os.WriteFile(gomodPath, []byte(tc.gomodContent), 0644)
			require.NoError(t, err, "failed to write go.mod")

			version, err := PackageVersionGoMod(gomodPath, tc.modulePath)
			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err, "unexpected error")

			expected, err := semver.NewVersion(tc.expectedVer)
			require.NoError(t, err)
			if !version.Equal(expected) {
				t.Errorf("expected version %s, got %s", expected, version)
			}
		})
	}
}
