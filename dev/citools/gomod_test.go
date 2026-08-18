// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package citools

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"
)

// goDirectiveVersion returns a go.mod-compatible version string for the
// running Go toolchain. Go 1.21+ allows a three-part "1.X.Y" form; older
// toolchains (and the golang.org/x/mod versions that ship with them) only
// accept "1.X", so we strip the patch component when running on Go < 1.21.
// This matters on backport branches, which keep their original (older) Go
// version and would fail to parse a fixture containing "go 1.24.2".
func goDirectiveVersion() string {
	v := strings.TrimPrefix(runtime.Version(), "go") // e.g. "1.24.2" or "1.19.1"
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return v
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil || minor < 21 {
		return fmt.Sprintf("%s.%s", parts[0], parts[1]) // major.minor only
	}
	return v // full major.minor.patch
}

func TestPackageVersionGoMod(t *testing.T) {
	gomod := fmt.Sprintf(`module example.com/test

go %s

require (
	github.com/elastic/elastic-package v1.2.3
	github.com/elastic/package-spec v0.1.0
)

require (
	github.com/elastic/elastic-package v0.1.0 // indirect
)
`, goDirectiveVersion())

	cases := []struct {
		name        string
		modulePath  string
		expectedVer string
		expectErr   bool
	}{
		{
			name:        "elastic-package version found",
			modulePath:  "github.com/elastic/elastic-package",
			expectedVer: "1.2.3",
			expectErr:   false,
		},
		{
			name:        "other version found",
			modulePath:  "github.com/elastic/package-spec",
			expectedVer: "0.1.0",
			expectErr:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gomodPath := tmpDir + "/go.mod"
			err := os.WriteFile(gomodPath, []byte(gomod), 0644)
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
