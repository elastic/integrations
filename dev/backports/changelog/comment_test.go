// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package changelog

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostComment_NoOp(t *testing.T) {
	t.Run("empty backport PR number is a no-op", func(t *testing.T) {
		require.NoError(t, PostComment("", "changelog/pr-42", "", "success", "123", "org/repo"))
	})
	t.Run("empty working branch is a no-op", func(t *testing.T) {
		require.NoError(t, PostComment("42", "", "", "success", "123", "org/repo"))
	})
}

func TestBuildCommentBody(t *testing.T) {
	noURL := func(_ string) (string, error) { return "", nil }
	withURL := func(_ string) (string, error) {
		return "https://github.com/org/repo/pull/99", nil
	}
	errURL := func(_ string) (string, error) { return "", fmt.Errorf("gh unavailable") }
	noBranch := func(_, _ string) (bool, error) { return false, nil }
	withBranch := func(_, _ string) (bool, error) { return true, nil }

	cases := []struct {
		title          string
		outcome        string
		workingBranch  string
		notFound       string
		runID          string
		repository     string
		syncURLFn      func(string) (string, error)
		branchExistsFn func(string, string) (bool, error)
		wantContains   []string
		wantErr        bool
	}{
		{
			title:          "skipped — reports versions already on main",
			outcome:        "skipped",
			workingBranch:  "changelog/pr-42",
			syncURLFn:      noURL,
			branchExistsFn: noBranch,
			wantContains:   []string{"skipped", "main"},
		},
		{
			title:          "success — includes sync PR URL",
			outcome:        "success",
			workingBranch:  "changelog/pr-42",
			syncURLFn:      withURL,
			branchExistsFn: noBranch,
			wantContains:   []string{"https://github.com/org/repo/pull/99"},
		},
		{
			title:          "success — appends warning for not-found packages",
			outcome:        "success",
			workingBranch:  "changelog/pr-42",
			notFound:       "missing_pkg",
			syncURLFn:      withURL,
			branchExistsFn: noBranch,
			wantContains:   []string{"https://github.com/org/repo/pull/99", "missing_pkg"},
		},
		{
			title:          "success — no sync URL shows compare link and could-not-retrieve message",
			outcome:        "success",
			workingBranch:  "changelog/pr-42",
			repository:     "org/repo",
			syncURLFn:      noURL,
			branchExistsFn: noBranch,
			wantContains:   []string{"could not be retrieved", "org/repo/compare/main...changelog/pr-42"},
		},
		{
			title:          "success — no sync URL with not-found packages shows compare link and warning",
			outcome:        "success",
			workingBranch:  "changelog/pr-42",
			notFound:       "missing_pkg",
			repository:     "org/repo",
			syncURLFn:      noURL,
			branchExistsFn: noBranch,
			wantContains:   []string{"could not be retrieved", "org/repo/compare/main...changelog/pr-42", "missing_pkg"},
		},
		{
			title:          "success — syncURL error propagates",
			outcome:        "success",
			workingBranch:  "changelog/pr-42",
			syncURLFn:      errURL,
			branchExistsFn: noBranch,
			wantErr:        true,
		},
		{
			title:          "failure — includes run URL",
			outcome:        "failure",
			workingBranch:  "changelog/pr-42",
			runID:          "99999",
			repository:     "org/repo",
			syncURLFn:      noURL,
			branchExistsFn: noBranch,
			wantContains:   []string{"99999", "org/repo"},
		},
		{
			title:          "failure — pushed branch includes compare URL",
			outcome:        "failure",
			workingBranch:  "changelog/pr-42",
			runID:          "123",
			repository:     "org/repo",
			syncURLFn:      noURL,
			branchExistsFn: withBranch,
			wantContains:   []string{"changelog/pr-42", "org/repo/compare/main...changelog/pr-42"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			body, err := buildCommentBody(
				tc.workingBranch, tc.notFound, tc.outcome,
				tc.runID, tc.repository,
				tc.syncURLFn, tc.branchExistsFn,
			)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			for _, want := range tc.wantContains {
				assert.Contains(t, body, want)
			}
		})
	}
}
