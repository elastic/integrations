package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdateObjectID(t *testing.T) {
	tests := map[string]struct {
		OrigID     string
		ModuleName string
		ExpectedID string
	}{
		"no_ecs_suffix": {
			"foo",
			"bar",
			"bar-foo",
		},
		"has_ecs_suffix": {
			"foo-ecs",
			"bar",
			"bar-foo",
		},
		"has_pkgname_lowercase_prefix_and_ecs_suffix": {
			"bar-foo-ecs",
			"bar",
			"bar-foo",
		},
		"has_pkgname_lowercase_prefix": {
			"bar-foo",
			"bar",
			"bar-foo-pkg",
		},
		"has_pkgname_mixedcase_prefix_and_ecs_suffix": {
			"bAr-foo-ecs",
			"bar",
			"bar-foo",
		},
		"has_pkgname_mixedcase_prefix": {
			"BaR-foo",
			"bar",
			"bar-foo",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actualID := updateObjectID(test.OrigID, test.ModuleName)
			require.Equal(t, test.ExpectedID, actualID)
		})
	}
}
