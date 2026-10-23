// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package groups

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoodGroups(t *testing.T) {
	assert.NoError(t, check("testdata/good.yml", "testdata/packages"))
}

func TestNoGroupsFile(t *testing.T) {
	assert.NoError(t, check("testdata/missing.yml", "testdata/packages"))
}

func TestBadGroups(t *testing.T) {
	err := check("testdata/bad.yml", "testdata/packages")
	require.Error(t, err)
	assert.Equal(t, `testdata/bad.yml is invalid:
group "nginx": exactly one schema must set default: true, found 0
group "nginx": icon "apache" is not a member package
group "web": schema "other" references package "missing_pkg", not found under testdata/packages/
package "nginx" is in more than one group: nginx, web`, err.Error())
}
