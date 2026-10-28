// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build tools

package main

import (
	_ "github.com/magefile/mage"
	_ "golang.org/x/tools/cmd/goimports"

	_ "github.com/elastic/go-licenser"
)
