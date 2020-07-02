// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"path/filepath"
	"strings"

	"github.com/magefile/mage/sh"
)

func main() {
	// Find all directories with ingest-pipeline
	ingestPipelineDirs, _ := filepath.Glob("./*/dataset/*/elasticsearch/ingest-pi*")

	for _, old := range ingestPipelineDirs {
		new := strings.Replace(old, "-", "_", -1)
		sh.Run("cp", "-r", old, new)
	}

}
