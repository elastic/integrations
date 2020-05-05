// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"strings"
)

func splitFilenameExt(path string) (string, string, error) {
	fileName := path
	if strings.Contains(path, "/") {
		fileName = path[strings.LastIndex(path, "/")+1:]
	}

	lastDot := strings.LastIndex(fileName, ".")
	if lastDot == -1 {
		return "", "", fmt.Errorf("filename doesn't have an extension")
	}

	fileNameWithoutExt := fileName[:lastDot]
	fileExt := fileName[lastDot+1:]
	return fileNameWithoutExt, fileExt, nil
}
