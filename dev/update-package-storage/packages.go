// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"io/ioutil"
	"path/filepath"
)

func listPackages(err error, options updateOptions) ([]string, error) {
	if err != nil {
		return nil, err
	}

	var folders []string
	fileInfos, err := ioutil.ReadDir(filepath.Join(options.packageStorageDir, "packages"))
	for _, fileInfo := range fileInfos {
		if fileInfo.IsDir() {
			folders = append(folders, fileInfo.Name())
		}
	}
	return folders, nil
}

func reviewPackages(err error, options updateOptions, packageNames []string, handlePackageChanges func(error, updateOptions, string) error) error {
	if err != nil {
		return err
	}

	for _, packageName := range packageNames {
		err = handlePackageChanges(err, options, packageName)
	}
	return err
}
