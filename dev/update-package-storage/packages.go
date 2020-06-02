// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"path/filepath"
)

type manifest struct {
	Version string `yaml:"version"`
}

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

func detectPackageVersion(err error, options updateOptions, packageName string) (string, error) {
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadFile(filepath.Join(options.packageStorageDir, packageName, "manifest.yml"))
	m, err := unmarshalManifestFile(err, body)
	return m.Version, nil
}

func unmarshalManifestFile(err error, body []byte) (*manifest, error) {
	if err != nil {
		return nil, err
	}

	var m manifest
	err = yaml.Unmarshal(body, &m)
	return &m, nil
}