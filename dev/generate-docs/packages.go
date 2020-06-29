package main

import (
	"github.com/pkg/errors"
	"io/ioutil"
)

func listPackages(options generateOptions) ([]string, error) {
	var folders []string
	fileInfos, err := ioutil.ReadDir(options.packagesSourceDir)
	if err != nil {
		return nil, errors.Wrapf(err, "reading packages source dir failed (path: %s)", options.packagesSourceDir)
	}

	for _, fileInfo := range fileInfos {
		if fileInfo.IsDir() {
			folders = append(folders, fileInfo.Name())
		}
	}
	return folders, nil
}