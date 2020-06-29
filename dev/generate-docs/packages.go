package main

import (
	"io/ioutil"

	"github.com/pkg/errors"
)

func listPackages(options generateOptions) ([]string, error) {
	if len(options.selectedPackages()) > 0 {
		return options.selectedPackages(), nil
	}

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