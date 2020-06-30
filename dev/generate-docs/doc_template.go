// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"text/template"

	"github.com/pkg/errors"
)

const (
	readmeFilename    = "README.md"
	resourcesDocsPath = "./dev/import-beats-resources/%s/docs"
)

func renderReadme(options generateOptions, packageName string) error {
	templatePath := filepath.Join(fmt.Sprintf(resourcesDocsPath, packageName), readmeFilename)

	_, err := os.Stat(templatePath)
	if os.IsNotExist(err) {
		log.Printf(`Template file "%s" does not exist. The README.md file will not be rendered.`, templatePath)
		return nil
	} else if err != nil {
		return errors.Wrapf(err, "stat file failed (path: %s)", templatePath)
	}

	t := template.New(readmeFilename)
	t, err = t.Funcs(template.FuncMap{
		"event": func(datasetName string) (string, error) {
			return renderSampleEvent(options, packageName, datasetName)
		},
		"fields": func(datasetName string) (string, error) {
			return renderExportedFields(options, packageName, datasetName)
		},
	}).ParseFiles(templatePath)
	if err != nil {
		return errors.Wrapf(err, "parsing README template failed (path: %s)", templatePath)
	}

	outputPath := filepath.Join(options.packagesSourceDir, packageName, "docs", readmeFilename)
	f, err := os.OpenFile(outputPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return errors.Wrapf(err, "opening README file for writing failed (path: %s)", outputPath)
	}
	defer f.Close()

	err = t.Execute(f, nil)
	if err != nil {
		return errors.Wrapf(err, "rendering README file failed (path: %s)", templatePath)
	}
	return nil
}
