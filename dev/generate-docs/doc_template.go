package main

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/pkg/errors"
)

const (
	resourcesDocsPath = "./dev/import-beats-resources/%s/docs/README.md"
	readmeFilename = "README.md"
)

func renderReadme(options generateOptions, packageName string) error {
	templatePath := fmt.Sprintf(resourcesDocsPath, packageName)

	t := template.New(readmeFilename)
	t, err := t.Funcs(template.FuncMap{
		"events": func(datasetName string) (string, error) {
			return renderSampleEvent(options, packageName, datasetName)
		},
		"fields": func(datasetName string) (string, error) {
			return "TODO fields", nil // TODO
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
