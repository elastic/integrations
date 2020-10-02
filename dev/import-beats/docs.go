// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/pkg/errors"
)

var emptyReadmeTemplate = template.Must(template.New("README.md").Parse("TODO"))

type fieldsTableRecord struct {
	name        string
	description string
	aType       string
}

type docContent struct {
	fileName     string
	templatePath string
}

func createDocTemplates(packageDocsPath string) ([]docContent, error) {
	readmePath := filepath.Join(packageDocsPath, "README.md")
	_, err := os.Stat(readmePath)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "reading README template failed")
	}
	if os.IsNotExist(err) {
		readmePath = ""
	}
	return []docContent{
		{fileName: "README.md", templatePath: readmePath},
	}, nil
}

func renderExportedFields(packageDataStream string, dataStreams dataStreamContentArray) (string, error) {
	for _, dataStream := range dataStreams {
		if packageDataStream == dataStream.name {
			var buffer strings.Builder
			buffer.WriteString("**Exported fields**")
			buffer.WriteString("\n\n")

			collected, err := collectFields(dataStream.fields)
			if err != nil {
				return "", errors.Wrapf(err, "collecting fields failed")
			}

			if len(collected) == 0 {
				buffer.WriteString("(no fields available)")
				return buffer.String(), nil
			}

			buffer.WriteString("| Field | Description | Type |\n")
			buffer.WriteString("|---|---|---|\n")
			for _, c := range collected {
				description := strings.TrimSpace(strings.ReplaceAll(c.description, "\n", " "))
				buffer.WriteString(fmt.Sprintf("| %s | %s | %s |\n", c.name, description, c.aType))
			}
			return buffer.String(), nil
		}
	}
	return "", fmt.Errorf("missing dataStream: %s", packageDataStream)
}

func collectFields(content fieldsContent) ([]fieldsTableRecord, error) {
	var records []fieldsTableRecord
	for _, fieldsFile := range content.files {
		r, err := collectFieldsFromFile(fieldsFile)
		if err != nil {
			return nil, errors.Wrapf(err, "collecting fields from file failed")
		}
		records = append(records, r...)
	}

	sort.Slice(records, func(i, j int) bool {
		return sort.StringsAreSorted([]string{records[i].name, records[j].name})
	})
	return uniqueTableRecords(records), nil
}

func uniqueTableRecords(records []fieldsTableRecord) []fieldsTableRecord {
	fieldNames := make(map[string]bool)
	var unique []fieldsTableRecord
	for _, r := range records {
		if _, ok := fieldNames[r.name]; !ok {
			fieldNames[r.name] = true
			unique = append(unique, r)
		}
	}
	return unique
}

func collectFieldsFromFile(fieldDefinitions []fieldDefinition) ([]fieldsTableRecord, error) {
	var records []fieldsTableRecord

	root := fieldDefinitions

	var err error
	for _, f := range root {
		records, err = visitFields("", f, records)
		if err != nil {
			return nil, errors.Wrapf(err, "visiting fields failed")
		}
	}
	return records, nil
}

func visitFields(namePrefix string, f fieldDefinition, records []fieldsTableRecord) ([]fieldsTableRecord, error) {
	var name = namePrefix
	if namePrefix != "" {
		name += "."
	}
	name += f.Name

	if len(f.Fields) == 0 && f.Type != "group" {
		records = append(records, fieldsTableRecord{
			name:        name,
			description: f.Description,
			aType:       f.Type,
		})
		return records, nil
	}

	var err error
	for _, fieldEntry := range f.Fields {
		records, err = visitFields(name, fieldEntry, records)
		if err != nil {
			return nil, errors.Wrapf(err, "recursive visiting fields failed (namePrefix: %s)", namePrefix)
		}
	}
	return records, nil
}
