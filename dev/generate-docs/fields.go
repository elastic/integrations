package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type fieldDefinition struct {
	Name        string `yaml:"name,omitempty"`
	Type        string `yaml:"type,omitempty"`
	Description string `yaml:"description,omitempty"`
	Fields      fieldDefinitionArray   `yaml:"fields,omitempty"`
}

type fieldDefinitionArray []fieldDefinition

type fieldsTableRecord struct {
	name        string
	description string
	aType       string
}

func renderFields(options generateOptions, packageName, datasetName string) (string, error) {
	datasetPath := filepath.Join(options.packagesSourceDir, packageName, "dataset", datasetName)
	fieldFiles, err := listFieldFields(datasetPath)
	if err != nil {
		return "", errors.Wrapf(err, "listing field files failed (datasetPath: %s)", datasetPath)
	}

	fields, err := loadFields(fieldFiles)
	if err != nil {
		return "", errors.Wrap(err, "loading fields files failed")
	}

	collected, err := collectFieldsFromDefinitions(fields)
	if err != nil {
		return "", errors.Wrap(err, "collecting fields files failed")
	}

	var builder strings.Builder
	builder.WriteString("**Exported fields**\n\n")

	if len(collected) == 0 {
		builder.WriteString("(no fields available)\n")
		return builder.String(), nil
	}
	builder.WriteString("| Field | Description | Type |\n")
	builder.WriteString("|---|---|---|\n")
	for _, c := range collected {
		description := strings.TrimSpace(strings.ReplaceAll(c.description, "\n", " "))
		builder.WriteString(fmt.Sprintf("| %s | %s | %s |\n", c.name, description, c.aType))
	}
	builder.WriteString("\n")
	return builder.String(), nil
}

func listFieldFields(datasetPath string) ([]string, error) {
	fieldsPath := filepath.Join(datasetPath, "fields")

	var files []string
	fileInfos, err := ioutil.ReadDir(fieldsPath)
	if err != nil {
		return nil, errors.Wrapf(err, "reading dataset fields dir failed (path: %s)", fieldsPath)
	}

	for _, fileInfo := range fileInfos {
		if !fileInfo.IsDir() {
			files = append(files, filepath.Join(fieldsPath, fileInfo.Name()))
		}
	}
	return files, nil
}

func loadFields(files []string) (fieldDefinitionArray, error) {
	var fdas fieldDefinitionArray

	for _, f := range files {
		var fda fieldDefinitionArray

		body, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, errors.Wrapf(err, "reading fields file failed (path: %s)", f)
		}

		err = yaml.Unmarshal(body, &fda)
		if err != nil {
			return nil, errors.Wrapf(err, "unmarshaling fields file failed (path: %s)", f)
		}
		fdas = append(fdas, fda...)
	}
	return fdas, nil
}

func collectFieldsFromDefinitions(fieldDefinitions []fieldDefinition) ([]fieldsTableRecord, error) {
	var records []fieldsTableRecord

	root := fieldDefinitions
	var err error
	for _, f := range root {
		records, err = visitFields("", f, records)
		if err != nil {
			return nil, errors.Wrapf(err, "visiting fields failed")
		}
	}
	return uniqueTableRecords(records), nil
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