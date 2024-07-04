// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v3"
)

type fieldsContent struct {
	files map[string]fieldDefinitionArray
}

type fieldDefinition struct {
	Name        string `yaml:"name,omitempty"`
	Key         string `yaml:"key,omitempty"`
	Title       string `yaml:"title,omitempty"`
	Group       *int   `yaml:"group,omitempty"`
	Level       string `yaml:"level,omitempty"`
	Required    *bool  `yaml:"required,omitempty"`
	Type        string `yaml:"type,omitempty"`
	Format      string `yaml:"format,omitempty"`
	Description string `yaml:"description,omitempty"`
	Release     string `yaml:"release,omitempty"`
	Alias       string `yaml:"alias,omitempty"`
	Path        string `yaml:"path,omitempty"`
	Footnote    string `yaml:"footnote,omitempty"`
	// Example is not consistent in ECS schema (either single field or array)
	// Example     string             `yaml:"example,omitempty"`
	IgnoreAbove *int                   `yaml:"ignore_above,omitempty"`
	MultiFields []multiFieldDefinition `yaml:"multi_fields,omitempty"`
	Fields      fieldDefinitionArray   `yaml:"fields,omitempty"`
	Migration   *bool                  `yaml:"migration,omitempty"`

	skipped bool
}

type fieldDefinitionArray []fieldDefinition

func (fda fieldDefinitionArray) names() []string {
	var names []string
	for _, f := range fda {
		names = append(names, collectFieldNames("", f)...)
	}
	return names
}

func (fda fieldDefinitionArray) stripped() fieldDefinitionArray {
	var arr fieldDefinitionArray
	for _, f := range fda {
		stripped := f
		if f.Type == "group" {
			stripped.Description = ""
		}
		stripped.Fields = stripped.Fields.stripped()
		arr = append(arr, stripped)
	}
	return arr
}

func collectFieldNames(namePrefix string, f fieldDefinition) []string {
	if namePrefix != "" {
		namePrefix = namePrefix + "." + f.Name
	} else {
		namePrefix = f.Name
	}

	if len(f.Fields) == 0 {
		return []string{namePrefix}
	}

	var collected []string
	for _, child := range f.Fields {
		collected = append(collected, collectFieldNames(namePrefix, child)...)
	}
	return collected
}

type multiFieldDefinition struct {
	Name         string `yaml:"name,omitempty"`
	Type         string `yaml:"type,omitempty"`
	Norms        *bool  `yaml:"norms,omitempty"`
	DefaultField *bool  `yaml:"default_field,omitempty"`
}

func loadEcsFields(ecsDir string) ([]fieldDefinition, error) {
	path := filepath.Join(ecsDir, "generated/beats/fields.ecs.yml")
	fs, err := loadFieldsFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "loading ECS fields file failed")
	}
	if len(fs) != 1 {
		return nil, errors.Wrapf(err, "expected single root field")
	}
	return fs[0].Fields, nil
}

func loadModuleFields(modulePath string) ([]fieldDefinition, string, error) {
	path := filepath.Join(modulePath, "_meta", "fields.yml")
	fs, err := loadFieldsFile(path)
	if err != nil {
		return nil, "", errors.Wrapf(err, "loading module fields file failed")
	}
	if len(fs) != 1 {
		return nil, "", errors.Wrapf(err, "expected single root field")
	}

	title := fs[0].Title

	var unwrapped []fieldDefinition
	unwrapped = append(unwrapped, fs[0].Fields...)

	fieldsEpr := filepath.Join(modulePath, "_meta", "fields.epr.yml")
	efs, err := loadFieldsFile(fieldsEpr)
	if err != nil {
		return nil, "", errors.Wrapf(err, "loading fields.epr.yml file failed")
	}

	unwrapped = append(unwrapped, efs...)
	return unwrapped, title, nil
}

func loadDataStreamFields(modulePath, moduleName, dataStreamName string) ([]fieldDefinition, error) {
	fieldsPath := filepath.Join(modulePath, dataStreamName, "_meta", "fields.yml")
	fs, err := loadFieldsFile(fieldsPath)
	if err != nil {
		return nil, errors.Wrapf(err, "loading data stream fields file failed")
	}
	for i, f := range fs {
		fs[i].Name = fmt.Sprintf("%s.%s", moduleName, f.Name)
	}

	fieldsEpr := filepath.Join(modulePath, dataStreamName, "_meta", "fields.epr.yml")
	efs, err := loadFieldsFile(fieldsEpr)
	if err != nil {
		return nil, errors.Wrapf(err, "loading fields.epr.yml file failed")
	}

	fs = append(fs, efs...)
	return fs, nil
}

func loadFieldsFile(path string) ([]fieldDefinition, error) {
	fields, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return []fieldDefinition{}, nil // return empty array, this is a valid state
	}
	if err != nil {
		return nil, errors.Wrapf(err, "reading fields failed (path: %s)", path)
	}

	var fs fieldDefinitionArray
	err = yaml.Unmarshal(fields, &fs)
	if err != nil {
		return nil, errors.Wrapf(err, "unmarshalling fields file failed (path: %s)", path)
	}
	fs = loadDefaultFieldValues(fs)
	return fs, nil
}

func loadDefaultFieldValues(fs fieldDefinitionArray) fieldDefinitionArray {
	var withDefaults fieldDefinitionArray
	for _, f := range fs {
		if f.Type == "" {
			f.Type = "keyword"
		}
		f.Fields = loadDefaultFieldValues(f.Fields)
		withDefaults = append(withDefaults, f)
	}
	return withDefaults
}

// filterMigratedFields method filters out fields with "migration: true" property or if it's defined in ECS.
// It returns a migrated fields file and found ECS fields.
func filterMigratedFields(fields []fieldDefinition, ecsFieldNames []string) ([]fieldDefinition, []string, error) {
	var filteredEcsFieldNames []string
	for i, f := range fields {
		fields[i], filteredEcsFieldNames = visitFieldForFilteringMigrated(f, ecsFieldNames, filteredEcsFieldNames)
	}
	return fields, filteredEcsFieldNames, nil
}

func visitFieldForFilteringMigrated(f fieldDefinition, ecsFieldNames, filteredEcsFieldNames []string) (fieldDefinition, []string) {
	if len(f.Fields) == 0 {
		// this field is not a group entry
		if f.Type == "alias" {
			if f.Migration != nil && *f.Migration {
				f.skipped = true // skip the field
			}

			for _, ecsFieldName := range ecsFieldNames {
				if ecsFieldName == f.Path {
					filteredEcsFieldNames = append(filteredEcsFieldNames, ecsFieldName)
					f.skipped = true
					break
				}
			}
		}
		return f, filteredEcsFieldNames
	}

	var updated fieldDefinitionArray
	for _, fieldsEntry := range f.Fields {
		var v fieldDefinition
		v, filteredEcsFieldNames = visitFieldForFilteringMigrated(fieldsEntry, ecsFieldNames, filteredEcsFieldNames)
		if !v.skipped {
			updated = append(updated, v)
		}
	}
	f.Fields = updated
	return f, filteredEcsFieldNames
}

func isPackageFields(fileName string) bool {
	return fileName == "package-fields.yml"
}

func filterEcsFields(ecsFields fieldDefinitionArray, filteredNames []string) fieldDefinitionArray {
	var filteredFields fieldDefinitionArray
	for _, f := range ecsFields {
		visited, checked := visitEcsFieldsToFilter("", f, filteredNames)
		if checked {
			filteredFields = append(filteredFields, visited)
		}
	}
	return filteredFields
}

func visitEcsFieldsToFilter(namePrefix string, f fieldDefinition, filteredNames []string) (fieldDefinition, bool) {
	name := namePrefix
	if namePrefix != "" {
		name += "."
	}
	name += f.Name

	if len(f.Fields) == 0 && f.Type != "group" {
		for _, fn := range filteredNames {
			if fn == name {
				return f, true
			}
		}
		return f, false
	}

	var checked bool
	var checkedFields fieldDefinitionArray
	for _, fieldEntry := range f.Fields {
		visited, fieldChecked := visitEcsFieldsToFilter(name, fieldEntry, filteredNames)
		if fieldChecked {
			checkedFields = append(checkedFields, visited)
			checked = true
		}
	}
	f.Fields = checkedFields
	return f, checked
}
