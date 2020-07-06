// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package util

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	handlebars "github.com/aymerick/raymond"
	"github.com/pkg/errors"
	yamlv2 "gopkg.in/yaml.v2"

	ucfg "github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/yaml"
)

const (
	DirIngestPipeline = "ingest_pipeline"

	DefaultPipelineName     = "default"
	DefaultPipelineNameJSON = "default.json"
	DefaultPipelineNameYAML = "default.yml"
)

var validTypes = map[string]string{
	"logs":    "Logs",
	"metrics": "Metrics",
}

type Dataset struct {
	// Name and type of the dataset. This is linked to dataset.name and dataset.type fields.
	Type string `config:"type" json:"type" validate:"required"`
	Name string `config:"name" json:"name,omitempty" yaml:"name,omitempty"`

	Title   string `config:"title" json:"title" validate:"required"`
	Release string `config:"release" json:"release"`

	// Deprecated: Replaced by elasticsearch.ingest_pipeline.name
	IngestPipeline string         `config:"ingest_pipeline,omitempty" config:"ingest_pipeline" json:"ingest_pipeline,omitempty" yaml:"ingest_pipeline,omitempty"`
	Streams        []Stream       `config:"streams" json:"streams,omitempty" yaml:"streams,omitempty" `
	Package        string         `json:"package,omitempty" yaml:"package,omitempty"`
	Elasticsearch  *Elasticsearch `config:"elasticsearch,omitempty" json:"elasticsearch,omitempty" yaml:"elasticsearch,omitempty"`

	// Generated fields
	Path string `json:"path,omitempty" yaml:"path,omitempty"`

	// Local path to the package dir
	BasePath string `json:"-" yaml:"-"`
}

type Input struct {
	Type        string     `config:"type" json:"type" validate:"required"`
	Vars        []Variable `config:"vars" json:"vars,omitempty" yaml:"vars,omitempty"`
	Title       string     `config:"title" json:"title,omitempty" yaml:"title,omitempty"`
	Description string     `config:"description" json:"description,omitempty" yaml:"description,omitempty"`
	Streams     []Stream   `config:"streams" json:"streams,omitempty" yaml:"streams,omitempty"`
}

type Stream struct {
	Input   string     `config:"input" json:"input" validate:"required"`
	Vars    []Variable `config:"vars" json:"vars,omitempty" yaml:"vars,omitempty"`
	Dataset string     `config:"dataset" json:"dataset,omitempty" yaml:"dataset,omitempty"`
	// TODO: This might cause issues when consuming the json as the key contains . (had been an issue in the past if I remember correctly)
	TemplatePath string `config:"template_path" json:"template_path,omitempty" yaml:"template_path,omitempty"`
	Title        string `config:"title" json:"title,omitempty" yaml:"title,omitempty"`
	Description  string `config:"description" json:"description,omitempty" yaml:"description,omitempty"`
	Enabled      *bool  `config:"enabled" json:"enabled,omitempty" yaml:"enabled,omitempty"`
}

type Variable struct {
	Name        string      `config:"name" json:"name" yaml:"name"`
	Type        string      `config:"type" json:"type" yaml:"type"`
	Title       string      `config:"title" json:"title,omitempty" yaml:"title,omitempty"`
	Description string      `config:"description" json:"description,omitempty" yaml:"description,omitempty"`
	Multi       bool        `config:"multi" json:"multi" yaml:"multi"`
	Required    bool        `config:"required" json:"required" yaml:"required"`
	ShowUser    bool        `config:"show_user" json:"show_user" yaml:"show_user"`
	Default     interface{} `config:"default" json:"default,omitempty" yaml:"default,omitempty"`
}

type Elasticsearch struct {
	IndexTemplateSettings map[string]interface{} `config:"index_template.settings" json:"index_template.settings,omitempty" yaml:"index_template.settings,omitempty"`
	IndexTemplateMappings map[string]interface{} `config:"index_template.mappings" json:"index_template.mappings,omitempty" yaml:"index_template.mappings,omitempty"`
	IngestPipelineName    string                 `config:"ingest_pipeline.name,omitempty" json:"ingest_pipeline.name,omitempty" yaml:"ingest_pipeline.name,omitempty"`
}

type fieldEntry struct {
	name  string
	aType string
}

func NewDataset(basePath string, p *Package) (*Dataset, error) {
	// Check if manifest exists
	manifestPath := filepath.Join(basePath, "manifest.yml")
	_, err := os.Stat(manifestPath)
	if err != nil && os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "manifest does not exist for package: %s", p.BasePath)
	}

	datasetPath := filepath.Base(basePath)

	manifest, err := yaml.NewConfigWithFile(manifestPath, ucfg.PathSep("."))
	if err != nil {
		return nil, errors.Wrapf(err, "error creating new manifest config %s", manifestPath)
	}
	var d = &Dataset{
		Package: p.Name,
		// This is the name of the directory of the dataset
		Path:     datasetPath,
		BasePath: basePath,
	}

	// go-ucfg automatically calls the `Validate` method on the Dataset object here
	err = manifest.Unpack(d, ucfg.PathSep("."))
	if err != nil {
		return nil, errors.Wrapf(err, "error building dataset (path: %s) in package: %s", datasetPath, p.Name)
	}

	// if id is not set, {package}.{datasetPath} is the default
	if d.Name == "" {
		d.Name = p.Name + "." + datasetPath
	}

	if d.Release == "" {
		d.Release = DefaultRelease
	}

	// Default for the enabled flags is true.
	trueValue := true
	for i, _ := range d.Streams {
		if d.Streams[i].Enabled == nil {
			d.Streams[i].Enabled = &trueValue
			// TODO: validate that the template path actually exists
			if d.Streams[i].TemplatePath == "" {
				d.Streams[i].TemplatePath = "stream.yml.hbs"
			}
		}
	}

	if !IsValidRelease(d.Release) {
		return nil, fmt.Errorf("invalid release: %s", d.Release)
	}
	return d, nil
}

func (d *Dataset) Validate() error {
	pipelineDir := filepath.Join(d.BasePath, "elasticsearch", DirIngestPipeline)
	paths, err := filepath.Glob(filepath.Join(pipelineDir, "*"))
	if err != nil {
		return err
	}

	if strings.Contains(d.Name, "-") {
		return fmt.Errorf("dataset name is not allowed to contain `-`: %s", d.Name)
	}

	if !d.validType() {
		return fmt.Errorf("type is not valid: %s", d.Type)
	}

	if d.Elasticsearch != nil && d.Elasticsearch.IngestPipelineName == "" {
		// Check that no ingest pipeline exists in the directory except default
		for _, path := range paths {
			if filepath.Base(path) == DefaultPipelineNameJSON || filepath.Base(path) == DefaultPipelineNameYAML {
				d.Elasticsearch.IngestPipelineName = DefaultPipelineName
				// TODO: remove because of legacy
				d.IngestPipeline = DefaultPipelineName
				break
			}
		}
		// TODO: Remove, only here for legacy
	} else if d.IngestPipeline == "" {
		// Check that no ingest pipeline exists in the directory except default
		for _, path := range paths {
			if filepath.Base(path) == DefaultPipelineNameJSON || filepath.Base(path) == DefaultPipelineNameYAML {
				d.IngestPipeline = DefaultPipelineName
				break
			}
		}
	}

	if d.IngestPipeline == "" && len(paths) > 0 {
		return fmt.Errorf("unused pipelines in the package (dataSetID: %s): %s", d.Name, strings.Join(paths, ","))
	}

	// In case an ingest pipeline is set, check if it is around
	if d.IngestPipeline != "" {
		var validFound bool

		jsonPipelinePath := filepath.Join(pipelineDir, d.IngestPipeline+".json")
		_, errJSON := os.Stat(jsonPipelinePath)
		if errJSON != nil && !os.IsNotExist(errJSON) {
			return errors.Wrapf(errJSON, "stat ingest pipeline JSON file failed (path: %s)", jsonPipelinePath)
		}
		if !os.IsNotExist(errJSON) {
			err = validateIngestPipelineFile(jsonPipelinePath)
			if err != nil {
				return errors.Wrapf(err, "validating ingest pipeline JSON file failed (path: %s)", jsonPipelinePath)
			}
			validFound = true
		}

		yamlPipelinePath := filepath.Join(pipelineDir, d.IngestPipeline+".yml")
		_, errYAML := os.Stat(yamlPipelinePath)
		if errYAML != nil && !os.IsNotExist(errYAML) {
			return errors.Wrapf(errYAML, "stat ingest pipeline YAML file failed (path: %s)", jsonPipelinePath)
		}
		if !os.IsNotExist(errYAML) {
			err = validateIngestPipelineFile(yamlPipelinePath)
			if err != nil {
				return errors.Wrapf(err, "validating ingest pipeline YAML file failed (path: %s)", jsonPipelinePath)
			}
			validFound = true
		}

		if !validFound {
			return fmt.Errorf("defined ingest_pipeline does not exist: %s", pipelineDir+d.IngestPipeline)
		}
	}

	err = d.validateRequiredFields()
	if err != nil {
		return errors.Wrap(err, "validating required fields failed")
	}
	return nil
}

func (d *Dataset) validType() bool {
	_, exists := validTypes[d.Type]
	return exists
}

func validateIngestPipelineFile(pipelinePath string) error {
	f, err := ioutil.ReadFile(pipelinePath)
	if err != nil {
		return errors.Wrapf(err, "reading ingest pipeline file failed (path: %s)", pipelinePath)
	}

	_, err = handlebars.Parse(string(f))
	if err != nil {
		return errors.Wrapf(err, "parsing handlebars syntax failed (path: %s)", pipelinePath)
	}

	ext := filepath.Ext(pipelinePath)
	var m map[string]interface{}
	switch ext {
	case ".json":
		err = json.Unmarshal(f, &m)
	case ".yml":
		err = yamlv2.Unmarshal(f, &m)
	default:
		return fmt.Errorf("unsupported pipeline extension (path: %s, ext: %s)", pipelinePath, ext)
	}
	return err
}

// validateRequiredFields method loads fields from all files and checks if required fields are present.
func (d *Dataset) validateRequiredFields() error {
	fieldsDirPath := filepath.Join(d.BasePath, "fields")

	// Collect fields from all files
	var allFields []MapStr
	err := filepath.Walk(fieldsDirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relativePath, err := filepath.Rel(fieldsDirPath, path)
		if err != nil {
			return errors.Wrapf(err, "cannot find relative path (fieldsDirPath: %s, path: %s)", fieldsDirPath, path)
		}

		if relativePath == "." {
			return nil
		}

		body, err := ioutil.ReadFile(path)
		if err != nil {
			return errors.Wrapf(err, "reading file failed (path: %s)", path)
		}

		var m []MapStr
		err = yamlv2.Unmarshal(body, &m)
		if err != nil {
			return errors.Wrapf(err, "unmarshaling file failed (path: %s)", path)
		}

		allFields = append(allFields, m...)
		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "walking through fields files failed")
	}

	// Flatten all fields
	for i, fields := range allFields {
		allFields[i] = fields.Flatten()
	}

	// Verify required keys
	err = requireField(allFields, "dataset.type", "constant_keyword", err)
	err = requireField(allFields, "dataset.name", "constant_keyword", err)
	err = requireField(allFields, "dataset.namespace", "constant_keyword", err)
	err = requireField(allFields, "@timestamp", "date", err)
	return err
}

func requireField(allFields []MapStr, searchedName, expectedType string, validationErr error) error {
	if validationErr != nil {
		return validationErr
	}

	f, err := findField(allFields, searchedName)
	if err != nil {
		f, err = findFieldSplit(allFields, searchedName)
		if err != nil {
			return errors.Wrapf(err, "finding field failed (searchedName: %s)", searchedName)
		}
	}

	if f.aType != expectedType {
		return fmt.Errorf("wrong field type for '%s' (expected: %s, got: %s)", searchedName, expectedType, f.aType)
	}
	return nil
}

func findFieldSplit(allFields []MapStr, searchedName string) (*fieldEntry, error) {
	levels := strings.Split(searchedName, ".")
	curFields := allFields
	var err error
	for _, part := range levels[:len(levels)-1] {
		curFields, err = getFieldsArray(curFields, part)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to find fields array")
		}
	}
	return findField(curFields, levels[len(levels)-1])
}

func createMapStr(in interface{}) (MapStr, error) {
	m := make(MapStr)
	v, ok := in.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("unable to convert %v to known type", in)
	}
	for k, val := range v {
		m[fmt.Sprintf("%v", k)] = fmt.Sprintf("%v", val)
	}
	return m, nil
}

func getFieldsArray(allFields []MapStr, searchedName string) ([]MapStr, error) {
	for _, fields := range allFields {
		name, err := fields.GetValue("name")
		if err != nil {
			return nil, errors.Wrapf(err, "cannot get value (key: name)")
		}
		if name == searchedName {
			value, err := fields.GetValue("fields")
			if err != nil {
				return nil, errors.Wrapf(err, "cannot get fields")
			}

			if inArray, ok := value.([]interface{}); ok {
				m := make([]MapStr, 0, len(inArray))
				for _, in := range inArray {
					mapStr, err := createMapStr(in)
					if err != nil {
						return nil, errors.Wrapf(err, "cannot create MapStr")
					}
					m = append(m, mapStr)
				}
				return m, nil
			}
			return nil, fmt.Errorf("fields was not []MapStr")
		}
	}
	return nil, fmt.Errorf("field '%s' not found", searchedName)
}

func findField(allFields []MapStr, searchedName string) (*fieldEntry, error) {
	for _, fields := range allFields {
		name, err := fields.GetValue("name")
		if err != nil {
			return nil, errors.Wrapf(err, "cannot get value (key: name)")
		}

		if name != searchedName {
			continue
		}

		aType, err := fields.GetValue("type")
		if err != nil {
			return nil, errors.Wrapf(err, "cannot get value (key: type)")
		}

		if aType == "" {
			return nil, fmt.Errorf("field '%s' found, but type is undefined", searchedName)
		}

		return &fieldEntry{
			name:  name.(string),
			aType: aType.(string),
		}, nil
	}
	return nil, fmt.Errorf("field '%s' not found", searchedName)
}
