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

	"github.com/pkg/errors"
	yamlv2 "gopkg.in/yaml.v2"

	ucfg "github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/yaml"
)

const (
	DirIngestPipeline = "ingest-pipeline"
)

type DataSet struct {
	ID             string   `config:"id" json:"id,omitempty" yaml:"id,omitempty"`
	Title          string   `config:"title" json:"title" validate:"required"`
	Release        string   `config:"release" json:"release"`
	Type           string   `config:"type" json:"type" validate:"required"`
	IngestPipeline string   `config:"ingest_pipeline,omitempty" config:"ingest_pipeline" json:"ingest_pipeline,omitempty" yaml:"ingest_pipeline,omitempty"`
	Streams        []Stream `config:"streams" json:"streams,omitempty" yaml:"streams,omitempty" validate:"required"`
	Package        string   `json:"package,omitempty" yaml:"package,omitempty"`

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
	TemplatePath    string `config:"template_path" json:"template_path,omitempty" yaml:"template_path,omitempty"`
	TemplateContent string `json:"template,omitempty" yaml:"template,omitempty"` // This is always generated in the json output
	Title           string `config:"title" json:"title,omitempty" yaml:"title,omitempty"`
	Description     string `config:"description" json:"description,omitempty" yaml:"description,omitempty"`
	Enabled         *bool  `config:"enabled" json:"enabled,omitempty" yaml:"enabled,omitempty"`
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
	Os          *Os         `config:"os" json:"os,omitempty" yaml:"os,omitempty"`
}

type Os struct {
	Darwin  interface{} `config:"darwin" json:"darwin,omitempty" yaml:"darwin,omitempty"`
	Windows interface{} `config:"windows" json:"windows,omitempty" yaml:"windows,omitempty"`
}

func NewDataset(basePath string, p *Package) (*DataSet, error) {

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
	var d = &DataSet{
		Package: p.Name,
		// This is the name of the directory of the dataset
		Path:     datasetPath,
		BasePath: basePath,
	}

	// go-ucfg automatically calls the `Validate` method on the Dataset object here
	err = manifest.Unpack(d)
	if err != nil {
		return nil, errors.Wrapf(err, "error building dataset (path: %s) in package: %s", datasetPath, p.Name)
	}

	// if id is not set, {package}.{datasetPath} is the default
	if d.ID == "" {
		d.ID = p.Name + "." + datasetPath
	}

	if d.Release == "" {
		d.Release = DefaultRelease
	}

	// Default for the enabled flags is true.
	trueValue := true
	for i, _ := range d.Streams {
		if d.Streams[i].Enabled == nil {
			d.Streams[i].Enabled = &trueValue
		}
	}

	if !IsValidRelase(d.Release) {
		return nil, fmt.Errorf("invalid release: %s", d.Release)
	}

	return d, nil
}

func (d *DataSet) Validate() error {
	pipelineDir := filepath.Join(d.BasePath, "elasticsearch", DirIngestPipeline)
	paths, err := filepath.Glob(filepath.Join(pipelineDir, "*"))
	if err != nil {
		return err
	}

	if strings.Contains(d.ID, "-") {
		return fmt.Errorf("dataset name is not allowed to contain `-`: %s", d.ID)
	}

	if d.IngestPipeline == "" {
		// Check that no ingest pipeline exists in the directory except default
		for _, path := range paths {
			if filepath.Base(path) == "default.json" || filepath.Base(path) == "default.yml" {
				d.IngestPipeline = "default"
				break
			}
		}
	}

	if d.IngestPipeline == "" && len(paths) > 0 {
		return fmt.Errorf("unused pipelines in the package (dataSetID: %s): %s", d.ID, strings.Join(paths, ","))
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
	return nil
}

func validateIngestPipelineFile(pipelinePath string) error {
	f, err := ioutil.ReadFile(pipelinePath)
	if err != nil {
		return errors.Wrapf(err, "reading ingest pipeline file failed (path: %s)", pipelinePath)
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
