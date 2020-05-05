// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/elastic/package-registry/util"
)

type datasetContent struct {
	name     string
	beatType string

	manifest util.DataSet

	agent         agentContent
	elasticsearch elasticsearchContent
	fields        fieldsContent
}

type datasetContentArray []datasetContent

func (dca datasetContentArray) names() []string {
	var names []string
	for _, dc := range dca {
		names = append(names, dc.name)
	}
	return names
}

type datasetManifestMultiplePipelines struct {
	IngestPipeline []string `yaml:"ingest_pipeline"`
}

type datasetManifestSinglePipeline struct {
	IngestPipeline string `yaml:"ingest_pipeline"`
}

func createDatasets(beatType, modulePath, moduleName, moduleTitle, moduleRelease string, moduleFields []fieldDefinition,
	filteredEcsModuleFieldNames []string, ecsFields fieldDefinitionArray) (datasetContentArray, error) {
	datasetDirs, err := ioutil.ReadDir(modulePath)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read module directory %s", modulePath)
	}

	var contents []datasetContent
	for _, datasetDir := range datasetDirs {
		if !datasetDir.IsDir() {
			continue
		}
		datasetName := datasetDir.Name()

		if datasetName == "_meta" {
			continue
		}

		datasetPath := filepath.Join(modulePath, datasetName)
		_, err := os.Stat(filepath.Join(datasetPath, "_meta"))
		if os.IsNotExist(err) {
			_, err = os.Stat(filepath.Join(datasetPath, "manifest.yml"))
			if os.IsNotExist(err) {
				log.Printf("\t%s: not a valid dataset, skipped", datasetName)
				continue
			}
		}

		log.Printf("\t%s: dataset found", datasetName)

		// fields
		datasetFields, err := loadDatasetFields(modulePath, moduleName, datasetName)
		if err != nil {
			return nil, errors.Wrapf(err, "loading dataset fields failed (modulePath: %s, datasetName: %s)",
				modulePath, datasetName)
		}
		datasetFields, filteredEcsDatasetFieldNames, err := filterMigratedFields(datasetFields, ecsFields.names())
		if err != nil {
			return nil, errors.Wrapf(err, "filtering uncommon migrated failed (modulePath: %s, datasetName: %s)",
				modulePath, datasetName)
		}

		foundEcsFieldNames := uniqueStringValues(append(filteredEcsModuleFieldNames, filteredEcsDatasetFieldNames...))
		ecsFields := filterEcsFields(ecsFields, foundEcsFieldNames)

		fieldsFiles := map[string]fieldDefinitionArray{}
		if len(ecsFields) > 0 {
			fieldsFiles["ecs.yml"] = ecsFields
		}
		if len(moduleFields) > 0 {
			fieldsFiles["package-fields.yml"] = moduleFields
		}
		if len(datasetFields) > 0 {
			fieldsFiles["fields.yml"] = datasetFields
		}
		fields := fieldsContent{
			files: fieldsFiles,
		}

		// elasticsearch
		elasticsearch, err := loadElasticsearchContent(datasetPath)
		if err != nil {
			return nil, errors.Wrapf(err, "loading elasticsearch content failed (datasetPath: %s)", datasetPath)
		}

		// streams and agents
		streams, agent, err := createStreams(modulePath, moduleName, moduleTitle, datasetName, beatType)
		if err != nil {
			return nil, errors.Wrapf(err, "creating streams failed (datasetPath: %s)", datasetPath)
		}

		// manifest
		manifest := util.DataSet{
			Title:   fmt.Sprintf("%s %s %s", moduleTitle, datasetName, beatType),
			Release: "experimental",
			Type:    beatType,
			Streams: streams,
		}

		contents = append(contents, datasetContent{
			name:          datasetName,
			beatType:      beatType,
			manifest:      manifest,
			agent:         agent,
			elasticsearch: elasticsearch,
			fields:        fields,
		})
	}
	return contents, nil
}
