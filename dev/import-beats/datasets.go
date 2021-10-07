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

	"github.com/elastic/package-registry/packages"
)

type dataStreamContent struct {
	name     string
	beatType string

	manifest packages.DataStream

	agent         agentContent
	elasticsearch elasticsearchContent
	fields        fieldsContent
}

type dataStreamContentArray []dataStreamContent

func (dca dataStreamContentArray) names() []string {
	var names []string
	for _, dc := range dca {
		names = append(names, dc.name)
	}
	return names
}

type dataStreamManifestMultiplePipelines struct {
	IngestPipeline []string `yaml:"ingest_pipeline"`
}

type dataStreamManifestSinglePipeline struct {
	IngestPipeline string `yaml:"ingest_pipeline"`
}

func createDataStreams(beatType, modulePath, moduleName, moduleTitle string, moduleFields []fieldDefinition,
	filteredEcsModuleFieldNames []string, ecsFields fieldDefinitionArray) (dataStreamContentArray, error) {
	dataStreamDirs, err := ioutil.ReadDir(modulePath)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read module directory %s", modulePath)
	}

	var contents []dataStreamContent
	for _, dataStreamDir := range dataStreamDirs {
		if !dataStreamDir.IsDir() {
			continue
		}
		dataStreamName := dataStreamDir.Name()

		if dataStreamName == "_meta" {
			continue
		}

		dataStreamPath := filepath.Join(modulePath, dataStreamName)
		_, err := os.Stat(filepath.Join(dataStreamPath, "_meta"))
		if os.IsNotExist(err) {
			_, err = os.Stat(filepath.Join(dataStreamPath, "manifest.yml"))
			if os.IsNotExist(err) {
				log.Printf("\t%s: not a valid dataStream, skipped", dataStreamName)
				continue
			}
		}

		log.Printf("\t%s: dataStream found", dataStreamName)

		// fields
		dataStreamFields, err := loadDataStreamFields(modulePath, moduleName, dataStreamName)
		if err != nil {
			return nil, errors.Wrapf(err, "loading dataStream fields failed (modulePath: %s, dataStreamName: %s)",
				modulePath, dataStreamName)
		}
		dataStreamFields, filteredEcsDataStreamFieldNames, err := filterMigratedFields(dataStreamFields, ecsFields.names())
		if err != nil {
			return nil, errors.Wrapf(err, "filtering uncommon migrated failed (modulePath: %s, dataStreamName: %s)",
				modulePath, dataStreamName)
		}

		foundEcsFieldNames := uniqueStringValues(append(filteredEcsModuleFieldNames, filteredEcsDataStreamFieldNames...))
		ecsFields := filterEcsFields(ecsFields, foundEcsFieldNames)

		fieldsFiles := map[string]fieldDefinitionArray{}
		if len(ecsFields) > 0 {
			fieldsFiles["ecs.yml"] = ecsFields
		}
		if len(moduleFields) > 0 && len(moduleFields[0].Fields) > 0 {
			fieldsFiles["package-fields.yml"] = moduleFields
		}
		if len(dataStreamFields) > 0 {
			fieldsFiles["fields.yml"] = dataStreamFields
		}
		fieldsFiles["base-fields.yml"] = baseFields

		fields := fieldsContent{
			files: fieldsFiles,
		}

		// elasticsearch
		elasticsearch, err := loadElasticsearchContent(dataStreamPath)
		if err != nil {
			return nil, errors.Wrapf(err, "loading elasticsearch content failed (dataStreamPath: %s)", dataStreamPath)
		}

		// streams and agents
		streams, agent, err := createStreams(modulePath, moduleName, moduleTitle, dataStreamName, beatType)
		if err != nil {
			return nil, errors.Wrapf(err, "creating streams failed (dataStreamPath: %s)", dataStreamPath)
		}

		// manifest
		manifest := packages.DataStream{
			Title:   fmt.Sprintf("%s %s %s", moduleTitle, dataStreamName, beatType),
			Release: "experimental",
			Type:    beatType,
			Streams: streams,
		}

		contents = append(contents, dataStreamContent{
			name:          dataStreamName,
			beatType:      beatType,
			manifest:      manifest,
			agent:         agent,
			elasticsearch: elasticsearch,
			fields:        fields,
		})
	}
	return contents, nil
}
