// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v3"
)

type elasticsearchContent struct {
	ingestPipelines []ingestPipelineContent
}

type ingestPipelineContent struct {
	targetFileName string
	body           []byte
}

var (
	reUnsupportedIfInPipeline             = regexp.MustCompile("{<[ ]{0,1}if[^(>})]+>}")
	reUnsupportedIngestPipelineInPipeline = regexp.MustCompile("('|\"){< (IngestPipeline).+>}('|\")")
	reUnsupportedPlaceholderInPipeline    = regexp.MustCompile("{<.+>}")
)

func loadElasticsearchContent(dataStreamPath string) (elasticsearchContent, error) {
	var esc elasticsearchContent

	dataStreamManifestPath := filepath.Join(dataStreamPath, "manifest.yml")
	dataStreamManifestFile, err := ioutil.ReadFile(dataStreamManifestPath)
	if os.IsNotExist(err) {
		return elasticsearchContent{}, nil // no manifest.yml file found,
	}
	if err != nil {
		return elasticsearchContent{}, errors.Wrapf(err, "reading dataStream manifest file failed (path: %s)", dataStreamManifestPath)
	}

	var ingestPipelines []string
	var dmsp dataStreamManifestSinglePipeline
	err = yaml.Unmarshal(dataStreamManifestFile, &dmsp)
	if err == nil {
		if len(dmsp.IngestPipeline) > 0 {
			ingestPipelines = append(ingestPipelines, dmsp.IngestPipeline)
		}
	} else {
		var dmmp dataStreamManifestMultiplePipelines
		err = yaml.Unmarshal(dataStreamManifestFile, &dmmp)
		if err != nil {
			return elasticsearchContent{}, errors.Wrapf(err, "unmarshalling dataStream manifest file failed (path: %s)", dataStreamManifestPath)
		}

		if len(dmmp.IngestPipeline) > 0 {
			ingestPipelines = append(ingestPipelines, dmmp.IngestPipeline...)
		}
	}

	for _, ingestPipeline := range ingestPipelines {
		ingestPipeline = ensurePipelineFormat(ingestPipeline)

		log.Printf("\tingest-pipeline found: %s", ingestPipeline)

		var targetFileName string
		if len(ingestPipelines) == 1 {
			targetFileName, err = buildSingleIngestPipelineTargetName(ingestPipeline)
			if err != nil {
				return elasticsearchContent{}, errors.Wrapf(err, "can't build single ingest pipeline target name (path: %s)", ingestPipeline)
			}
		} else {
			targetFileName, err = determineIngestPipelineTargetName(ingestPipeline)
			if err != nil {
				return elasticsearchContent{}, errors.Wrapf(err, "can't determine ingest pipeline target name (path: %s)", ingestPipeline)
			}
		}

		pipelinePath := filepath.Join(dataStreamPath, ingestPipeline)
		body, err := ioutil.ReadFile(pipelinePath)
		if err != nil {
			return elasticsearchContent{}, errors.Wrapf(err, "reading pipeline body failed (path: %s)", pipelinePath)
		}

		// Fix missing "---" at the beginning of the YAML pipeline.
		if strings.HasSuffix(targetFileName, ".yml") && bytes.Index(body, []byte("---")) != 0 {
			body = append([]byte("---\n"), body...)
		}

		ipc := ingestPipelineContent{
			targetFileName: targetFileName,
			body:           adjustUnsupportedStructuresInPipeline(body),
		}

		err = validateIngestPipeline(ipc)
		if err != nil {
			return elasticsearchContent{},
				errors.Wrapf(err, "validation of modified ingest pipeline failed (original path: %s)", pipelinePath)
		}

		esc.ingestPipelines = append(esc.ingestPipelines, ipc)
	}

	return esc, nil
}

func buildSingleIngestPipelineTargetName(path string) (string, error) {
	_, ext, err := splitFilenameExt(path)
	if err != nil {
		return "", errors.Wrapf(err, "processing filename failed (path: %s)", path)
	}
	return "default." + ext, nil
}

func ensurePipelineFormat(ingestPipeline string) string {
	if strings.Contains(ingestPipeline, "{{.format}}") {
		ingestPipeline = strings.ReplaceAll(ingestPipeline, "{{.format}}", "json")
	}
	return ingestPipeline
}

func determineIngestPipelineTargetName(path string) (string, error) {
	name, ext, err := splitFilenameExt(path)
	if err != nil {
		return "", errors.Wrapf(err, "processing filename failed (path: %s)", path)
	}

	if name == "pipeline" || name == "pipeline-entry" {
		return "default." + ext, nil
	}
	return fmt.Sprintf("%s.%s", name, ext), nil
}

func adjustUnsupportedStructuresInPipeline(data []byte) []byte {
	data = reUnsupportedIfInPipeline.ReplaceAll(data, []byte{})
	data = bytes.ReplaceAll(data, []byte("{< end >}"), []byte{})

	data = reUnsupportedIngestPipelineInPipeline.ReplaceAllFunc(data, func(found []byte) []byte {
		found = bytes.ReplaceAll(found, []byte("{<"), []byte("{{"))
		found = bytes.ReplaceAll(found, []byte(">}"), []byte("}}"))

		if found[0] == '"' {
			found = bytes.ReplaceAll(found, []byte(`"`), []byte(`'`))
			found[0] = '"'
			found[len(found)-1] = '"'
		}
		return found
	})

	data = reUnsupportedPlaceholderInPipeline.ReplaceAll(data, []byte("FIX_ME"))
	return data
}

func validateIngestPipeline(content ingestPipelineContent) error {
	_, ext, err := splitFilenameExt(content.targetFileName)
	if err != nil {
		return errors.Wrapf(err, "processing filename failed (path: %s)", content.targetFileName)
	}

	var m mapStr
	switch ext {
	case "json":
		err = json.Unmarshal(content.body, &m)
	case "yml":
		err = yaml.Unmarshal(content.body, &m)
	default:
		return fmt.Errorf("unsupported pipeline extension (path: %s)", content.targetFileName)
	}
	return err
}
