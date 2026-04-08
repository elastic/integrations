// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package packagenames

import (
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

var validTypes = []string{"integration", "input", "content"}

type packageManifest struct {
	FormatVersion string `yaml:"format_version"`
	Name          string `yaml:"name"`
	Type          string `yaml:"type"`
	Version       string `yaml:"version"`
}

func (m *packageManifest) isValid() bool {
	if m.FormatVersion == "" || m.Name == "" || m.Type == "" || m.Version == "" {
		return false
	}
	return slices.Contains(validTypes, m.Type)
}

func readManifest(path string) (*packageManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m packageManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("error parsing manifest: %w", err)
	}
	return &m, nil
}
