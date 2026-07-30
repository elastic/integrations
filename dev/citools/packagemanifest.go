// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package citools

import (
	"fmt"
	"os"

	"github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/yaml"
)

// kibanaConditions defines conditions for Kibana (e.g. required version).
type kibanaConditions struct {
	Version string `config:"version" json:"version" yaml:"version"`
}

// elasticConditions defines conditions related to Elastic subscriptions or partnerships.
type elasticConditions struct {
	Subscription string `config:"subscription" json:"subscription" yaml:"subscription"`
}

// conditions define requirements for different parts of the Elastic stack.
type conditions struct {
	Kibana  kibanaConditions  `config:"kibana" json:"kibana" yaml:"kibana"`
	Elastic elasticConditions `config:"elastic" json:"elastic" yaml:"elastic"`
}

type requiresEntry struct {
	Package string `config:"package" json:"package" yaml:"package"`
	Version string `config:"version" json:"version" yaml:"version"`
}

type requiresBlock struct {
	Input   []requiresEntry `config:"input"   json:"input"   yaml:"input"`
	Content []requiresEntry `config:"content" json:"content" yaml:"content"`
}

// owner identifies the GitHub owner of a package, as recorded in its manifest.yml.
type owner struct {
	Github string `config:"github" json:"github" yaml:"github"`
}

type packageManifest struct {
	FormatVersion string         `config:"format_version" json:"format_version"          yaml:"format_version"`
	Name          string         `config:"name"           json:"name"                    yaml:"name"`
	Type          string         `config:"type"           json:"type"                    yaml:"type"`
	Version       string         `config:"version"        json:"version"                 yaml:"version"`
	License       string         `config:"license"        json:"license"                 yaml:"license"`
	Conditions    conditions     `config:"conditions"     json:"conditions"               yaml:"conditions"`
	Requires      *requiresBlock `config:"requires"       json:"requires,omitempty"       yaml:"requires,omitempty"`
	Owner         owner          `config:"owner" json:"owner" yaml:"owner"`
}

func (m *packageManifest) IsValid() bool {
	return m.FormatVersion != "" && m.Name != "" && m.Type != "" && m.Version != ""
}

func (m *packageManifest) HasRequires() bool {
	return m.Requires != nil && (len(m.Requires.Input) > 0 || len(m.Requires.Content) > 0)
}

// ParsePackageManifest parses manifest.yml content read from anywhere — a
// worktree file, or content read from another git ref (e.g. via `git show
// <ref>:packages/<pkg>/manifest.yml`).
func ParsePackageManifest(content []byte) (*packageManifest, error) {
	cfg, err := yaml.NewConfig(content, ucfg.PathSep("."))
	if err != nil {
		return nil, fmt.Errorf("failed to parse package manifest: %w", err)
	}

	var manifest packageManifest
	if err := cfg.Unpack(&manifest); err != nil {
		return nil, fmt.Errorf("failed to unpack package manifest: %w", err)
	}
	return &manifest, nil
}

func ReadPackageManifest(path string) (*packageManifest, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file failed (path: %s): %w", path, err)
	}

	manifest, err := ParsePackageManifest(content)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return manifest, nil
}
