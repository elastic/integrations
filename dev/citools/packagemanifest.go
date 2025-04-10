// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package citools

import (
	"fmt"

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

type packageManifest struct {
	Name       string     `config:"name" json:"name" yaml:"name"`
	License    string     `config:"license" json:"license" yaml:"license"`
	Conditions conditions `config:"conditions" json:"conditions" yaml:"conditions"`
}

func readPackageManifest(path string) (*packageManifest, error) {
	cfg, err := yaml.NewConfigWithFile(path, ucfg.PathSep("."))
	if err != nil {
		return nil, fmt.Errorf("reading file failed (path: %s): %w", path, err)
	}

	var manifest packageManifest
	err = cfg.Unpack(&manifest)
	if err != nil {
		return nil, fmt.Errorf("unpacking package manifest failed (path: %s): %w", path, err)
	}
	return &manifest, nil
}
