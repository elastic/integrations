// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"flag"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/pkg/errors"
)

type importerOptions struct {
	// Beats repository directory
	beatsDir string

	// Kibana host and port
	kibanaHostPort string
	// Kibana username
	kibanaUsername string
	// Kibana password
	kibanaPassword string
	// Kibana repository directory
	kibanaDir string
	// Skip storing Kibana objects
	skipKibana bool

	// Elastic UI Framework directory
	euiDir string

	// Elastic Common Schema directory
	ecsDir string

	// Packages selected for the import (comma-delimited list)
	packages string

	// Target public directory where the generated packages should end up in
	outputDir string
}

func (o *importerOptions) validate() error {
	_, err := os.Stat(o.beatsDir)
	if err != nil {
		return errors.Wrapf(err, "stat file failed (path: %s)", o.beatsDir)
	}

	_, err = url.Parse(o.kibanaHostPort)
	if err != nil {
		return errors.Wrapf(err, "parsing Kibana's host:port failed (hostPort: %s)", o.kibanaHostPort)
	}

	_, err = os.Stat(o.kibanaDir)
	if err != nil {
		return errors.Wrapf(err, "stat file failed (path: %s)", o.kibanaDir)
	}

	_, err = os.Stat(o.euiDir)
	if err != nil {
		return errors.Wrapf(err, "stat file failed (path: %s)", o.euiDir)
	}

	_, err = os.Stat(o.outputDir)
	if err != nil {
		return errors.Wrapf(err, "stat file failed (path: %s)", o.outputDir)
	}
	return nil
}

func (o *importerOptions) selectedPackages() []string {
	var selected []string
	p := strings.TrimSpace(o.packages)
	if len(p) > 0 {
		selected = strings.Split(p, ",")
	}
	return selected
}

func main() {
	log.Println("Deprecated: https://github.com/elastic/integrations/blob/main/dev/import-beats/README.md")

	var options importerOptions

	flag.StringVar(&options.beatsDir, "beatsDir", "../beats", "Path to the beats repository")
	flag.StringVar(&options.kibanaDir, "kibanaDir", "../kibana", "Path to the kibana repository")
	flag.StringVar(&options.kibanaHostPort, "kibanaHostPort", "http://localhost:5601", "Kibana host and port")
	flag.StringVar(&options.kibanaUsername, "kibanaUsername", "elastic", "Kibana username")
	flag.StringVar(&options.kibanaPassword, "kibanaPassword", "changeme", "Kibana password")
	flag.BoolVar(&options.skipKibana, "skipKibana", false, "Skip storing Kibana objects")
	flag.StringVar(&options.euiDir, "euiDir", "../eui", "Path to the Elastic UI framework repository")
	flag.StringVar(&options.ecsDir, "ecsDir", "../ecs", "Path to the Elastic Common Schema repository")
	flag.StringVar(&options.packages, "packages", "", "Packages selected for the import")
	flag.StringVar(&options.outputDir, "outputDir", "packages", "Path to the output directory")
	flag.Parse()

	err := options.validate()
	if err != nil {
		log.Fatal(err)
	}

	if err := build(options); err != nil {
		log.Fatal(err)
	}
}

// build method visits all beats in beatsDir to collect configuration data for modules.
// The package-registry groups integrations per target product not per module type. It's opposite to the beats project,
// where logs and metrics are distributed with different beats (oriented either on logs or metrics - metricbeat,
// filebeat, etc.).
func build(options importerOptions) error {
	iconRepository, err := newIconRepository(options.euiDir, options.kibanaDir)
	if err != nil {
		return errors.Wrap(err, "creating icon repository failed")
	}
	kibanaMigrator := newKibanaMigrator(options.kibanaHostPort,
		options.kibanaUsername,
		options.kibanaPassword,
		options.skipKibana)
	ecsFields, err := loadEcsFields(options.ecsDir)
	if err != nil {
		return errors.Wrap(err, "loading ECS fields failed")
	}

	repository := newPackageRepository(iconRepository, kibanaMigrator, ecsFields, options.selectedPackages())

	for _, beatName := range logSources {
		err := repository.createPackagesFromSource(options.beatsDir, beatName, "logs")
		if err != nil {
			return errors.Wrap(err, "creating from logs source failed")
		}
	}
	for _, beatName := range metricSources {
		err := repository.createPackagesFromSource(options.beatsDir, beatName, "metrics")
		if err != nil {
			return errors.Wrap(err, "creating from metrics source failed")
		}
	}
	return repository.save(options.outputDir)
}
