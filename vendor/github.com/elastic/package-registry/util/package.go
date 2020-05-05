// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package util

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/blang/semver"

	ucfg "github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/yaml"
)

const defaultType = "integration"

var CategoryTitles = map[string]string{
	"logs":     "Logs",
	"metrics":  "Metrics",
	"security": "Security",
}

type Package struct {
	FormatVersion string `config:"format_version" json:"format_version" yaml:"format_version"`

	Name          string  `config:"name" json:"name"`
	Title         *string `config:"title,omitempty" json:"title,omitempty" yaml:"title,omitempty"`
	Version       string  `config:"version" json:"version"`
	Readme        *string `config:"readme,omitempty" json:"readme,omitempty" yaml:"readme,omitempty"`
	License       string  `config:"license,omitempty" json:"license,omitempty" yaml:"license,omitempty"`
	versionSemVer semver.Version
	Description   string       `config:"description" json:"description"`
	Type          string       `config:"type" json:"type"`
	Categories    []string     `config:"categories" json:"categories"`
	Release       string       `config:"release,omitempty" json:"release,omitempty"`
	Removable     bool         `config:"removable" json:"removable"`
	Requirement   Requirement  `config:"requirement" json:"requirement"`
	Screenshots   []Image      `config:"screenshots,omitempty" json:"screenshots,omitempty" yaml:"screenshots,omitempty"`
	Icons         []Image      `config:"icons,omitempty" json:"icons,omitempty" yaml:"icons,omitempty"`
	Assets        []string     `config:"assets,omitempty" json:"assets,omitempty" yaml:"assets,omitempty"`
	Internal      bool         `config:"internal,omitempty" json:"internal,omitempty" yaml:"internal,omitempty"`
	DataSets      []*DataSet   `config:"datasets,omitempty" json:"datasets,omitempty" yaml:"datasets,omitempty"`
	Datasources   []Datasource `config:"datasources,omitempty" json:"datasources,omitempty" yaml:"datasources,omitempty"`
	Download      string       `json:"download" yaml:"download,omitempty"`
	Path          string       `json:"path" yaml:"path,omitempty"`

	// Local path to the package dir
	BasePath string `json:"-" yaml:"-"`
}

type Datasource struct {
	Name        string  `config:"name" json:"name" validate:"required"`
	Title       string  `config:"title" json:"title" validate:"required"`
	Description string  `config:"description" json:"description" validate:"required"`
	Solution    string  `config:"solution" json:"solution,omitempty" yaml:"solution,omitempty"`
	Inputs      []Input `config:"inputs" json:"inputs"`
	Multiple    *bool   `config:"multiple" json:"multiple,omitempty" yaml:"multiple,omitempty"`
}

type Requirement struct {
	Kibana        ProductRequirement `config:"kibana" json:"kibana,omitempty" yaml:"kibana"`
	Elasticsearch ProductRequirement `config:"elasticsearch" json:"elasticsearch,omitempty" yaml:"elasticsearch"`
}

type ProductRequirement struct {
	Versions    string `config:"versions,omitempty" json:"versions,omitempty" yaml:"versions,omitempty"`
	semVerRange semver.Range
}

type Version struct {
	Min string `config:"min,omitempty" json:"min,omitempty"`
	Max string `config:"max,omitempty" json:"max,omitempty"`
}

type Image struct {
	Src   string `config:"src" json:"src" validate:"required"`
	Title string `config:"title" json:"title,omitempty"`
	Size  string `config:"size" json:"size,omitempty"`
	Type  string `config:"type" json:"type,omitempty"`
}

func (i Image) getPath(p *Package) string {
	return path.Join("/package", p.Name, p.Version, i.Src)
}

// NewPackage creates a new package instances based on the given base path.
// The path passed goes to the root of the package where the manifest.yml is.
func NewPackage(basePath string) (*Package, error) {

	manifest, err := yaml.NewConfigWithFile(filepath.Join(basePath, "manifest.yml"), ucfg.PathSep("."))
	if err != nil {
		return nil, err
	}

	var p = &Package{
		BasePath:  basePath,
		Removable: true,
	}
	err = manifest.Unpack(p)
	if err != nil {
		return nil, err
	}

	// Default for the multiple flags is true.
	trueValue := true
	for i, _ := range p.Datasources {
		if p.Datasources[i].Multiple == nil {
			p.Datasources[i].Multiple = &trueValue
		}
	}
	if p.Type == "" {
		p.Type = defaultType
	}

	// If not license is set, basic is assumed
	if p.License == "" {
		p.License = "basic"
	}

	if p.Icons != nil {
		for k, i := range p.Icons {
			p.Icons[k].Src = i.getPath(p)
		}
	}

	if p.Screenshots != nil {
		for k, s := range p.Screenshots {
			p.Screenshots[k].Src = s.getPath(p)
		}
	}

	if p.Requirement.Kibana.Versions != "" {
		p.Requirement.Kibana.semVerRange, err = semver.ParseRange(p.Requirement.Kibana.Versions)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid Kibana versions range: %s", p.Requirement.Kibana.Versions)
		}
	}

	if p.Release == "" {
		p.Release = DefaultRelease
	}

	if !IsValidRelase(p.Release) {
		return nil, fmt.Errorf("invalid release: %s", p.Release)
	}

	p.versionSemVer, err = semver.Parse(p.Version)
	if err != nil {
		return nil, err
	}

	readmePath := filepath.Join(p.BasePath, "docs", "README.md")
	// Check if readme
	readme, err := os.Stat(readmePath)
	if err != nil {
		return nil, fmt.Errorf("no readme file found, README.md is required: %s", err)
	}

	if readme != nil {
		if readme.IsDir() {
			return nil, fmt.Errorf("README.md is a directory")
		}
		readmePathShort := path.Join("/package", p.Name, p.Version, "docs", "README.md")
		p.Readme = &readmePathShort
	}

	// Assign download path to be part of the output
	p.Download = p.GetDownloadPath()
	p.Path = p.GetUrlPath()

	return p, nil
}

func (p *Package) HasCategory(category string) bool {
	for _, c := range p.Categories {
		if c == category {
			return true
		}
	}

	return false
}

func (p *Package) HasKibanaVersion(version *semver.Version) bool {

	// If the version is not specified, it is for all versions
	if p.Requirement.Kibana.Versions == "" {
		return true
	}

	if version != nil {
		if !p.Requirement.Kibana.semVerRange(*version) {
			return false
		}
	}
	return true
}

func (p *Package) IsNewer(pp Package) bool {
	return p.versionSemVer.GT(pp.versionSemVer)
}

// LoadAssets (re)loads all the assets of the package
// Based on the time when this is called, it might be that not all assets for a package exist yet, so it is reset every time.
func (p *Package) LoadAssets(packagePath string) (err error) {
	// Reset Assets
	p.Assets = nil

	// Iterates recursively through all the levels to find assets
	// If we need more complex matching a library like https://github.com/bmatcuk/doublestar
	// could be used but the below works and is pretty simple.
	assets, err := collectAssets(filepath.Join(p.BasePath, "*"))
	if err != nil {
		return err
	}

	for _, a := range assets {
		// Unfortunately these files keep sneaking in
		if strings.Contains(a, ".DS_Store") {
			continue
		}

		info, err := os.Stat(a)
		if err != nil {
			return err
		}

		if info.IsDir() {
			continue
		}

		// Strip away the basePath from the local system
		a = a[len(p.BasePath)+1:]

		a = path.Join("/package", packagePath, a)
		p.Assets = append(p.Assets, a)
	}
	return nil
}

func collectAssets(pattern string) ([]string, error) {
	assets, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(assets) != 0 {
		a, err := collectAssets(filepath.Join(pattern, "*"))
		if err != nil {
			return nil, err
		}
		return append(assets, a...), nil
	}
	return nil, nil
}

func (p *Package) Validate() error {

	if p.FormatVersion == "" {
		return fmt.Errorf("no format_version set: %v", p)
	}

	_, err := semver.New(p.FormatVersion)
	if err != nil {
		return fmt.Errorf("invalid package version: %s, %s", p.FormatVersion, err)
	}

	if p.Title == nil || *p.Title == "" {
		return fmt.Errorf("no title set for package: %s", p.Name)
	}

	if p.Description == "" {
		return fmt.Errorf("no description set")
	}

	if p.Requirement.Elasticsearch.Versions != "" {
		_, err := semver.ParseRange(p.Requirement.Elasticsearch.Versions)
		if err != nil {
			return fmt.Errorf("invalid Elasticsearch versions: %s, %s", p.Requirement.Elasticsearch.Versions, err)
		}
	}

	if p.Requirement.Kibana.Versions != "" {
		_, err := semver.ParseRange(p.Requirement.Kibana.Versions)
		if err != nil {
			return fmt.Errorf("invalid Kibana versions: %s, %s", p.Requirement.Kibana.Versions, err)
		}
	}

	for _, c := range p.Categories {
		if _, ok := CategoryTitles[c]; !ok {
			return fmt.Errorf("invalid category: %s", c)
		}
	}

	return nil
}

// GetDatasetPaths returns a list with the dataset paths inside this package
func (p *Package) GetDatasetPaths() ([]string, error) {
	datasetBasePath := filepath.Join(p.BasePath, "dataset")

	// Check if this package has datasets
	_, err := os.Stat(datasetBasePath)
	// If no datasets exist, just return
	if os.IsNotExist(err) {
		return nil, nil
	}
	// An other error happened, report it
	if err != nil {
		return nil, err
	}

	paths, err := filepath.Glob(filepath.Join(datasetBasePath, "*"))
	if err != nil {
		return nil, err
	}

	for i, _ := range paths {
		paths[i] = paths[i][len(datasetBasePath)+1:]
	}

	return paths, nil
}

func (p *Package) LoadDataSets(packagePath string) error {

	datasetPaths, err := p.GetDatasetPaths()
	if err != nil {
		return err
	}

	datasetsBasePath := filepath.Join(p.BasePath, "dataset")

	for _, datasetPath := range datasetPaths {

		datasetBasePath := filepath.Join(datasetsBasePath, datasetPath)

		d, err := NewDataset(datasetBasePath, p)
		if err != nil {
			return err
		}

		// Iterate through all datasources and inputs to find the matching streams and add them to the output.
		for dK, datasource := range p.Datasources {
			for iK, _ := range datasource.Inputs {
				for _, stream := range d.Streams {
					if stream.Input == p.Datasources[dK].Inputs[iK].Type {
						if stream.TemplatePath == "" {
							stream.TemplatePath = "stream.yml.hbs"
						}
						stream.Dataset = d.ID
						streamTemplate := filepath.Join(datasetBasePath, "agent", "stream", stream.TemplatePath)

						streamTemplateData, err := ioutil.ReadFile(streamTemplate)
						if err != nil {
							return err
						}

						stream.TemplateContent = string(streamTemplateData)

						// Add template to stream
						p.Datasources[dK].Inputs[iK].Streams = append(p.Datasources[dK].Inputs[iK].Streams, stream)
					}
				}
			}
		}

		p.DataSets = append(p.DataSets, d)
	}

	return nil
}

func (p *Package) GetPath() string {
	return p.Name + "/" + p.Version
}

func (p *Package) GetDownloadPath() string {
	return path.Join("/epr", p.Name, p.Name+"-"+p.Version+".tar.gz")
}

func (p *Package) GetUrlPath() string {
	return path.Join("/package", p.Name, p.Version)
}
