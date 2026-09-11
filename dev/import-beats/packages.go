// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v3"

	"github.com/elastic/package-registry/packages"
)

var ignoredModules = map[string]bool{"apache2": true}

type packageContent struct {
	manifest       packages.Package
	dataStreams    dataStreamContentArray
	images         []imageContent
	kibana         kibanaContent
	docs           []docContent
	policyTemplate policyTemplateContent
}

func newPackageContent(name string) packageContent {
	return packageContent{
		manifest: packages.Package{
			FormatVersion: "1.0.0",
			BasePackage: packages.BasePackage{
				Name:    name,
				Version: "0.0.1", // TODO
				Type:    "integration",
				Release: "experimental",
				Owner: &packages.Owner{
					Github: "elastic/integrations",
				},
			},
			License: "basic",
		},
		kibana: kibanaContent{
			files: map[string]map[string][]byte{},
		},
	}
}

func (pc *packageContent) addDataStreams(ds []dataStreamContent) {
	for _, dc := range ds {
		for i, v := range pc.dataStreams {
			if v.name == dc.name {
				if v.beatType != dc.beatType {
					pc.dataStreams[i].name = fmt.Sprintf("%s_%s", pc.dataStreams[i].name, pc.dataStreams[i].beatType)
					dc.name = fmt.Sprintf("%s_%s", dc.name, dc.beatType)
					pc.dataStreams = append(pc.dataStreams, dc)
				} else {
					log.Printf("Resolve naming conflict (packageName: %s, beatType: %s)", dc.name, dc.beatType)
					pc.dataStreams[i] = dc
				}
				break
			}
		}
		pc.dataStreams = append(pc.dataStreams, dc)
	}
}

func (pc *packageContent) addKibanaContent(kc kibanaContent) {
	if kc.files != nil {
		for objectType, objects := range kc.files {
			if _, ok := pc.kibana.files[objectType]; !ok {
				pc.kibana.files[objectType] = map[string][]byte{}
			}

			for k, v := range objects {
				pc.kibana.files[objectType][k] = v
			}
		}
	}
}

type packageRepository struct {
	iconRepository       *iconRepository
	kibanaMigrator       *kibanaMigrator
	ecsFields            fieldDefinitionArray
	selectedPackageNames []string

	packages map[string]packageContent
}

func newPackageRepository(iconRepository *iconRepository, kibanaMigrator *kibanaMigrator,
	ecsFields fieldDefinitionArray, selectedPackageNames []string,
) *packageRepository {
	return &packageRepository{
		iconRepository:       iconRepository,
		kibanaMigrator:       kibanaMigrator,
		ecsFields:            ecsFields,
		selectedPackageNames: selectedPackageNames,

		packages: map[string]packageContent{},
	}
}

func (r *packageRepository) createPackagesFromSource(beatsDir, beatName, beatType string) error {
	beatPath := filepath.Join(beatsDir, beatName)
	beatModulesPath := filepath.Join(beatPath, "module")

	moduleDirs, err := ioutil.ReadDir(beatModulesPath)
	if err != nil {
		return errors.Wrapf(err, "cannot read directory '%s'", beatModulesPath)
	}

	for _, moduleDir := range moduleDirs {
		if !moduleDir.IsDir() {
			continue
		}
		moduleName := moduleDir.Name()

		if !r.packageSelected(moduleName) {
			continue
		}

		log.Printf("%s %s: module found\n", beatName, moduleName)
		if _, ok := ignoredModules[moduleName]; ok {
			log.Printf("%s %s: module skipped\n", beatName, moduleName)
			continue
		}
		modulePath := path.Join(beatModulesPath, moduleName)

		_, ok := r.packages[moduleName]
		if !ok {
			r.packages[moduleName] = newPackageContent(moduleName)
		}

		aPackage := r.packages[moduleName]
		manifest := aPackage.manifest

		// fields
		moduleFields, maybeTitle, err := loadModuleFields(modulePath)
		if err != nil {
			return err
		}
		moduleFields, filteredEcsModuleFieldNames, err := filterMigratedFields(moduleFields, r.ecsFields.names())
		if err != nil {
			return err
		}

		// title
		if maybeTitle != "" {
			manifest.Title = &maybeTitle
			manifest.Description = maybeTitle + " Integration"
		}

		// img
		beatDocsPath := selectDocsPath(beatsDir, beatName)
		images, err := createImages(beatDocsPath, modulePath)
		if err != nil {
			return err
		}
		aPackage.images = append(aPackage.images, images...)

		// img/icons
		// The condition prevents from adding an icon multiple times (e.g. for metricbeat and filebeat).
		if len(manifest.Icons) == 0 {
			icons, err := createIcons(r.iconRepository, moduleName)
			if err != nil {
				return err
			}
			aPackage.images = append(aPackage.images, icons...)

			manifestIcons, err := icons.toManifestImages()
			if err != nil {
				return err
			}
			manifest.Icons = append(manifest.Icons, manifestIcons...)
		}

		// img/screenshots
		screenshots, err := images.toManifestImages()
		if err != nil {
			return err
		}
		manifest.Screenshots = append(manifest.Screenshots, screenshots...)

		// docs
		if len(aPackage.docs) == 0 {
			packageDocsPath := filepath.Join("packages", moduleDir.Name(), "_dev", "build", "docs")
			docs, err := createDocTemplates(packageDocsPath)
			if err != nil {
				return err
			}
			aPackage.docs = append(aPackage.docs, docs...)
		}

		// dataStreams
		moduleTitle := "TODO"
		if manifest.Title != nil {
			moduleTitle = *manifest.Title
		}

		dataStreams, err := createDataStreams(beatType, modulePath, moduleName, moduleTitle, moduleFields, filteredEcsModuleFieldNames, r.ecsFields)
		if err != nil {
			return err
		}
		dataStreams, inputVarsPerInputType, err := compactDataStreamVariables(dataStreams)
		if err != nil {
			return err
		}
		aPackage.addDataStreams(dataStreams)

		// policyTemplates
		aPackage.policyTemplate, err = updatePolicyTemplate(aPackage.policyTemplate, updatePolicyTemplateParameters{
			moduleName:  moduleName,
			moduleTitle: moduleTitle,
			packageType: beatType,
			dataStreams: dataStreams,
			inputVars:   inputVarsPerInputType,
		})
		if err != nil {
			return err
		}
		manifest.PolicyTemplates = aPackage.policyTemplate.toMetadataPolicyTemplates()

		// kibana
		kibana, err := createKibanaContent(r.kibanaMigrator, modulePath, moduleName, dataStreams.names())
		if err != nil {
			return err
		}
		aPackage.addKibanaContent(kibana)
		manifest.Conditions = createConditions()

		aPackage.manifest = manifest
		r.packages[moduleDir.Name()] = aPackage
	}
	return nil
}

func (r *packageRepository) packageSelected(packageName string) bool {
	if len(r.selectedPackageNames) == 0 {
		return true
	}

	for _, f := range r.selectedPackageNames {
		if f == packageName {
			return true
		}
	}
	return false
}

func (r *packageRepository) save(outputDir string) error {
	for packageName, content := range r.packages {
		manifest := content.manifest

		log.Printf("%s/%s write package content\n", packageName, manifest.Version)

		packagePath := filepath.Join(outputDir, packageName)
		err := os.MkdirAll(packagePath, 0755)
		if err != nil {
			return errors.Wrapf(err, "cannot make directory for module: '%s'", packagePath)
		}

		m, err := yaml.Marshal(content.manifest)
		if err != nil {
			return errors.Wrapf(err, "marshaling package manifest failed (packageName: %s)", packageName)
		}

		manifestFilePath := filepath.Join(packagePath, "manifest.yml")
		err = ioutil.WriteFile(manifestFilePath, m, 0644)
		if err != nil {
			return errors.Wrapf(err, "writing manifest file failed (path: %s)", manifestFilePath)
		}

		// dataStream
		for _, dataStream := range content.dataStreams {
			dataStreamPath := filepath.Join(packagePath, "data_stream", dataStream.name)
			err := os.MkdirAll(dataStreamPath, 0755)
			if err != nil {
				return errors.Wrapf(err, "cannot make directory for dataStream: '%s'", dataStreamPath)
			}

			// dataStream/manifest.yml
			m, err := yaml.Marshal(dataStream.manifest)
			if err != nil {
				return errors.Wrapf(err, "marshaling data stream manifest failed (dataStreamName: %s)", dataStream.name)
			}

			manifestFilePath := filepath.Join(dataStreamPath, "manifest.yml")
			err = ioutil.WriteFile(manifestFilePath, m, 0644)
			if err != nil {
				return errors.Wrapf(err, "writing data stream manifest file failed (path: %s)", manifestFilePath)
			}

			// dataStream/fields
			if len(dataStream.fields.files) > 0 {
				dataStreamFieldsPath := filepath.Join(dataStreamPath, "fields")
				err := os.MkdirAll(dataStreamFieldsPath, 0755)
				if err != nil {
					return errors.Wrapf(err, "cannot make directory for data stream fields: '%s'", dataStreamPath)
				}

				for fieldsFileName, definitions := range dataStream.fields.files {
					log.Printf("%s: write '%s' file\n", dataStream.name, fieldsFileName)

					fieldsFilePath := filepath.Join(dataStreamFieldsPath, fieldsFileName)
					var fieldsFile []byte

					stripped := definitions.stripped()
					fieldsFile, err := yaml.Marshal(&stripped)
					if err != nil {
						return errors.Wrapf(err, "marshalling fields file failed (path: %s)", fieldsFilePath)
					}
					err = ioutil.WriteFile(fieldsFilePath, fieldsFile, 0644)
					if err != nil {
						return errors.Wrapf(err, "writing fields file failed (path: %s)", fieldsFilePath)
					}
				}
			}

			// dataStream/elasticsearch
			if len(dataStream.elasticsearch.ingestPipelines) > 0 {
				ingestPipelinesPath := filepath.Join(dataStreamPath, "elasticsearch", packages.DirIngestPipeline)
				err := os.MkdirAll(ingestPipelinesPath, 0755)
				if err != nil {
					return errors.Wrapf(err, "cannot make directory for data stream ingest pipelines: '%s'", ingestPipelinesPath)
				}

				for _, ingestPipeline := range dataStream.elasticsearch.ingestPipelines {
					ingestPipelinePath := filepath.Join(ingestPipelinesPath, ingestPipeline.targetFileName)
					log.Printf("write ingest pipeline file '%s'", ingestPipelinePath)

					err := ioutil.WriteFile(ingestPipelinePath, ingestPipeline.body, 0644)
					if err != nil {
						return errors.Wrapf(err, "writing ingest pipeline failed")
					}
				}
			}

			// dataStream/agent/stream
			if len(dataStream.agent.streams) > 0 {
				agentStreamPath := filepath.Join(dataStreamPath, "agent", "stream")
				err := os.MkdirAll(agentStreamPath, 0755)
				if err != nil {
					return errors.Wrapf(err, "cannot make directory for data stream agent stream: '%s'", agentStreamPath)
				}

				for _, agentStream := range dataStream.agent.streams {
					err := ioutil.WriteFile(path.Join(agentStreamPath, agentStream.targetFileName), agentStream.body, 0644)
					if err != nil {
						return errors.Wrapf(err, "writing agent stream file failed")
					}
				}
			}
		}

		// img
		imgDstDir := path.Join(packagePath, "img")
		for _, image := range content.images {
			log.Printf("copy image file '%s' to '%s'", image.source, imgDstDir)
			err := copyFile(image.source, imgDstDir)
			if err != nil {
				return errors.Wrapf(err, "copying file failed")
			}
		}

		// kibana
		if len(content.kibana.files) > 0 {
			kibanaPath := filepath.Join(packagePath, "kibana")

			for objectType, objects := range content.kibana.files {
				resourcePath := filepath.Join(kibanaPath, objectType)

				err := os.MkdirAll(resourcePath, 0755)
				if err != nil {
					return errors.Wrapf(err, "cannot make directory for dashboard files: '%s'", resourcePath)
				}

				for fileName, body := range objects {
					resourceFilePath := filepath.Join(resourcePath, fileName)

					log.Printf("create resource file: %s", resourceFilePath)
					err = ioutil.WriteFile(resourceFilePath, body, 0644)
					if err != nil {
						return errors.Wrapf(err, "writing resource file failed (path: %s)", resourceFilePath)
					}
				}
			}
		}

		// docs
		if len(content.docs) > 0 {
			docsPath := filepath.Join(packagePath, "docs")
			err := os.MkdirAll(docsPath, 0755)
			if err != nil {
				return errors.Wrapf(err, "cannot make directory for docs: '%s'", docsPath)
			}

			for _, doc := range content.docs {
				err = writeDoc(docsPath, doc, content)
				if err != nil {
					return errors.Wrapf(err, "cannot write docs (docsPath: %s, fileName: %s)", docsPath,
						doc.fileName)
				}
			}
		}

		// changelog
		changelog := newChangelog(manifest.Version)

		c, err := yaml.Marshal(changelog)
		if err != nil {
			return errors.Wrap(err, "marshalling changelog failed")
		}

		header := "# newer versions go on top"
		contents := strings.Replace(string(c), "entries:", header, 1) // HACK: cannot marshal sequence at root level!
		c = []byte(contents)

		changelogPath := filepath.Join(packagePath, "changelog.yml")
		if err := ioutil.WriteFile(changelogPath, c, 0644); err != nil {
			return errors.Wrap(err, "writing changelog file failed")
		}
	}
	return nil
}

func writeDoc(docsPath string, doc docContent, aPackage packageContent) error {
	log.Printf("write '%s' file\n", doc.fileName)

	docFilePath := filepath.Join(docsPath, doc.fileName)
	f, err := os.OpenFile(docFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	defer f.Close()

	if err != nil {
		return errors.Wrapf(err, "opening doc file failed (path: %s)", docFilePath)
	}
	t := template.New(doc.fileName)
	if doc.templatePath == "" {
		t = template.Must(t.Parse("TODO"))
	} else {
		t, err = t.Funcs(template.FuncMap{
			"event": func(dataStream string) (string, error) {
				return "TODO", nil
			},
			"fields": func(dataStream string) (string, error) {
				return renderExportedFields(dataStream, aPackage.dataStreams)
			},
		}).ParseFiles(doc.templatePath)
		if err != nil {
			return errors.Wrapf(err, "parsing doc template failed (path: %s)", doc.templatePath)
		}
	}
	err = t.Execute(f, nil)
	if err != nil {
		return errors.Wrapf(err, "rendering doc file failed (path: %s)", docFilePath)
	}
	return nil
}

func copyFile(src, dstDir string) error {
	i := strings.LastIndex(src, "/")
	sourceFileName := src[i:]

	return copyFileToTarget(src, dstDir, sourceFileName)
}

func copyFileToTarget(src, dstDir, targetFileName string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return errors.Wrapf(err, "opening file failed (src: %s)", src)
	}
	defer sourceFile.Close()

	dst := path.Join(dstDir, targetFileName)
	err = os.MkdirAll(dstDir, 0755)
	if err != nil {
		return errors.Wrapf(err, "cannot make directory: '%s'", dst)
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return errors.Wrapf(err, "creating target file failed (dst: %s)", dst)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, sourceFile)
	if err != nil {
		return errors.Wrapf(err, "copying file failed (src: %s, dst: %s)", src, dst)
	}
	return nil
}

func selectDocsPath(beatsDir, beatName string) string {
	if strings.HasPrefix(beatName, "x-pack/") {
		return path.Join(beatsDir, beatName[7:], "docs")
	}
	return path.Join(beatsDir, beatName, "docs")
}
