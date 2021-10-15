// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bufio"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

const (
	tutorialsPath   = "src/plugins/home/server/tutorials"
	kibanaLogosPath = "src/plugins/home/public/assets/logos"
)

var (
	errIconNotFound = errors.New("icon not found")
	iconRe          = regexp.MustCompile(`euiIconType: '[^']+'`)

	aliasedModuleNames = map[string]string{
		"redisenterprise": "redis",
		"php_fpm":         "php",
		"postgresql":      "postgres",
		"appsearch":       "app_search",
		"googlecloud":     "gcp",
	}
)

type iconRepository struct {
	icons map[string]string
}

func newIconRepository(euiDir, kibanaDir string) (*iconRepository, error) {
	icons, err := populateIconRepository(euiDir, kibanaDir)
	if err != nil {
		return nil, errors.Wrapf(err, "populating icon repository failed")
	}
	return &iconRepository{icons: icons}, nil
}

func populateIconRepository(euiDir, kibanaDir string) (map[string]string, error) {
	log.Println("Populate icon registry")

	kibanaIconRefs, err := retrieveIconPathFromTutorials(kibanaDir)
	if err != nil {
		return nil, errors.Wrapf(err, "retrieving icon references failed")
	}

	euiRefs, err := retrieveIconPathFromEUI(euiDir)
	if err != nil {
		return nil, errors.Wrapf(err, "collecting icon data failed")
	}

	refs := map[string]string{}
	for k, v := range kibanaIconRefs {
		refs[k] = v
	}
	for k, v := range euiRefs {
		refs[k] = v
	}
	return refs, nil
}

func retrieveIconPathFromTutorials(kibanaDir string) (map[string]string, error) {
	refs := map[string]string{}

	tutorialsPath := filepath.Join(kibanaDir, tutorialsPath)
	tutorialFilePaths, err := filepath.Glob(filepath.Join(tutorialsPath, "*_*", "index.ts"))
	if err != nil {
		return nil, errors.Wrapf(err, "globbing tutorial files failed (path: %s)", tutorialsPath)
	}

	for _, tutorialFilePath := range tutorialFilePaths {
		log.Printf("Scan tutorial file: %s", tutorialFilePath)

		tutorialFile, err := ioutil.ReadFile(tutorialFilePath)
		if err != nil {
			return nil, errors.Wrapf(err, "reading tutorial file failed (path: %s)", tutorialFile)
		}

		m := iconRe.Find(tutorialFile)
		if m == nil {
			log.Printf("\t%s: icon not found", tutorialFilePath)
			continue
		}

		s := strings.Split(string(m), `'`)
		val := s[1]

		// Extracting module name from tutorials path
		// e.g. ./src/plugins/home/server/tutorials//php_fpm_metrics/index.ts -> php_fpm
		moduleName := filepath.Base(filepath.Dir(tutorialFilePath))
		moduleName = moduleName[:strings.LastIndex(moduleName, "_")]

		if filepath.IsAbs(val) {
			iconFileName := filepath.Base(val)
			val = path.Join(kibanaDir, kibanaLogosPath, iconFileName)
			refs[moduleName] = val
		}
	}
	return refs, nil
}

func retrieveIconPathFromEUI(euiDir string) (map[string]string, error) {
	refs := map[string]string{}

	iconMapPath := filepath.Join(euiDir, "src/components/icon/icon.tsx")
	iconMapFile, err := os.Open(iconMapPath)
	if err != nil {
		return nil, errors.Wrapf(err, "opening icon map file failed (path: %s)", iconMapPath)
	}

	scanner := bufio.NewScanner(iconMapFile)
	var mapFound bool
	for scanner.Scan() {
		line := scanner.Text()
		if mapFound {
			line = strings.TrimLeft(line, " ")
			if strings.HasPrefix(line, "logo") {
				s := strings.Split(line, `'`)
				fileName := s[1]
				fileNameWithExt := fileName + ".svg"
				filePath := filepath.Join(euiDir, "src/components/icon/assets", fileNameWithExt)
				moduleName := fileName[strings.Index(fileName, "_")+1:]
				refs[moduleName] = filePath
			}
		} else if strings.HasPrefix(line, `const typeToPathMap = {`) {
			mapFound = true
		}
	}
	return refs, nil
}

func (ir *iconRepository) iconForModule(moduleName string) (imageContent, error) {
	source, ok := ir.icons[aliasModuleName(moduleName)]
	if !ok {
		return imageContent{}, errIconNotFound
	}
	return imageContent{source: source}, nil
}

func aliasModuleName(moduleName string) string {
	if v, ok := aliasedModuleNames[moduleName]; ok {
		return v
	}
	return moduleName
}

func createIcons(iconRepository *iconRepository, moduleName string) (imageContentArray, error) {
	anIcon, err := iconRepository.iconForModule(moduleName)
	if err == errIconNotFound {
		log.Printf("\t%s: icon not found", moduleName)
		return []imageContent{}, nil
	}
	if err != nil {
		return nil, errors.Wrapf(err, "fetching icon for module failed (moduleName: %s)", moduleName)
	}
	return []imageContent{anIcon}, nil
}
