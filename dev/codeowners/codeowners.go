// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package codeowners

import (
	"bufio"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

const (
	codeownersPath = ".github/CODEOWNERS"
)

func Check() error {
	codeowners, err := readGithubOwners(codeownersPath)
	if err != nil {
		return err
	}

	const packagesDir = "packages"
	return filepath.WalkDir(packagesDir, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			if path != packagesDir && filepath.Dir(path) != packagesDir {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "manifest.yml" {
			return nil
		}

		return codeowners.checkManifest(path)
	})
}

type githubOwners struct {
	owners map[string][]string
	path   string
}

func readGithubOwners(codeownersPath string) (*githubOwners, error) {
	f, err := os.Open(codeownersPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %q", codeownersPath)
	}
	defer f.Close()

	codeowners := githubOwners{
		owners: make(map[string][]string),
		path:   codeownersPath,
	}

	scanner := bufio.NewScanner(f)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, errors.Errorf("invalid line %d in %q: %q", lineNumber, codeownersPath, line)
		}
		path, owners := fields[0], fields[1:]

		// It is ok to overwrite because latter lines have precedence in these files.
		codeowners.owners[path] = owners
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrapf(err, "scanner error")
	}

	return &codeowners, nil
}

func (codeowners *githubOwners) checkManifest(path string) error {
	pkgDir := filepath.Dir(path)
	owners, found := codeowners.owners["/"+pkgDir]
	if !found {
		return errors.Errorf("there is no owner for %q in %q", pkgDir, codeowners.path)
	}

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	var manifest struct {
		Owner struct {
			Github string `yaml:"github"`
		} `yaml:"owner"`
	}
	err = yaml.Unmarshal(content, &manifest)
	if err != nil {
		return err
	}

	if manifest.Owner.Github == "" {
		return errors.Errorf("no owner specified in %q", path)
	}

	found = false
	for _, owner := range owners {
		if owner == "@"+manifest.Owner.Github {
			found = true
			break
		}
	}
	if !found {
		return errors.Errorf("owner %q defined in %q is not in %q", manifest.Owner.Github, path, codeowners.path)
	}
	return nil
}
