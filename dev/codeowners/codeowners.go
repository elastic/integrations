// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package codeowners

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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
		return nil, fmt.Errorf("failed to open %q: %w", codeownersPath, err)
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
		if len(fields) == 1 {
			err := codeowners.checkSingleField(fields[0])
			if err != nil {
				return nil, fmt.Errorf("invalid line %d in %q: %w", lineNumber, codeownersPath, err)
			}
			continue
		}
		path, owners := fields[0], fields[1:]

		// It is ok to overwrite because latter lines have precedence in these files.
		codeowners.owners[path] = owners
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return &codeowners, nil
}

// checkSingleField checks if a single field in a CODEOWNERS file is valid.
// We allow single fields to add files for which we don't need to have owners.
func (codeowners *githubOwners) checkSingleField(field string) error {
	switch field[0] {
	case '/':
		// Allow only rules that wouldn't remove owners for previously
		// defined rules.
		for path := range codeowners.owners {
			matches, err := filepath.Match(field, path)
			if err != nil {
				return err
			}
			if matches || strings.HasPrefix(field, path) {
				return fmt.Errorf("%q would remove owners for %q", field, path)
			}

			if strings.HasPrefix(path, field) {
				_, err := filepath.Rel(field, path)
				if err == nil {
					return fmt.Errorf("%q would remove owners for %q", field, path)
				}
			}
		}

		// Excluding other files is fine.
		return nil
	case '@':
		return fmt.Errorf("rule with owner without path: %q", field)
	default:
		return fmt.Errorf("unexpected field found: %q", field)
	}
}

func (codeowners *githubOwners) checkManifest(path string) error {
	pkgDir := filepath.Dir(path)
	owners, found := codeowners.owners["/"+pkgDir]
	if !found {
		return fmt.Errorf("there is no owner for %q in %q", pkgDir, codeowners.path)
	}

	content, err := os.ReadFile(path)
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
		return fmt.Errorf("no owner specified in %q", path)
	}

	found = false
	for _, owner := range owners {
		if owner == "@"+manifest.Owner.Github {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("owner %q defined in %q is not in %q", manifest.Owner.Github, path, codeowners.path)
	}
	return nil
}
