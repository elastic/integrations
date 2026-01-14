// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package codeowners

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultCodeownersPath = ".github/CODEOWNERS"

func Check() error {
	codeowners, err := readGithubOwners(DefaultCodeownersPath)
	if err != nil {
		return err
	}
	const packagesDir = "packages"
	if err := validatePackages(codeowners, packagesDir); err != nil {
		return err
	}

	return nil
}

func PackageOwners(packageName, dataStream, codeownersPath string) ([]string, error) {
	owners, err := readGithubOwners(codeownersPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CODEOWNERS file: %w", err)
	}
	packagePath := fmt.Sprintf("/packages/%s", packageName)
	packageTeams, found := owners.owners[packagePath]
	if !found {
		return nil, fmt.Errorf("no owner found for package %s", packageName)
	}

	if dataStream == "" {
		return packageTeams, nil
	}

	dataStreamPath := fmt.Sprintf("/packages/%s/data_stream/%s", packageName, dataStream)
	dataStreamTeams, found := owners.owners[dataStreamPath]
	if !found {
		return packageTeams, nil
	}
	return dataStreamTeams, nil
}

type githubOwners struct {
	owners map[string][]string
	path   string
}

// validatePackages checks if all packages in packagesDir have a manifest.yml file
// with the correct owner as captured in codeowners. Also, for packages that share ownership across
// data_streams, it checks that all data_streams are explicitly owned by a single owner. Such ownership
// sharing packages are identified by having at least one data_stream with explicit ownership in codeowners.
func validatePackages(codeowners *githubOwners, packagesDir string) error {
	foundPackages := false
	err := filepath.WalkDir(packagesDir, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			return nil
		}

		packageManifestPath := filepath.Join(path, "manifest.yml")
		_, err = os.Stat(packageManifestPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}

		err = codeowners.checkManifest(packageManifestPath)
		if err != nil {
			return err
		}

		err = codeowners.checkDataStreams(path)
		if err != nil {
			return err
		}

		foundPackages = true

		// No need to look deeper, we already found a package.
		return fs.SkipDir
	})
	if err != nil {
		return err
	}

	if !foundPackages {
		if len(codeowners.owners) == 0 {
			return nil
		}
		return fmt.Errorf("no packages found in %q", packagesDir)
	}

	return nil
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
	owners, found := codeowners.findOwnerForFile(path)
	if !found {
		return fmt.Errorf("there is no owner for %q in %q", filepath.Dir(path), codeowners.path)
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

func (codeowners *githubOwners) findOwnerForFile(path string) ([]string, bool) {
	ownerDir := filepath.Dir(path)
	for {
		owners, found := codeowners.owners["/"+filepath.ToSlash(ownerDir)]
		if found {
			return owners, found
		}

		ownerDir = filepath.Dir(ownerDir)
		if ownerDir == "." {
			break
		}
	}

	return nil, false
}

func (codeowners *githubOwners) checkDataStreams(packagePath string) error {
	packageDataStreamsPath := filepath.Join(packagePath, "data_stream")
	if _, err := os.Stat(packageDataStreamsPath); os.IsNotExist(err) {
		// package doesn't have data_streams
		return nil
	}

	dataStreamDirEntries, err := os.ReadDir(packageDataStreamsPath)
	if err != nil {
		return err
	}

	totalDataStreams := len(dataStreamDirEntries)
	if totalDataStreams == 0 {
		// package doesn't have data_streams
		return nil
	}

	var dataStreamsWithoutOwner []string
	for _, dataStreamDirEntry := range dataStreamDirEntries {
		dataStreamName := dataStreamDirEntry.Name()
		dataStreamDir := filepath.Join(packageDataStreamsPath, dataStreamName)
		dataStreamOwners, found := codeowners.owners["/"+filepath.ToSlash(dataStreamDir)]
		if !found {
			dataStreamsWithoutOwner = append(dataStreamsWithoutOwner, dataStreamDir)
			continue
		}
		if len(dataStreamOwners) > 1 {
			return fmt.Errorf("data stream \"%s\" of package \"%s\" has more than one owners [%s]", dataStreamDir,
				packagePath, strings.Join(dataStreamOwners, ", "))
		}
	}

	if notFound := len(dataStreamsWithoutOwner); notFound > 0 && notFound != totalDataStreams {
		return fmt.Errorf("package \"%s\" shares ownership across data streams but these ones [%s] lack owners", packagePath,
			strings.Join(dataStreamsWithoutOwner, ", "))
	}

	return nil
}
