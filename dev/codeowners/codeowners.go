// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package codeowners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/elastic/integrations/dev/citools"
)

const DefaultCodeownersPath = ".github/CODEOWNERS"

func Check() error {
	owners, err := LoadOwners(DefaultCodeownersPath)
	if err != nil {
		return fmt.Errorf("error reading %s: %w", DefaultCodeownersPath, err)
	}
	const packagesDir = "packages"
	if err := validatePackages(owners, packagesDir); err != nil {
		return fmt.Errorf("error validating packages in directory '%s': %w", packagesDir, err)
	}

	return nil
}

// PackageOwners returns the owning team(s) for packageName (and, if
// dataStream is set, the more specific data-stream-level owner when one is
// defined) from the CODEOWNERS file at codeownersPath.
func PackageOwners(packageName, dataStream, codeownersPath string) ([]string, error) {
	owners, err := LoadOwners(codeownersPath)
	if err != nil {
		return nil, err
	}
	return owners.PackageOwners(packageName, dataStream)
}

// Owners is a CODEOWNERS file parsed once and kept in memory, so callers
// that need repeated lookups (e.g. across many packages) don't re-read and
// re-parse the file on every call.
type Owners struct {
	owners map[string][]string
	path   string
}

// LoadOwners parses the CODEOWNERS file at codeownersPath.
func LoadOwners(codeownersPath string) (*Owners, error) {
	f, err := os.Open(codeownersPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %q: %w", codeownersPath, err)
	}
	defer f.Close()

	owners := &Owners{
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
			if err := owners.checkSingleField(fields[0]); err != nil {
				return nil, fmt.Errorf("invalid line %d in %q: %w", lineNumber, codeownersPath, err)
			}
			continue
		}
		path, teams := fields[0], fields[1:]

		// remove trailing slash from path
		path = strings.TrimSuffix(path, "/")
		owners.owners[path] = teams
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return owners, nil
}

// PackageOwners returns the owning team(s) for packageName (and, if
// dataStream is set, the more specific data-stream-level owner when one is
// defined), from the CODEOWNERS file this Owners was loaded from.
func (o *Owners) PackageOwners(packageName, dataStream string) ([]string, error) {
	// look for the path of the package taking into account nested directories
	packagePath := ""
	for path := range o.owners {
		if !strings.HasSuffix(path, "/"+packageName) {
			continue
		}
		// Verify the path is a valid package path: /packages/<name> or /packages/<category>/<name>.
		// This prevents matching data stream paths or other sub-paths that happen to end with the package name.
		if path == "/packages/"+packageName {
			packagePath = path
			break
		}
		// Check for a nested package path: /packages/<category>/<name>, where <category> is a single path segment.
		prefix := strings.TrimSuffix(path, "/"+packageName)
		if strings.HasPrefix(prefix, "/packages/") && !strings.Contains(prefix[len("/packages/"):], "/") {
			packagePath = path
			break
		}
	}
	packageTeams, found := o.owners[packagePath]
	if !found {
		return nil, fmt.Errorf("no owner found for package %s", packageName)
	}

	if dataStream == "" {
		return packageTeams, nil
	}

	dataStreamPath := fmt.Sprintf("/packages/%s/data_stream/%s", packageName, dataStream)
	dataStreamTeams, found := o.owners[dataStreamPath]
	if !found {
		return packageTeams, nil
	}
	return dataStreamTeams, nil
}

// validatePackages checks if all packages in packagesDir have a manifest.yml file
// with the correct owner as captured in codeowners. Also, for packages that share ownership across
// data_streams, it checks that all data_streams are explicitly owned by a single owner. Such ownership
// sharing packages are identified by having at least one data_stream with explicit ownership in codeowners.
func validatePackages(owners *Owners, packagesDir string) error {
	paths, err := citools.ListPackages(packagesDir)
	if err != nil {
		return fmt.Errorf("error listing packages in %s: %w", packagesDir, err)
	}
	for _, path := range paths {
		err = owners.checkManifest(filepath.Join(path, citools.ManifestFileName))
		if err != nil {
			return fmt.Errorf("error checking manifest '%s': %w", path, err)
		}
		err = owners.checkDataStreams(path)
		if err != nil {
			return fmt.Errorf("error checking data streams from '%s': %w", path, err)
		}
	}

	if len(paths) == 0 {
		if len(owners.owners) == 0 {
			return nil
		}
		return fmt.Errorf("no packages found in %q", packagesDir)
	}

	return nil
}

// checkSingleField checks if a single field in a CODEOWNERS file is valid.
// We allow single fields to add files for which we don't need to have owners.
func (o *Owners) checkSingleField(field string) error {
	switch field[0] {
	case '/':
		// Allow only rules that wouldn't remove owners for previously
		// defined rules.
		for path := range o.owners {
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

func (o *Owners) checkManifest(path string) error {
	owners, found := o.findOwnerForFile(path)
	if !found {
		return fmt.Errorf("there is no owner for %q in %q", filepath.Dir(path), o.path)
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
		return fmt.Errorf("owner %q defined in %q is not in %q", manifest.Owner.Github, path, o.path)
	}
	return nil
}

func (o *Owners) findOwnerForFile(path string) ([]string, bool) {
	// Usually paths are related to the root of the repository. Examples:
	// - "packages/package-name/manifest.yml"
	// - "packages/technology/package-name/manifest.yml"
	// Just in case, if an absolute path is provided, we remove the leading separator.
	if filepath.IsAbs(path) {
		path = strings.TrimPrefix(path, string(filepath.Separator))
	}
	ownerDir := filepath.Dir(path)
	for {
		owners, found := o.owners["/"+filepath.ToSlash(ownerDir)]
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

func (o *Owners) checkDataStreams(packagePath string) error {
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
		dataStreamOwners, found := o.owners["/"+filepath.ToSlash(dataStreamDir)]
		if !found {
			dataStreamsWithoutOwner = append(dataStreamsWithoutOwner, dataStreamDir)
			continue
		}
		if len(dataStreamOwners) > 1 {
			return fmt.Errorf("data stream \"%s\" of package \"%s\" has more than one owner [%s]", dataStreamDir,
				packagePath, strings.Join(dataStreamOwners, ", "))
		}
	}

	if notFound := len(dataStreamsWithoutOwner); notFound > 0 && notFound != totalDataStreams {
		return fmt.Errorf("package \"%s\" shares ownership across data streams but these ones [%s] lack owners", packagePath,
			strings.Join(dataStreamsWithoutOwner, ", "))
	}

	return nil
}
