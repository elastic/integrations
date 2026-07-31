// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package codeowners

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/elastic/integrations/dev/citools"
)

const DefaultCodeownersPath = ".github/CODEOWNERS"

func Check() error {
	codeowners, err := readGithubOwners(DefaultCodeownersPath)
	if err != nil {
		return fmt.Errorf("error reading %s: %w", DefaultCodeownersPath, err)
	}
	const packagesDir = "packages"
	if err := validatePackages(codeowners, packagesDir); err != nil {
		return fmt.Errorf("error validating packages in directory '%s': %w", packagesDir, err)
	}

	return nil
}

func PackageOwners(packageName, dataStream, codeownersPath string) ([]string, error) {
	owners, err := readGithubOwners(codeownersPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CODEOWNERS file: %w", err)
	}
	// look for the path of the package taking into account nested directories
	packagePath := ""
	for path := range owners.owners {
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

// Owners holds a parsed CODEOWNERS file for repeated lookups without re-reading disk.
// Obtain one via LoadOwners; use PackageOwnersByPath to look up a package by its
// filesystem path rather than its folder basename.
type Owners struct {
	inner *githubOwners
}

// LoadOwners parses the CODEOWNERS file at codeownersPath once. Use the returned
// *Owners for repeated lookups across many packages instead of calling
// PackageOwners (which re-reads the file on every call).
func LoadOwners(codeownersPath string) (*Owners, error) {
	inner, err := readGithubOwners(codeownersPath)
	if err != nil {
		return nil, err
	}
	return &Owners{inner: inner}, nil
}

// ParseOwners parses CODEOWNERS content from a string, applying the same
// single-field exclusion-rule validation that readGithubOwners does when
// reading from disk. A file that passes mage check never triggers this error.
func ParseOwners(content string) (*Owners, error) {
	o, err := scanGithubOwners(strings.NewReader(content), "<in-memory>")
	if err != nil {
		return nil, err
	}
	return &Owners{inner: o}, nil
}

// Resolve returns the owners that apply to p, walking up parent directories
// until an explicit CODEOWNERS entry is found. p must be a CODEOWNERS-style
// slash-prefixed path (e.g. "/packages/aws/data_stream/cloudtrail"). Returns
// (nil, false) when no entry exists for p or any of its ancestors.
func (o *Owners) Resolve(p string) ([]string, bool) {
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		p = "/"
	}
	for {
		if owners, ok := o.inner.owners[p]; ok {
			return owners, true
		}
		if p == "/" || p == "." {
			return nil, false
		}
		p = path.Dir(p)
	}
}

// EntriesUnder returns the full CODEOWNERS paths of every explicit entry
// nested under prefix (e.g. "/packages/aws" returns
// "/packages/aws/data_stream/cloudtrail" and "/packages/aws/kibana", but not
// "/packages/aws" itself or the unrelated "/packages/awsome"). Order is
// unspecified.
func (o *Owners) EntriesUnder(prefix string) []string {
	prefix = strings.TrimSuffix(prefix, "/") + "/"
	var paths []string
	for p := range o.inner.owners {
		if strings.HasPrefix(p, prefix) {
			paths = append(paths, p)
		}
	}
	return paths
}

// ExplicitEntry returns the owners explicitly defined for exactly this
// CODEOWNERS path — no walk-up/fallback resolution. Returns (nil, false) if
// no explicit entry exists for this exact path.
func (o *Owners) ExplicitEntry(p string) ([]string, bool) {
	p = strings.TrimSuffix(p, "/")
	owners, ok := o.inner.owners[p]
	return owners, ok
}

// PackageOwnersByPath returns the owning team(s) for the package at pkgPath
// (relative to the repo root, e.g. "packages/observability/nginx") and, when
// dataStream is set, the more-specific data-stream-level owner if one is defined.
//
// Prefer this over PackageOwners when the full package path is available:
// it handles arbitrary directory nesting by walking up the tree and avoids
// the folder-basename ambiguity in PackageOwners. See
// https://github.com/elastic/elastic-package/issues/3586.
func (o *Owners) PackageOwnersByPath(pkgPath, dataStream string) ([]string, error) {
	teams, found := o.inner.findOwnerForFile(filepath.Join(pkgPath, citools.ManifestFileName))
	if !found {
		return nil, fmt.Errorf("no owner found for package path %q", pkgPath)
	}
	if dataStream == "" {
		return teams, nil
	}
	dataStreamDir := filepath.Join(pkgPath, "data_stream", dataStream)
	dataStreamTeams, found := o.inner.owners["/"+filepath.ToSlash(dataStreamDir)]
	if !found {
		return teams, nil
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
	paths, err := citools.ListPackages(packagesDir)
	if err != nil {
		return fmt.Errorf("error listing packages in %s: %w", packagesDir, err)
	}
	for _, path := range paths {
		err = codeowners.checkManifest(filepath.Join(path, citools.ManifestFileName))
		if err != nil {
			return fmt.Errorf("error checking manifest '%s': %w", path, err)
		}
		err = codeowners.checkDataStreams(path)
		if err != nil {
			return fmt.Errorf("error checking data streams from '%s': %w", path, err)
		}
	}

	if len(paths) == 0 {
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
	return scanGithubOwners(f, codeownersPath)
}

func scanGithubOwners(r io.Reader, sourcePath string) (*githubOwners, error) {
	codeowners := githubOwners{
		owners: make(map[string][]string),
		path:   sourcePath,
	}

	scanner := bufio.NewScanner(r)
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
				return nil, fmt.Errorf("invalid line %d in %q: %w", lineNumber, sourcePath, err)
			}
			continue
		}
		ownerPath, owners := fields[0], fields[1:]

		// remove trailing slash from path
		ownerPath = strings.TrimSuffix(ownerPath, "/")
		codeowners.owners[ownerPath] = owners
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
	// Usually paths are related to the root of the repository. Examples:
	// - "packages/package-name/manifest.yml"
	// - "packages/technology/package-name/manifest.yml"
	// Just in case, if an absolute path is provided, we remove the leading separator.
	if filepath.IsAbs(path) {
		path = strings.TrimPrefix(path, string(filepath.Separator))
	}
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
