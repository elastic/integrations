// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const githubTagsURL = "https://api.github.com/repos/%s/tags?per_page=100"

type versionConfig struct {
	Version string `yaml:"version"`
}

type config struct {
	Osquery versionConfig `yaml:"osquery"`
	Beats   versionConfig `yaml:"beats"`
}

type packageBuildYAML struct {
	Dependencies struct {
		ECS struct {
			Reference string `yaml:"reference"`
		} `yaml:"ecs"`
	} `yaml:"dependencies"`
}

type semver struct {
	Major int
	Minor int
	Patch int
}

type releaseTag struct {
	Sem semver
}

func main() {
	cfgPath := flag.String("config", "config.yml", "Path to YAML config file.")
	skipPackageCheck := flag.Bool("skip-package-check", false, "Skip elastic-package check (dev only).")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	outputRoot := findRepoRoot()
	if outputRoot == "." {
		log.Fatal("failed to detect integrations repo root")
	}

	osqueryVersion, err := resolveLatestPatch("osquery/osquery", cfg.Osquery.Version)
	if err != nil {
		log.Fatalf("resolve osquery version: %v", err)
	}
	beatsTag, err := resolveLatestPatch("elastic/beats", cfg.Beats.Version)
	if err != nil {
		log.Fatalf("resolve beats version: %v", err)
	}
	beatsRef, err := resolveBeatsSpecsRef(cfg.Beats.Version, beatsTag)
	if err != nil {
		log.Fatalf("resolve beats specs ref: %v", err)
	}
	ecsVersionSpec, err := loadECSVersionSpecFromBuildYAML(outputRoot)
	if err != nil {
		log.Fatalf("load ecs version from build.yml: %v", err)
	}
	ecsVersion, err := resolveLatestPatch("elastic/ecs", ecsVersionSpec)
	if err != nil {
		log.Fatalf("resolve ecs version: %v", err)
	}

	log.Printf("Resolved versions: osquery=%s beats=%s ecs=%s", osqueryVersion, beatsRef, ecsVersion)
	if err := generateArtifacts(outputRoot, osqueryVersion, ecsVersion, beatsRef, !*skipPackageCheck); err != nil {
		log.Fatalf("generate artifacts: %v", err)
	}
	log.Println("Done.")
}

func loadConfig(path string) (config, error) {
	var cfg config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if strings.TrimSpace(cfg.Osquery.Version) == "" {
		return cfg, fmt.Errorf("osquery.version is required")
	}
	if strings.TrimSpace(cfg.Beats.Version) == "" {
		return cfg, fmt.Errorf("beats.version is required")
	}
	return cfg, nil
}

func loadECSVersionSpecFromBuildYAML(repoRoot string) (string, error) {
	path := filepath.Join(repoRoot, "packages", "osquery_manager", "_dev", "build", "build.yml")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	var doc packageBuildYAML
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	ref := strings.TrimSpace(doc.Dependencies.ECS.Reference)
	if ref == "" {
		return "", fmt.Errorf("%s: dependencies.ecs.reference is required", path)
	}
	ref = strings.TrimPrefix(ref, "git@")
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("%s: dependencies.ecs.reference must be a git ref (e.g. git@v9.3.0)", path)
	}
	return ref, nil
}

func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "packages", "osquery_manager", "manifest.yml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

func resolveLatestPatch(repo string, versionSpec string) (string, error) {
	versionSpec = strings.TrimSpace(versionSpec)
	tags, err := fetchReleaseTags(repo)
	if err != nil {
		return "", err
	}
	if len(tags) == 0 {
		return "", fmt.Errorf("no semver tags found in %s", repo)
	}
	if sv, ok := parseSemver(versionSpec); ok {
		return sv.String(), nil
	}

	prefixParts := strings.Split(versionSpec, ".")
	if len(prefixParts) > 2 {
		return "", fmt.Errorf("unsupported version format %q", versionSpec)
	}

	wanted := make([]int, 0, len(prefixParts))
	for _, p := range prefixParts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return "", fmt.Errorf("invalid version part %q", p)
		}
		wanted = append(wanted, v)
	}

	for _, tag := range tags {
		if matchesPrefix(tag.Sem, wanted) {
			return tag.Sem.String(), nil
		}
	}
	return "", fmt.Errorf("no tags in %s match version prefix %q", repo, versionSpec)
}

func fetchReleaseTags(repo string) ([]releaseTag, error) {
	body, err := downloadBytes(fmt.Sprintf(githubTagsURL, repo))
	if err != nil {
		return nil, err
	}
	var raw []map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	out := make([]releaseTag, 0, len(raw))
	for _, entry := range raw {
		name, _ := entry["name"].(string)
		sv, ok := parseSemver(name)
		if !ok {
			continue
		}
		key := sv.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, releaseTag{Sem: sv})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Sem.GreaterThan(out[j].Sem)
	})
	return out, nil
}

func parseSemver(v string) (semver, bool) {
	re := regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)$`)
	m := re.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return semver{}, false
	}
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return semver{}, false
	}
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return semver{}, false
	}
	patch, err := strconv.Atoi(m[3])
	if err != nil {
		return semver{}, false
	}
	return semver{Major: major, Minor: minor, Patch: patch}, true
}

func matchesPrefix(v semver, prefix []int) bool {
	switch len(prefix) {
	case 1:
		return v.Major == prefix[0]
	case 2:
		return v.Major == prefix[0] && v.Minor == prefix[1]
	default:
		return false
	}
}

func (s semver) GreaterThan(other semver) bool {
	if s.Major != other.Major {
		return s.Major > other.Major
	}
	if s.Minor != other.Minor {
		return s.Minor > other.Minor
	}
	return s.Patch > other.Patch
}

func (s semver) String() string {
	return fmt.Sprintf("%d.%d.%d", s.Major, s.Minor, s.Patch)
}

func resolveBeatsSpecsRef(versionSpec, resolvedPatch string) (string, error) {
	candidates := make([]string, 0, 4)
	if resolvedPatch != "" {
		candidates = append(candidates, "v"+resolvedPatch)
	}

	versionSpec = strings.TrimSpace(versionSpec)
	parts := strings.Split(versionSpec, ".")
	if len(parts) >= 2 {
		majorMinor := strings.TrimSpace(parts[0]) + "." + strings.TrimSpace(parts[1])
		if majorMinor != "." {
			candidates = append(candidates, majorMinor)
		}
	}
	candidates = append(candidates, "main")

	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		ok, err := refHasBeatsSpecs(candidate)
		if err != nil {
			return "", err
		}
		if ok {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no usable beats specs ref found from candidates %v", candidates)
}

func refHasBeatsSpecs(ref string) (bool, error) {
	resp, err := http.Get(fmt.Sprintf(beatsSpecsAPI, ref))
	if err != nil {
		return false, err
	}
	defer closeBody(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return false, fmt.Errorf("beats specs probe failed for ref %s: status=%d body=%q", ref, resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

func downloadBytes(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer closeBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		log.Printf("warning: close response body: %v", err)
	}
}
