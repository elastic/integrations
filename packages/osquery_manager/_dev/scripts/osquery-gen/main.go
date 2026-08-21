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

const (
	githubTagsURL          = "https://api.github.com/repos/%s/tags?per_page=100"
	githubLatestReleaseURL = "https://api.github.com/repos/%s/releases/latest"
)

type versionConfig struct {
	Version string `yaml:"version"`
}

type beatsConfig struct {
	// Tag is an exact git ref (e.g. v9.4.2). Takes precedence over Branch and Version.
	Tag string `yaml:"tag"`
	// Branch is a git branch name (e.g. main). Used when Tag is empty.
	Branch string `yaml:"branch"`
	// Version is a semver or major.minor prefix; used to resolve a tag when Tag and Branch are empty.
	Version string `yaml:"version"`
}

type ecsConfig struct {
	KeepFields []string `yaml:"keep_fields"`
}

type config struct {
	Osquery versionConfig `yaml:"osquery"`
	Beats   beatsConfig   `yaml:"beats"`
	ECS     ecsConfig     `yaml:"ecs"`
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
	osqueryVersionOverride := flag.String("osquery-version", "", "Override osquery.version; use latest for the latest stable release.")
	beatsPath := flag.String("beats-path", "", "Read extension specs from a local Beats checkout or specs directory.")
	updateConfig := flag.Bool("update-config", false, "Write the resolved osquery version back to the config file after successful generation.")
	updatePackage := flag.Bool("update-package", false, "Bump osquery_manager and add its changelog entry when the osquery version changes.")
	changelogLink := flag.String("changelog-link", "", "Issue or pull request URL for a generated package changelog entry.")
	kibanaVersion := flag.String("kibana-version", "", "Kibana version constraint for releases containing the upgraded osquery runtime.")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	outputRoot := findRepoRoot()
	if outputRoot == "." {
		log.Fatal("failed to detect integrations repo root")
	}

	osqueryVersionSpec := cfg.Osquery.Version
	if strings.TrimSpace(*osqueryVersionOverride) != "" {
		osqueryVersionSpec = *osqueryVersionOverride
	}
	osqueryVersion, err := resolveLatestPatch("osquery/osquery", osqueryVersionSpec)
	if err != nil {
		log.Fatalf("resolve osquery version: %v", err)
	}
	beatsRef := "local"
	if strings.TrimSpace(*beatsPath) == "" {
		beatsRef, err = resolveBeatsGitRef(cfg.Beats)
		if err != nil {
			log.Fatalf("resolve beats git ref: %v", err)
		}
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
	if *updatePackage && osqueryVersion != strings.TrimSpace(cfg.Osquery.Version) {
		if err := updatePackageMetadata(outputRoot, osqueryVersion, *changelogLink, *kibanaVersion); err != nil {
			log.Fatalf("update package metadata: %v", err)
		}
	}
	if err := generateArtifacts(outputRoot, osqueryVersion, ecsVersion, beatsRef, *beatsPath, cfg.ECS.KeepFields, !*skipPackageCheck); err != nil {
		log.Fatalf("generate artifacts: %v", err)
	}
	if *updateConfig {
		if err := updateConfigOsqueryVersion(*cfgPath, osqueryVersion); err != nil {
			log.Fatalf("update config: %v", err)
		}
	}
	log.Println("Done.")
}

func updatePackageMetadata(repoRoot, osqueryVersion, changelogLink, kibanaVersion string) error {
	manifestPath := filepath.Join(repoRoot, "packages", "osquery_manager", "manifest.yml")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	versionRE := regexp.MustCompile(`(?m)^version:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\s*$`)
	match := versionRE.FindSubmatch(manifest)
	if match == nil {
		return fmt.Errorf("package version not found in %s", manifestPath)
	}
	kibanaVersion = strings.TrimSpace(kibanaVersion)
	if kibanaVersion == "" {
		return errors.New("KIBANA_VERSION is required to identify stack releases containing the upgraded osquery runtime")
	}
	kibanaVersionRE := regexp.MustCompile(`(?m)^(  kibana:\s*\n    version:)\s*"[^"]+"\s*$`)
	if !kibanaVersionRE.Match(manifest) {
		return fmt.Errorf("Kibana version condition not found in %s", manifestPath)
	}
	manifest = kibanaVersionRE.ReplaceAll(manifest, []byte(`${1} "`+kibanaVersion+`"`))

	changelogPath := filepath.Join(repoRoot, "packages", "osquery_manager", "changelog.yml")
	changelog, err := os.ReadFile(changelogPath)
	if err != nil {
		return err
	}
	header := "# newer versions go on top\n"
	if !strings.HasPrefix(string(changelog), header) {
		return fmt.Errorf("unexpected changelog header in %s", changelogPath)
	}
	description := "Upgrade osquery schema artifacts to version " + osqueryVersion
	if strings.Contains(string(changelog), "description: "+description) {
		topVersion := regexp.MustCompile(`(?m)^- version: "([0-9]+\.[0-9]+\.[0-9]+)"$`).FindSubmatch(changelog)
		if topVersion == nil {
			return fmt.Errorf("top package version not found in %s", changelogPath)
		}
		manifest = versionRE.ReplaceAll(manifest, []byte("version: "+string(topVersion[1])))
		return os.WriteFile(manifestPath, manifest, 0o644)
	}
	if !regexp.MustCompile(`^https://github\.com/[^/]+/[^/]+/(?:issues|pull)/[1-9][0-9]*$`).MatchString(strings.TrimSpace(changelogLink)) {
		return errors.New("CHANGELOG_LINK must be a GitHub issue or pull request URL with a positive number")
	}
	major, _ := strconv.Atoi(string(match[1]))
	minor, _ := strconv.Atoi(string(match[2]))
	nextVersion := fmt.Sprintf("%d.%d.0", major, minor+1)
	entry := fmt.Sprintf("- version: %q\n  changes:\n    - description: Upgrade osquery schema artifacts to version %s; require Kibana %s so the upgraded runtime is available\n      type: enhancement\n      link: %s\n", nextVersion, osqueryVersion, kibanaVersion, strings.TrimSpace(changelogLink))
	updated := header + entry + strings.TrimPrefix(string(changelog), header)
	if err := os.WriteFile(changelogPath, []byte(updated), 0o644); err != nil {
		return err
	}
	manifest = versionRE.ReplaceAll(manifest, []byte("version: "+nextVersion))
	return os.WriteFile(manifestPath, manifest, 0o644)
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
	if strings.TrimSpace(cfg.Beats.Tag) == "" && strings.TrimSpace(cfg.Beats.Branch) == "" && strings.TrimSpace(cfg.Beats.Version) == "" {
		return cfg, fmt.Errorf("beats: at least one of tag, branch, or version is required")
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
	if strings.EqualFold(versionSpec, "latest") {
		return resolveLatestRelease(repo)
	}
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

func resolveLatestRelease(repo string) (string, error) {
	body, err := downloadBytes(fmt.Sprintf(githubLatestReleaseURL, repo))
	if err != nil {
		return "", err
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return "", err
	}
	version, ok := parseSemver(release.TagName)
	if !ok {
		return "", fmt.Errorf("latest release in %s has invalid tag %q", repo, release.TagName)
	}
	return version.String(), nil
}

func updateConfigOsqueryVersion(path, version string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.SplitAfter(string(b), "\n")
	inOsquery := false
	updated := false
	versionLine := regexp.MustCompile(`^(\s+version:\s*)["']?[^"'\s]+["']?(\s*(?:#.*)?(?:\n)?)$`)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inOsquery {
			inOsquery = trimmed == "osquery:"
			continue
		}
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			break
		}
		if versionLine.MatchString(line) {
			lines[i] = versionLine.ReplaceAllString(line, `${1}"`+version+`"${2}`)
			updated = true
			break
		}
	}
	if !updated {
		return fmt.Errorf("osquery.version not found in %s", path)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "")), 0o644)
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

// resolveBeatsGitRef picks the elastic/beats ref for extension specs: tag > branch > semver version resolution.
func resolveBeatsGitRef(cfg beatsConfig) (string, error) {
	if ref := strings.TrimSpace(cfg.Tag); ref != "" {
		ok, err := refHasBeatsSpecs(ref)
		if err != nil {
			return "", fmt.Errorf("beats tag %q: %w", ref, err)
		}
		if !ok {
			return "", fmt.Errorf("beats tag %q: no osquery extension specs at that ref", ref)
		}
		return ref, nil
	}
	if ref := strings.TrimSpace(cfg.Branch); ref != "" {
		ok, err := refHasBeatsSpecs(ref)
		if err != nil {
			return "", fmt.Errorf("beats branch %q: %w", ref, err)
		}
		if !ok {
			return "", fmt.Errorf("beats branch %q: no osquery extension specs at that ref", ref)
		}
		return ref, nil
	}
	versionSpec := strings.TrimSpace(cfg.Version)
	if versionSpec == "" {
		return "", fmt.Errorf("beats version is required when tag and branch are empty")
	}
	beatsTag, err := resolveLatestPatch("elastic/beats", versionSpec)
	if err != nil {
		return "", err
	}
	return resolveBeatsSpecsRef(versionSpec, beatsTag)
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
	resp, err := httpGet(fmt.Sprintf(beatsSpecsAPI, ref))
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
	resp, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	defer closeBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func httpGet(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(url, "https://api.github.com/") {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	return http.DefaultClient.Do(req)
}

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		log.Printf("warning: close response body: %v", err)
	}
}
