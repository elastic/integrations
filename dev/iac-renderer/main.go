// iac-renderer constructs a deployable IaC artifact for a given blueprint ID by:
//  1. Loading the package manifest (from a local package directory or a live EPR)
//  2. Collecting all iac_blueprints entries that match the requested blueprint ID and format
//  3. Loading the canonical base blueprint from the shared blueprints directory
//  4. Applying each RFC 6902 patch file in sequence
//  5. Emitting the composed artifact — or deploying it directly via the AWS CLI
//
// Usage (local filesystem):
//
//	iac-renderer --source ./packages/cloud_security_posture \
//	             --blueprints-dir ./blueprints
//
// Usage (live EPR):
//
//	iac-renderer --source http://localhost:8080 \
//	             --package cloud_security_posture \
//	             --blueprints-dir ./blueprints
//
// Usage (deploy to AWS):
//
//	iac-renderer --source ./packages/cloud_security_posture \
//	             --blueprints-dir ./blueprints \
//	             --deploy --resource-id <elastic-resource-id>
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"gopkg.in/yaml.v3"
)

// --- manifest types (only fields we need) ---

type Manifest struct {
	Name            string           `yaml:"name"`
	Version         string           `yaml:"version"`
	FormatVersion   string           `yaml:"format_version"`
	IACBlueprints   []IACBlueprint   `yaml:"iac_blueprints"`
	PolicyTemplates []PolicyTemplate `yaml:"policy_templates"`
}

type PolicyTemplate struct {
	Name          string         `yaml:"name"`
	IACBlueprints []IACBlueprint `yaml:"iac_blueprints"`
	Inputs        []Input        `yaml:"inputs"`
}

type Input struct {
	Type          string         `yaml:"type"`
	IACBlueprints []IACBlueprint `yaml:"iac_blueprints"`
}

type IACBlueprint struct {
	ID      string `yaml:"id"`
	Format  string `yaml:"format"`
	Patches string `yaml:"patches"`
	Title   string `yaml:"title"`
}

// --- source abstraction: local dir or live EPR ---

type Source interface {
	ReadManifest() ([]byte, error)
	ReadFile(relPath string) ([]byte, error)
	Describe() string
}

// LocalSource reads from a package directory on disk.
type LocalSource struct{ dir string }

func (s *LocalSource) ReadManifest() ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir, "manifest.yml"))
}
func (s *LocalSource) ReadFile(p string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir, p))
}
func (s *LocalSource) Describe() string { return "local:" + s.dir }

// EPRSource reads a package from a live Elastic Package Registry.
type EPRSource struct {
	baseURL string
	name    string
	version string
	client  *http.Client
}

func newHTTPClient(caCertPath string, insecure bool) (*http.Client, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: insecure} //nolint:gosec
	if caCertPath != "" {
		pem, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert %s: %w", caCertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certs found in %s", caCertPath)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
}

func newEPRSource(baseURL, name, caCertPath string, insecure bool) (*EPRSource, error) {
	client, err := newHTTPClient(caCertPath, insecure)
	if err != nil {
		return nil, err
	}
	s := &EPRSource{baseURL: baseURL, name: name, client: client}

	url := fmt.Sprintf("%s/search?package=%s&experimental=true", baseURL, name)
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("EPR search %s: %w", url, err)
	}
	defer resp.Body.Close()
	var results []struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, fmt.Errorf("decoding EPR search results: %w", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("package %q not found at %s", name, baseURL)
	}
	s.version = results[0].Version
	return s, nil
}

func (s *EPRSource) ReadManifest() ([]byte, error) {
	return s.get(fmt.Sprintf("%s/package/%s/%s/manifest.yml", s.baseURL, s.name, s.version))
}
func (s *EPRSource) ReadFile(p string) ([]byte, error) {
	return s.get(fmt.Sprintf("%s/package/%s/%s/%s", s.baseURL, s.name, s.version, p))
}
func (s *EPRSource) Describe() string {
	return fmt.Sprintf("epr:%s package=%s version=%s", s.baseURL, s.name, s.version)
}
func (s *EPRSource) get(url string) ([]byte, error) {
	resp, err := s.client.Get(url) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// --- blueprint collection ---

func collectPatches(m *Manifest, blueprintID, format string) []string {
	var paths []string
	add := func(entries []IACBlueprint) {
		for _, e := range entries {
			if e.ID == blueprintID && e.Format == format {
				paths = append(paths, e.Patches)
			}
		}
	}
	add(m.IACBlueprints) // package level
	for _, pt := range m.PolicyTemplates {
		add(pt.IACBlueprints) // policy_template level
		for _, inp := range pt.Inputs {
			add(inp.IACBlueprints) // input level
		}
	}
	return paths
}

// --- main ---

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func main() {
	var (
		source        = flag.String("source", "", "Local package directory OR EPR base URL (http://… or https://…)")
		packageName   = flag.String("package", "cloud_security_posture", "Package name (EPR mode only)")
		blueprintID   = flag.String("blueprint-id", "aws/federated-identity/account", "Blueprint ID to render")
		format        = flag.String("format", "cloudformation", "IaC format")
		blueprintsDir = flag.String("blueprints-dir", "", "Directory containing canonical base blueprints (required)")
		output        = flag.String("output", "", "Write rendered template to this file (default: stdout)")
		deploy        = flag.Bool("deploy", false, "Deploy rendered template via 'aws cloudformation deploy'")
		stackName     = flag.String("stack-name", "ElasticFederatedIdentity", "CloudFormation stack name (--deploy)")
		resourceID    = flag.String("resource-id", "", "Elastic resource ID; sets ElasticResourceId parameter (required with --deploy)")
		caCert        = flag.String("ca-cert", "", "Path to CA certificate for EPR TLS (e.g. ~/.elastic-package/profiles/default/certs/ca-cert.pem)")
		insecure      = flag.Bool("insecure", false, "Skip TLS certificate verification for EPR (use only for local dev)")
	)
	flag.Parse()

	if *blueprintsDir == "" {
		fatalf("--blueprints-dir is required")
	}

	// --- resolve source ---
	var src Source
	switch {
	case strings.HasPrefix(*source, "http://") || strings.HasPrefix(*source, "https://"):
		s, err := newEPRSource(*source, *packageName, *caCert, *insecure)
		if err != nil {
			fatalf("connecting to EPR: %v", err)
		}
		src = s
	case *source != "":
		src = &LocalSource{dir: *source}
	default:
		fatalf("--source is required (local package directory or EPR URL)")
	}
	logf("→ source: %s", src.Describe())

	// --- load manifest ---
	manifestData, err := src.ReadManifest()
	if err != nil {
		fatalf("reading manifest: %v", err)
	}
	var manifest Manifest
	if err := yaml.Unmarshal(manifestData, &manifest); err != nil {
		fatalf("parsing manifest: %v", err)
	}
	logf("→ package: %s v%s (format_version: %s)", manifest.Name, manifest.Version, manifest.FormatVersion)

	// --- collect patch paths ---
	patchPaths := collectPatches(&manifest, *blueprintID, *format)
	if len(patchPaths) == 0 {
		fatalf("no iac_blueprints entries found for id=%q format=%q — check the manifest", *blueprintID, *format)
	}
	logf("→ %d patch file(s) for blueprint %s/%s:", len(patchPaths), *blueprintID, *format)
	for _, p := range patchPaths {
		logf("    %s", p)
	}

	// --- load canonical base blueprint ---
	// Convention: blueprints-dir/<blueprint-id>.<format>.json
	basePath := filepath.Join(*blueprintsDir, filepath.FromSlash(*blueprintID+"."+*format+".json"))
	baseData, err := os.ReadFile(basePath)
	if err != nil {
		fatalf("loading base blueprint %s: %v", basePath, err)
	}
	logf("→ base blueprint: %s", basePath)

	// --- apply patches in sequence ---
	composed := baseData
	for _, patchPath := range patchPaths {
		patchData, err := src.ReadFile(patchPath)
		if err != nil {
			fatalf("loading patch %s: %v", patchPath, err)
		}
		patch, err := jsonpatch.DecodePatch(patchData)
		if err != nil {
			fatalf("decoding patch %s: %v", patchPath, err)
		}
		composed, err = patch.Apply(composed)
		if err != nil {
			fatalf("applying patch %s: %v", patchPath, err)
		}
		logf("  ✓ applied %s", patchPath)
	}

	// --- pretty-print ---
	var doc any
	if err := json.Unmarshal(composed, &doc); err != nil {
		fatalf("marshalling result: %v", err)
	}
	pretty, _ := json.MarshalIndent(doc, "", "  ")
	pretty = append(pretty, '\n')

	// --- write output ---
	outFile := *output
	if outFile != "" {
		if err := os.WriteFile(outFile, pretty, 0o644); err != nil {
			fatalf("writing output: %v", err)
		}
		logf("→ rendered template written to %s", outFile)
	} else {
		fmt.Print(string(pretty))
	}

	// --- optional AWS deployment ---
	if !*deploy {
		return
	}
	if *resourceID == "" {
		fatalf("--resource-id is required when using --deploy")
	}

	// write to a temp file if no --output was given
	templateFile := outFile
	if templateFile == "" {
		f, err := os.CreateTemp("", "elastic-iac-*.json")
		if err != nil {
			fatalf("creating temp file: %v", err)
		}
		if _, err := f.Write(pretty); err != nil {
			fatalf("writing temp file: %v", err)
		}
		f.Close()
		templateFile = f.Name()
		defer os.Remove(templateFile)
	}

	logf("→ deploying CloudFormation stack %q (this may take a few minutes)…", *stackName)
	cmd := exec.Command("aws", "cloudformation", "deploy",
		"--template-file", templateFile,
		"--stack-name", *stackName,
		"--capabilities", "CAPABILITY_NAMED_IAM",
		"--parameter-overrides",
		"ElasticResourceId="+*resourceID,
	)
	cmd.Stdout = os.Stderr // progress output to stderr so stdout stays clean
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatalf("CloudFormation deployment failed: %v", err)
	}
	logf("✓ stack %q deployed", *stackName)

	// Print the role ARN and external ID for the user to register in Kibana
	descCmd := exec.Command("aws", "cloudformation", "describe-stacks",
		"--stack-name", *stackName,
		"--query", "Stacks[0].Outputs",
		"--output", "json",
	)
	descOut, err := descCmd.Output()
	if err == nil {
		var outputs []struct {
			OutputKey   string `json:"OutputKey"`
			OutputValue string `json:"OutputValue"`
			Description string `json:"Description"`
		}
		if err := json.Unmarshal(descOut, &outputs); err == nil {
			logf("\n── Stack outputs ──────────────────────────────")
			for _, o := range outputs {
				logf("  %-12s  %s", o.OutputKey, o.OutputValue)
			}
			logf("────────────────────────────────────────────────")
			logf("Supply RoleArn and ExternalId to Kibana when configuring CSPM with federated identity.")
		}
	}
}
