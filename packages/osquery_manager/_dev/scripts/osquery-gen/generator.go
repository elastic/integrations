// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bytes"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	osquerySiteSchemaURL = "https://raw.githubusercontent.com/osquery/osquery-site/source/src/data/osquery_schema_versions/%s.json"
	ecsFieldsURL         = "https://raw.githubusercontent.com/elastic/ecs/v%s/generated/beats/fields.ecs.yml"
	ecsCSVURL            = "https://raw.githubusercontent.com/elastic/ecs/v%s/generated/csv/fields.csv"
	beatsSpecsAPI        = "https://api.github.com/repos/elastic/beats/contents/x-pack/osquerybeat/ext/osquery-extension/specs?ref=%s"
	beatsRawSpecURL      = "https://raw.githubusercontent.com/elastic/beats/%s/x-pack/osquerybeat/ext/osquery-extension/specs/%s"
)

var excludeFromTopLevel = []string{
	"as", "code_signature", "elf", "entity", "macho", "pe", "risk", "x509",
}

var ecsRestrictedFields = []string{
	"agent.name", "agent.id", "agent.ephemeral_id", "agent.type", "agent.version",
	"ecs.version", "event.agent_id_status", "event.ingested", "event.module",
	"host.hostname", "host.os.build", "host.os.kernel", "host.os.name", "host.os.family",
	"host.os.type", "host.os.version", "host.platform", "host.ip", "host.id", "host.mac",
	"host.architecture", "@timestamp",
}

var (
	excludeFromTopLevelSet = makeSet(excludeFromTopLevel)
	ecsRestrictedSet       = makeSet(ecsRestrictedFields)
)

//go:embed ecs_keep_fields.txt
var ecsKeepFieldsContent string

type kibanaOsqueryTable struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Platforms   []string           `json:"platforms"`
	Columns     []kibanaOsqueryCol `json:"columns"`
	Owner       string             `json:"owner,omitempty"`
	View        bool               `json:"view,omitempty"`
}

type kibanaOsqueryCol struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Notes       string   `json:"notes"`
	Hidden      bool     `json:"hidden"`
	Required    bool     `json:"required"`
	Index       bool     `json:"index"`
	Platforms   []string `json:"platforms,omitempty"`
}

type kibanaECSField struct {
	Field         string `json:"field"`
	Type          string `json:"type"`
	Normalization string `json:"normalization"`
	Example       any    `json:"example"`
	Description   string `json:"description"`
}

type beatsSpec struct {
	Type        string        `yaml:"type"`
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Platforms   []string      `yaml:"platforms"`
	Group       string        `yaml:"group,omitempty"`
	SharedTypes []string      `yaml:"shared_types,omitempty"`
	Columns     []beatsColumn `yaml:"columns"`
}

type beatsColumn struct {
	Name         string `yaml:"name"`
	Type         string `yaml:"type"`
	Description  string `yaml:"description"`
	EmbeddedType string `yaml:"embedded_type,omitempty"`
	SharedType   string `yaml:"shared_type,omitempty"`
}

type beatsSharedTypeSpec struct {
	Name    string        `yaml:"name"`
	Columns []beatsColumn `yaml:"columns"`
}

type beatsSharedTypesFile struct {
	Type  string                `yaml:"type"`
	Group string                `yaml:"group"`
	Types []beatsSharedTypeSpec `yaml:"types"`
}

type osqueryTable struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Platforms   []string     `json:"platforms"`
	Columns     []osqueryCol `json:"columns"`
	View        bool         `json:"view,omitempty"`
}

type osqueryCol struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
}

type columnInfo struct {
	Column osqueryCol
}

func generateArtifacts(outputRoot, osqueryVersion, ecsVersion, beatsRef string, runPackageCheck bool) error {
	outFields := filepath.Join(outputRoot, "packages", "osquery_manager", "data_stream", "result", "fields")
	outSchemas := filepath.Join(outputRoot, "packages", "osquery_manager", "schemas")

	if err := os.MkdirAll(outFields, 0755); err != nil {
		return fmt.Errorf("mkdir output: %w", err)
	}
	if err := os.MkdirAll(outSchemas, 0755); err != nil {
		return fmt.Errorf("mkdir schemas output: %w", err)
	}

	coreURL := fmt.Sprintf(osquerySiteSchemaURL, osqueryVersion)
	log.Printf("Downloading osquery schema: %s", coreURL)
	coreSchemaRaw, err := downloadJSON[[]any](coreURL)
	if err != nil {
		return fmt.Errorf("download osquery schema: %w", err)
	}

	tablesForYAML := rawSchemaToOsqueryTables(coreSchemaRaw)
	extTables, err := downloadBeatsExtensionSpecs(beatsRef)
	if err != nil {
		return fmt.Errorf("download beats extension specs: %w", err)
	}
	tablesForYAML = append(tablesForYAML, extTables...)
	log.Printf("Merged %d extension tables from beats", len(extTables))

	columns, duplicateTypeColumns := preprocessTables(tablesForYAML)
	osqueryYAML, err := generateOsqueryFieldsYAML(columns, duplicateTypeColumns)
	if err != nil {
		return fmt.Errorf("generate osquery.yml: %w", err)
	}
	osqueryPath := filepath.Join(outFields, "osquery.yml")
	if err := os.WriteFile(osqueryPath, osqueryYAML, 0644); err != nil {
		return fmt.Errorf("write %s: %w", osqueryPath, err)
	}

	ecsURL := fmt.Sprintf(ecsFieldsURL, ecsVersion)
	log.Printf("Downloading ECS fields: %s", ecsURL)
	ecsYAML, err := downloadBytes(ecsURL)
	if err != nil {
		return fmt.Errorf("download ECS fields: %w", err)
	}
	ecsOut, err := generateECSFieldsYAML(ecsYAML)
	if err != nil {
		return fmt.Errorf("generate ecs.yml: %w", err)
	}
	ecsPath := filepath.Join(outFields, "ecs.yml")
	if err := os.WriteFile(ecsPath, ecsOut, 0644); err != nil {
		return fmt.Errorf("write %s: %w", ecsPath, err)
	}

	osqueryFormatted := formatOsquerySchemaForKibanaRaw(coreSchemaRaw, tablesForYAML)
	osquerySchemaJSON, err := json.Marshal(osqueryFormatted)
	if err != nil {
		return fmt.Errorf("marshal osquery schema: %w", err)
	}
	osquerySchemaPath := filepath.Join(outSchemas, "osquery.json")
	if err := os.WriteFile(osquerySchemaPath, osquerySchemaJSON, 0644); err != nil {
		return fmt.Errorf("write %s: %w", osquerySchemaPath, err)
	}

	csvBody, err := downloadBytes(fmt.Sprintf(ecsCSVURL, ecsVersion))
	if err != nil {
		return fmt.Errorf("download ECS CSV: %w", err)
	}
	ecsRawRecords, err := convertECSCSVToJSONRecords(csvBody)
	if err != nil {
		return fmt.Errorf("convert ECS CSV: %w", err)
	}
	ecsFormatted := formatECSSchemaForKibana(ecsRawRecords)
	ecsSchemaJSON, err := json.Marshal(ecsFormatted)
	if err != nil {
		return fmt.Errorf("marshal ECS schema: %w", err)
	}
	ecsSchemaPath := filepath.Join(outSchemas, "ecs.json")
	if err := os.WriteFile(ecsSchemaPath, ecsSchemaJSON, 0644); err != nil {
		return fmt.Errorf("write %s: %w", ecsSchemaPath, err)
	}

	metadataJSON, err := json.Marshal(struct {
		EcsVersion     string `json:"ecs_version"`
		OsqueryVersion string `json:"osquery_version"`
	}{
		EcsVersion:     ecsVersion,
		OsqueryVersion: osqueryVersion,
	})
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	metadataPath := filepath.Join(outSchemas, "metadata.json")
	if err := os.WriteFile(metadataPath, metadataJSON, 0644); err != nil {
		return fmt.Errorf("write %s: %w", metadataPath, err)
	}

	if runPackageCheck {
		if err := runElasticPackageCheck(outputRoot, "osquery_manager"); err != nil {
			return err
		}
	}
	return nil
}

func downloadJSON[T any](url string) (T, error) {
	var zero T
	body, err := downloadBytes(url)
	if err != nil {
		return zero, err
	}
	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return zero, err
	}
	return out, nil
}

func runElasticPackageCheck(repoRoot, packageName string) error {
	ep, err := findElasticPackageBinary()
	if err != nil {
		return err
	}
	packageDir := filepath.Join(repoRoot, "packages", packageName)
	cmd := exec.Command(ep, "-C", packageDir, "check")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("Running elastic-package check: %s -C %s check", ep, packageDir)
	return cmd.Run()
}

func findElasticPackageBinary() (string, error) {
	if p, err := exec.LookPath("elastic-package"); err == nil {
		return p, nil
	}
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		out, err := exec.Command("go", "env", "GOPATH").Output()
		if err != nil {
			return "", fmt.Errorf("elastic-package not found in PATH and failed to resolve GOPATH: %w", err)
		}
		goPath = strings.TrimSpace(string(out))
	}
	candidate := filepath.Join(goPath, "bin", "elastic-package")
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}
	return "", fmt.Errorf("elastic-package not found in PATH or %s", candidate)
}

func downloadBeatsExtensionSpecs(ref string) ([]osqueryTable, error) {
	type ghEntry struct {
		Name string `json:"name"`
	}
	body, err := downloadBytes(fmt.Sprintf(beatsSpecsAPI, ref))
	if err != nil {
		return nil, err
	}
	var entries []ghEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	type parsedSpecFile struct {
		Name string
		Body []byte
		Kind string
	}
	var specFiles []parsedSpecFile
	sharedTypesByGroup := make(map[string]map[string][]beatsColumn)

	for _, e := range entries {
		if !strings.HasSuffix(e.Name, ".yaml") && !strings.HasSuffix(e.Name, ".yml") {
			continue
		}
		specBody, err := downloadBytes(fmt.Sprintf(beatsRawSpecURL, ref, e.Name))
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", e.Name, err)
		}
		var header struct {
			Type string `yaml:"type"`
		}
		if err := yaml.Unmarshal(specBody, &header); err != nil {
			return nil, fmt.Errorf("parse header %s: %w", e.Name, err)
		}

		if strings.EqualFold(header.Type, "shared_types") {
			var stf beatsSharedTypesFile
			if err := yaml.Unmarshal(specBody, &stf); err != nil {
				return nil, fmt.Errorf("parse shared_types %s: %w", e.Name, err)
			}
			if stf.Group == "" {
				return nil, fmt.Errorf("shared_types file %s missing group", e.Name)
			}
			if _, ok := sharedTypesByGroup[stf.Group]; !ok {
				sharedTypesByGroup[stf.Group] = make(map[string][]beatsColumn)
			}
			for _, t := range stf.Types {
				sharedTypesByGroup[stf.Group][t.Name] = t.Columns
			}
			continue
		}

		if !strings.EqualFold(header.Type, "table") && !strings.EqualFold(header.Type, "view") {
			continue
		}
		specFiles = append(specFiles, parsedSpecFile{
			Name: e.Name,
			Body: specBody,
			Kind: header.Type,
		})
	}

	var tables []osqueryTable
	for _, f := range specFiles {
		var spec beatsSpec
		if err := yaml.Unmarshal(f.Body, &spec); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f.Name, err)
		}
		if spec.Name == "" || len(spec.Columns) == 0 {
			continue
		}

		t := osqueryTable{
			Name:        spec.Name,
			Description: spec.Description,
			Platforms:   spec.Platforms,
			Columns:     make([]osqueryCol, 0, len(spec.Columns)),
			View:        strings.EqualFold(spec.Type, "view"),
		}

		for _, c := range spec.Columns {
			embeddedName := embeddedTypeName(c)
			if embeddedName != "" || strings.EqualFold(c.Type, "EMBEDDED") {
				if embeddedName == "" {
					embeddedName = c.Name
				}
				groupTypes := sharedTypesByGroup[spec.Group]
				embeddedCols, ok := groupTypes[embeddedName]
				if !ok {
					return nil, fmt.Errorf("%s: column %s references unknown embedded/shared type %s in group %s", f.Name, c.Name, embeddedName, spec.Group)
				}
				for _, ec := range embeddedCols {
					t.Columns = append(t.Columns, osqueryCol{
						Name:        ec.Name,
						Description: ec.Description,
						Type:        strings.ToLower(ec.Type),
					})
				}
				continue
			}
			t.Columns = append(t.Columns, osqueryCol{
				Name:        c.Name,
				Description: c.Description,
				Type:        strings.ToLower(c.Type),
			})
		}
		tables = append(tables, t)
	}
	return tables, nil
}

func embeddedTypeName(col beatsColumn) string {
	if col.EmbeddedType != "" {
		return col.EmbeddedType
	}
	if col.SharedType != "" {
		return col.SharedType
	}
	return ""
}

func convergeToESType(t string) string {
	switch t {
	case "integer", "unsigned_bigint", "bigint":
		return "long"
	}
	return t
}

func preprocessTables(tables []osqueryTable) (map[string]columnInfo, map[string]struct{}) {
	columns := make(map[string]columnInfo)
	duplicateTypeColumns := make(map[string]struct{})
	for _, table := range tables {
		for _, col := range table.Columns {
			col.Type = convergeToESType(col.Type)
			col.Description = table.Name + "." + col.Name + " - " + col.Description
			existing, ok := columns[col.Name]
			if ok {
				existing.Column.Description += "\n" + col.Description
				columns[col.Name] = existing
				if existing.Column.Type != col.Type {
					duplicateTypeColumns[col.Name] = struct{}{}
				}
			} else {
				columns[col.Name] = columnInfo{Column: col}
			}
		}
	}
	return columns, duplicateTypeColumns
}

func generateOsqueryFieldsYAML(columns map[string]columnInfo, duplicateTypeColumns map[string]struct{}) ([]byte, error) {
	type node struct {
		Name        string `yaml:"name,omitempty"`
		Title       string `yaml:"title,omitempty"`
		Description string `yaml:"description,omitempty"`
		Type        string `yaml:"type,omitempty"`
		Fields      []any  `yaml:"fields,omitempty"`
	}
	type field struct {
		Name        string `yaml:"name,omitempty"`
		Description string `yaml:"description,omitempty"`
		Type        string `yaml:"type,omitempty"`
		IgnoreAbove int    `yaml:"ignore_above,omitempty"`
		Multifields []any  `yaml:"multi_fields,omitempty"`
	}
	type mulField struct {
		Name         string `yaml:"name,omitempty"`
		Type         string `yaml:"type,omitempty"`
		Norms        bool   `yaml:"norms"`
		DefaultField bool   `yaml:"default_field"`
	}
	type numMulField struct {
		Name         string `yaml:"name,omitempty"`
		Type         string `yaml:"type,omitempty"`
		DefaultField bool   `yaml:"default_field"`
	}

	conf := node{
		Name:        "osquery",
		Title:       "Osquery result",
		Description: "Fields related to the Osquery result",
		Type:        "group",
	}
	var names []string
	for k := range columns {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, colName := range names {
		info := columns[colName]
		f := field{
			Name:        colName,
			Description: info.Column.Description,
			Type:        "keyword",
			IgnoreAbove: 1024,
		}
		if info.Column.Type == "text" {
			f.Multifields = []any{
				mulField{Name: "text", Type: "text", Norms: false, DefaultField: false},
			}
		} else if _, isDup := duplicateTypeColumns[colName]; !isDup {
			f.Multifields = []any{
				numMulField{Name: "number", Type: info.Column.Type, DefaultField: false},
			}
		}
		conf.Fields = append(conf.Fields, f)
	}

	out := []node{conf}
	return marshalYAMLWithIndent(out, 2)
}

func marshalYAMLWithIndent(v any, indent int) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(indent)
	defer enc.Close()
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func loadKeepFields() []string {
	var out []string
	for _, line := range strings.Split(ecsKeepFieldsContent, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func generateECSFieldsYAML(ecsBeatsYAML []byte) ([]byte, error) {
	keepFields := makeSet(loadKeepFields())
	var root any
	if err := yaml.Unmarshal(ecsBeatsYAML, &root); err != nil {
		return nil, err
	}

	var ecsFields []string
	collectECSFieldNames(root, "", keepFields, &ecsFields)

	var buf strings.Builder
	buf.WriteString("# Generated by packages/osquery_manager/_dev/scripts/osquery-gen. Do not edit by hand.\n")
	buf.WriteString("# Regenerate with: go run ./packages/osquery_manager/_dev/scripts/osquery-gen -config ./packages/osquery_manager/_dev/scripts/osquery-gen/config.yml\n")
	buf.WriteString("# ECS version: packages/osquery_manager/_dev/build/build.yml (dependencies.ecs.reference)\n")
	for _, name := range ecsFields {
		buf.WriteString("- external: ecs\n")
		buf.WriteString("  name: " + name + "\n")
	}
	return []byte(buf.String()), nil
}

func collectECSFieldNames(root any, parent string, keepFields map[string]struct{}, ecsFields *[]string) {
	nodes, ok := root.([]any)
	if !ok {
		return
	}
	for _, node := range nodes {
		m, ok := toStringMap(node)
		if !ok {
			continue
		}
		var name string
		if v, exists := m["name"]; exists {
			name, _ = v.(string)
		}
		if parent == "" && inSet(excludeFromTopLevelSet, name) {
			continue
		}
		if childFields, hasFields := m["fields"]; hasFields {
			collectECSFieldNames(childFields, joinPath(parent, name), keepFields, ecsFields)
		} else {
			fieldName := joinPath(parent, name)
			typ, _ := m["type"].(string)
			if (inSet(keepFields, fieldName) || isAllowedECSType(typ)) && name != "@timestamp" {
				*ecsFields = append(*ecsFields, fieldName)
			}
		}
	}
}

func toStringMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			ks, ok := k.(string)
			if !ok {
				return nil, false
			}
			out[ks] = val
		}
		return out, true
	default:
		return nil, false
	}
}

func joinPath(parent, name string) string {
	if parent != "" {
		return parent + "." + name
	}
	return name
}

func isAllowedECSType(t string) bool {
	switch t {
	case "date", "ip", "long", "float", "boolean":
		return true
	default:
		return false
	}
}

func makeSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		out[v] = struct{}{}
	}
	return out
}

func inSet(set map[string]struct{}, value string) bool {
	_, ok := set[value]
	return ok
}

func rawSchemaToOsqueryTables(raw []any) []osqueryTable {
	var out []osqueryTable
	for _, v := range raw {
		t, _ := v.(map[string]any)
		if t == nil {
			continue
		}
		name, _ := t["name"].(string)
		desc, _ := t["description"].(string)
		var platforms []string
		if p, ok := t["platforms"].([]any); ok {
			for _, x := range p {
				if s, ok := x.(string); ok {
					platforms = append(platforms, s)
				}
			}
		}
		var cols []osqueryCol
		if c, ok := t["columns"].([]any); ok {
			for _, x := range c {
				cm, _ := x.(map[string]any)
				if cm == nil {
					continue
				}
				cn, _ := cm["name"].(string)
				cd, _ := cm["description"].(string)
				ct, _ := cm["type"].(string)
				cols = append(cols, osqueryCol{Name: cn, Description: cd, Type: ct})
			}
		}
		out = append(out, osqueryTable{Name: name, Description: desc, Platforms: platforms, Columns: cols})
	}
	return out
}

func mapToKibanaCol(m map[string]any) kibanaOsqueryCol {
	c := kibanaOsqueryCol{
		Notes:    "",
		Hidden:   false,
		Required: false,
		Index:    false,
	}
	if v, ok := m["name"].(string); ok {
		c.Name = v
	}
	if v, ok := m["description"].(string); ok {
		c.Description = v
	}
	if v, ok := m["type"].(string); ok {
		c.Type = v
	}
	if v, ok := m["notes"].(string); ok {
		c.Notes = v
	}
	if v, ok := m["hidden"].(bool); ok {
		c.Hidden = v
	}
	if v, ok := m["required"].(bool); ok {
		c.Required = v
	}
	if v, ok := m["index"].(bool); ok {
		c.Index = v
	}
	if p, ok := m["platforms"].([]any); ok && len(p) > 0 {
		for _, x := range p {
			if s, ok := x.(string); ok {
				c.Platforms = append(c.Platforms, s)
			}
		}
	}
	return c
}

func formatOsquerySchemaForKibanaRaw(coreRaw []any, extensionTables []osqueryTable) []kibanaOsqueryTable {
	out := make([]kibanaOsqueryTable, 0)
	coreNames := make(map[string]bool)

	for _, v := range coreRaw {
		t, _ := v.(map[string]any)
		if t == nil {
			continue
		}
		var platforms []string
		if p, ok := t["platforms"].([]any); ok {
			for _, x := range p {
				if s, ok := x.(string); ok {
					platforms = append(platforms, s)
				}
			}
		}
		var cols []kibanaOsqueryCol
		if c, ok := t["columns"].([]any); ok {
			for _, x := range c {
				cm, _ := x.(map[string]any)
				if cm != nil {
					cols = append(cols, mapToKibanaCol(cm))
				}
			}
		}
		name, _ := t["name"].(string)
		desc, _ := t["description"].(string)
		if name != "" {
			coreNames[name] = true
		}
		view := false
		if v, ok := t["view"].(bool); ok {
			view = v
		}
		out = append(out, kibanaOsqueryTable{Name: name, Description: desc, Platforms: platforms, Columns: cols, View: view})
	}

	for _, t := range extensionTables {
		if coreNames[t.Name] {
			continue
		}
		cols := make([]kibanaOsqueryCol, 0, len(t.Columns))
		for _, c := range t.Columns {
			cols = append(cols, kibanaOsqueryCol{
				Name: c.Name, Description: c.Description, Type: c.Type,
				Notes: "", Hidden: false, Required: false, Index: false,
			})
		}
		out = append(out, kibanaOsqueryTable{
			Name:        t.Name,
			Description: t.Description,
			Platforms:   t.Platforms,
			Columns:     cols,
			Owner:       "elastic",
			View:        t.View,
		})
	}
	return out
}

func formatECSSchemaForKibana(records []map[string]any) []kibanaECSField {
	var out []kibanaECSField
	for _, rec := range records {
		fieldVal, _ := rec["field"].(string)
		if inSet(ecsRestrictedSet, fieldVal) {
			continue
		}
		getStr := func(k string) string {
			for _, key := range []string{strings.ToLower(k), k} {
				if v, ok := rec[key]; ok {
					if s, ok := v.(string); ok {
						return s
					}
				}
			}
			return ""
		}
		getAny := func(k string) any {
			if v, ok := rec[strings.ToLower(k)]; ok {
				return v
			}
			if v, ok := rec[k]; ok {
				return v
			}
			return nil
		}
		out = append(out, kibanaECSField{
			Field:         fieldVal,
			Type:          getStr("type"),
			Normalization: getStr("normalization"),
			Example:       getAny("example"),
			Description:   getStr("description"),
		})
	}
	return out
}

func convertECSCSVToJSONRecords(csvContent []byte) ([]map[string]any, error) {
	r := csv.NewReader(strings.NewReader(string(csvContent)))
	lines, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(lines) < 2 {
		return nil, fmt.Errorf("CSV has insufficient data")
	}
	headers := lines[0]
	for i, h := range headers {
		headers[i] = strings.ToLower(strings.TrimSpace(h))
	}
	var records []map[string]any
	for _, row := range lines[1:] {
		if len(row) != len(headers) {
			continue
		}
		rec := make(map[string]any)
		for j, val := range row {
			v := strings.TrimSpace(val)
			var parsed any = v
			if headers[j] == "example" {
				_ = json.Unmarshal([]byte(val), &parsed)
			}
			rec[headers[j]] = parsed
		}
		records = append(records, rec)
	}
	return records, nil
}
