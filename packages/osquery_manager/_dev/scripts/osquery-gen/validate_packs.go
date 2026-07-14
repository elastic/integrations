// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	shadowAIPackPrefix = "osquery_manager-e7a1b2c3-"
)

var (
	dropECSKeys = []string{
		"host.os.type",
		"event.module",
		"event.dataset",
		"threat.framework",
		"threat.tactic.id",
		"threat.tactic.name",
		"threat.technique.id",
		"threat.technique.name",
	}
	requiredECSKeys = []string{
		"event.category",
		"event.type",
		"event.action",
		"tags",
	}
	staticArrayECSKeys = []string{
		"event.category",
		"event.type",
		"tags",
	}
	actionFormatRE = regexp.MustCompile(`^osquery\.[a-z][a-z0-9_]*$`)

	// sharedActionOverrides maps platform-specific query IDs to their emitted event.action.
	sharedActionOverrides = map[string]string{
		"ai_config_file_changes_linux":        "osquery.ai_config_file_changes",
		"ai_config_file_changes_macos":        "osquery.ai_config_file_changes",
		"ai_config_file_changes_windows":      "osquery.ai_config_file_changes",
		"ai_sensitive_file_proximity_linux":   "osquery.ai_sensitive_file_access",
		"ai_sensitive_file_proximity_macos":   "osquery.ai_sensitive_file_access",
		"ai_sensitive_file_proximity_windows": "osquery.ai_sensitive_file_colocation",
	}

	// partialSharedQueryPlatforms documents cross-platform query IDs that intentionally
	// appear on only a subset of platforms.
	partialSharedQueryPlatforms = map[string][]string{
		"ai_gpu_systems":         {"linux", "windows"},
		"ai_network_connections": {"linux", "macos"},
		"ai_ssh_tunnels":         {"linux", "macos"},
		"ai_vscode_extensions":   {"linux", "macos"},
	}

	whereClauseRE = regexp.MustCompile(`(?is)\bWHERE\b(.*)$`)
	orLineRE      = regexp.MustCompile(`(?im)^\s*OR\s+((?:p|l|u|ve|pp|pos|sens|f|dp|bd|m|db)\.\w+\s+(?:LIKE|IN)\s+(?:\([^)]*\)|'[^']*').*)\s*$`)
	orPredicateRE = regexp.MustCompile(`(?is)\bOR\s+((?:p|l|u|ve|pp|pos|sens|f|dp|bd|m|db|pp)\.\w+\s+(?:LIKE|IN)\s+(?:\([^;]*?\)|'[^']*'))`)
	aliasRE       = regexp.MustCompile(`(?i)\bAS\s+([a-z][a-z0-9_]*)\s*$`)
	bareColumnRE  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.]*$`)
)

type packExpectation struct {
	suffix     string
	name       string
	platform   string
	queryCount int
}

var expectedShadowAIPacks = []packExpectation{
	{suffix: "lin0-4f6a-8b9c-0d1e2f3a4b5c", name: "ai-asset-discovery-linux", platform: "linux", queryCount: 28},
	{suffix: "mac0-4f6a-8b9c-0d1e2f3a4b5c", name: "ai-asset-discovery-macos", platform: "darwin", queryCount: 29},
	{suffix: "win0-4f6a-8b9c-0d1e2f3a4b5c", name: "ai-asset-discovery-windows", platform: "windows", queryCount: 27},
}

type ecsMappingEntry struct {
	Key   string         `json:"key"`
	Value map[string]any `json:"value"`
}

type packQuery struct {
	ID         string            `json:"id"`
	Query      string            `json:"query"`
	Interval   int               `json:"interval"`
	Platform   string            `json:"platform"`
	Timeout    int               `json:"timeout"`
	ECSMapping []ecsMappingEntry `json:"ecs_mapping"`
	Snapshot   bool              `json:"snapshot"`
}

type packAttributes struct {
	Description string      `json:"description"`
	Name        string      `json:"name"`
	Version     int         `json:"version"`
	Queries     []packQuery `json:"queries"`
}

type packAsset struct {
	Attributes packAttributes `json:"attributes"`
	ID         string         `json:"id"`
}

type loadedShadowAIPack struct {
	expectation packExpectation
	path        string
	asset       packAsset
}

type sharedQueryContract struct {
	action   string
	interval int
	snapshot bool
	category string
	eventTyp string
}

// ValidateShadowAIPacks enforces Shadow AI pack contracts.
func ValidateShadowAIPacks(repoRoot string) []error {
	packs, err := loadShadowAIPacks(repoRoot)
	if err != nil {
		return []error{err}
	}

	var errs []error
	errs = append(errs, validatePackSet(packs)...)
	for _, pack := range packs {
		errs = append(errs, validatePackContents(pack)...)
	}
	errs = append(errs, validateSharedQueryContracts(packs)...)
	errs = append(errs, validateOpenClawListeningPortContracts(packs)...)

	sort.Slice(errs, func(i, j int) bool {
		return errs[i].Error() < errs[j].Error()
	})
	return errs
}

func loadShadowAIPacks(repoRoot string) ([]loadedShadowAIPack, error) {
	packDir := filepath.Join(repoRoot, "packages", "osquery_manager", "kibana", "osquery_pack_asset")
	var out []loadedShadowAIPack
	for _, exp := range expectedShadowAIPacks {
		path := filepath.Join(packDir, shadowAIPackPrefix+exp.suffix+".json")
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read pack %s: %w", path, err)
		}
		var asset packAsset
		if err := json.Unmarshal(b, &asset); err != nil {
			return nil, fmt.Errorf("parse pack %s: %w", path, err)
		}
		out = append(out, loadedShadowAIPack{
			expectation: exp,
			path:        path,
			asset:       asset,
		})
	}
	return out, nil
}

func validatePackSet(packs []loadedShadowAIPack) []error {
	if len(packs) != len(expectedShadowAIPacks) {
		return []error{fmt.Errorf("expected %d Shadow AI packs, found %d", len(expectedShadowAIPacks), len(packs))}
	}
	var errs []error
	for _, pack := range packs {
		exp := pack.expectation
		attrs := pack.asset.Attributes
		if attrs.Name != exp.name {
			errs = append(errs, fmt.Errorf("%s: expected pack name %q, got %q", pack.path, exp.name, attrs.Name))
		}
		if len(attrs.Queries) != exp.queryCount {
			errs = append(errs, fmt.Errorf("%s: expected %d queries, got %d", pack.path, exp.queryCount, len(attrs.Queries)))
		}
	}
	return errs
}

func validatePackContents(pack loadedShadowAIPack) []error {
	var errs []error
	seenIDs := make(map[string]struct{}, len(pack.asset.Attributes.Queries))
	for _, query := range pack.asset.Attributes.Queries {
		ctx := fmt.Sprintf("%s query %q", pack.expectation.name, query.ID)

		if _, exists := seenIDs[query.ID]; exists {
			errs = append(errs, fmt.Errorf("%s: duplicate query id %q within pack", pack.expectation.name, query.ID))
		}
		seenIDs[query.ID] = struct{}{}

		if query.Platform != pack.expectation.platform {
			errs = append(errs, fmt.Errorf("%s: expected platform %q, got %q", ctx, pack.expectation.platform, query.Platform))
		}
		if query.Interval <= 0 {
			errs = append(errs, fmt.Errorf("%s: interval must be positive", ctx))
		}

		errs = append(errs, validateQueryReviewMappings(ctx, query)...)
		errs = append(errs, validateMappedColumns(ctx, query)...)
		errs = append(errs, validateDuplicateOrPredicates(ctx, query.Query)...)
		errs = append(errs, validateFleetSafeSQL(ctx, query.Query)...)

		expectedAction := expectedEventAction(query.ID)
		actualAction, ok := mappingStaticString(query.ECSMapping, "event.action")
		if !ok {
			errs = append(errs, fmt.Errorf("%s: missing event.action mapping", ctx))
		} else {
			if !actionFormatRE.MatchString(actualAction) {
				errs = append(errs, fmt.Errorf("%s: event.action %q must match osquery.<snake_case>", ctx, actualAction))
			}
			if actualAction != expectedAction {
				errs = append(errs, fmt.Errorf("%s: event.action %q does not match contract %q", ctx, actualAction, expectedAction))
			}
		}
	}
	return errs
}

func validateFleetSafeSQL(ctx, sql string) []error {
	if !hasSQLLineComment(sql) {
		return nil
	}
	return []error{fmt.Errorf("%s: SQL line comments are not allowed because Fleet removes query newlines", ctx)}
}

func hasSQLLineComment(sql string) bool {
	inString := false
	for i := 0; i < len(sql); i++ {
		if sql[i] == '\'' {
			if inString && i+1 < len(sql) && sql[i+1] == '\'' {
				i++
				continue
			}
			inString = !inString
			continue
		}
		if !inString && sql[i] == '-' && i+1 < len(sql) && sql[i+1] == '-' {
			return true
		}
	}
	return false
}

func validateQueryReviewMappings(ctx string, query packQuery) []error {
	var errs []error
	keys := mappingKeys(query.ECSMapping)

	for _, dropKey := range dropECSKeys {
		if containsString(keys, dropKey) {
			errs = append(errs, fmt.Errorf("%s: DROP field %q must not be mapped (Query Review Guide)", ctx, dropKey))
		}
	}
	for _, keepKey := range requiredECSKeys {
		if !containsString(keys, keepKey) {
			errs = append(errs, fmt.Errorf("%s: required KEEP field %q is missing", ctx, keepKey))
		}
	}

	for _, entry := range query.ECSMapping {
		if strings.HasPrefix(entry.Key, "gen_ai.") {
			errs = append(errs, fmt.Errorf("%s: gen_ai.* mapping %q is not allowed in inventory packs", ctx, entry.Key))
		}
		if strings.HasPrefix(entry.Key, "code_signature.") {
			errs = append(errs, fmt.Errorf("%s: unprefixed code_signature mapping %q is not allowed", ctx, entry.Key))
		}
	}

	for _, arrayKey := range staticArrayECSKeys {
		entry, ok := findMapping(query.ECSMapping, arrayKey)
		if !ok {
			continue
		}
		if fieldRef, hasField := entry.Value["field"]; hasField {
			errs = append(errs, fmt.Errorf("%s: %q must be a static array, not field reference %v", ctx, arrayKey, fieldRef))
			continue
		}
		raw, ok := entry.Value["value"]
		if !ok {
			errs = append(errs, fmt.Errorf("%s: %q must use a static value array", ctx, arrayKey))
			continue
		}
		switch typed := raw.(type) {
		case []any:
			if len(typed) == 0 {
				errs = append(errs, fmt.Errorf("%s: %q static array must not be empty", ctx, arrayKey))
			}
			for _, item := range typed {
				if _, isString := item.(string); !isString {
					errs = append(errs, fmt.Errorf("%s: %q array entries must be strings", ctx, arrayKey))
				}
			}
		case string:
			errs = append(errs, fmt.Errorf("%s: %q must be a JSON array, not string %q", ctx, arrayKey, typed))
		default:
			errs = append(errs, fmt.Errorf("%s: %q must be a static string array", ctx, arrayKey))
		}
	}

	return errs
}

func validateMappedColumns(ctx string, query packQuery) []error {
	columns := extractOutputColumns(query.Query)
	var errs []error
	for _, entry := range query.ECSMapping {
		fieldName, ok := entry.Value["field"].(string)
		if !ok || fieldName == "" {
			continue
		}
		if _, exists := columns[fieldName]; !exists {
			errs = append(errs, fmt.Errorf("%s: ecs_mapping field %q -> %q is not selected or aliased in SQL", ctx, fieldName, entry.Key))
		}
	}
	return errs
}

func validateDuplicateOrPredicates(ctx, sql string) []error {
	where := extractWhereClause(sql)
	if where == "" {
		return nil
	}

	predicates := extractLineOrPredicates(where)
	if len(predicates) == 0 {
		predicates = extractInlineOrPredicates(where)
	}

	counts := make(map[string]int)
	for _, pred := range predicates {
		norm := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(pred)), " "))
		if norm != "" {
			counts[norm]++
		}
	}

	var dups []string
	for pred, count := range counts {
		if count > 1 {
			dups = append(dups, pred)
		}
	}
	sort.Strings(dups)

	var errs []error
	for _, dup := range dups {
		errs = append(errs, fmt.Errorf("%s: duplicate OR predicate in WHERE clause: %s", ctx, dup))
	}
	return errs
}

func extractLineOrPredicates(where string) []string {
	var preds []string
	for _, line := range strings.Split(where, "\n") {
		if m := orLineRE.FindStringSubmatch(line); len(m) == 2 {
			preds = append(preds, m[1])
		}
	}
	return preds
}

func extractInlineOrPredicates(where string) []string {
	var preds []string
	for _, m := range orPredicateRE.FindAllStringSubmatch(where, -1) {
		if len(m) == 2 {
			preds = append(preds, m[1])
		}
	}
	return preds
}

func validateSharedQueryContracts(packs []loadedShadowAIPack) []error {
	byID := make(map[string]map[string]packQuery)
	for _, pack := range packs {
		for _, query := range pack.asset.Attributes.Queries {
			if byID[query.ID] == nil {
				byID[query.ID] = make(map[string]packQuery)
			}
			byID[query.ID][pack.expectation.name] = query
		}
	}

	var errs []error
	for queryID, perPack := range byID {
		if len(perPack) < 2 {
			continue
		}

		var contracts []sharedQueryContract
		for packName, query := range perPack {
			action, ok := mappingStaticString(query.ECSMapping, "event.action")
			if !ok {
				errs = append(errs, fmt.Errorf("shared query %q in %s: missing event.action", queryID, packName))
				continue
			}
			category, _ := mappingStaticStringSlice(query.ECSMapping, "event.category")
			eventType, _ := mappingStaticStringSlice(query.ECSMapping, "event.type")
			contracts = append(contracts, sharedQueryContract{
				action:   action,
				interval: query.Interval,
				snapshot: query.Snapshot,
				category: strings.Join(category, ","),
				eventTyp: strings.Join(eventType, ","),
			})
		}
		if len(contracts) < 2 {
			continue
		}
		base := contracts[0]
		for i := 1; i < len(contracts); i++ {
			other := contracts[i]
			if other.action != base.action {
				errs = append(errs, fmt.Errorf("shared query %q: inconsistent event.action %q vs %q", queryID, other.action, base.action))
			}
			if other.interval != base.interval {
				errs = append(errs, fmt.Errorf("shared query %q: inconsistent interval %d vs %d", queryID, other.interval, base.interval))
			}
			if other.snapshot != base.snapshot {
				errs = append(errs, fmt.Errorf("shared query %q: inconsistent snapshot %t vs %t", queryID, other.snapshot, base.snapshot))
			}
			if other.category != base.category {
				errs = append(errs, fmt.Errorf("shared query %q: inconsistent event.category %q vs %q", queryID, other.category, base.category))
			}
			if other.eventTyp != base.eventTyp {
				errs = append(errs, fmt.Errorf("shared query %q: inconsistent event.type %q vs %q", queryID, other.eventTyp, base.eventTyp))
			}
		}
	}

	for queryID, allowed := range partialSharedQueryPlatforms {
		actual := make([]string, 0, len(byID[queryID]))
		for packName := range byID[queryID] {
			switch packName {
			case "ai-asset-discovery-linux":
				actual = append(actual, "linux")
			case "ai-asset-discovery-macos":
				actual = append(actual, "macos")
			case "ai-asset-discovery-windows":
				actual = append(actual, "windows")
			}
		}
		sort.Strings(actual)
		expected := append([]string(nil), allowed...)
		sort.Strings(expected)
		if strings.Join(actual, ",") != strings.Join(expected, ",") {
			errs = append(errs, fmt.Errorf("partial shared query %q: expected platforms %v, found %v", queryID, expected, actual))
		}
	}

	return errs
}

var openClawProcessCorroborationMarkers = []string{
	"p.cmdline like '%openclaw%'",
	"p.cmdline like '%moltbot%'",
	"p.cmdline like '%clawdbot%'",
	"p.name like '%openclaw%'",
}

func validateOpenClawListeningPortContracts(packs []loadedShadowAIPack) []error {
	var errs []error
	for _, pack := range packs {
		exposureQuery, ok := findPackQuery(pack, "ai_listening_ports")
		if !ok {
			errs = append(errs, fmt.Errorf("%s: missing query %q", pack.expectation.name, "ai_listening_ports"))
			continue
		}
		localQuery, ok := findPackQuery(pack, "ai_listening_ports_local")
		if !ok {
			errs = append(errs, fmt.Errorf("%s: missing query %q", pack.expectation.name, "ai_listening_ports_local"))
			continue
		}

		errs = append(errs, validateOpenClawExposureListeningPorts(pack.expectation.name, exposureQuery.Query)...)
		errs = append(errs, validateOpenClawLocalListeningPorts(pack.expectation.name, localQuery.Query)...)
	}
	return errs
}

func findPackQuery(pack loadedShadowAIPack, queryID string) (packQuery, bool) {
	for _, query := range pack.asset.Attributes.Queries {
		if query.ID == queryID {
			return query, true
		}
	}
	return packQuery{}, false
}

func validateOpenClawExposureListeningPorts(packName, sql string) []error {
	ctx := fmt.Sprintf("%s query %q", packName, "ai_listening_ports")
	normalized := normalizeListeningPortSQL(sql)
	var errs []error

	errs = append(errs, requireOpenClawGatewayPort(ctx, normalized)...)
	errs = append(errs, requireOpenClawProcessCorroboration(ctx, normalized)...)
	if !strings.Contains(normalized, "l.address != '127.0.0.1'") || !strings.Contains(normalized, "l.address != '::1'") {
		errs = append(errs, fmt.Errorf("%s: must exclude loopback addresses for non-local exposure inventory", ctx))
	}
	if strings.Contains(normalized, "l.address = '127.0.0.1'") || strings.Contains(normalized, "l.address = '::1'") {
		errs = append(errs, fmt.Errorf("%s: must not require loopback-only addresses", ctx))
	}
	if !hasGroupedAddressExclusions(normalized) {
		errs = append(errs, fmt.Errorf("%s: loopback exclusions must apply to the full port predicate group (explicit parentheses)", ctx))
	}
	return errs
}

func validateOpenClawLocalListeningPorts(packName, sql string) []error {
	ctx := fmt.Sprintf("%s query %q", packName, "ai_listening_ports_local")
	normalized := normalizeListeningPortSQL(sql)
	var errs []error

	errs = append(errs, requireOpenClawGatewayPort(ctx, normalized)...)
	errs = append(errs, requireOpenClawProcessCorroboration(ctx, normalized)...)
	if !hasOpenClawLoopbackPredicate(normalized) {
		errs = append(errs, fmt.Errorf("%s: OpenClaw gateway port 18789 must be scoped to loopback addresses", ctx))
	}
	if strings.Contains(normalized, "l.address != '127.0.0.1'") || strings.Contains(normalized, "l.address != '::1'") {
		errs = append(errs, fmt.Errorf("%s: must not exclude loopback addresses globally", ctx))
	}
	return errs
}

func requireOpenClawGatewayPort(ctx, normalized string) []error {
	if strings.Contains(normalized, "l.port = 18789") {
		return nil
	}
	return []error{fmt.Errorf("%s: missing OpenClaw gateway port 18789 coverage", ctx)}
}

func requireOpenClawProcessCorroboration(ctx, normalized string) []error {
	var errs []error
	for _, marker := range openClawProcessCorroborationMarkers {
		if !strings.Contains(normalized, marker) {
			errs = append(errs, fmt.Errorf("%s: missing OpenClaw process corroboration %q", ctx, marker))
		}
	}
	if !strings.Contains(normalized, "l.port = 18789 and (") {
		errs = append(errs, fmt.Errorf("%s: port 18789 must be AND-grouped with process corroboration predicates", ctx))
	}
	return errs
}

func hasOpenClawLoopbackPredicate(normalized string) bool {
	idx := strings.Index(normalized, "l.port = 18789")
	if idx < 0 {
		return false
	}
	segment := normalized[idx:]
	if end := strings.Index(segment, ");"); end >= 0 {
		segment = segment[:end]
	}
	return strings.Contains(segment, "l.address = '127.0.0.1'") &&
		strings.Contains(segment, "l.address = '::1'")
}

func hasGroupedAddressExclusions(normalized string) bool {
	where := extractWhereClause(normalized)
	if where == "" {
		return false
	}
	trimmed := strings.TrimSpace(where)
	return strings.HasPrefix(trimmed, "(") &&
		strings.Contains(trimmed, "l.port = 18789") &&
		strings.HasSuffix(strings.TrimSpace(trimmed), "and l.address != '127.0.0.1' and l.address != '::1'")
}

func normalizeListeningPortSQL(sql string) string {
	return strings.ToLower(strings.Join(strings.Fields(sql), " "))
}

func expectedEventAction(queryID string) string {
	if action, ok := sharedActionOverrides[queryID]; ok {
		return action
	}
	return "osquery." + queryID
}

func mappingKeys(entries []ecsMappingEntry) []string {
	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, entry.Key)
	}
	return keys
}

func findMapping(entries []ecsMappingEntry, key string) (ecsMappingEntry, bool) {
	for _, entry := range entries {
		if entry.Key == key {
			return entry, true
		}
	}
	return ecsMappingEntry{}, false
}

func mappingStaticString(entries []ecsMappingEntry, key string) (string, bool) {
	entry, ok := findMapping(entries, key)
	if !ok {
		return "", false
	}
	if _, hasField := entry.Value["field"]; hasField {
		return "", false
	}
	raw, ok := entry.Value["value"]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	return s, ok
}

func mappingStaticStringSlice(entries []ecsMappingEntry, key string) ([]string, bool) {
	entry, ok := findMapping(entries, key)
	if !ok {
		return nil, false
	}
	raw, ok := entry.Value["value"]
	if !ok {
		return nil, false
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func extractWhereClause(sql string) string {
	m := whereClauseRE.FindStringSubmatch(sql)
	if len(m) < 2 {
		return ""
	}
	where := m[1]
	upper := strings.ToUpper(where)
	for _, stop := range []string{"ORDER BY", "GROUP BY", "LIMIT", ";"} {
		if idx := strings.Index(upper, stop); idx >= 0 {
			where = where[:idx]
			upper = strings.ToUpper(where)
		}
	}
	return where
}

func extractOutputColumns(sql string) map[string]struct{} {
	selectPart := extractSelectList(sql)
	columns := make(map[string]struct{})
	for _, expr := range splitSelectColumns(selectPart) {
		expr = strings.TrimSpace(expr)
		if expr == "" || expr == "*" {
			continue
		}
		if m := aliasRE.FindStringSubmatch(expr); len(m) == 2 {
			columns[m[1]] = struct{}{}
			continue
		}
		expr = strings.TrimSpace(expr)
		if i := strings.LastIndex(expr, "."); i >= 0 {
			columns[expr[i+1:]] = struct{}{}
			continue
		}
		if bareColumnRE.MatchString(expr) {
			columns[expr] = struct{}{}
		}
	}
	return columns
}

func extractSelectList(sql string) string {
	upper := strings.ToUpper(sql)
	start := strings.Index(upper, "SELECT")
	if start < 0 {
		return ""
	}
	rest := sql[start+len("SELECT"):]
	depth := 0
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && strings.HasPrefix(strings.ToUpper(rest[i:]), "FROM") {
				return rest[:i]
			}
		}
	}
	return ""
}

func splitSelectColumns(selectList string) []string {
	var cols []string
	var current strings.Builder
	depth := 0
	for i := 0; i < len(selectList); i++ {
		ch := selectList[i]
		switch ch {
		case '(':
			depth++
			current.WriteByte(ch)
		case ')':
			if depth > 0 {
				depth--
			}
			current.WriteByte(ch)
		case ',':
			if depth == 0 {
				cols = append(cols, current.String())
				current.Reset()
				continue
			}
			current.WriteByte(ch)
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		cols = append(cols, current.String())
	}
	return cols
}
