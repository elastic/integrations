// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package main provides a mock Atlas API server for integration tests.
// It serves realistic Atlas API responses and supports special group IDs
// that exercise error paths in the CEL programs.
//
// Special group IDs (set as `groupId` in the system test config):
//   - "empty-processes-group"  — /processes returns an empty results list.
//     Triggers the 0 >= 0 terminal-branch state-wipe bug (before the fix).
//   - "non200-processes-group" — /processes returns HTTP 503.
//   - "non200-meas-group"      — /processes OK, but measurements return HTTP 503.
//     Triggered the missing-group_id-after-error bug (before the fix).
//
// All other group IDs (including "mongodb-group1") return normal data.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	listenAddr   = ":7780"
	digestRealm  = "MongoDB Atlas"
	digestNonce  = "mock-nonce-not-cryptographically-verified"
	expectedUser = "admin"
	dataDir      = "/data"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", route)
	log.Printf("Starting mock Atlas API on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func route(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" || r.URL.Path == "/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !isDigestAuthed(r) {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Digest realm=%q, nonce=%q, qop="auth"`, digestRealm, digestNonce))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/atlas/v2/groups/"):
		routeGroups(w, r, strings.TrimPrefix(r.URL.Path, "/api/atlas/v2/groups/"))
	case strings.HasPrefix(r.URL.Path, "/api/atlas/v2/orgs/"):
		routeOrgs(w, r, strings.TrimPrefix(r.URL.Path, "/api/atlas/v2/orgs/"))
	default:
		http.NotFound(w, r)
	}
}

// isDigestAuthed returns true when the request carries a Digest Authorization
// header with the expected username. Cryptographic verification is skipped in
// tests — only the scheme and username are checked.
func isDigestAuthed(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	return strings.HasPrefix(auth, "Digest") &&
		strings.Contains(auth, `username="`+expectedUser+`"`)
}

// routeGroups handles /api/atlas/v2/groups/{groupID}/...
func routeGroups(w http.ResponseWriter, r *http.Request, rest string) {
	groupID, tail, ok := strings.Cut(rest, "/")
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Use r.URL.Path (no query string) for routing; path ends without trailing
	// query params so HasSuffix comparisons are reliable.
	p := r.URL.Path
	switch {
	// Disk measurements must be checked before disk list and process
	// measurements because the path contains both "/disks/" and "/measurements".
	case strings.HasPrefix(tail, "processes/") &&
		strings.Contains(p, "/disks/") &&
		strings.HasSuffix(p, "/measurements"):
		handleDiskMeasurements(w, r, groupID)

	// Disk list: .../processes/{pid}/disks/   (trailing slash from CEL URL build)
	case strings.HasPrefix(tail, "processes/") &&
		strings.HasSuffix(p, "/disks/"):
		handleDiskList(w, r)

	// Process measurements: .../processes/{pid}/measurements
	case strings.HasPrefix(tail, "processes/") &&
		strings.HasSuffix(p, "/measurements"):
		handleProcessMeasurements(w, r, groupID)

	// Process list: .../processes   (query string handled via r.URL.Query())
	case tail == "processes":
		handleProcessList(w, r, groupID)

	// Hardware measurements: .../hosts/{hid}/fts/metrics/measurements
	case strings.HasPrefix(tail, "hosts/") &&
		strings.Contains(p, "/fts/metrics/measurements"):
		handleHardwareMeasurements(w, r, groupID)

	// Database logs: .../clusters/{name}/logs/mongodb.gz
	case strings.HasPrefix(tail, "clusters/") &&
		strings.HasSuffix(p, "/logs/mongodb.gz"):
		handleLog(w, r, "mongod_database_data.log")

	// Audit logs: .../clusters/{name}/logs/mongodb-audit-log.gz
	case strings.HasPrefix(tail, "clusters/") &&
		strings.HasSuffix(p, "/logs/mongodb-audit-log.gz"):
		handleLog(w, r, "mongod_audit_data.log")

	// Alerts: .../alerts
	case tail == "alerts":
		handleAlerts(w, r)

	// Events: .../events
	case tail == "events":
		handleEvents(w, r)

	// Project settings
	case tail == "settings":
		handleSettings(w, r)

	default:
		http.NotFound(w, r)
	}
}

// routeOrgs handles /api/atlas/v2/orgs/{orgID}/...
func routeOrgs(w http.ResponseWriter, r *http.Request, rest string) {
	_, tail, ok := strings.Cut(rest, "/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	if tail == "events" {
		handleEvents(w, r)
		return
	}
	http.NotFound(w, r)
}

// --------------------------------------------------------------------------
// Handlers
// --------------------------------------------------------------------------

func handleProcessList(w http.ResponseWriter, r *http.Request, groupID string) {
	switch groupID {
	case "empty-processes-group":
		// Error scenario: empty results → the 0 >= 0 terminal branch fires and
		// returns {} (before fix) or a proper reset state (after fix).
		writeJSON(w, map[string]any{
			"results":    []any{},
			"totalCount": 0,
			"links":      []any{selfLink(r)},
		})
	case "non200-processes-group":
		// Error scenario: non-200 from processes endpoint.
		writeErrorJSON(w, http.StatusServiceUnavailable,
			"SERVICE_UNAVAILABLE", "mock: process list unavailable")
	default:
		// Shape mirrors a real Atlas /processes result object (synthetic
		// identifiers only — no real host names or group IDs).
		writeJSON(w, map[string]any{
			"results": []map[string]any{{
				"id":             "hostname-1.example.mongodb.net:27017",
				"hostname":       "hostname-1.example.mongodb.net",
				"port":           27017,
				"typeName":       "REPLICA_PRIMARY",
				"version":        "8.0.27",
				"replicaSetName": "atlas-mock-shard-0",
				"userAlias":      "mock-shard-00-00.example.mongodb.net",
				"groupId":        groupID,
				"created":        "2024-01-01T00:00:00Z",
				"lastPing":       "2024-01-01T00:01:00Z",
				"links":          []any{selfLink(r)},
			}},
			"totalCount": 1,
			"links":      []any{selfLink(r)},
		})
	}
}

func handleProcessMeasurements(w http.ResponseWriter, r *http.Request, groupID string) {
	if groupID == "non200-meas-group" {
		// Error scenario: non-200 from measurements. Before the fix, the returned
		// state dropped group_id so the next evaluation crashed.
		writeErrorJSON(w, http.StatusServiceUnavailable,
			"SERVICE_UNAVAILABLE", "mock: measurements unavailable")
		return
	}
	// Top-level shape mirrors a real Atlas process-measurements response:
	// groupId, hostId, processId, start, end, granularity (ISO-8601, uppercase),
	// measurements, links. Real Atlas has no top-level "period".
	writeJSON(w, map[string]any{
		"groupId":     groupID,
		"hostId":      "hostname-1.example.mongodb.net:27017",
		"processId":   "hostname-1.example.mongodb.net:27017",
		"granularity": "PT10M",
		"start":       "2024-01-01T00:00:00Z",
		"end":         "2024-01-01T00:10:00Z",
		"measurements": []map[string]any{
			dataPoint("CONNECTIONS", "SCALAR", 38.0),
			dataPoint("ASSERT_REGULAR", "SCALAR_PER_SECOND", 0.332),
			dataPoint("PROCESS_CPU_USER", "RAW", 1.07),
			dataPoint("PROCESS_CPU_KERNEL", "RAW", 0.237),
			dataPoint("PROCESS_NORMALIZED_CPU_USER", "RAW", 0.654),
			dataPoint("PROCESS_NORMALIZED_CPU_KERNEL", "RAW", 0.073),
		},
		"links": []any{selfLink(r)},
	})
}

func handleDiskList(w http.ResponseWriter, r *http.Request) {
	// Real Atlas names the data partition "data".
	writeJSON(w, map[string]any{
		"results": []map[string]any{{
			"partitionName": "data",
			"links":         []any{selfLink(r)},
		}},
		"totalCount": 1,
		"links":      []any{selfLink(r)},
	})
}

func handleDiskMeasurements(w http.ResponseWriter, r *http.Request, groupID string) {
	if groupID == "non200-meas-group" {
		writeErrorJSON(w, http.StatusServiceUnavailable,
			"SERVICE_UNAVAILABLE", "mock: disk measurements unavailable")
		return
	}
	// Note: real Atlas disk-measurement responses omit start/end (unlike process
	// measurements, which include them).
	writeJSON(w, map[string]any{
		"groupId":       groupID,
		"hostId":        "hostname-1.example.mongodb.net:27017",
		"processId":     "hostname-1.example.mongodb.net:27017",
		"partitionName": "data",
		"granularity":   "PT10M",
		"measurements": []map[string]any{
			dataPoint("DISK_PARTITION_IOPS_READ", "SCALAR_PER_SECOND", 0.332),
			dataPoint("DISK_PARTITION_IOPS_WRITE", "SCALAR_PER_SECOND", 5.224),
			dataPoint("DISK_PARTITION_SPACE_FREE", "BYTES", 6.334e9),
			dataPoint("DISK_PARTITION_SPACE_USED", "BYTES", 1.279e9),
		},
		"links": []any{selfLink(r)},
	})
}

func handleHardwareMeasurements(w http.ResponseWriter, r *http.Request, groupID string) {
	if groupID == "non200-meas-group" {
		writeErrorJSON(w, http.StatusServiceUnavailable,
			"SERVICE_UNAVAILABLE", "mock: hardware measurements unavailable")
		return
	}
	// The hardware (FTS) endpoint returns two arrays — hardwareMeasurements and
	// statusMeasurements — which the CEL program reads by name; keep that shape.
	// hostId is intentionally omitted (the hardware pipeline maps groupId only).
	writeJSON(w, map[string]any{
		"groupId":     groupID,
		"processId":   "hostname-1.example.mongodb.net:27017",
		"granularity": "PT10M",
		"hardwareMeasurements": []map[string]any{
			dataPoint("FTS_PROCESS_CPU_USER", "RAW", 0.779),
			dataPoint("FTS_PROCESS_CPU_KERNEL", "RAW", 0.164),
			dataPoint("FTS_DISK_USAGE", "BYTES", 115420774.4),
		},
		"statusMeasurements": []map[string]any{
			dataPoint("JVM_CURRENT_MEMORY", "BYTES", 132.4),
			dataPoint("JVM_MAX_MEMORY", "BYTES", 511.0),
		},
		"links": []any{selfLink(r)},
	})
}

func handleLog(w http.ResponseWriter, _ *http.Request, filename string) {
	raw, err := os.ReadFile(dataDir + "/" + filename)
	if err != nil {
		log.Printf("WARN: cannot read %s: %v — using synthetic log line", filename, err)
		raw = []byte(`{"t":{"$date":"2024-01-01T00:00:00Z"},"s":"I","c":"NETWORK","msg":"mock log"}`)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		http.Error(w, fmt.Sprintf("gzip write: %v", err), http.StatusInternalServerError)
		return
	}
	if err := gz.Close(); err != nil {
		http.Error(w, fmt.Sprintf("gzip close: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	w.Write(buf.Bytes())
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	// Return one synthetic alert so system tests can collect and validate events.
	writeJSON(w, map[string]any{
		"results": []map[string]any{{
			"alertConfigId": "alert-config-mock-001",
			"clusterName":   "atlas-mock-cluster",
			"created":       "2024-01-01T00:00:00Z",
			"currentValue": map[string]any{
				"number": 1.0,
				"units":  "RAW",
			},
			"eventTypeName":   "OUTSIDE_METRIC_THRESHOLD",
			"groupId":         "mock-group-001",
			"hostnameAndPort": "hostname-1.example.mongodb.net:27017",
			"id":              "alert-mock-001",
			"lastNotified":    "2024-01-01T00:01:00Z",
			"metricName":      "FTS_PROCESS_CPU_USER",
			"orgId":           "mock-org-001",
			"replicaSetName":  "atlas-mock-shard-0",
			"resolved":        "2024-01-01T00:01:00Z",
			"status":          "CLOSED",
			"updated":         "2024-01-01T00:01:00Z",
		}},
		"links":      []any{selfLink(r)},
		"totalCount": 1,
	})
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	// Return one synthetic event so system tests (organization and project
	// data streams) can collect and validate events instead of timing out.
	writeJSON(w, map[string]any{
		"results": []map[string]any{{
			"created":       "2024-01-01T00:00:00Z",
			"eventTypeName": "INVITED_TO_GROUP",
			"groupId":       "mock-group-001",
			"id":            "event-mock-001",
			"isGlobalAdmin": false,
			"raw": map[string]any{
				"_t":          "USER_AUDIT",
				"cre":         "2024-01-01T00:00:00Z",
				"description": "Mock event",
				"et":          "INVITED_TO_GROUP",
				"hidden":      false,
				"id":          "event-mock-001",
				"isMmsAdmin":  false,
				"newRoles":    []string{},
				"remoteAddr":  "0.0.0.0",
				"severity":    "INFO",
				"source":      "USER",
				"un":          "mock.user@example.com",
				"ut":          "LOCAL",
			},
			"orgId":          "mock-org-001",
			"remoteAddress":  "0.0.0.0",
			"targetUsername": "mock.user@example.com",
			"userId":         "mock-user-001",
			"username":       "mock.user@example.com",
		}},
		"links":      []any{selfLink(r)},
		"totalCount": 1,
	})
}

func handleSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"isCollectDatabaseSpecificsStatisticsEnabled": true,
		"isDataExplorerEnabled":                       true,
		"isPerformanceAdvisorEnabled":                 true,
	})
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// dataPoint mirrors a real Atlas measurement entry: {name, units, dataPoints}.
// The `units` field is part of the real API shape (e.g. SCALAR, BYTES,
// SCALAR_PER_SECOND); the CEL programs read only name + dataPoints and drop the
// rest, so units never reaches an indexed document — it is here for fidelity.
func dataPoint(name, units string, value float64) map[string]any {
	return map[string]any{
		"name":  name,
		"units": units,
		"dataPoints": []map[string]any{
			{"timestamp": "2024-01-01T00:00:00Z", "value": value},
		},
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErrorJSON(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error":  code,
		"detail": detail,
	})
}

func selfLink(r *http.Request) map[string]string {
	return map[string]string{"rel": "self", "href": r.URL.String()}
}
