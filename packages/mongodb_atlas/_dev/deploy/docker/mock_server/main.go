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
		writeJSON(w, map[string]any{
			"results": []map[string]any{{
				"id":             "hostname-1:27017",
				"hostname":       "hostname-1",
				"port":           27017,
				"typeName":       "REPLICA_PRIMARY",
				"version":        "7.0.6",
				"replicaSetName": "rs0",
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
	writeJSON(w, map[string]any{
		"processId":   "hostname-1:27017",
		"granularity": "PT1M",
		"period":      "PT1M",
		"start":       "2024-01-01T00:00:00Z",
		"end":         "2024-01-01T00:01:00Z",
		"measurements": []map[string]any{
			dataPoint("CONNECTIONS", 38.0),
			dataPoint("ASSERT_REGULAR", 0.332),
			dataPoint("PROCESS_CPU_USER", 1.07),
			dataPoint("PROCESS_CPU_KERNEL", 0.237),
			dataPoint("PROCESS_NORMALIZED_CPU_USER", 0.654),
			dataPoint("PROCESS_NORMALIZED_CPU_KERNEL", 0.073),
		},
		"links": []any{selfLink(r)},
	})
}

func handleDiskList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"results": []map[string]any{{
			"partitionName": "xvdf",
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
	writeJSON(w, map[string]any{
		"processId":     "hostname-1:27017",
		"partitionName": "xvdf",
		"granularity":   "PT1M",
		"period":        "PT1M",
		"start":         "2024-01-01T00:00:00Z",
		"end":           "2024-01-01T00:01:00Z",
		"measurements": []map[string]any{
			dataPoint("DISK_PARTITION_IOPS_READ", 0.332),
			dataPoint("DISK_PARTITION_IOPS_WRITE", 5.224),
			dataPoint("DISK_PARTITION_SPACE_FREE", 6.334e9),
			dataPoint("DISK_PARTITION_SPACE_USED", 1.279e9),
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
	writeJSON(w, map[string]any{
		"processId":   "hostname-1:27017",
		"granularity": "PT1M",
		"hardwareMeasurements": []map[string]any{
			dataPoint("FTS_PROCESS_CPU_USER", 0.779),
			dataPoint("FTS_PROCESS_CPU_KERNEL", 0.164),
			dataPoint("FTS_DISK_USAGE", 115420774.4),
		},
		"statusMeasurements": []map[string]any{
			dataPoint("JVM_CURRENT_MEMORY", 132.4),
			dataPoint("JVM_MAX_MEMORY", 511.0),
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
	gz.Write(raw)
	gz.Close()

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	w.Write(buf.Bytes())
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"results":    []any{},
		"links":      []any{selfLink(r)},
		"totalCount": 0,
	})
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"results":    []any{},
		"links":      []any{selfLink(r)},
		"totalCount": 0,
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

func dataPoint(name string, value float64) map[string]any {
	return map[string]any{
		"name": name,
		"dataPoints": []map[string]any{
			{"value": value, "timestamp": "2024-01-01T00:00:00Z"},
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
