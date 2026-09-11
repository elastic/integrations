// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Command transport-error-mock is a synthetic Office 365 Management Activity
// API used by the audit data stream's transport-error system test. It walks the
// CEL program through the normal token -> subscribe -> list -> fetch flow, but
// the first fetch of one content blob is answered with a truncated body so the
// HTTP client fails the read with io.ErrUnexpectedEOF ("unexpected EOF"). The
// same blob succeeds on retry, which lets the test confirm that a transient
// transport failure no longer stalls collection: the other blob is still
// fetched and the failed blob is picked up on a later evaluation.
//
// All data served here is synthetic and contains no real tenant information.
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

const (
	tenant = "test-cel-tenant-id"

	goodContentID      = "blob-good"
	transientContentID = "blob-transient"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port

	m := &mock{}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", m.route)
	log.Printf("transport-error mock listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// mock holds the small amount of state needed to make the scenario
// deterministic: the content listing is served once, and the transient blob
// fails exactly once before succeeding.
type mock struct {
	mu              sync.Mutex
	listingServed   bool
	transientFailed bool
}

func (m *mock) route(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/oauth2/v2.0/token"):
		writeJSON(w, `{"access_token":"synthetic-token","token_type":"Bearer","expires_in":3600,"ext_expires_in":3600}`)
	case strings.HasSuffix(p, "/activity/feed/subscriptions/start"):
		writeJSON(w, `{"contentType":"Audit.Exchange","status":"enabled","webhook":null}`)
	case strings.HasSuffix(p, "/activity/feed/subscriptions/content"):
		m.serveListing(w, r)
	case strings.HasSuffix(p, "/activity/feed/audit/"+transientContentID):
		m.serveTransientContent(w)
	case strings.HasSuffix(p, "/activity/feed/audit/"+goodContentID):
		writeJSON(w, auditEvent("synthetic-good-0001"))
	default:
		http.NotFound(w, r)
	}
}

// serveListing returns the two content blobs on the first call and an empty
// list afterwards, so the scenario cannot grow unbounded across polls.
func (m *mock) serveListing(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	served := m.listingServed
	m.listingServed = true
	m.mu.Unlock()

	if served {
		writeJSON(w, `[]`)
		return
	}
	base := "http://" + r.Host + "/api/v1.0/" + tenant + "/activity/feed/audit/"
	writeJSON(w, `[`+
		contentRef(transientContentID, base)+`,`+
		contentRef(goodContentID, base)+
		`]`)
}

// serveTransientContent truncates the body on the first request to simulate a
// dropped connection, then serves a valid event on every later request.
func (m *mock) serveTransientContent(w http.ResponseWriter) {
	m.mu.Lock()
	failed := m.transientFailed
	m.transientFailed = true
	m.mu.Unlock()

	if failed {
		writeJSON(w, auditEvent("synthetic-transient-0001"))
		return
	}
	truncate(w)
}

// truncate advertises a large Content-Length, writes a few bytes, and then
// closes the connection so the client's body read ends with io.ErrUnexpectedEOF.
func truncate(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	bufrw.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n")
	bufrw.WriteString(`[{"Id":"synthetic-truncated"`)
	bufrw.Flush()
}

func contentRef(id, base string) string {
	return `{"contentType":"Audit.Exchange","contentId":"` + id + `","contentUri":"` + base + id + `","contentCreated":"2020-01-01T00:00:00.000Z","contentExpiration":"2199-12-31T23:59:59.000Z"}`
}

func auditEvent(id string) string {
	return `[{"Id":"` + id + `","CreationTime":"2020-01-01T00:00:00","Operation":"MailItemsAccessed","Workload":"Exchange","RecordType":2,"OrganizationId":"00000000-0000-0000-0000-000000000000","UserId":"analyst@example.com","ClientIP":"192.0.2.10"}]`
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(body))
}
