// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// zipkin-trace-sender sends sample trace JSON files to a Zipkin endpoint on SIGHUP.
// It treats HTTP 200 and 202 as success (unlike the stream container which fails on 202).
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	defaultEndpoint   = "http://elastic-agent:9411"
	defaultTracesDir  = "/sample_traces"
	defaultTracesGlob = "sample*.json"
	spansPath         = "/api/v2/spans"

	defaultTimeout = 5 * time.Second
)

func main() {
	ctx := context.Background()
	endpoint := getEnv("ZIPKIN_ENDPOINT", defaultEndpoint)
	endpoint = normalizeEndpoint(endpoint)
	spansURL := endpoint + spansPath

	tracesPattern := getEnv("TRACES_PATTERN", "")
	if tracesPattern == "" {
		tracesDir := getEnv("TRACES_DIR", defaultTracesDir)
		tracesPattern = filepath.Join(tracesDir, defaultTracesGlob)
	}

	sendDelay := time.Duration(0)
	if d := getEnv("SEND_DELAY", ""); d != "" {
		var err error
		sendDelay, err = time.ParseDuration(d)
		if err != nil {
			log.Printf("invalid SEND_DELAY %q: %v; using 0", d, err)
		}
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGHUP)
	defer stop()

	log.Printf("zipkin-trace-sender: endpoint=%s traces_pattern=%s send_delay=%s; waiting for SIGHUP", spansURL, tracesPattern, sendDelay)

	<-ctx.Done()

	if sendDelay > 0 {
		log.Printf("waiting for %s before tearing down...", sendDelay)
		select {
		case <-time.After(sendDelay):
		case <-ctx.Done():
		}
	}

	if err := sendTraces(spansURL, tracesPattern); err != nil {
		log.Printf("send failed: %v", err)
		os.Exit(1)
	}
	log.Printf("send completed successfully")
}

func normalizeEndpoint(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultEndpoint
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	return strings.TrimSuffix(u.String(), "/")
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func sendTraces(spansURL, pattern string) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob %s: %w", pattern, err)
	}
	if len(matches) == 0 {
		log.Printf("no files matched %s", pattern)
		return nil
	}

	client := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	for _, path := range matches {
		if err := sendTraceFile(client, spansURL, path); err != nil {
			return err
		}
	}

	return nil
}

// sendTraceFile reads one trace file and POSTs it to the Zipkin spans endpoint.
// It is a separate function so that defer resp.Body.Close() runs at the end of
// each call, not at the end of the loop.
func sendTraceFile(client *http.Client, spansURL, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	resp, err := client.Post(spansURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	// Zipkin returns 202 for accepted traces
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/a13d183f72cd20c2c705ec63cb5180ddb3d9b751/receiver/zipkinreceiver/trace_receiver.go#L240-L246
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("POST %s: status %d", path, resp.StatusCode)
	}
	log.Printf("posted %s -> %d", path, resp.StatusCode)
	return nil
}
