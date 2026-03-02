// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// HTTP server instrumented with Elastic APM Go agent for system tests.
// Sends APM Intake v2 data (traces, metrics, logs) to the collector (elastic-agent:8200).
// Waits for SIGHUP to start load, then runs continuous load until SIGTERM.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmhttp"
	"go.elastic.co/apm/module/apmzap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	// Zap logger with apmzap core so that Error-level logs are sent to APM and captured as the logs signal.
	zapLogger := zap.New(&apmzap.Core{}, zap.IncreaseLevel(zapcore.ErrorLevel))
	defer func() { _ = zapLogger.Sync() }()

	// Register custom metrics gatherer for explicit metrics.
	var requestCount atomic.Uint64
	tracer := apm.DefaultTracer
	tracer.RegisterMetricsGatherer(apm.GatherMetricsFunc(func(ctx context.Context, m *apm.Metrics) error {
		c := requestCount.Load()
		m.Add("apm-app.test.counter", nil, float64(c))
		m.AddHistogram("apm-app.test.latency", nil, []float64{0.001, 0.005, 0.01}, []uint64{1, 2, 1})
		return nil
	}))

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Custom spans for simulated work (db, cache, external).
		ctx := r.Context()
		span1, ctx := apm.StartSpan(ctx, "SELECT users", "db.postgresql.query")
		time.Sleep(2 * time.Millisecond)
		span1.End()

		span2, ctx := apm.StartSpan(ctx, "cache.get", "cache.redis")
		time.Sleep(1 * time.Millisecond)
		span2.End()

		span3, ctx := apm.StartSpan(ctx, "fetch upstream", "external.http")
		time.Sleep(3 * time.Millisecond)
		span3.End()

		// Log via APM (with trace context from apmhttp) so the logs signal is captured.
		zapLogger.Error("request received", apmzap.TraceContext(ctx)...)
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := apmhttp.Wrap(mux)
	server := &http.Server{Addr: ":8080", Handler: handler}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Block until SIGHUP (agent ready); elastic-package sends SIGHUP when policy is applied.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	log.Printf("waiting for SIGHUP to start load...")
	<-sigCh
	signal.Stop(sigCh)
	log.Printf("SIGHUP received, starting continuous load...")

	// Continuous load: periodic HTTP requests until SIGTERM (test stops container).
	client := &http.Client{Timeout: 5 * time.Second}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// Handle SIGTERM to exit cleanly when test stops container.
	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, syscall.SIGTERM)

	for {
		select {
		case <-termCh:
			log.Printf("SIGTERM received, apm-app done")
			return
		case <-ticker.C:
			resp, err := client.Get("http://localhost:8080/")
			if err != nil {
				log.Printf("request: %v", err)
				continue
			}
			_ = resp.Body.Close()
			// Log outside request for logs signal even when no transaction sampled.
			zapLogger.Error("apm-app continuous load log", zap.String("source", "elasticapm_input_otel"))
			// Flush custom metrics periodically.
			tracer.SendMetrics(nil)
		}
	}
}
