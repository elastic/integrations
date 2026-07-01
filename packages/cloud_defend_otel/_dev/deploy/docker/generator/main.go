// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
)

const (
	endpointGRPC = "elastic-agent:4317"
	count        = 50
)

func main() {
	// Wait for SIGHUP from elastic-package (agent ready signal).
	log.Println("waiting for SIGHUP...")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	<-sig
	log.Println("received SIGHUP, starting generator")

	ctx := context.Background()

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName("generator")),
	)
	if err != nil {
		log.Fatalf("failed to create resource: %v", err)
	}

	log.Printf("sending %d logs to %s", count, endpointGRPC)
	if err := sendLogs(ctx, res); err != nil {
		log.Fatalf("logs error: %v", err)
	}
	log.Println("logs sent successfully, exiting")
}

func sendLogs(ctx context.Context, res *resource.Resource) error {
	exporter, err := otlploggrpc.New(ctx,
		otlploggrpc.WithInsecure(),
		otlploggrpc.WithEndpoint(endpointGRPC),
	)
	if err != nil {
		return fmt.Errorf("create log exporter: %w", err)
	}
	log.Println("logs: exporter created")

	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)
	defer lp.Shutdown(ctx)

	logger := lp.Logger("generator")
	severities := []otellog.Severity{
		otellog.SeverityDebug,
		otellog.SeverityInfo,
		otellog.SeverityWarn,
		otellog.SeverityError,
	}
	for i := range count {
		var r otellog.Record
		r.SetSeverity(severities[i%len(severities)])
		r.SetBody(otellog.StringValue(fmt.Sprintf("log record %d", i)))
		r.SetTimestamp(time.Now())
		logger.Emit(ctx, r)
	}
	log.Printf("logs: %d records emitted, flushing", count)

	if err := lp.ForceFlush(ctx); err != nil {
		return fmt.Errorf("flush logs: %w", err)
	}
	return nil
}
