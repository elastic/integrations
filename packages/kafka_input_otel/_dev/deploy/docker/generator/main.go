// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	endpoint       = "otelcol:4317"
	healthURL      = "http://otelcol:13133"
	count          = 1000
	metricInterval = 100 * time.Millisecond
)

func main() {
	waitForOtelcol()

	ctx := context.Background()

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName("generator")),
	)
	if err != nil {
		log.Fatalf("failed to create resource: %v", err)
	}

	var wg sync.WaitGroup
	wg.Go(func() { sendSignal("traces", func() error { return sendTraces(ctx, res) }) })
	wg.Go(func() { sendSignal("metrics", func() error { return sendMetrics(ctx, res) }) })
	wg.Go(func() { sendSignal("logs", func() error { return sendLogs(ctx, res) }) })
	wg.Wait()
	log.Println("all signals sent, exiting")
}

func sendSignal(name string, send func() error) {
	log.Printf("sending %d %s to %s", count, name, endpoint)
	if err := send(); err != nil {
		log.Printf("%s error: %v", name, err)
		return
	}
	log.Printf("%s sent successfully", name)
}

func waitForOtelcol() {
	log.Println("waiting for otelcol to be ready...")
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		resp, err := client.Get(healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			log.Println("otelcol is ready")
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}
}

func sendTraces(ctx context.Context, res *resource.Resource) error {
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint(endpoint),
	)
	if err != nil {
		return fmt.Errorf("create trace exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	defer tp.Shutdown(ctx)

	tracer := tp.Tracer("generator")
	for i := range count {
		_, span := tracer.Start(ctx, fmt.Sprintf("span-%d", i))
		span.AddEvent("generator.event", trace.WithAttributes(attribute.Int("event.index", i)))
		span.End()
	}
	log.Printf("traces: %d spans created, flushing", count)

	if err := tp.ForceFlush(ctx); err != nil {
		return fmt.Errorf("flush traces: %w", err)
	}
	return nil
}

func sendMetrics(ctx context.Context, res *resource.Resource) error {
	exporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithInsecure(),
		otlpmetricgrpc.WithEndpoint(endpoint),
	)
	if err != nil {
		return fmt.Errorf("create metric exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(metricInterval))),
		sdkmetric.WithResource(res),
	)
	defer mp.Shutdown(ctx)

	meter := mp.Meter("generator")
	counter, err := meter.Int64Counter("generator.requests")
	if err != nil {
		return fmt.Errorf("create counter: %w", err)
	}

	gauge, err := meter.Float64Gauge("generator.value")
	if err != nil {
		return fmt.Errorf("create gauge: %w", err)
	}

	for i := range count {
		attrs := metric.WithAttributes(attribute.Int("index", i))
		counter.Add(ctx, 1, attrs)
		gauge.Record(ctx, float64(i), attrs)
	}
	log.Printf("metrics: %d data points recorded, flushing", count)

	if err := mp.ForceFlush(ctx); err != nil {
		return fmt.Errorf("flush metrics: %w", err)
	}
	return nil
}

func sendLogs(ctx context.Context, res *resource.Resource) error {
	exporter, err := otlploggrpc.New(ctx,
		otlploggrpc.WithInsecure(),
		otlploggrpc.WithEndpoint(endpoint),
	)
	if err != nil {
		return fmt.Errorf("create log exporter: %w", err)
	}

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
