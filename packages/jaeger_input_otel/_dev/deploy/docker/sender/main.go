// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	v1 "github.com/jaegertracing/jaeger-idl/model/v1"
	"github.com/jaegertracing/jaeger-idl/proto-gen/api_v2"
	"github.com/opentracing/opentracing-go"
	otlog "github.com/opentracing/opentracing-go/log"
	"github.com/uber/jaeger-client-go"
	jaegercfg "github.com/uber/jaeger-client-go/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	iterations            = 5
	defaultHTTPTracesURL  = "http://elastic-agent:14268/api/traces"
	defaultGRPCTarget     = "elastic-agent:14250"
	envProtocol           = "JAEGER_PROTOCOL"
	envServiceName        = "JAEGER_SERVICE_NAME"
	envOTELServiceName    = "OTEL_SERVICE_NAME"
	envHTTPTracesURL      = "JAEGER_ENDPOINT"
	envOTELJaegerEndpoint = "OTEL_EXPORTER_JAEGER_ENDPOINT"
	envGRPCTarget         = "JAEGER_GRPC_TARGET"
	envUDPTarget          = "JAEGER_UDP_TARGET"
	defaultUDPCompact     = "elastic-agent:6831"
	defaultUDPBinary      = "elastic-agent:6832"
)

func main() {
	log.Println("waiting for SIGHUP...")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	<-sigCh
	log.Println("received SIGHUP, sending traces")

	protocol := strings.ToLower(strings.TrimSpace(os.Getenv(envProtocol)))
	if protocol == "" {
		protocol = "grpc"
	}

	serviceName := strings.TrimSpace(os.Getenv(envServiceName))
	if serviceName == "" {
		serviceName = strings.TrimSpace(os.Getenv(envOTELServiceName))
	}
	if serviceName == "" {
		serviceName = "test-service"
	}

	var err error
	switch protocol {
	case "grpc":
		err = sendGRPC(serviceName)
	case "http":
		err = sendHTTPThrift(serviceName)
	case "thrift_compact":
		err = sendThriftCompactUDP(serviceName)
	case "thrift_binary":
		err = sendThriftBinaryUDP(serviceName)
	default:
		log.Fatalf("unsupported %s=%q (want grpc, http, thrift_compact, thrift_binary)", envProtocol, protocol)
	}
	if err != nil {
		log.Fatalf("send failed: %v", err)
	}
	log.Println("traces sent successfully")
}

func sendHTTPThrift(serviceName string) error {
	endpoint := strings.TrimSpace(os.Getenv(envHTTPTracesURL))
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv(envOTELJaegerEndpoint))
	}
	if endpoint == "" {
		endpoint = defaultHTTPTracesURL
	}
	endpoint = ensureJaegerThriftFormat(endpoint)

	cfg := jaegercfg.Configuration{
		ServiceName: serviceName,
		Sampler: &jaegercfg.SamplerConfig{
			Type:  jaeger.SamplerTypeConst,
			Param: 1,
		},
		Reporter: &jaegercfg.ReporterConfig{
			CollectorEndpoint: endpoint,
		},
	}

	tracer, closer, err := cfg.NewTracer()
	if err != nil {
		return fmt.Errorf("jaeger tracer: %w", err)
	}
	defer closer.Close()

	log.Printf("sending HTTP Thrift Jaeger spans to %s", endpoint)

	runOpenTracingSpanScenario(tracer, serviceName)
	return nil
}

func sendThriftCompactUDP(serviceName string) error {
	target := strings.TrimSpace(os.Getenv(envUDPTarget))
	if target == "" {
		target = defaultUDPCompact
	}

	cfg := jaegercfg.Configuration{
		ServiceName: serviceName,
		Sampler: &jaegercfg.SamplerConfig{
			Type:  jaeger.SamplerTypeConst,
			Param: 1,
		},
		Reporter: &jaegercfg.ReporterConfig{
			LocalAgentHostPort: target,
		},
	}

	tracer, closer, err := cfg.NewTracer()
	if err != nil {
		return fmt.Errorf("jaeger UDP compact tracer: %w", err)
	}
	defer closer.Close()

	log.Printf("sending Jaeger Thrift compact UDP (agent EmitBatch) to %s", target)
	runOpenTracingSpanScenario(tracer, serviceName)
	return nil
}

func sendThriftBinaryUDP(serviceName string) error {
	target := strings.TrimSpace(os.Getenv(envUDPTarget))
	if target == "" {
		target = defaultUDPBinary
	}

	transport, err := newBinaryUDPTransport(target, 0)
	if err != nil {
		return fmt.Errorf("binary UDP transport: %w", err)
	}
	reporter := jaeger.NewRemoteReporter(transport)

	cfg := jaegercfg.Configuration{
		ServiceName: serviceName,
		Sampler: &jaegercfg.SamplerConfig{
			Type:  jaeger.SamplerTypeConst,
			Param: 1,
		},
		Reporter: &jaegercfg.ReporterConfig{},
	}

	tracer, closer, err := cfg.NewTracer(jaegercfg.Reporter(reporter))
	if err != nil {
		return fmt.Errorf("jaeger UDP binary tracer: %w", err)
	}
	defer closer.Close()

	log.Printf("sending Jaeger Thrift binary UDP (agent EmitBatch) to %s", target)
	runOpenTracingSpanScenario(tracer, serviceName)
	return nil
}

func runOpenTracingSpanScenario(tracer opentracing.Tracer, serviceName string) {
	for i := range iterations {
		parent := tracer.StartSpan(fmt.Sprintf("operation-%d", i))
		parent.SetTag("test.iteration", i)
		parent.SetTag("test.service", serviceName)
		t0 := time.Now()
		parent.LogFields(
			otlog.Event("iteration.start"),
			otlog.Int("test.iteration", i),
			otlog.String("test.service", serviceName),
		)

		child := tracer.StartSpan("child-span", opentracing.ChildOf(parent.Context()))
		child.LogFields(
			otlog.Event("child.checkpoint"),
			otlog.Int("test.iteration", i),
			otlog.String("checkpoint.phase", "mid-work"),
		)
		time.Sleep(100 * time.Millisecond)
		child.Finish()

		parent.LogFields(
			otlog.Event("iteration.complete"),
			otlog.Int64("elapsed_ms", time.Since(t0).Milliseconds()),
		)
		parent.Finish()
	}
}

func ensureJaegerThriftFormat(endpoint string) string {
	if strings.Contains(endpoint, "format=") {
		return endpoint
	}
	if strings.Contains(endpoint, "?") {
		return endpoint + "&format=jaeger.thrift"
	}
	return endpoint + "?format=jaeger.thrift"
}

func sendGRPC(serviceName string) error {
	target := strings.TrimSpace(os.Getenv(envGRPCTarget))
	if target == "" {
		target = defaultGRPCTarget
	}

	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("grpc dial %s: %w", target, err)
	}
	defer conn.Close()

	client := api_v2.NewCollectorServiceClient(conn)

	spans := buildSpans(serviceName)
	batch := v1.Batch{
		Spans:   spans,
		Process: &v1.Process{ServiceName: serviceName},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Printf("sending gRPC Jaeger api_v2 spans to %s (%d spans)", target, len(spans))

	_, err = client.PostSpans(ctx, &api_v2.PostSpansRequest{Batch: batch})
	if err != nil {
		return fmt.Errorf("PostSpans: %w", err)
	}
	return nil
}

func buildSpans(serviceName string) []*v1.Span {
	out := make([]*v1.Span, 0, iterations*2)
	now := time.Now()

	for i := range iterations {
		traceID := v1.NewTraceID(randUint64(), randUint64())
		parentID := v1.NewSpanID(randUint64())
		childID := v1.NewSpanID(randUint64())

		tParent := now.Add(time.Duration(i) * time.Millisecond)
		tChild := tParent.Add(10 * time.Millisecond)
		parentEnd := tParent.Add(100 * time.Millisecond)

		// Jaeger span Logs map to OpenTelemetry span events; downstream they may surface on the logs signal.
		parentLogs := []v1.Log{
			{
				Timestamp: tParent.Add(2 * time.Millisecond),
				Fields: []v1.KeyValue{
					v1.String("event", "iteration.start"),
					v1.Int64("test.iteration", int64(i)),
					v1.String("test.service", serviceName),
				},
			},
			{
				Timestamp: parentEnd.Add(-5 * time.Millisecond),
				Fields: []v1.KeyValue{
					v1.String("event", "iteration.complete"),
					v1.Int64("elapsed_ms", 100),
				},
			},
		}
		childLogs := []v1.Log{
			{
				Timestamp: tChild.Add(5 * time.Millisecond),
				Fields: []v1.KeyValue{
					v1.String("event", "child.checkpoint"),
					v1.Int64("test.iteration", int64(i)),
					v1.String("checkpoint.phase", "mid-work"),
				},
			},
		}

		parent := &v1.Span{
			TraceID:       traceID,
			SpanID:        parentID,
			OperationName: fmt.Sprintf("operation-%d", i),
			StartTime:     tParent,
			Duration:      parentEnd.Sub(tParent),
			Tags: []v1.KeyValue{
				v1.Int64("test.iteration", int64(i)),
				v1.String("test.service", serviceName),
			},
			Logs: parentLogs,
		}
		child := &v1.Span{
			TraceID:       traceID,
			SpanID:        childID,
			OperationName: "child-span",
			StartTime:     tChild,
			Duration:      50 * time.Millisecond,
			References: []v1.SpanRef{
				v1.NewChildOfRef(traceID, parentID),
			},
			Tags: []v1.KeyValue{
				v1.Int64("test.iteration", int64(i)),
				v1.String("test.service", serviceName),
			},
			Logs: childLogs,
		}
		out = append(out, parent, child)
	}
	return out
}

func randUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint64(b[:])
}
