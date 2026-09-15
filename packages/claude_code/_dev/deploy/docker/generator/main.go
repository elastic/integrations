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

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const endpoint = "elastic-agent:4318"
const traceEndpoint = "elastic-agent:4317"

func sendTraces(ctx context.Context, res *resource.Resource) {
	traceExporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint(traceEndpoint),
	)
	if err != nil {
		log.Fatalf("failed to create trace exporter: %v", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)
	defer tp.Shutdown(ctx)

	tracer := tp.Tracer("com.anthropic.claude_code.events",
		oteltrace.WithInstrumentationVersion("2.1.175"),
	)

	sessionAttrs := []attribute.KeyValue{
		attribute.String("session.id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
		attribute.String("organization.id", "00000000-0000-0000-0000-000000000001"),
		attribute.String("user.email", "test@example.com"),
		attribute.String("user.id", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"),
		attribute.String("user.account_id", "user_01ExampleAccountId00000"),
		attribute.String("user.account_uuid", "00000000-1111-2222-3333-444444444444"),
		attribute.String("terminal.type", "xterm-256color"),
	}

	// Root span: claude_code.interaction
	ctxInteraction, spanInteraction := tracer.Start(ctx, "claude_code.interaction")
	spanInteraction.SetAttributes(append(sessionAttrs,
		attribute.Int64("interaction.sequence", 1),
	)...)

	// Child: claude_code.llm_request
	_, spanLLM := tracer.Start(ctxInteraction, "claude_code.llm_request",
		oteltrace.WithSpanKind(oteltrace.SpanKindClient))
	spanLLM.SetAttributes(append(sessionAttrs,
		attribute.String("model", "claude-sonnet-4-6"),
		attribute.Int64("input_tokens", 1024),
		attribute.Int64("output_tokens", 256),
		attribute.Int64("cache_read_tokens", 512),
		attribute.Int64("cache_creation_tokens", 0),
		attribute.Int64("duration_ms", 1500),
		attribute.Int64("ttft_ms", 450),
		attribute.String("request_id", "req_01ExampleRequestId0000000"),
		attribute.String("stop_reason", "end_turn"),
		attribute.String("success", "true"),
	)...)
	spanLLM.End()

	// Child: claude_code.tool
	ctxTool, spanTool := tracer.Start(ctxInteraction, "claude_code.tool")
	spanTool.SetAttributes(append(sessionAttrs,
		attribute.String("tool_name", "Bash"),
		attribute.String("tool_use_id", "toolu_01ExampleToolUseId00000"),
		attribute.Int64("duration_ms", 500),
		attribute.Int64("result_tokens", 10),
		attribute.String("success", "true"),
	)...)

	// Grandchild: claude_code.tool.blocked_on_user
	_, spanBlocked := tracer.Start(ctxTool, "claude_code.tool.blocked_on_user")
	spanBlocked.SetAttributes(append(sessionAttrs,
		attribute.Int64("duration_ms", 120),
		attribute.String("decision", "accept"),
		attribute.String("source", "config"),
	)...)
	spanBlocked.End()

	// Grandchild: claude_code.tool.execution
	_, spanExec := tracer.Start(ctxTool, "claude_code.tool.execution")
	spanExec.SetAttributes(append(sessionAttrs,
		attribute.Int64("duration_ms", 350),
		attribute.String("success", "true"),
	)...)
	spanExec.End()

	spanTool.End()
	spanInteraction.End()

	if err := tp.ForceFlush(ctx); err != nil {
		log.Printf("trace flush failed: %v", err)
	}
	log.Println("all traces sent")
}

func main() {
	log.Println("waiting for SIGHUP...")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	<-sig
	log.Println("received SIGHUP, starting generator")

	ctx := context.Background()

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("claude-code"),
			semconv.ServiceVersion("2.1.175"),
			attribute.String("host.arch", "amd64"),
			attribute.String("os.type", "linux"),
			attribute.String("os.version", "6.17.0-14-generic"),
		),
	)
	if err != nil {
		log.Fatalf("failed to create resource: %v", err)
	}

	exporter, err := otlploghttp.New(ctx,
		otlploghttp.WithInsecure(),
		otlploghttp.WithEndpoint(endpoint),
	)
	if err != nil {
		log.Fatalf("failed to create exporter: %v", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)
	defer provider.Shutdown(ctx)

	logger := provider.Logger("com.anthropic.claude_code.events",
		otellog.WithInstrumentationVersion("2.1.175"),
	)

	events := buildEvents()
	for i, e := range events {
		var r otellog.Record
		r.SetTimestamp(time.Now())
		r.SetBody(otellog.StringValue(fmt.Sprintf("claude_code.%s", e.name)))
		r.AddAttributes(e.attrs...)
		logger.Emit(ctx, r)
		log.Printf("emitted event %d/%d: %s", i+1, len(events), e.name)
	}

	if err := provider.ForceFlush(ctx); err != nil {
		log.Printf("flush failed: %v", err)
	}

	sendTraces(ctx, res)
	log.Println("all events sent, exiting")
}

type event struct {
	name  string
	attrs []otellog.KeyValue
}

func kv(k, v string) otellog.KeyValue {
	return otellog.String(k, v)
}

func kvInt(k string, v int64) otellog.KeyValue {
	return otellog.Int64(k, v)
}

func kvFloat(k string, v float64) otellog.KeyValue {
	return otellog.Float64(k, v)
}

func commonAttrs(name string, seq int64) []otellog.KeyValue {
	return []otellog.KeyValue{
		kv("event.name", name),
		kvInt("event.sequence", seq),
		kv("event.timestamp", time.Now().UTC().Format(time.RFC3339Nano)),
		kv("session.id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
		kv("organization.id", "00000000-0000-0000-0000-000000000001"),
		kv("user.email", "test@example.com"),
		kv("user.id", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"),
		kv("user.account_id", "user_01ExampleAccountId00000"),
		kv("user.account_uuid", "00000000-1111-2222-3333-444444444444"),
		kv("terminal.type", "xterm-256color"),
	}
}

func buildEvents() []event {
	var seq int64

	e := func(name string, extra ...otellog.KeyValue) event {
		attrs := commonAttrs(name, seq)
		attrs = append(attrs, extra...)
		seq++
		return event{name: name, attrs: attrs}
	}

	return []event{
		e("user_prompt",
			kv("prompt.id", "11111111-2222-3333-4444-555555555555"),
			kvInt("prompt_length", 18),
			kv("prompt", "What is 2 plus 2?"),
			kv("has_hooks", "true"),
			kv("has_mcp", "true"),
		),

		e("api_request",
			kv("prompt.id", "11111111-2222-3333-4444-555555555555"),
			kv("model", "claude-sonnet-4-6"),
			kvFloat("cost_usd", 0.05),
			kvInt("cost_usd_micros", 50000),
			kvInt("input_tokens", 1024),
			kvInt("output_tokens", 256),
			kvInt("cache_read_tokens", 512),
			kvInt("cache_creation_tokens", 0),
			kvInt("duration_ms", 1500),
			kv("query_source", "repl_main_thread"),
			kv("request_id", "req_01ExampleRequestId0000000"),
			kv("speed", "normal"),
			kv("effort", "high"),
		),

		e("tool_decision",
			kv("prompt.id", "11111111-2222-3333-4444-555555555555"),
			kv("tool_name", "Bash"),
			kv("tool_use_id", "toolu_01ExampleToolUseId00000"),
			kv("decision", "accept"),
			kv("source", "config"),
		),

		e("tool_result",
			kv("prompt.id", "11111111-2222-3333-4444-555555555555"),
			kv("tool_name", "Bash"),
			kv("tool_use_id", "toolu_01ExampleToolUseId00000"),
			kv("success", "true"),
			kvInt("duration_ms", 150),
			kv("decision_source", "config"),
			kv("decision_type", "accept"),
			kv("tool_parameters", `{"bash_command":"echo hello","full_command":"echo hello","description":"Test command"}`),
			kv("tool_input", `{"command":"echo hello","description":"Test command"}`),
			kv("tool_input_size_bytes", "55"),
			kv("tool_result_size_bytes", "6"),
		),

		e("tool_result",
			kv("prompt.id", "11111111-2222-3333-4444-555555555555"),
			kv("tool_name", "mcp_tool"),
			kv("tool_use_id", "toolu_01ExampleToolUseId00001"),
			kv("success", "true"),
			kvInt("duration_ms", 200),
			kv("decision_source", "user_temporary"),
			kv("decision_type", "accept"),
			kv("tool_parameters", `{"mcp_server_name":"test-mcp","mcp_tool_name":"search"}`),
			kv("tool_input", `{"query":"test"}`),
			kv("tool_input_size_bytes", "16"),
			kv("tool_result_size_bytes", "42"),
			kv("mcp_server_scope", "user"),
		),

		e("tool_decision",
			kv("prompt.id", "11111111-2222-3333-4444-555555555555"),
			kv("tool_name", "Write"),
			kv("tool_use_id", "toolu_01ExampleToolUseId00002"),
			kv("decision", "reject"),
			kv("source", "user_temporary"),
		),

		e("mcp_server_connection",
			kv("server_name", "test-mcp"),
			kv("server_scope", "user"),
			kv("transport_type", "stdio"),
			kv("status", "connected"),
			kvInt("duration_ms", 150),
			kv("is_plugin", "false"),
			kv("managed_only", "false"),
		),

		e("permission_mode_changed",
			kv("from_mode", "default"),
			kv("to_mode", "plan"),
			kv("trigger", "user"),
			kv("safe_mode", "false"),
		),

		e("hook_registered",
			kv("hook_name", "test-hook"),
			kv("hook_event", "PreToolUse"),
			kv("hook_source", "settings.json"),
			kv("hook_type", "command"),
			kv("hook_matcher", "Bash"),
		),

		e("hook_execution_start",
			kv("hook_name", "test-hook"),
			kv("hook_event", "PreToolUse"),
			kv("hook_source", "settings.json"),
			kvInt("num_hooks", 1),
		),

		e("hook_execution_complete",
			kv("hook_name", "test-hook"),
			kv("hook_event", "PreToolUse"),
			kv("hook_source", "settings.json"),
			kvInt("num_hooks", 1),
			kvInt("num_success", 1),
			kvInt("num_blocking", 0),
			kvInt("num_non_blocking_error", 0),
			kvInt("num_cancelled", 0),
			kvInt("total_duration_ms", 50),
		),

		e("plugin_loaded",
			kv("plugin.name", "test-plugin"),
			kv("plugin.scope", "project"),
			kv("plugin.version", "1.0.0"),
			kv("plugin_id_hash", "0000000000000000"),
			kv("enabled_via", "user-install"),
			kvInt("agent_path_count", 0),
			kvInt("command_path_count", 0),
			kvInt("skill_path_count", 1),
		),

		e("skill_activated",
			kv("skill.name", "test-skill"),
			kv("skill.source", "plugin"),
			kv("invocation_trigger", "user-slash"),
		),
	}
}
