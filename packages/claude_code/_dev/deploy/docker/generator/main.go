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
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	logsEndpoint   = "elastic-agent:4318"
	tracesEndpoint = "elastic-agent:4320"
)

func main() {
	log.Println("waiting for SIGHUP...")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	<-sig
	log.Println("received SIGHUP, starting generator")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

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

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := emitLogs(ctx, res); err != nil {
			log.Printf("log export failed: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := emitTraces(ctx, res); err != nil {
			log.Printf("trace export failed: %v", err)
		}
	}()
	wg.Wait()

	log.Println("generator finished, exiting")
}

func emitLogs(ctx context.Context, res *resource.Resource) error {
	exporter, err := otlploghttp.New(ctx,
		otlploghttp.WithInsecure(),
		otlploghttp.WithEndpoint(logsEndpoint),
	)
	if err != nil {
		return fmt.Errorf("create log exporter: %w", err)
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
		return fmt.Errorf("flush logs: %w", err)
	}
	log.Println("all events sent")
	return nil
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

func emitTraces(ctx context.Context, res *resource.Resource) error {
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithInsecure(),
		otlptracehttp.WithEndpoint(tracesEndpoint),
	)
	if err != nil {
		return fmt.Errorf("create trace exporter: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	defer provider.Shutdown(ctx)

	tracer := provider.Tracer("com.anthropic.claude_code.tracing",
		trace.WithInstrumentationVersion("1.0.0"),
	)

	count := buildInteraction(ctx, tracer)

	if err := provider.ForceFlush(ctx); err != nil {
		return fmt.Errorf("flush spans: %w", err)
	}
	log.Printf("all %d spans sent", count)
	return nil
}

func commonSpanAttrs(spanType string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("span.type", spanType),
		attribute.String("session.id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
		attribute.String("organization.id", "00000000-0000-0000-0000-000000000001"),
		attribute.String("user.email", "test@example.com"),
		attribute.String("user.id", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"),
		attribute.String("user.account_id", "user_01ExampleAccountId00000"),
		attribute.String("user.account_uuid", "00000000-1111-2222-3333-444444444444"),
		attribute.String("terminal.type", "xterm-256color"),
	}
}

func spanAttrs(spanType string, extra ...attribute.KeyValue) []attribute.KeyValue {
	return append(commonSpanAttrs(spanType), extra...)
}

func buildInteraction(ctx context.Context, tracer trace.Tracer) int {
	start := time.Now().Add(-13 * time.Second)
	at := func(offsetMS int64) time.Time {
		return start.Add(time.Duration(offsetMS) * time.Millisecond)
	}

	const interactionDurationMS = 12545

	interactionCtx, interaction := tracer.Start(ctx, "claude_code.interaction",
		trace.WithTimestamp(at(0)),
		trace.WithAttributes(spanAttrs("interaction",
			attribute.Int64("interaction.sequence", 1),
			attribute.Int64("interaction.duration_ms", interactionDurationMS),
			attribute.String("parent.source", "none"),
			attribute.Int64("user_prompt_length", 17),
			attribute.Int64("queued_sends", 0),
		)...),
	)

	count := 1
	count += llmRequest(interactionCtx, tracer, llmRequestSpec{
		startMS:     120,
		durationMS:  2310,
		ttftMS:      640,
		stopReason:  "tool_use",
		hasToolCall: true,
		requestID:   "req_01ExampleRequestId00000",
		at:          at,
	})
	count += toolCall(interactionCtx, tracer, toolCallSpec{
		startMS:        2500,
		blockedMS:      35,
		executionMS:    13,
		toolName:       "Read",
		toolUseID:      "toolu_01ExampleToolUseId0000",
		decisionSource: "config",
		extra: []attribute.KeyValue{
			attribute.String("file_path", "/home/user/project/README.md"),
		},
		at: at,
	})
	count += toolCall(interactionCtx, tracer, toolCallSpec{
		startMS:        2600,
		blockedMS:      820,
		executionMS:    214,
		toolName:       "Bash",
		toolUseID:      "toolu_01ExampleToolUseId0001",
		decisionSource: "user_temporary",
		failed:         true,
		extra: []attribute.KeyValue{
			attribute.String("full_command", "ls -la /home/user/project"),
			attribute.String("bash_argv0", "ls"),
			attribute.String("bash_command_class", "other"),
		},
		at: at,
	})
	count += llmRequest(interactionCtx, tracer, llmRequestSpec{
		startMS:    3700,
		durationMS: 8700,
		ttftMS:     1944,
		stopReason: "end_turn",
		requestID:  "req_01ExampleRequestId00001",
		at:         at,
	})

	interaction.End(trace.WithTimestamp(at(interactionDurationMS)))
	return count
}

type llmRequestSpec struct {
	startMS     int64
	durationMS  int64
	ttftMS      int64
	stopReason  string
	hasToolCall bool
	requestID   string
	at          func(int64) time.Time
}

func llmRequest(ctx context.Context, tracer trace.Tracer, spec llmRequestSpec) int {
	_, span := tracer.Start(ctx, "claude_code.llm_request",
		trace.WithTimestamp(spec.at(spec.startMS)),
		trace.WithAttributes(spanAttrs("llm_request",
			attribute.String("model", "claude-sonnet-5"),
			attribute.String("gen_ai.system", "anthropic"),
			attribute.String("gen_ai.request.model", "claude-sonnet-5"),
			attribute.String("query_source_safe", "repl_main_thread"),
			attribute.String("llm_request.context", "interaction"),
			attribute.String("speed", "normal"),
			attribute.String("effort", "high"),
			attribute.Int64("duration_ms", spec.durationMS),
			attribute.Int64("ttft_ms", spec.ttftMS),
			attribute.Int64("first_content_ms", spec.ttftMS+3),
			attribute.Int64("input_tokens", 94),
			attribute.Int64("output_tokens", 65),
			attribute.Int64("cache_read_tokens", 46982),
			attribute.Int64("cache_creation_tokens", 0),
			attribute.Int64("attempt", 1),
			attribute.String("request_id", spec.requestID),
			attribute.String("gen_ai.response.id", spec.requestID),
			attribute.String("client_request_id", "11111111-2222-3333-4444-555555555555"),
			attribute.Bool("success", true),
			attribute.Bool("response.has_tool_call", spec.hasToolCall),
			attribute.String("stop_reason", spec.stopReason),
			attribute.StringSlice("gen_ai.response.finish_reasons", []string{spec.stopReason}),
		)...),
	)
	span.End(trace.WithTimestamp(spec.at(spec.startMS + spec.durationMS)))
	return 1
}

type toolCallSpec struct {
	startMS        int64
	blockedMS      int64
	executionMS    int64
	toolName       string
	toolUseID      string
	decisionSource string
	failed         bool
	extra          []attribute.KeyValue
	at             func(int64) time.Time
}

func toolCall(ctx context.Context, tracer trace.Tracer, spec toolCallSpec) int {
	totalMS := spec.blockedMS + spec.executionMS

	toolAttrs := spanAttrs("tool",
		attribute.String("tool_name", spec.toolName),
		attribute.String("tool_name_safe", spec.toolName),
		attribute.Int64("duration_ms", totalMS),
		attribute.Int64("result_tokens", 128),
		attribute.String("tool_use_id", spec.toolUseID),
		attribute.String("gen_ai.tool.call.id", spec.toolUseID),
	)
	toolCtx, tool := tracer.Start(ctx, "claude_code.tool",
		trace.WithTimestamp(spec.at(spec.startMS)),
		trace.WithAttributes(append(toolAttrs, spec.extra...)...),
	)

	_, blocked := tracer.Start(toolCtx, "claude_code.tool.blocked_on_user",
		trace.WithTimestamp(spec.at(spec.startMS)),
		trace.WithAttributes(spanAttrs("tool.blocked_on_user",
			attribute.Int64("duration_ms", spec.blockedMS),
			attribute.String("decision", "accept"),
			attribute.String("source", spec.decisionSource),
		)...),
	)
	blocked.End(trace.WithTimestamp(spec.at(spec.startMS + spec.blockedMS)))

	executionAttrs := spanAttrs("tool.execution",
		attribute.Int64("duration_ms", spec.executionMS),
		attribute.String("tool_use_id", spec.toolUseID),
		attribute.String("gen_ai.tool.call.id", spec.toolUseID),
		attribute.Bool("success", !spec.failed),
	)
	if spec.failed {
		executionAttrs = append(executionAttrs,
			attribute.String("error", "Error:ENOENT"),
			attribute.String("error_class", "Error_ENOENT"),
		)
	}
	_, execution := tracer.Start(toolCtx, "claude_code.tool.execution",
		trace.WithTimestamp(spec.at(spec.startMS+spec.blockedMS)),
		trace.WithAttributes(executionAttrs...),
	)
	if spec.failed {
		execution.SetStatus(codes.Error, "Error:ENOENT")
	}
	execution.End(trace.WithTimestamp(spec.at(spec.startMS + totalMS)))

	tool.End(trace.WithTimestamp(spec.at(spec.startMS + totalMS)))
	return 3
}
