// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// emitTraces sends one Claude Code interaction trace: a root interaction span
// with two LLM requests and two tool calls, each tool call wrapping a permission
// wait and an execution span. The hierarchy and the attributes on each span type
// follow https://code.claude.com/docs/en/monitoring-usage.
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

// commonSpanAttrs are the standard attributes Claude Code sets on every span.
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
	// Lay the spans out on a fixed timeline so the duration_ms attributes agree
	// with the span durations the backend derives from start and end times.
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

// toolCall emits the parent claude_code.tool span plus its two children. The
// parent's duration_ms covers the permission wait and the execution; only the
// execution span carries success.
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
