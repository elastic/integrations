# Claude Code

## Overview

The Claude Code integration collects [OpenTelemetry](https://opentelemetry.io/) log events and traces emitted by [Anthropic Claude Code](https://code.claude.com/), the AI coding agent. It provides typed field mappings, ingest pipelines for structured queries, security-focused dashboards for tool invocation auditing, cost monitoring, and permission analysis, and a traces overview dashboard for LLM usage, latency, and tool activity.

Claude Code exports telemetry as OTLP (OpenTelemetry Protocol) logs or traces. Each log event represents an action in an agentic session: tool calls (shell commands, file operations, MCP tool invocations), API requests, user prompts, permission decisions, and lifecycle events. Trace spans connect interactions, LLM requests, and tool calls into one trace per user turn. Trace export is in beta.

### Compatibility

This integration requires Claude Code CLI version 2.1.0 or later, which supports OTLP log export. Traces require a version that supports `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA`.

### How it works

Claude Code emits structured OTLP log records during agentic sessions. Each record carries an event name attribute identifying its type (mapped to `event.action` in ECS), along with event-specific attributes namespaced under `claude_code.*`. The Elastic Agent receives these events via its built-in OTLP HTTP receiver, applies an ingest pipeline that parses JSON-encoded tool parameters, extracts security-relevant fields, and categorizes events using ECS. The processed events are indexed into the `logs-claude_code.events.otel-*` data stream.

Trace spans are indexed into the `traces-claude_code.otel-*` data stream. Span attributes stay under `attributes` and use Elastic's native OTel mappings. The traces ingest pipeline adds ECS categorization based on `span.type`.

## What data does this integration collect?

| Data stream | Description |
|-------------|-------------|
| `events`    | All Claude Code OTLP log events — tool executions, API requests, permission decisions, MCP connections, hooks, plugins, and session lifecycle. |
| `traces` (beta) | Claude Code OTLP trace spans — interactions, LLM requests, and tool calls. |

The integration processes these event types:

| Event | Description | ECS category |
|-------|-------------|--------------|
| `tool_result` | Tool execution outcome (success/failure, duration, parameters). | `process` |
| `tool_decision` | Permission decision for a tool call (accept/reject, source). | `iam` |
| `api_request` | API call to Anthropic (model, cost, tokens, duration). | `api` |
| `user_prompt` | User prompt submission (length, command, optionally text). | — |
| `api_error` | API request failure (error, status code, retry attempt). | `api` |
| `api_refusal` | Content safety refusal from the model. | `api` |
| `permission_mode_changed` | Permission mode change (from/to mode, trigger). | `configuration` |
| `mcp_server_connection` | MCP server connection attempt (status, transport type). | `network` |
| `hook_registered` | Hook registration (name, event type, matcher). | `configuration` |
| `hook_execution_start` | Hook execution start. | `process` |
| `hook_execution_complete` | Hook execution result (success/failure counts, duration). | `process` |
| `plugin_loaded` | Plugin loaded (name, scope, paths). | `library` |
| `skill_activated` | Skill activation (name, source, trigger). | — |

And these span types:

| `span.type` | Description | ECS category |
|-------------|-------------|--------------|
| `interaction` | Root span for one user turn. | `session` |
| `llm_request` | A model request (tokens, latency, stop reason). | `api` |
| `tool` | A tool invocation within an interaction. | `process` |

Claude Code also emits other span types (for example `hook`, and nested `tool.blocked_on_user`/`tool.execution` spans). These are indexed into the `traces` data stream but aren't ECS-categorized by the ingest pipeline.

## What do I need to use this integration?

- An Elastic deployment running version 9.4.0 or later.
- Claude Code CLI with telemetry enabled (`CLAUDE_CODE_ENABLE_TELEMETRY=1`).
- For traces: `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1`.

### Verbosity gates

Claude Code has four environment variables that control how much detail is included in log events and spans:

| Variable | What it enables | Default |
|----------|----------------|---------|
| `OTEL_LOG_USER_PROMPTS` | Include the `prompt` text in `user_prompt` events and spans. | Off |
| `OTEL_LOG_TOOL_DETAILS` | Include `tool_parameters` and `tool_input` in tool events and spans. | Off |
| `OTEL_LOG_TOOL_CONTENT` | Include `tool_result` content in tool events and spans. | Off |
| `OTEL_LOG_RAW_API_BODIES` | Include raw API request/response bodies. | Off |

Enabling these gates provides richer forensic data but indexes potentially sensitive content (commands, file contents, prompts). When a gate is disabled, the corresponding fields are absent from the document — the pipeline handles this gracefully.

### Managed settings

Organizations can enforce telemetry and verbosity gates fleet-wide via MDM profiles or the admin console. Managed settings cannot be overridden by user environment variables. This ensures telemetry cannot be silently redirected or disabled on managed devices.

## How do I deploy this integration?

For general instructions on installing integrations and deploying Elastic Agent, refer to the [Getting started guide](https://www.elastic.co/docs/solutions/observability/get-started).

**Prerequisites:** Install this integration in Fleet before sending data. The installation creates the ingest pipelines, field mappings, and dashboards required for processing Claude Code events and spans.

Claude Code exports telemetry via OTLP. There are three deployment paths.

### Option A: Managed OTLP (mOTLP) (recommended)

If your Elastic Cloud deployment supports managed OTLP ingestion, point Claude Code directly at the Elastic Cloud OTLP endpoint, no agent or collector infrastructure required. Configure the environment:

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1
export OTEL_LOGS_EXPORTER=otlp
export OTEL_TRACES_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_ENDPOINT="<your-elastic-cloud-otlp-endpoint>"
export OTEL_RESOURCE_ATTRIBUTES="data_stream.dataset=claude_code.events.otel"
```

`OTEL_RESOURCE_ATTRIBUTES` applies to both logs and traces, so spans also arrive with the events dataset, in `traces-claude_code.events.otel-*`. Run the following in Kibana Dev Tools to reroute them to `traces-claude_code.otel-*`. The same pipeline handles Claude Code Desktop spans, which land in `traces-generic.otel-*` (see [Claude Code Desktop traces](#claude-code-desktop-traces)).

```console
PUT _ingest/pipeline/traces-claude-code-reroute
{
  "processors": [
    {
      "reroute": {
        "if": "['claude-code', 'claude-code-desktop'].contains(ctx.resource?.attributes?.get('service.name'))",
        "dataset": "claude_code.otel",
        "namespace": ["{{`{{data_stream.namespace}}`}}", "default"]
      }
    }
  ]
}

PUT _index_template/traces-claude-code-reroute
{
  "index_patterns": ["traces-claude_code.events.otel-*", "traces-generic.otel-*"],
  "priority": 150,
  "composed_of": ["traces@mappings", "traces@settings", "otel@mappings", "otel@settings", "traces-otel@mappings", "semconv-resource-to-ecs@mappings", "traces@custom", "traces-otel@custom", "ecs@mappings"],
  "ignore_missing_component_templates": ["traces@custom", "traces-otel@custom"],
  "template": {
    "settings": { "index.default_pipeline": "traces-claude-code-reroute" },
    "mappings": { "properties": { "data_stream.type": { "type": "constant_keyword", "value": "traces" } } }
  },
  "data_stream": { "hidden": false, "allow_custom_routing": false },
  "allow_auto_create": true
}
```

If either data stream already exists, roll it over so it picks up the new template, for example `POST traces-generic.otel-default/_rollover`. Run a rollover for each namespace you use.


### Option B: Elastic Agent OTLP receiver

The Elastic Agent exposes an OTLP HTTP receiver for each data stream on its configured HTTP endpoint (default port: 4318 for events, 4320 for traces). Configure Claude Code to send events and spans to the agent:

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1
export OTEL_LOGS_EXPORTER=otlp
export OTEL_TRACES_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://<agent-host>:4318/v1/logs"
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="http://<agent-host>:4320/v1/traces"
export OTEL_RESOURCE_ATTRIBUTES="data_stream.dataset=claude_code.events.otel"
```

### Option C: EDOT Collector

Run the [Elastic Distribution of the OpenTelemetry Collector](https://www.elastic.co/docs/reference/edot-collector) as a gateway for your Claude Code clients. The collector sets the dataset for each signal, so Claude Code doesn't need `OTEL_RESOURCE_ATTRIBUTES` or auth headers. Configure Claude Code to send events and spans to the collector:

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1
export OTEL_LOGS_EXPORTER=otlp
export OTEL_TRACES_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_ENDPOINT="http://<collector-host>:4318"
```

Example collector configuration:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

connectors:
  elasticapm:

processors:
  elasticapm:
  transform/claude_code_logs:
    log_statements:
      - context: log
        statements:
          - set(attributes["data_stream.dataset"], "claude_code.events")
  transform/claude_code_traces:
    trace_statements:
      - context: span
        statements:
          - set(attributes["data_stream.dataset"], "claude_code")
      - context: spanevent
        statements:
          - set(attributes["data_stream.dataset"], "claude_code.events")

exporters:
  otlphttp/elasticsearch:
    endpoint: ${env:ELASTIC_ENDPOINT}/_otlp
    headers:
      Authorization: "ApiKey ${env:ELASTIC_API_KEY}"

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [transform/claude_code_logs]
      exporters: [otlphttp/elasticsearch]
    traces:
      receivers: [otlp]
      processors: [transform/claude_code_traces, elasticapm]
      exporters: [elasticapm, otlphttp/elasticsearch]
    metrics/aggregated-otel-metrics:
      receivers: [elasticapm]
      processors: []
      exporters: [otlphttp/elasticsearch]
```

Without the `transform` processors, data goes to `logs-generic.otel-*` and `traces-generic.otel-*`. Elasticsearch adds the `.otel` suffix to the dataset.

### Validation

After deploying, run a short Claude Code session with telemetry enabled and confirm events appear in the `logs-claude_code.events.otel-*` data stream. For example, in Kibana Discover, filter on `data_stream.dataset: claude_code.events.otel`. For traces, filter on `data_stream.dataset: claude_code.otel`.

*Note: to use a namespace other than `default`, add `data_stream.namespace` to `OTEL_RESOURCE_ATTRIBUTES`.*

### Claude Code Desktop traces

Claude Code Desktop ignores `OTEL_RESOURCE_ATTRIBUTES` ([open issue](https://github.com/anthropics/claude-code/issues/95269)) and reports `resource.attributes.service.name: claude-code-desktop`. When Desktop sends traces directly to Elasticsearch, its spans go to `traces-generic.otel-*`. Option B and Option C set the dataset for you. For Option A, the reroute pipeline in [Option A](#option-a-managed-otlp-motlp-recommended) moves Desktop spans to `traces-claude_code.otel-*` by `service.name`.

## Troubleshooting

### No events arriving

- Verify `CLAUDE_CODE_ENABLE_TELEMETRY=1` is set in the environment where Claude Code runs.
- Check that the logs OTLP endpoint is reachable from the Claude Code host (`curl -v http://<agent-host>:<port>/v1/logs`, where `<port>` matches the HTTP Endpoint configured in the integration policy, default `4318`).
- Confirm the Elastic Agent is running and the integration policy is assigned.

### No traces arriving

- Verify `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1` and `OTEL_TRACES_EXPORTER=otlp` are set.
- Check that the traces endpoint is reachable (`curl -v http://<agent-host>:<port>/v1/traces`, default port `4320`).
- For Option A, check `traces-claude_code.events.otel-*` and `traces-generic.otel-*`. If Claude Code spans are there, confirm the reroute pipeline and template from [Option A](#option-a-managed-otlp-motlp-recommended) are installed and that the data streams were rolled over.

### Missing tool parameters or prompt text

Tool parameters, tool input, and prompt text are gated by environment variables (see [Verbosity gates](#verbosity-gates)). If these fields are absent, enable the relevant gate. On managed devices, these may be controlled by organizational policy and cannot be overridden locally.

### Pipeline errors

Events with `event.kind: pipeline_error` and a `preserve_original_event` tag indicate the events ingest pipeline encountered an error (typically malformed JSON in `tool_parameters` or `tool_input`). The original event is preserved for inspection. Spans with `event.kind: pipeline_error` indicate the traces ingest pipeline encountered an error. The failure details are in `error.message`.

## Performance and scaling

Data volume grows with usage: each user turn produces several log events and spans. Verbosity gates and **Preserve original event** (events data stream only) increase document size. For many clients, use an [EDOT Collector](#option-c-edot-collector) gateway, which batches data and can be scaled horizontally.

## Reference

### Ingest pipelines

**Events** — parses JSON-encoded tool parameters and inputs into structured fields for querying:

- `tool_parameters` (JSON string) → `tool_parameters_flattened` (flattened object)
- `tool_input` (JSON string) → `tool_input_flattened` (flattened object)

It also extracts:
- `process.command_line` from Bash tool `full_command`
- `mcp_server_name` and `mcp_tool_name` from MCP tool parameters
- `file.path` from file operation tool parameters
- `url.full` from web tool parameters

**Traces** — sets `event.category` and `event.type` from `span.type`, `related.user` from the user attributes, and extracts `process.command_line` and `file.path` from tool spans.

### Security use cases

**Tool invocation auditing** — query all Bash commands executed by a user:

```
gen_ai.tool.name: "Bash" AND event.action: "tool_result"
```

**Permission decision analysis** — find `user_permanent` auto-approvals (potential risk signal):

```
event.action: "tool_decision" AND claude_code.events.source: "user_permanent"
```

**Cost anomaly detection** — aggregate `cost_usd` per user per day to detect unusual spending patterns.

**MCP server access monitoring** — track which MCP servers users connect to and which tools they invoke:

```
event.action: "mcp_server_connection" OR (event.action: "tool_result" AND claude_code.events.mcp_server_name: *)
```

### Logs reference

#### Events

{{ event "events" }}

{{ fields "events" }}

### Traces reference

#### Spans

{{ event "traces" }}

{{ fields "traces" }}
