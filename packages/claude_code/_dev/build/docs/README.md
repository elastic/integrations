# Claude Code

## Overview

The Claude Code integration collects [OpenTelemetry](https://opentelemetry.io/) log events emitted by [Anthropic Claude Code](https://code.claude.com/), the AI coding agent. It provides typed field mappings, an ingest pipeline for structured queries, and security-focused dashboards for tool invocation auditing, cost monitoring, and permission analysis.

Claude Code exports telemetry as OTLP (OpenTelemetry Protocol) logs. Each event represents an action in an agentic session: tool calls (shell commands, file operations, MCP tool invocations), API requests, user prompts, permission decisions, and lifecycle events.

### Compatibility

This integration requires Claude Code CLI version 2.1.0 or later, which supports OTLP log export.

### How it works

Claude Code emits structured OTLP log records during agentic sessions. Each record carries an event name attribute identifying its type (mapped to `event.action` in ECS), along with event-specific attributes namespaced under `claude_code.*`. The Elastic Agent receives these events via its built-in OTLP HTTP receiver, applies an ingest pipeline that parses JSON-encoded tool parameters, extracts security-relevant fields, and categorizes events using ECS. The processed events are indexed into the `logs-claude_code.events.otel-*` data stream.

## What data does this integration collect?

| Data stream | Description |
|-------------|-------------|
| `events`    | All Claude Code OTLP log events — tool executions, API requests, permission decisions, MCP connections, hooks, plugins, and session lifecycle. |

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

## What do I need to use this integration?

- An Elastic deployment running version 9.4.0 or later.
- Claude Code CLI with telemetry enabled (`CLAUDE_CODE_ENABLE_TELEMETRY=1`).

### Verbosity gates

Claude Code has four environment variables that control how much detail is included in telemetry events:

| Variable | What it enables | Default |
|----------|----------------|---------|
| `OTEL_LOG_USER_PROMPTS` | Include the `prompt` text in `user_prompt` events. | Off |
| `OTEL_LOG_TOOL_DETAILS` | Include `tool_parameters` and `tool_input` in tool events. | Off |
| `OTEL_LOG_TOOL_CONTENT` | Include `tool_result` content in tool events. | Off |
| `OTEL_LOG_RAW_API_BODIES` | Include raw API request/response bodies. | Off |

Enabling these gates provides richer forensic data but indexes potentially sensitive content (commands, file contents, prompts). When a gate is disabled, the corresponding fields are absent from the document — the pipeline handles this gracefully.

### Managed settings

Organizations can enforce telemetry and verbosity gates fleet-wide via MDM profiles or the admin console. Managed settings cannot be overridden by user environment variables. This ensures telemetry cannot be silently redirected or disabled on managed devices.

## How do I deploy this integration?

For general instructions on installing integrations and deploying Elastic Agent, refer to the [Getting started guide](https://www.elastic.co/docs/solutions/observability/get-started).

**Prerequisites:** Install this integration in Fleet before sending data. The installation creates the ingest pipeline, field mappings, and dashboards required for processing Claude Code events.

Claude Code exports telemetry via OTLP. There are three deployment paths.

### Option A: Managed OTLP (mOTLP) (recommended)

If your Elastic Cloud deployment supports managed OTLP ingestion, point Claude Code directly at the Elastic Cloud OTLP endpoint, no agent or collector infrastructure required. Configure the environment:

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_ENDPOINT="<your-elastic-cloud-otlp-endpoint>"
export OTEL_RESOURCE_ATTRIBUTES="data_stream.dataset=claude_code.events.otel"
```

### Option B: Elastic Agent OTLP receiver

The Elastic Agent exposes an OTLP HTTP receiver on port 4318. Configure Claude Code to send events to the agent:

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_ENDPOINT="http://<agent-host>:4318"
export OTEL_RESOURCE_ATTRIBUTES="data_stream.dataset=claude_code.events.otel"
```

### Option C: EDOT Collector

Run the [Elastic Distribution of the OpenTelemetry Collector](https://github.com/elastic/elastic-agent) with an `otlp` receiver and an `elasticsearch` exporter. Configure the `data_stream.dataset` resource attribute as above. The collector routes events to `logs-claude_code.events.otel-*`.

### Validation

After deploying, run a short Claude Code session with telemetry enabled and confirm events appear in the `logs-claude_code.events.otel-*` data stream. For example, in Kibana Discover, filter on `data_stream.dataset: claude_code.events.otel`.

## Troubleshooting

### No events arriving

- Verify `CLAUDE_CODE_ENABLE_TELEMETRY=1` is set in the environment where Claude Code runs.
- Check that the OTLP endpoint is reachable from the Claude Code host (`curl -v http://<agent-host>:4318/v1/logs`).
- Confirm the Elastic Agent is running and the integration policy is assigned.

### Missing tool parameters or prompt text

Tool parameters, tool input, and prompt text are gated by environment variables (see [Verbosity gates](#verbosity-gates)). If these fields are absent, enable the relevant gate. On managed devices, these may be controlled by organizational policy and cannot be overridden locally.

### Pipeline errors

Events with `event.kind: pipeline_error` and a `preserve_original_event` tag indicate the ingest pipeline encountered an error (typically malformed JSON in `tool_parameters` or `tool_input`). The original event is preserved for inspection.

## Reference

### Ingest pipeline

The ingest pipeline parses JSON-encoded tool parameters and inputs into structured fields for querying:

- `tool_parameters` (JSON string) → `tool_parameters_flattened` (flattened object)
- `tool_input` (JSON string) → `tool_input_flattened` (flattened object)

It also extracts:
- `process.command_line` from Bash tool `full_command`
- `mcp_server_name` and `mcp_tool_name` from MCP tool parameters
- `file.path` from file operation tool parameters
- `url.full` from web tool parameters

### Security use cases

**Tool invocation auditing** — query all Bash commands executed by a user:

```
claude_code.tool_name: "Bash" AND event.action: "tool_result"
```

**Permission decision analysis** — find `user_permanent` auto-approvals (potential risk signal):

```
event.action: "tool_decision" AND claude_code.decision_source: "user_permanent"
```

**Cost anomaly detection** — aggregate `cost_usd` per user per day to detect unusual spending patterns.

**MCP server access monitoring** — track which MCP servers users connect to and which tools they invoke:

```
event.action: "mcp_server_connection" OR (event.action: "tool_result" AND claude_code.tool_name: "mcp_tool")
```

### Logs reference

#### Events

{{ event "events" }}

{{ fields "events" }}
