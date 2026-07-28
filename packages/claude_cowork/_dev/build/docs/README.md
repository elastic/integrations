# Claude Cowork

## Overview

The Claude Cowork integration collects [OpenTelemetry](https://opentelemetry.io/) log events emitted by [Anthropic Claude Cowork](https://www.anthropic.com/), the headless AI agent for enterprise workflows. It provides typed field mappings, an ingest pipeline for structured queries, and security-focused dashboards for tool invocation auditing, cost monitoring, and permission analysis.

Claude Cowork exports telemetry as OTLP (OpenTelemetry Protocol) logs. Each event represents an action in an agentic session: tool calls, API requests, user prompts, permission decisions, and lifecycle events. Unlike the interactive Claude Code CLI, Cowork runs non-interactively (no terminal) and is typically provisioned via an organization's admin portal.

### Compatibility

This integration requires Claude Cowork with OTLP log export support.

### How it works

Claude Cowork emits structured OTLP log records during agentic sessions. Each record carries an event name attribute identifying its type (mapped to `event.action` in ECS), along with event-specific attributes namespaced under `claude_cowork.*`. The Elastic Agent receives these events via its built-in OTLP HTTP receiver, applies an ingest pipeline that extracts security-relevant fields and categorizes events using ECS. The processed events are indexed into the `logs-claude_cowork.events.otel-*` data stream.

## What data does this integration collect?

| Data stream | Description |
|-------------|-------------|
| `events`    | All Claude Cowork OTLP log events — tool executions, API requests, permission decisions, MCP connections, hooks, plugins, and session lifecycle. |

The integration processes these event types:

| Event | Description | ECS category |
|-------|-------------|--------------|
| `tool_result` | Tool execution outcome (success/failure, duration). | `process` |
| `tool_decision` | Permission decision for a tool call (accept/reject, source). | `iam` |
| `api_request` | API call to Anthropic (model, cost, tokens, duration). | `api` |
| `api_error` | Failed API call to Anthropic. | `api` |
| `api_refusal` | Content safety refusal from the model. | `api` |
| `api_retries_exhausted` | API call gave up after retries. | `api` |
| `user_prompt` | User prompt submission (length, optionally text). | |
| `auth` | Authentication event. | `authentication` |
| `permission_mode_changed` | Session permission mode change. | `configuration` |
| `mcp_server_connection` | MCP server connection state change. | `network` |
| `hook_registered` | Hook registered for an event. | `configuration` |
| `hook_execution_start` | Hook execution start. | `process` |
| `hook_execution_complete` | Hook execution result (success/failure counts, duration). | `process` |
| `plugin_loaded` | Plugin loaded (name, scope, paths). | `library` |
| `plugin_installed` | Plugin installed. | `package` |
| `skill_activated` | Skill activated. | |

## What do I need to use this integration?

- An Elastic deployment running version 9.4.0 or later.
- Claude Cowork with telemetry configured to send to your Elastic deployment.

## How do I deploy this integration?

For general instructions on installing integrations and deploying Elastic Agent, refer to the [Getting started guide](https://www.elastic.co/docs/solutions/observability/get-started).

**Prerequisites:** Install this integration in Fleet before sending data. The installation creates the ingest pipeline, field mappings, and dashboards required for processing Claude Cowork events.

Claude Cowork exports telemetry via OTLP. There are three deployment paths.

### Option A: Managed OTLP (mOTLP) (recommended)

If your Elastic Cloud deployment supports managed OTLP ingestion, configure the Cowork environment to point directly at the Elastic Cloud OTLP endpoint, no agent or collector infrastructure required:

```bash
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_ENDPOINT="<your-elastic-cloud-otlp-endpoint>"
export OTEL_RESOURCE_ATTRIBUTES="data_stream.dataset=claude_cowork.events.otel"
```

### Option B: Elastic Agent OTLP receiver

The Elastic Agent exposes an OTLP HTTP receiver on port 4318. Configure Cowork to send events to the agent:

```bash
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_ENDPOINT="http://<agent-host>:4318"
export OTEL_RESOURCE_ATTRIBUTES="data_stream.dataset=claude_cowork.events.otel"
```

### Option C: EDOT Collector

Run the [Elastic Distribution of the OpenTelemetry Collector](https://github.com/elastic/elastic-agent) with an `otlp` receiver and an `elasticsearch` exporter. Configure the `data_stream.dataset` resource attribute as above. The collector routes events to `logs-claude_cowork.events.otel-*`.

### Validation

After deploying, run a Claude Cowork session and confirm events appear in the `logs-claude_cowork.events.otel-*` data stream. For example, in Kibana Discover, filter on `data_stream.dataset: claude_cowork.events.otel`.

## Troubleshooting

### No events arriving

- Verify the Cowork instance has OTLP export configured.
- Check that the OTLP endpoint is reachable from the Cowork host (`curl -v http://<agent-host>:4318/v1/logs`).
- Confirm the Elastic Agent is running and the integration policy is assigned.

### Pipeline errors

Events with `event.kind: pipeline_error` and a `preserve_original_event` tag indicate the ingest pipeline encountered an error. The original event is preserved for inspection.

## Reference

### Ingest pipeline

The ingest pipeline expands dotted OTel attributes into a structured namespace (`claude_cowork.events.*`), converts numeric strings to typed fields, and enriches ECS fields for correlation.

### Security use cases

**Tool invocation auditing** — query all tool executions by a user:

```
event.action: "tool_result" AND related.user: "user@example.com"
```

**Cost anomaly detection** — aggregate `cost_usd` per user per day to detect unusual spending patterns.

**MCP tool access monitoring** — track which MCP tools are invoked:

```
event.action: "tool_result" AND claude_cowork.events.mcp_server.name: *
```

### Logs reference

#### Events

{{ event "events" }}

{{ fields "events" }}
