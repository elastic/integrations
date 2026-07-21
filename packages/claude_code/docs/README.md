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

An example event for `events` looks as following:

```json
{
    "@timestamp": "2026-07-06T03:25:40.439Z",
    "claude_code": {
        "events": {
            "event": {
                "name": "user_prompt",
                "sequence": 0,
                "timestamp": "2026-07-06T03:25:40.439Z"
            },
            "has_hooks": true,
            "has_mcp": true,
            "prompt": {
                "id": "11111111-2222-3333-4444-555555555555"
            },
            "prompt_length": 18,
            "prompt_text": "What is 2 plus 2?",
            "session": {
                "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            },
            "terminal": {
                "type": "xterm-256color"
            },
            "user": {
                "account_id": "user_01ExampleAccountId00000",
                "account_uuid": "00000000-1111-2222-3333-444444444444"
            }
        }
    },
    "data_stream": {
        "dataset": "claude_code.events.otel",
        "namespace": "55955",
        "type": "logs"
    },
    "ecs": {
        "version": "9.3.0"
    },
    "event": {
        "action": "user_prompt",
        "agent_id_status": "missing",
        "dataset": "claude_code.events.otel",
        "ingested": "2026-07-06T03:25:50Z",
        "kind": "event",
        "original": "{\"observed_timestamp\":\"1783308340439.840708\",\"@timestamp\":\"1783308340439.834018\",\"resource\":{\"attributes\":{\"service.name\":\"claude-code\",\"service.version\":\"2.1.175\",\"host.arch\":\"amd64\",\"os.type\":\"linux\",\"os.version\":\"6.17.0-14-generic\"}},\"data_stream\":{\"namespace\":\"55955\",\"type\":\"logs\",\"dataset\":\"claude_code.events.otel\"},\"scope\":{\"name\":\"com.anthropic.claude_code.events\",\"version\":\"2.1.175\"},\"event_name\":\"user_prompt\",\"attributes\":{\"user.id\":\"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\",\"user.account_uuid\":\"00000000-1111-2222-3333-444444444444\",\"terminal.type\":\"xterm-256color\",\"event.name\":\"user_prompt\",\"event.timestamp\":\"2026-07-06T03:25:40.439819114Z\",\"prompt.id\":\"11111111-2222-3333-4444-555555555555\",\"event.sequence\":0,\"user.email\":\"test@example.com\",\"prompt_length\":18,\"elastic.preserve_original_event\":\"true\",\"organization.id\":\"00000000-0000-0000-0000-000000000001\",\"has_mcp\":\"true\",\"user.account_id\":\"user_01ExampleAccountId00000\",\"prompt\":\"What is 2 plus 2?\",\"session.id\":\"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\",\"has_hooks\":\"true\"},\"body\":{\"text\":\"claude_code.user_prompt\"},\"event\":{},\"_version_type\":\"internal\",\"_index\":\"logs-claude_code.events.otel-55955\",\"_id\":null,\"_version\":-4}",
        "outcome": "unknown",
        "provider": "claude-code"
    },
    "gen_ai": {
        "provider": {
            "name": "anthropic"
        }
    },
    "host": {
        "arch": "amd64",
        "architecture": "amd64",
        "os": {
            "platform": "linux",
            "version": "6.17.0-14-generic"
        }
    },
    "observed_timestamp": "2026-07-06T03:25:40.439840708Z",
    "organization": {
        "id": "00000000-0000-0000-0000-000000000001"
    },
    "os": {
        "type": "linux",
        "version": "6.17.0-14-generic"
    },
    "related": {
        "user": [
            "test@example.com",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
        ]
    },
    "resource": {
        "attributes": {
            "host": {
                "arch": "amd64"
            },
            "os": {
                "type": "linux",
                "version": "6.17.0-14-generic"
            },
            "service": {
                "name": "claude-code",
                "version": "2.1.175"
            }
        }
    },
    "scope": {
        "name": "com.anthropic.claude_code.events",
        "version": "2.1.175"
    },
    "service": {
        "name": "claude-code",
        "version": "2.1.175"
    },
    "tags": "preserve_original_event",
    "user": {
        "email": "test@example.com",
        "id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| claude_code.events.agent_path_count | Number of agent paths in the plugin. | long |
| claude_code.events.command_name | Slash command name from user_prompt events. | keyword |
| claude_code.events.command_path_count | Number of command paths in the plugin. | long |
| claude_code.events.cost_usd | Cost of the API request in USD. | double |
| claude_code.events.cost_usd_micros | Cost of the API request in millionths of a USD. | long |
| claude_code.events.decision | Permission decision (accept, reject). | keyword |
| claude_code.events.decision_source | Source of the permission decision (config, user_temporary, user_permanent). | keyword |
| claude_code.events.decision_type | Decision type (accept, reject). | keyword |
| claude_code.events.effort | Thinking effort level (high, medium, low). | keyword |
| claude_code.events.enabled_via | How the plugin was enabled (for example user-install). | keyword |
| claude_code.events.error | Error message from a failed operation. | keyword |
| claude_code.events.event.name | Event name from OTel attributes. | keyword |
| claude_code.events.event.sequence | Event sequence number within a prompt turn. | long |
| claude_code.events.event.timestamp | Event timestamp from OTel attributes. | date |
| claude_code.events.from_mode | Permission mode before the change. | keyword |
| claude_code.events.has_hooks | Whether the session has registered hooks. | boolean |
| claude_code.events.has_mcp | Whether the session has MCP servers. | boolean |
| claude_code.events.hook_event | Hook event type (for example SessionStart, PreToolUse). | keyword |
| claude_code.events.hook_matcher | Pattern the hook matches against (for example Bash). | keyword |
| claude_code.events.hook_name | Name of the registered hook. | keyword |
| claude_code.events.hook_source | Source of the hook definition (for example settings.json). | keyword |
| claude_code.events.hook_type | Hook type (for example command). | keyword |
| claude_code.events.host_owned_mcp | Whether MCP servers are host-owned ("true" or "false"). | boolean |
| claude_code.events.invocation_trigger | How the skill was invoked (for example user-slash). | keyword |
| claude_code.events.is_plugin | Whether the MCP server is a plugin. | boolean |
| claude_code.events.managed_only | Whether the MCP server is managed-only ("true" or "false"). | keyword |
| claude_code.events.marketplace.name | Name of the marketplace entry. | keyword |
| claude_code.events.mcp_server_name | Name of the MCP server. Extracted from tool_parameters_flattened by the ingest pipeline. | keyword |
| claude_code.events.mcp_server_scope | MCP server scope from tool_parameters. | keyword |
| claude_code.events.num_blocking | Number of hooks that blocked execution. | long |
| claude_code.events.num_cancelled | Number of hooks that were cancelled. | long |
| claude_code.events.num_hooks | Number of hooks registered for this event. | long |
| claude_code.events.num_non_blocking_error | Number of hooks that failed without blocking. | long |
| claude_code.events.num_success | Number of hooks that completed successfully. | long |
| claude_code.events.plugin.name | Plugin name. | keyword |
| claude_code.events.plugin.scope | Plugin scope (for example project, user). | keyword |
| claude_code.events.plugin.version | Plugin version. | keyword |
| claude_code.events.plugin_id_hash | Hash of the plugin identifier. | keyword |
| claude_code.events.prompt.id | Prompt turn identifier within a session. | keyword |
| claude_code.events.prompt_length | Length of the user prompt in characters. | long |
| claude_code.events.prompt_text | User prompt text. Only present when OTEL_LOG_USER_PROMPTS is enabled. Renamed from OTel attribute 'prompt' to avoid conflict with prompt.id path. | text |
| claude_code.events.safe_mode | Whether safe mode is active ("true" or "false"). | keyword |
| claude_code.events.server_name | MCP server name from connection events. | keyword |
| claude_code.events.server_scope | MCP server scope (for example project, user). | keyword |
| claude_code.events.session.id | Claude Code session identifier. | keyword |
| claude_code.events.skill.name | Activated skill name. | keyword |
| claude_code.events.skill.source | Source of the skill definition. | keyword |
| claude_code.events.skill_path_count | Number of skill paths in the plugin. | long |
| claude_code.events.source | Source of the event (for example user, system). | keyword |
| claude_code.events.speed | Request speed tier (normal, fast). | keyword |
| claude_code.events.status | Connection status (for example connected, failed). | keyword |
| claude_code.events.success | Whether the tool call succeeded ("true" or "false"). | keyword |
| claude_code.events.terminal.type | Terminal emulator type or "non-interactive" for Cowork. | keyword |
| claude_code.events.to_mode | Permission mode after the change. | keyword |
| claude_code.events.tool_input | JSON-encoded tool input. Only present when OTEL_LOG_TOOL_DETAILS is enabled. | text |
| claude_code.events.tool_input_size_bytes | Size of tool input in bytes. | long |
| claude_code.events.tool_parameters | JSON-encoded tool parameters. Only present when OTEL_LOG_TOOL_DETAILS is enabled. | text |
| claude_code.events.tool_parameters_flattened | Parsed tool_parameters as a flattened object for structured queries. Populated by the ingest pipeline. | flattened |
| claude_code.events.tool_result_size_bytes | Size of tool result in bytes. | long |
| claude_code.events.total_duration_ms | Total duration of all hook executions in milliseconds. | long |
| claude_code.events.transport_type | MCP transport type (for example stdio, sse). | keyword |
| claude_code.events.trigger | What triggered the permission mode change. | keyword |
| claude_code.events.user.account_id | Anthropic account identifier. | keyword |
| claude_code.events.user.account_uuid | Anthropic account UUID. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | match_only_text |
| error.type | The type of the error, for example the class name of the exception. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| gen_ai.operation.name | Source or type of the generative AI operation. | keyword |
| gen_ai.provider.name | Generative AI provider name. | constant_keyword |
| gen_ai.request.model | Model used for the generative AI request. | keyword |
| gen_ai.response.id | Identifier for the generative AI response. | keyword |
| gen_ai.response.model | Model that generated the response. | keyword |
| gen_ai.tool.call.arguments | Arguments passed to the tool call. | flattened |
| gen_ai.tool.call.id | Unique identifier for the tool call. | keyword |
| gen_ai.tool.name | Name of the tool invoked by the model. | keyword |
| gen_ai.usage.cache_creation.input_tokens | Number of input tokens used for cache creation. | long |
| gen_ai.usage.cache_read.input_tokens | Number of input tokens served from cache. | long |
| gen_ai.usage.input_tokens | Number of input tokens consumed. | long |
| gen_ai.usage.output_tokens | Number of output tokens generated. | long |
| organization.id | Unique identifier for the organization. | keyword |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |

