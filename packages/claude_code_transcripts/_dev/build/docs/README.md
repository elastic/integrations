# Claude Code Transcripts Integration for Elastic

## Overview

The Claude Code Transcripts integration for Elastic collects the local log files written by [Claude Desktop](https://claude.ai/download), Anthropic's desktop app for Claude, including its Model Context Protocol (MCP) traffic. It maps each line to ECS and the `gen_ai.*` fields, and redacts secrets at ingest, before anything is stored.

Use it to audit which MCP servers and tools Claude Desktop calls on each host, to troubleshoot MCP server and app errors, and to find credentials that were written to the logs.

### Compatibility

- Claude Desktop on Windows and macOS. There is no official Linux build.
- Current Claude Desktop builds log a summary of each MCP message (method, request ID and number of result blocks). Older builds logged the full JSON-RPC message, which the integration also parses.

### How it works

Elastic Agent runs on each host where Claude Desktop is installed and tails its log files with the `filestream` input. Multi-line entries, such as stack traces, are joined into one event. The agent adds the host's time zone offset, because `main.log` is written in local time.

The ingest pipeline then:

1. Parses the timestamp, level and component of each line, and takes the user name from the log file path.
2. Recognises MCP messages and sets `event.action`, `claude_desktop.mcp.*`, and the `gen_ai` tool call fields for `tools/call` requests.
3. Scans the message, and any parsed JSON-RPC payload, for credentials such as API keys, tokens, private keys and passwords. Each one is replaced with `[REDACTED:<type>]`, and only its type and length are recorded in `claude_desktop.secrets`.

## What data does this integration collect?

The Claude Code Transcripts integration collects log messages of the following types:

- Claude Desktop app logs (`main.log`, `chrome-native-host.log` and other app log files): sign-in, plugin and update activity, and app errors.
- MCP logs (`mcp.log` and `mcp-server-<name>.log`): MCP server start-up and errors, and each MCP request, response and notification.

### Supported use cases

- Tool auditing: which MCP servers and tools are used, on which hosts and by which users. `tools/call` requests set `gen_ai.operation.name: execute_tool`.
- Troubleshooting: MCP server crashes, failed responses (`event.outcome: failure`) and app errors, by host and by server.
- Secret exposure: `claude_desktop.secrets.types` shows which kinds of credentials appeared in the logs, without storing them.

## What do I need to use this integration?

- An Elastic deployment (Elastic Cloud or self-managed) running Elastic Stack 9.4.0 or later, with Fleet.
- Elastic Agent 9.4.0 or later on each Windows or macOS host where Claude Desktop runs.
- Read access to the Claude Desktop log directories for the user that Elastic Agent runs as. Elastic Agent normally runs as a privileged service and has this access.

## How do I deploy this integration?

For general instructions on installing integrations and deploying Elastic Agent, refer to the {{ url "getting-started-observability" "Observability getting started guide" }}.

### Agent-based deployment

Elastic Agent must be installed on each host where Claude Desktop runs. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/docs/reference/fleet/install-elastic-agents). You can install only one Elastic Agent per host.

Both Fleet-managed and standalone Elastic Agents are supported. Agentless deployment is not supported, because the integration reads local files.

### Onboard and configure

No set-up is needed in Claude Desktop: it writes these logs by default. Its log files are in:

- Windows: `%APPDATA%\Claude\logs` and `%LOCALAPPDATA%\Claude\Logs`
- macOS: `~/Library/Logs/Claude`

To add the integration in Kibana:

1. In Kibana, go to **Management > Integrations**, search for **Claude Code Transcripts** and select **Add Claude Code Transcripts**.
2. Under **Collect Claude Desktop logs**, check the settings:
   - **Paths**: the log files to read. The defaults cover every user's logs on Windows and macOS.
   - **Ignore older** (advanced): skip files that have not changed within this period. Default `720h`.
   - **Maximum event size (bytes)** (advanced): the largest multi-line event the agent reads. The pipeline truncates `message` at 64 KiB in any case, and sets `claude_desktop.truncated`.
   - **Tags**, **Processors** and **Custom configurations** (advanced): extra tags, agent-side processors, and extra `filestream` options.
3. Add the integration to the agent policy of the hosts where Claude Desktop runs, and save.

### Validation

1. Open Claude Desktop on a host with the agent, and use an MCP tool, or restart the app.
2. In Kibana, go to **Discover** and filter on `data_stream.dataset: "claude_code_transcripts.desktop_log"`.
3. Check that events arrive with `service.name: claude-desktop`, that `claude_desktop.log_file` shows the source files, and that MCP messages have an `event.action` such as `mcp-request` or `mcp-response`.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

- No data is collected: check that the agent is healthy in Fleet, that the configured paths match where Claude Desktop writes its logs on that host, and that the agent can read them.
- Events are tagged `claude_desktop_unparsed_line`: the line has no recognised timestamp. The line is kept as it is in `message`.
- Events have `event.kind: pipeline_error`: the ingest pipeline failed on the line, and the reason is in `error.message`. These events are tagged `preserve_original_event`.
- Events are tagged `claude_desktop_redaction_failed` and have no `message`: the pipeline failed before the line could be scanned for credentials, so the line and the MCP, `gen_ai` and `log.logger` fields taken from it were dropped rather than stored unredacted. `error.message` names the processor that failed, without the failure message, which can quote the line.
- MCP messages are counted twice: each MCP message is written to both `mcp.log` and `mcp-server-<name>.log`. Filter on one `claude_desktop.log_file` when counting.
- Tool names are missing: current Claude Desktop builds log only a summary of each MCP message, so `gen_ai.tool.name` is set only for older builds that logged the full JSON-RPC message.
- Times are off by hours: `main.log` uses local time, and the agent adds the host's offset as `event.timezone`. Check the host's time zone settings.
- `claude_desktop.secrets.errors` is set: a secret pattern could not be evaluated on that line, for example because the line hit a regex limit. The rest of the scan still ran.

For MCP server problems themselves, check [Debugging MCP servers](https://modelcontextprotocol.io/legacy/tools/debugging).

## Performance and scaling

Each host runs its own agent and reads only its own files, so the integration scales with the number of hosts. Log volume per host is low.

Secret redaction runs in the ingest pipeline, about 20 pattern checks on each line, so it uses ingest node CPU. Most patterns find a keyword first and inspect only a short window of text after it, so the cost grows linearly with line length.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### Vendor documentation links

- [Claude Desktop](https://claude.ai/download)
- [Model Context Protocol specification](https://modelcontextprotocol.io/specification)
- [Debugging MCP servers in Claude Desktop](https://modelcontextprotocol.io/legacy/tools/debugging)

### Data streams

#### Desktop logs

The `desktop_log` data stream provides events from the Claude Desktop log files of the following types: app log lines, and MCP requests, responses and notifications.

- `log.logger` holds the app component (`oauth-v2`, `RemotePluginManager`, ...) or the MCP server name. `claude_desktop.log_file` is the file name without `.log`.
- `event.action` is `log`, `mcp-request`, `mcp-server-request`, `mcp-response` or `mcp-notification`. `event.outcome` is set on responses.
- For older builds that logged the full JSON-RPC message, the message is kept, after redaction and without being indexed, in `claude_desktop.mcp.payload`, and a JSON-RPC error is copied to `claude_desktop.mcp.error`. Parts of the message nested more than 25 levels deep are not scanned, so they are replaced with `[TRUNCATED:depth]`.
- Redaction covers every field taken from the line: `message`, `claude_desktop.mcp.*` (including the request ID), `gen_ai.*` and `log.logger`. A JSON value under a credential key, such as `"password"` or `"Authorization"`, is redacted whole, including when it contains spaces or escapes.

##### Desktop logs fields

{{ fields "desktop_log" }}

##### Desktop logs sample event

{{ event "desktop_log" }}
