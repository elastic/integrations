# Claude Code Transcripts

Collects **Claude Desktop app/MCP logs** with Elastic Agent, maps them to ECS and the `gen_ai.*` fields, and redacts secrets at ingest.

## Data streams

| Data stream | Dataset | Source |
|---|---|---|
| `desktop_log` | `claude_code_transcripts.desktop_log` | Claude Desktop `main.log`, `mcp.log`, `mcp-server-*.log` (Windows, macOS) |

### Desktop logs
- `log.logger` holds the app component (`[oauth-v2]`, `[RemotePluginManager]`, …) or the MCP server name. `claude_desktop.log_file` is the file name (`main`, `mcp`, `mcp-server-<name>`, `chrome-native-host`, …).
- `event.action`: `log`, `mcp-request`, `mcp-response`, `mcp-notification`, `mcp-server-request`, with `claude_desktop.mcp.{server,method,id,direction,result_blocks}`. `event.outcome` is set on responses.
- Current Claude Desktop builds log only a **summary** of each MCP message (`method="tools/call" id=10 params`, `id=10 result(1 blocks)`), so tool names and arguments are not in these logs. `tools/call` sets `gen_ai.operation.name: execute_tool` and `gen_ai.tool.call.id`.
- Older builds logged the full JSON-RPC message. The pipeline parses it, adds `gen_ai.tool.name` and `error.*`, and keeps the payload unindexed in `claude_desktop.mcp.payload` after secret redaction.
- Each MCP message is written to both `mcp.log` and `mcp-server-<name>.log`. Filter on one `claude_desktop.log_file` when counting.
- `main.log` uses local time, so the agent adds `event.timezone` for it. Lines that match no known format are kept and tagged `claude_desktop_unparsed_line`.

## Requirements
Elastic Stack 9.4+ and Elastic Agent 9.4+ on the hosts where Claude Desktop runs.

## Reference

### Desktop logs

{{fields "desktop_log"}}
