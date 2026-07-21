# Osquery Manager integration

With this integration, you can centrally manage [Osquery](https://osquery.io/) deployments to Elastic Agents in your Fleet and query host data through distributed SQL. 

This integration adds an Osquery UI in Kibana where you can:

 - Run live queries for one or more agents
 - View a history of past queries and their results
 - Schedule queries to capture OS state changes over time
 - Save queries and build a library of queries for specific use cases

Osquery results are stored in Elasticsearch, so that you can use the power of the stack to search, analyze, and visualize Osquery data.

## Investigate with Osquery
For information about using Osquery, refer to the [Osquery Kibana documentation](https://www.elastic.co/docs/solutions/security/investigate/osquery). 
This includes information about required privileges; how to run, schedule, and save queries; how to map osquery fields to ECS; and other useful information about managing Osquery with this integration.

For information about Osquery tables, refer to the [Osquery schema documentation](https://osquery.io/schema) and [Osquery Extension for Elastic](https://github.com/elastic/beats/blob/main/x-pack/osquerybeat/ext/osquery-extension/README.md).

## Shadow AI Discovery

The integration ships three canonical platform packs for endpoint AI inventory:

| Pack | Platform | Queries |
|------|----------|---------|
| `ai-asset-discovery-windows` | Windows | 19 |
| `ai-asset-discovery-macos` | macOS | 19 |
| `ai-asset-discovery-linux` | Linux | 18 |

Assign the pack matching each agent's OS to your Osquery Manager policy in Fleet. Pack queries emit `event.action: osquery.ai_*` and `osquery.mcp_*` once scheduled pack queries run on assigned agents.

### Snapshot duplicate semantics

Many inventory queries use `snapshot: true`. Each scheduled run emits a full current-state row set. Osquery Manager does not deduplicate snapshot documents in this package; analysts should expect repeated rows across intervals and use latest-per-host aggregation or time-range filters in their hunts and visualizations.

### Metadata-only privacy boundary

Pack queries inventory installed tools, paths, ports, and configuration locations. They report credential-adjacent **path metadata only** (for example Chrome Login Data, keychain paths, AWS credential file locations) and never read file contents, prompts, completions, hook payloads, consent databases, or sandbox-escalation events.

### Risk-context queries

Some queries provide detection context rather than pure inventory:

- `ai_config_file_changes` — recent MCP/AI config modifications (7200s lookback)
- `ai_sensitive_file_access` (macOS/Linux) — AI processes with open handles to sensitive paths via `process_open_files`
- `ai_sensitive_file_colocation` (Windows) — uid co-occurrence between AI processes and sensitive paths; **not access proof**
- `ai_process_network_summary` — outbound socket inventory for classified AI processes (`osquery.process_category` required); non-loopback sockets with active-ish TCP state; `is_rfc1918_destination` flags private IPv4 destinations (10/8, 172.16/12, 192.168/16)
- `ai_sensitive_file_proximity` — emits `osquery.process_category` on macOS/Linux access evidence and Windows colocation rows

macOS/Linux access evidence (`ai_sensitive_file_access`) is distinct from Windows colocation inventory (`ai_sensitive_file_colocation`).

### Platform differences

- **Windows** uses `programs`, `services`, `scheduled_tasks`, `ai_programs_windows`, and `ai_sensitive_file_colocation`.
- **macOS** uses `apps`, `launchd`, `homebrew_packages`, and `ai_sensitive_file_access`.
- **Linux** uses `deb_packages`/`rpm_packages`, `systemd`, `crontab`, and `ai_sensitive_file_access`.
- Cross-platform queries may emit platform-adapted ECS shapes (for example Windows docker uses `process.*` fallback; macOS/Linux use `container.*`; `ai_python_packages` maps Python package output to `package.*` on all platforms).

Model-file size thresholds use 100 MiB (104857600 bytes).

### Correlation with activity telemetry

Osquery inventory documents endpoint state. They do **not** emit `gen_ai.*` fields. The deprecated `gen_ai.system` ECS field was renamed to `gen_ai.provider.name` (ECS RFC 0052); that field belongs on GenAI **activity** telemetry when a request proves the provider, not on installed-process inventory.

Correlate osquery inventory with hook or OpenTelemetry activity streams by `host.*`, `user.*`, normalized process or tool identity, and time—not by manufacturing `gen_ai.*` fields in inventory rows.

### Copilot variant classification

Process queries (`ai_processes`, `ai_process_network_summary`, `ai_listening_ports`, `ai_sensitive_file_proximity`) classify running processes via a shared `CASE` subquery joined on `pid`, mapped to `osquery.process_category` (`mcp`, `agent`, `llm_runtime`). Derived queries reference that subquery once rather than re-evaluating the full detection expression in both `SELECT` and `WHERE`.

Install-time inventory queries (programs, apps, packages, browser/IDE extensions) classify Copilot-related hits into `osquery.copilot_variant` (`developer`, `productivity`, `browser`, `unknown`) where source fields support disambiguation — for example GitHub Copilot vs Microsoft 365 Copilot. Process queries do **not** emit `copilot_variant`; use `osquery.process_category` or process name/cmdline instead. The field is sparse (mostly `NULL` outside Copilot hits) and variant taxonomies differ by source, so treat it as best-effort context on install inventory only.

### Deferred follow-ups (not collected by this package)

The following are tracked separately and are **out of scope** for these inventory packs:

- Hook/OpenTelemetry GenAI activity correlation and ingest pipelines
- Windows ODR ETW / consent-database telemetry
- Sandbox-elevation and session-level telemetry
- Unsigned AI binary detection and YARA/session scanning
- Snapshot document deduplication in ingest
- Orphaned saved-search object cleanup
