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

The integration ships prebuilt osquery **packs** that inventory AI and LLM tooling across your endpoints, giving security and platform teams a single-policy way to answer "what AI is running in my fleet?" — local model runtimes, AI coding agents, Model Context Protocol (MCP) servers, model files, AI packages, browser and editor extensions, and the network and persistence footprint of AI tools.

There is one pack per operating system:

| Pack | Platform |
|------|----------|
| `ai-asset-discovery-windows` | Windows |
| `ai-asset-discovery-macos` | macOS |
| `ai-asset-discovery-linux` | Linux |

Assign the pack matching each agent's OS to your Osquery Manager policy in Fleet. Once the scheduled queries run, results are stored in Elasticsearch and tagged with an `event.action` of `osquery.ai_*`, so you can search, visualize, and build detections on top of them.

### What it inventories

- **Running AI tools** — local LLM runtimes, AI coding agents, and MCP servers, classified by role in `labels.process_category` (`llm_runtime`, `agent`, `mcp`).
- **Installed AI software** — desktop apps, OS packages, Python and npm packages, and browser/editor extensions (Chrome, Firefox, Safari, VS Code).
- **AI configuration and models** — MCP and AI tool config files, large model files, and model cache usage.
- **AI network and persistence footprint** — listening ports, outbound sockets for AI processes, and auto-start entries (Windows services, scheduled tasks, launchd, systemd, cron).

### Interpreting results

Inventory queries run in snapshot mode: every scheduled run emits a full, current-state set of rows. Expect the same asset to reappear on each interval, and use latest-per-host aggregation or time-range filters when building dashboards and hunts.

### Privacy

These queries collect **metadata only** — names, versions, paths, ports, and configuration locations. They do not read file contents, prompts, completions, or credentials.
