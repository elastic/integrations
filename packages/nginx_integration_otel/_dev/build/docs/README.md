{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# Nginx (composable) Integration for Elastic

## Overview
{{/* Complete this section with a short summary of what data this integration collects and the service it integrates with.*/}}
The Nginx (composable) integration collects Nginx access and error logs plus stub status metrics using OpenTelemetry-based input packages. It composes the `filelog_otel` input package for log files, the `nginx_otel_input` input package for `stub_status` metrics, and the `nginx_otel` content package so dashboards and assets stay aligned with the OTel pipeline.

### Compatibility
{{/* Complete this section with information on what 3rd party software or hardware versions this integration is compatible with */}}
- **Elastic Stack**: Kibana `^9.4.0` (see the integration manifest). An **Elastic** subscription of **basic** or higher is required.
- **Nginx access and error logs** were tested with Nginx **1.19.5** and **1.28.2** (same range as the classic Nginx integration logs). Other Nginx versions are expected to work when log paths and formats match your configuration.
- **Stub status metrics** require the [`ngx_http_stub_status_module`](http://nginx.org/en/docs/http/ngx_http_stub_status_module.html) and an HTTP endpoint the Elastic Agent can reach (for example the default `http://localhost:80/server-status`).

### How it works
{{/* Add a high level overview on how this integration works. For example, does it collect data from API calls or recieving data from a network or file.*/}}
Fleet configures Elastic Agent with this integration’s data streams. The Agent runs the EDOT collector with the [filelog receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver) to tail your access and error log files, and the [nginx receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/nginxreceiver) to scrape the configured `stub_status` URL. Telemetry is exported to Elasticsearch; the bundled **nginx_otel** content package provides dashboards once data is flowing.

Each data stream declares an explicit `dataset` override so that `data_stream.dataset` matches what the `nginx_otel` content package expects: `nginx.access.otel` (access logs), `nginx.error.otel` (error logs), and `nginxreceiver.otel` (stub status metrics). Without these overrides Fleet would default to `nginx_otel_integration.<stream>.otel`, which the content package dashboards do not filter on.

## What data does this integration collect?
{{/* Complete this section with information on what types of data the integration collects, and link to reference documentation if available
*/}}
The integration collects the following:

* **Access logs** — HTTP access lines from the files matched by your include globs (default `/var/log/nginx/access.log*`). Events are ingested as OpenTelemetry logs (for example `message` / `body` carrying the log line).
* **Error logs** — Nginx error log lines from the matched files (default `/var/log/nginx/error.log*`).
* **Stub status metrics** — Connection and request counters from the `stub_status` page, following the [nginx receiver metrics](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/nginxreceiver/documentation.md) model.

### Supported use cases
{{/* Add details on the use cases that can be enabled by using this integration. Explain why a user would want to install and use this integration. */}}
Use this integration to monitor web traffic and errors, correlate logs with stub status health metrics, and visualize Nginx observability in Kibana using the OTel-aligned **nginx_otel** dashboards. It suits deployments that already standardize on Elastic Agent with composable input packages and OpenTelemetry collectors.

## What do I need to use this integration?
{{/* List any Elastic or vendor-specific prerequisites needed before starting to install the integration. For example, Elastic self-managed or cloud deployment, or a vendor-specific credentials or accounts */}}
* Elasticsearch and Kibana meeting the integration version conditions, and Fleet set up to manage Elastic Agents.
* Elastic Agent on hosts where Nginx runs (or where log files and the stub status URL are reachable), with permission to read the configured log paths.
* Nginx configured to write access and error logs to those paths, and a working `stub_status` location reachable at the **endpoint** you configure for the stub status data stream.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent tails the Nginx log files you configure and scrapes the stub status HTTP endpoint, then ships the data to Elasticsearch for indexing and analysis.

{{/* If agentless is available for this integration, Include the below section. You can determine if agentless is available for this integration by checking the `manifest.yml` file, and looking for the existance of "policy_templates.deployment_modes.agentless.enabled": "true".
### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html) 
*/}}

### Set up steps in nginx_otel_integration
{{/* List the steps that are required to set up the 3rd party system to send data to Elastic. 
This should be specific to the steps needed to set up the 3rd party system to send data to Elastic. It should not include generic information about how to install or set up the 3rd party system itself.
*/}}
1. Ensure **access** and **error** logs are written to paths that match the globs you will set in the integration (defaults assume `/var/log/nginx/access.log*` and `/var/log/nginx/error.log*`).
2. Enable **`stub_status`** on a server block and choose a URL path (for example `/server-status`). The integration’s default **endpoint** is `http://localhost:80/server-status`; your path and port must match what you enter in Fleet.
3. Restrict who can scrape `stub_status` in production (for example allow only the Agent host or localhost), since the status page exposes server metrics.

Example `stub_status` location (adapt `listen`, `server_name`, path, and access rules to your environment):

```
location /server-status {
    stub_status;
    allow 127.0.0.1;
    deny all;
}
```

#### Vendor resources
{{/* Add vendor documentation links that are specific to the steps needed to set up the vendor system to send data to Elastic. Exclude this section if no vendor setup links are available. */}}
- [ngx_http_stub_status_module](http://nginx.org/en/docs/http/ngx_http_stub_status_module.html)
- [Nginx logging](http://nginx.org/en/docs/http/ngx_http_log_module.html)

### Set up steps in Kibana
{{/* List the steps that are required to set up the integration in Kibana.
This includes how to add the integration, and how to configure the integration, with descriptions of each available configuration option.

If multiple input types are supported, add instructions for each in a subsection.
*/}}
1. In Fleet, add the **Nginx (composable)** integration to an agent policy assigned to your Elastic Agents.
2. Enable the **access** data stream and set **Include paths** to the glob patterns for access logs (multi-value). Defaults target `/var/log/nginx/access.log*`.
3. Enable the **error** data stream and set **Include paths** for error logs. Defaults target `/var/log/nginx/error.log*`.
4. Enable the **stubstatus** data stream and set **endpoint** to the full URL of your `stub_status` page (default `http://localhost:80/server-status`). Use a hostname or IP the Agent can resolve and reach from its network namespace.

### Validation
{{/* In this section, describe the actions required to validate that the integration is working properly, and data is flowing into Elasticsearch.
If required, list the steps needed in the vendor product to start sending events or trigger alerts.
Then list how to validate that the data is in Elasticsearch, using Kibana. This could be which indices to check in the Discover table, or which built in dashboards to look at to see the data.
*/}}
1. Generate a few HTTP requests against Nginx and, if needed, trigger a benign error log line so both log types have recent data.
2. In Kibana, open **Discover** and search for the integration’s logs and metrics (for example filter by `data_stream.dataset` values such as `nginx.access.otel`, `nginx.error.otel`, and `nginxreceiver.otel`).
3. Open the **nginx_otel** dashboards supplied by the content package to confirm charts populate after documents appear.

## Troubleshooting
{{/* The troubleshooting section should contain troubleshooting for common issues specific to this integration. Do not include generic troubleshooting information. Where appropriate, include details specific to each input type.
Whenever possible, link to the troubleshooting documentation provided by the third-party software. 

IMPORTANT: Use plain text for issue descriptions, NOT bold. Example:
- No data is being collected: Verify network...
- TCP framing issues: Check that both...
Do NOT use **bold** for issue names like "**No data is being collected**:".
*/}}
- No access or error log documents: Confirm the **Include paths** globs match rotated files (for example `access.log.1`), that the Agent user can read those files, and that the Agent is assigned to the same host or volume as the logs.
- Stub status metrics missing or failing: Verify the **endpoint** URL path matches your Nginx `location`, that `stub_status` is enabled, and that firewall or `allow`/`deny` rules permit the Agent to reach the URL. A `404` usually means the path is wrong; `403` often means access control blocked the scrape.
- For Elastic Agent and Fleet issues: see [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Known issues and limitations

### Access and error log fields not parsed from raw log lines

The fields `attributes.http.request.method`, `attributes.http.response.status_code`, `attributes.http.version`, `attributes.source.address`, `attributes.url.original`, and `attributes.user_agent.name` (access logs), and `attributes.log.level` and `attributes.process.pid` (error logs) are declared in the index mappings so Elasticsearch accepts and stores them correctly when they are present. However, these fields are **not populated today**. The `filelog_otel` input package is a generic log tailer: it emits the raw log line as `body.text` and `message` but does not parse the Nginx Combined Log Format or the Nginx error log format into OTel semantic conventions.

As a result, the **[Nginx OTel] Request Health** and **[Nginx OTel] Traffic & Capacity** dashboard panels that rely on these parsed fields (status code breakdowns, top URLs, client addresses, user agents, log levels) will be empty until the limitation is addressed upstream.


## Performance and scaling
{{/* Add any vendor specific performance and scaling information to this section.
Performance and scaling information should be specific to sending data to Elasticsearch. It should not include information about the vendor product itself or generic information about performance and scaling.
*/}}
High-traffic Nginx nodes produce large log volume; tailing many large files increases Agent CPU and I/O. Stub status scraping is comparatively small; keep a single reachable endpoint per instance.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used
{{/* All inputs used by this package will be automatically listed here. Do not modify this section. */}}
This integration composes the **filelog** and **nginx** OpenTelemetry receivers via the `filelog_otel` and `nginx_otel_input` input packages. Details of each receiver appear below.

{{ inputDocs }}

### API usage
{{/* For integrations that use APIs to collect data, document all the APIs that are used, and link to relevent information. For integrations that do not use APIs, do not include this section. */}}
Stub status collection uses a simple **HTTP GET** request to the configured **endpoint** URL (the Nginx `stub_status` page). There is no separate vendor REST API for logs; access and error streams read bytes from the filesystem through the filelog receiver.

### Vendor documentation links
{{/* Add vendor documentation links which provide useful general information about the integration.*/}}
- [Nginx documentation](http://nginx.org/en/docs/)
- [filelog receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver)
- [nginx receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/nginxreceiver)

### Data streams
{{/* Repeat all information in this section for each data stream the package collects.*/}}

#### access

The `access` data stream collects Nginx HTTP access log lines from files matched by the configured include globs. Events are stored as OpenTelemetry-aligned logs. The dataset is overridden to `nginx.access` so documents land under `data_stream.dataset: nginx.access.otel`, matching the `nginx_otel` content package dashboards.

##### access fields

{{ fields "access" }}

##### access sample event

{{ event "access" }}

#### error

The `error` data stream collects Nginx error log lines from files matched by the configured include globs. The dataset is overridden to `nginx.error` so documents land under `data_stream.dataset: nginx.error.otel`, matching the `nginx_otel` content package dashboards.

##### error fields

{{ fields "error" }}

##### error sample event

{{ event "error" }}

#### stubstatus

The `stubstatus` data stream collects metrics from the Nginx `stub_status` endpoint exposed over HTTP. The dataset is overridden to `nginxreceiver` so documents land under `data_stream.dataset: nginxreceiver.otel`, matching the `nginx_otel` content package dashboards.

##### stubstatus fields

{{ fields "stubstatus" }}

##### stubstatus sample event

{{ event "stubstatus" }}

{{/* Export ILM Policies
     This accepts a list of data stream names as arguments, and will export the ILM Policies
     for each given data stream name. If no arguments are provided, all ILM Policies will be
     exported.

     If there are no ILM Policies defined, this will be an empty string.
*/}}
{{ ilm }}

{{/* Export Transforms
     This will export the transforms used by this integration.
     If there are no transforms defined, this will be an empty string.
*/}}
{{ transform }}
