# HarfangLab EDR

This integration collects security telemetry from the HarfangLab EDR agent and ingests it into Elasticsearch.

The HarfangLab agent emits events already formatted against the Elastic Common Schema
(ECS) version 9.0.0. The integration supports two collection modes, and a lightweight
ingest pipeline restores and cleans up each event before indexing regardless of the mode:

- **Push mode** — the integration exposes an HTTP endpoint that the HarfangLab solution
  posts events to.
- **Pull mode** — the integration periodically polls the HarfangLab API and retrieves
  queued events.

Enable whichever input matches how your HarfangLab solution is configured. Both write to
the same `harfanglab.generic` data stream and produce identical documents.

## Requirements

- Elastic Stack 9.x (tested on 9.2.x).
- An Elastic Agent.
  - For **push mode**, the HarfangLab solution must be able to reach the Elastic Agent's
    HTTP endpoint over the network.
  - For **pull mode**, the Elastic Agent must be able to reach the HarfangLab API over the
    network.

## Data collection

### Push mode (`http_endpoint`)

The integration configures the Elastic Agent `http_endpoint` input. The HarfangLab
solution sends events as JSON in the body of an HTTP request. The raw request body is
preserved on `event.original`, so the unmodified event is always available.

### Pull mode (`cel`)

The integration configures the Elastic Agent `cel` input to poll
`<base URL>/api/data/connectors/elastic/pull/` on a fixed interval. Each request returns
the oldest queued chunk and removes it server-side; an empty response means the queue is
drained. A single poll keeps requesting until the queue is empty, so a backlog clears
within one interval. The raw JSON of each event is preserved on `event.original`.

Requests authenticate with a HarfangLab API token sent as `Authorization: Token <value>`.
The token must belong to a user granted the **elastic pull** permission.

## Configuration

When adding the integration to an Agent policy, enable the input for your chosen mode.

### Push mode settings

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| Listen address | text | `0.0.0.0` | Bind address the HTTP endpoint listens on. |
| Listen port | integer | `8080` | Port the HTTP endpoint listens on. |
| Secret header name | text | `Authorization` | Name of the HTTP request header used to authenticate incoming requests. |
| Secret header value | password | _(none)_ | Expected value of the secret header. When set, requests without a matching header value are rejected. Leave empty to disable header authentication. |
| TLS configuration | yaml | _(none)_ | Optional TLS settings. When a server certificate and key are provided, the endpoint serves HTTPS instead of HTTP. Supports client-certificate authentication (mTLS). |

### Pull mode settings

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| HarfangLab base URL | text | _(none)_ | Base URL of the HarfangLab instance (for example `https://edr.example.com`). A trailing slash is stripped automatically. The fixed pull endpoint path is appended. |
| API token | password | _(none)_ | API token of a HarfangLab user granted the **elastic pull** permission. A leading `Token ` prefix is stripped automatically. |
| Polling interval | text | `1m` | How often to poll for new events. Supports duration units such as `30s`, `1m`, `5m`. |
| TLS configuration | yaml | _(none)_ | Optional TLS settings for the connection to the HarfangLab API. Use it to trust a private CA or to relax verification in test environments. Leave empty for full verification against the system trust store. |

### Push mode TLS

By default the endpoint serves plain HTTP. To serve HTTPS, fill in the **TLS configuration**
setting with at least a server certificate and key:

```yaml
certificate: "/etc/elastic-agent/certs/server.crt"
key: "/etc/elastic-agent/certs/server.key"
```

To additionally require clients to present a certificate (mutual TLS), add
`certificate_authorities` and set `client_authentication` to `required`. Leaving the setting
empty (or fully commented out) keeps the endpoint on plain HTTP.

## Data streams

Events are split into two data streams at ingest:

- **`harfanglab.detection`** — detection alerts (events with `event.kind: alert`), indexed as
  `logs-harfanglab.detection-<namespace>`.
- **`harfanglab.generic`** — all other telemetry, indexed as `logs-harfanglab.generic-<namespace>`.

Both inputs (push and pull) ingest into `harfanglab.generic`; a `reroute` processor in the ingest
pipeline moves detection alerts into `harfanglab.detection`.

## Processing

The ingest pipeline:

1. Parses the JSON request body and merges it to the document root.
2. Restores `event.original` with the unmodified request body.
3. Derives the canonical ECS fields `host.name` (from `host.hostname`) and `user.name` (from
   `process.user.name`) when the event does not already set them. Elastic Security relies on
   `host.name` and `user.name` for its host/user pivots, detail pages and alert columns.
4. Removes intermediate fields created while parsing.
5. Drops empty `{}` payloads, which the agent sends to test connectivity.
6. Reroutes detection alerts (`event.kind: alert`) to the `harfanglab.detection` data stream.

## Detection rule

The integration ships a detection rule, **HarfangLab EDR: strong-confidence detection**, which
raises a high-severity alert whenever the HarfangLab EDR reports a detection with
`hlab.detection.confidence: "strong"`. It is a simple custom query rule
(`hlab.detection.confidence : "strong"`) over `logs-harfanglab.*`, running every 5 minutes.
(Detections are rerouted to `logs-harfanglab.detection-*`; the rule's index pattern covers both
data streams.)

The rule installs automatically with the integration (it requires the `security` capability,
i.e. an Elastic deployment with Security enabled). After installing the integration:

1. Go to **Security → Rules → Detection rules (SIEM)**.
2. Find **HarfangLab EDR: strong-confidence detection** — it installs **disabled**, so toggle it
   on to start generating alerts.
3. Optionally add an action (email, Slack, etc.) to be notified outside the Alerts table, and
   tune the severity, schedule, or query to fit your environment.

The `hlab.detection.confidence` field is mapped as a `keyword` by this integration so the query
matches exact values.

## Process tree (Visual Event Analyzer)

Elastic Security can draw a process tree (the **Analyze event** button → Visual Event Analyzer)
from process events. Kibana only offers that button for an allowlist of sources, which does not
include custom integrations, so this integration relabels process-bearing events as
Sysmon-via-Winlogbeat (`agent.type: winlogbeat`, `event.module: sysmon`). With that in place,
**Analyze event** appears on process events and HarfangLab detection alerts that carry a
`process.entity_id`, and the tree is built from your process telemetry.

Notes and trade-offs:

- Only events that carry `process.entity_id` are relabeled; the original value is preserved in
  `labels.agent_type` (e.g. `hurukai`).
- The Sysmon schema resolves ancestors by walking `process.parent.entity_id` across documents,
  so the tree goes back as far as the matching process events exist in the index.
- This source is treated as ingested logs (not a managed agent), so it does not appear as an
  endpoint with an agent status — there is no misleading "offline" badge.

## Dashboards

- **HarfangLab EDR - Detections** — an overview of detection alerts (`logs-harfanglab.detection-*`):
  total count and trend over time, with breakdowns by severity (`hlab.detection.level`),
  confidence (`hlab.detection.confidence`), engine (`hlab.detection.engine.name`), rule
  (`hlab.detection.title`), host (`host.name`) and user (`user.name`), plus a table listing the
  individual detections.
- **HarfangLab EDR - Process activity** — process telemetry from `logs-harfanglab.generic-*`
  (`event.category: process`): volume over time by `event.type`, top hosts, users, executables and
  parent executables, an OS breakdown, and a process details table.
- **HarfangLab EDR - Telemetry overview** — all generic telemetry from `logs-harfanglab.generic-*`:
  volume over time by `event.category`, breakdowns by category/type/OS, top hosts and users, and an
  events table.

Find them under **Analytics → Dashboards** after installing the integration.
