# OpenText Service Manager

This integration is **community supported**. It is maintained by the Elastic integrations community and is **not** covered by Elastic support SLAs; report problems or contribute fixes via the [Elastic integrations repository](https://github.com/elastic/integrations).

This integration is also in **Technical Preview**. Behavior and schema may change; use in non-production or pilot environments until promoted to GA.

## Overview

The [OpenText Service Manager](https://docs.microfocus.com/doc/Service_Manager/9.80/Home) integration collects **incident** records over HTTP using the Service Manager REST API (historically documented under Micro Focus / HP Service Manager). Elastic can index incidents for search, alerting, and correlation alongside other security and IT operations data.

The Fleet icon uses the OpenText wordmark on a dark background so white artwork remains visible, consistent with [OpenText documentation](https://docs.microfocus.com/) branding ([reference SVG](https://docs.microfocus.com/assets/global/opentext-logo.svg)).

### Compatibility

- Service Manager deployments that expose the REST **incidents** collection (URL path varies by version and gateway; confirm with your administrator).
- Elastic Agent with the **CEL** input (Custom API / Common Expression Language).
- Operator credentials permitted to **GET** incidents with `view=expand`. Authentication follows [RESTful Authentication](https://docs.microfocus.com/SM/9.51/Hybrid/Content/webservicesguide/rest_authentication.htm) (HTTP Basic is typical).

### How it works

The Elastic Agent periodically executes a CEL program that:

1. Builds a native Service Manager **`query`** string (URL-encoded) plus an incremental time window and tie-breaker so rows are not fetched twice across polls when possible.
2. Calls **`GET`** on your incidents URL with **`sort`**, **`view=expand`**, **`start`**, and **`count`** for bounded pages ([RESTful Queries](https://docs.microfocus.com/SM/9.52/Hybrid/Content/webservicesguide/rest_queries.htm), [RESTful Commands](https://docs.microfocus.com/SM/9.51/Hybrid/Content/webservicesguide/rest_commands.htm)).
3. Chains **`want_more`** to walk **`start` / `count`** pagination within the same poll upper bound for large result sets ([pagination example](https://docs.microfocus.com/SM/9.51/Hybrid/Content/webservicesguide/tasks/example_use_web_service_with_pagination__to_retrieve_data__from_service_manager.htm)).
4. Emits one document per incident using the REST **`properties`** map (when present).

## What data does this integration collect?

### Data streams

- **`incident`** (`logs-opentext_service_manager.incident-*`) — Incident records returned under REST `entities` / expanded properties for each polling interval.

Use **Discover** with `logs-*` (or the integration data stream) to inspect documents.

## What do I need to use this integration?

- Elasticsearch and Kibana (Elastic Cloud or self-managed).
- Network path from Elastic Agent to the Service Manager REST base URL.
- A Service Manager **operator** username and password for HTTP Basic authentication (ASCII username per vendor guidance).
- Optional: TLS trust configuration (certificate authority or verification mode) if you terminate HTTPS on the integration.

## How do I deploy this integration?

1. In Fleet, add this integration to an Elastic Agent policy.
2. Set **Incidents REST URL** to the full incidents resource (for example `https://host.example/SM/9/rest/incidents`).
3. Provide **operator** credentials and tune **native query**, **initial lookback**, **page size (count)**, and **interval** for your environment. Narrow `native_query` in large deployments.
4. Validate in Discover: new documents should appear with `data_stream.dataset` `opentext_service_manager.incident`.

For generic Fleet steps, see the Elastic Agent [documentation](https://www.elastic.co/guide/en/fleet/current/fleet-overview.html).

## Troubleshooting

- **401 / 403** — Confirm operator password, Basic auth requirements, and REST enablement on the gateway.
- **Empty responses** — Check `native_query`, cursor field names (`last.update.time`, `number`), and clock/timezone alignment with ISO timestamps in SM queries.
- **Duplicates** — Narrow overlapping time windows; ensure sort keys match cursor fields; consider a `fingerprint` ingest processor on stable incident identifiers if the API allows replays.

Refer to OpenText / Micro Focus REST documentation for server-side limits and query syntax.

## Performance and scaling

- Prefer smaller **`count`** (page size) with more frequent polls when incident volume is high.
- Restrict **`native_query`** (assignment group, priority, status) to reduce REST payload size.
- Monitor Agent logs and enable **request tracing** only temporarily for debugging.

## Logs reference

### Incident

{{event "incident"}}

{{fields "incident"}}
