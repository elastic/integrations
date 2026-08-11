{{- generatedHeader }}

# Backstage Integration for Elastic

## Overview

The Backstage integration for Elastic collects audit log events emitted by [Backstage](https://backstage.io)'s built-in `auditor` service, giving you visibility into user actions, plugin activity, and catalog operations across your Backstage instance. Events are parsed and normalized into the Elastic Common Schema (ECS) so you can search, alert on, and visualize user and plugin activity across your developer platform.

### Compatibility

This integration is compatible with Backstage backends built on `@backstage/backend-plugin-api` version `1.2.0` or later, the release that introduced the built-in `auditor` core service (implemented by default via `@backstage/backend-defaults`). No additional Backstage plugin is required — every Backstage backend created with `createBackend()` emits audit events through this service automatically.

### How it works

Backstage's `auditor` service formats each audit event as a single JSON log line (message format `<plugin>.<eventId>`) through the root Winston logger, along with fields such as the acting user, HTTP request details, the originating plugin, event status, and severity level. This integration's filestream input reads those JSON lines from a log file — for example, captured container or pod output, or a file the Backstage backend writes to directly — and the ingest pipeline parses and maps them to ECS.

## What data does this integration collect?

The Backstage integration collects audit log events of the following types, depending on which plugins emit `auditor` events in your Backstage instance:
* Catalog operations: entity fetch and catalog query events, including the requested fields and applied filters.
* User and plugin activity: the acting user or service, the plugin and event name, HTTP method and URL, and whether the operation succeeded, failed, or is still in progress.
* Severity-classified events: each event carries a Backstage-assigned severity level (`low`, `medium`, or `high`), mapped to `event.severity`.

### Log scope

This integration primarily targets Backstage **audit** logs — emitted by the `auditor` service as NDJSON (one JSON object per line) — which are fully normalized to ECS and `backstage.*` fields.

Backstage application logs — valid JSON lines where `isAuditEvent` is either absent or is not set to `true` — are also retained. The original line is preserved in `event.original`. Common fields such as messages, service names, log levels, timestamps, tracing IDs, URLs, user agents, HTTP methods, and HTTP response values are mapped to ECS. Other parsed fields remain under `backstage.log.*` as keywords. Audit-specific fields are not mapped for these records.

Deeper mapping of these logs will be driven by customer requests and observed usage.

### Supported use cases

Integrating Backstage audit logs with the Elastic Stack lets you:
* Monitor user activity: track who accessed or modified catalog entities, and from where.
* Investigate plugin behavior: correlate events by `event.provider` (the Backstage plugin) and `event.code` (the audit event ID) to debug or audit plugin-specific actions.
* Support compliance and security monitoring: maintain a searchable, ECS-normalized record of administrative and catalog actions performed through Backstage.

## What do I need to use this integration?

To use this integration, you'll need the following vendor prerequisites:
- A Backstage backend built with `createBackend()` from `@backstage/backend-defaults` (version `1.2.0` or later), so the `auditor` service is available and emitting events automatically.
- The audit log output written to a location the Elastic Agent can read as a file — for example, captured container/pod logs mounted into the Elastic Agent's filesystem, or a file the Backstage backend logs to directly.

You'll also need the following Elastic prerequisites:
- Elastic Stack (Elasticsearch and Kibana) version `8.19.0` or later.
- An active Elastic Agent installed and enrolled in Fleet, with filesystem access to the Backstage audit log file(s).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host or container that has access to the Backstage audit log file(s). For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to collect the log file(s) and ship the data to Elastic, where the events are then processed by this integration's ingest pipeline.

### Onboard / configure

1. In Kibana, navigate to **Management → Integrations**.
2. Search for **Backstage** and select the integration.
3. Click **Add Backstage**.
4. Configure **Paths** to point to the location of the Backstage audit log file(s) — for example, a mounted volume or captured container log path. The default is `/var/log/*.log`.
5. (Optional) Configure **Exclude files** to skip rotated or compressed log files. The default already excludes `.gz` files.
6. (Optional) Configure **Parsers** if your Backstage audit log lines are pretty-printed across multiple lines rather than one JSON object per line. See the field's description for `ndjson` and `multiline` examples.
7. Assign the integration to an Elastic Agent policy and click **Save and continue**.

### Validation

After the configuration is complete, follow these steps to verify data is flowing correctly from Backstage to the Elastic Stack:

1. Trigger an audit event in Backstage — for example, browse the Software Catalog to trigger a `catalog.entity-fetch` event.
2. In Kibana, navigate to **Analytics → Discover**.
3. Select the `logs-*` data view.
4. In the search bar, enter the filter: `data_stream.dataset: "backstage.logs"`.
5. Verify that events appear with a non-null `event.action` field, and that `event.provider` reflects the Backstage plugin that generated the event (for example, `catalog`).

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

- **No events collected**: Confirm the Backstage backend is emitting audit events (not every plugin calls the `auditor` service for every operation) and that the configured **Paths** match the actual log file location.
- **Multi-line JSON not parsed**: If your Backstage deployment pretty-prints JSON log lines across multiple lines, enable the `multiline` parser under **Parsers**. Otherwise each partial line fails JSON parsing.
- **Application logs have limited mapping**: For this release and the short term future, application logs have limited mappings. This is by design to limit the scope of our initial release which focuses on audit logs (see [Log scope](#log-scope)). In the meantime, you can create some custom processors to mitigate this, the original log line is kept in `event.original`, and other parsed fields land under `backstage.log.*` as keywords. Should this not be sufficient, please contact us so we can review your requests and improve the mappings of backstage application logs. 
- **Permission denied reading the log file**: Elastic Agent needs read access to the Backstage audit log file(s). If your environment writes them with restrictive ownership/permissions, deploy Elastic Agent as `root` (or a user with equivalent read access) on that host or container. This is a deployment-time decision, not a setting configurable through this integration.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

The following inputs are used by this integration:

{{ inputDocs }}

### Data streams

#### logs

The `logs` data stream provides application logs, with a focus on audit events from Backstage's `auditor` service, including catalog operations, user activity, and other plugin-specific audit events. General Backstage application logs where `isAuditEvent` is not `true` are also retained with common fields mapped to ECS, the original line in `event.original`, and other parsed fields under `backstage.log.*` as keywords; see [Log scope](#log-scope).

##### logs fields

{{ fields "logs" }}

##### logs sample event

{{ event "logs" }}

### Vendor documentation links

For more information about Backstage's auditor service, refer to:
* [Backstage Auditor Service documentation](https://backstage.io/docs/backend-system/core-services/auditor)
