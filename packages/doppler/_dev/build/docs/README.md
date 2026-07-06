{{- generatedHeader }}
# Doppler Integration for Elastic

## Overview

[Doppler](https://www.doppler.com/) is a secrets management platform (SecretOps) that stores, syncs, and audits application secrets and configuration across environments. The Doppler integration for Elastic collects Doppler's activity logs and secret-access events, normalizes them to the Elastic Common Schema (ECS), and ships them to Elasticsearch so security teams can monitor secret access, detect anomalous identity behavior, and investigate workplace configuration changes.

### Compatibility

This integration is compatible with Doppler's [Generic HTTPS Log Stream](https://docs.doppler.com/docs/generic-https), available on Doppler's Team and Enterprise plans. It is compatible with Elastic Stack 8.16 and later.

### How it works

Doppler delivers these events by POSTing newline-delimited JSON to a single user-configured HTTPS destination (a "Log Stream"). This integration stands up an HTTP endpoint (the Elastic Agent `http_endpoint` input) that receives those events. Incoming requests are authenticated with a static `Authorization` header, parsed, mapped to ECS, and then routed:

- **Activity** events are stored in the `doppler.activity` data stream.
- High-volume `security.secret_read` events are rerouted at ingest time to the dedicated `doppler.secret_read` data stream, so secret-access telemetry can be retained, indexed, and alerted on independently of general activity.

## What data does this integration collect?

The Doppler integration collects two families of events:

* **Activity logs** — workplace and project lifecycle events such as project/config/environment creation and deletion, secret value changes, member and group management, role changes, service-account and token lifecycle, and access grants.
* **Secret read events** (`security.secret_read`) — a record each time secrets are fetched (via the dashboard, CLI, API, or integrations), including which projects/configs/environments and secret names were accessed and the source session (IP, method, browser/OS where available).

### Supported use cases

Normalizing Doppler events to ECS in Elasticsearch makes the data searchable, visualizable, and correlatable alongside other sources. The collected fields support, for example:

- Secret-access analysis: which secrets, projects, configs, and environments were read, by whom, and from which source IP, geo, and user agent (the `doppler.secret_read.*`, `source.*`, and `user_agent.*` fields).
- Identity and configuration history: actor, target, role, token, and group activity across workplace and project events (the `user.*`, `user.target.*`, and `doppler.activity.*` fields).
- Long-term retention of an auditable record of secrets-platform activity.

## What do I need to use this integration?

- An Elastic deployment (self-managed, Elastic Cloud, or Serverless) and an Elastic Agent.
- A Doppler Team or Enterprise plan with permission to configure a workplace Log Stream.
- A network path that allows Doppler's servers to reach the Agent's HTTPS endpoint (a public ingress, load balancer, or reverse proxy terminating TLS in front of the Agent).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Because Doppler requires the destination to be reachable over HTTPS from the public internet, terminate TLS either on the Agent (configure the SSL options on the input) or on a reverse proxy / load balancer placed in front of the Agent that forwards to the listener.

### Set up steps in Doppler

1. In the Doppler dashboard, open your **Workplace Settings** and go to **Logging**.
2. Add a new **Log Stream** of type **Generic HTTPS**.
3. Set the **Endpoint** to the public HTTPS URL that reaches the Agent's listener (host/port plus the path configured below, e.g. `https://<your-host>/doppler`).
4. Add an **Authorization** header whose value is a long, random shared secret. Doppler sends this header as `Authorization: <value>` on every request; use the form `Bearer <token>` and configure the same value in Kibana (below).
5. Save and send a test event.

#### Vendor resources

- [Doppler Generic HTTPS Log Stream](https://docs.doppler.com/docs/generic-https)
- [Doppler Workplace Logs](https://docs.doppler.com/docs/workplace-logs)

### Set up steps in Kibana

1. In Kibana, go to **Management > Integrations**, search for **Doppler**, and select **Add Doppler**.
2. Configure the **Collect Doppler logs via webhook** input:
   - **Listen Address** and **Listen Port** — the address/port the Agent binds (defaults `0.0.0.0` and port `9080`).
   - **URL** — the request path Doppler posts to (e.g. `/doppler`); it must match the endpoint set in Doppler.
   - **Authorization Token** — the exact value Doppler sends in the `Authorization` header, e.g. `Bearer <token>`. The listener fixes the header name to `Authorization`; requests whose header value does not match are rejected.
   - **TLS** — provide a certificate and key if the Agent terminates HTTPS directly.
3. Save and deploy the integration to the Agent policy.

No separate input exists for secret-read events; they arrive on the same listener and are routed automatically to the `doppler.secret_read` data stream.

### Validation

1. In Doppler, trigger a test event from the Log Stream configuration, or perform an action (for example, read a secret) that generates an event.
2. In Kibana, open **Discover** and select the `logs-doppler.activity-*` data view to confirm activity events are arriving, and `logs-doppler.secret_read-*` to confirm secret-read events are being routed.
3. Confirm fields such as `event.action`, `user.name`, `organization.name`, and (for secret reads) `source.geo.*` and `doppler.secret_read.secret_names` are populated.

## Troubleshooting

- No data is being collected: Confirm Doppler can reach the endpoint over HTTPS from the public internet, that the Agent is healthy, and that the listener address/port/path match the Doppler Log Stream configuration.
- All requests are rejected (401/403): Verify the Authorization Token in Kibana exactly matches the `Authorization` header value configured in Doppler, including the `Bearer ` prefix.
- Secret-read events missing from `doppler.activity`: This is expected — `security.secret_read` events are rerouted to the `doppler.secret_read` data stream.
- Missing geo enrichment: `source.geo.*` is derived from `source.ip`; private or non-routable source IPs will not resolve.

## Performance and scaling

`security.secret_read` is typically the highest-volume Doppler event type. Routing it to its own data stream lets you size shards, retention (ILM), and alerting independently from lower-volume activity events. For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### Dashboards

The integration ships a **Doppler Overview** dashboard that summarizes
activity and secret-access events — event volume over time, top actors and
actions, and a breakdown of secret reads by method and geography. It is tagged
**Security Solution**, so it also appears in the Security app, and can be found
in Kibana under **Dashboards** after installing the integration.

### Vendor documentation links

- [Doppler documentation](https://docs.doppler.com/)
- [Doppler Workplace Logs](https://docs.doppler.com/docs/workplace-logs)
- [Doppler Generic HTTPS Log Stream](https://docs.doppler.com/docs/generic-https)

### Data streams

#### activity

The `activity` data stream contains Doppler workplace and project activity events — project/config/environment lifecycle, secret changes, member/group management, role changes, and service-account/token lifecycle. The raw event is preserved (when enabled) in `event.original`, and Doppler-specific context is kept under `doppler.activity.*` and `doppler.actor.*`.

##### activity fields

{{ fields "activity" }}

##### activity sample event

{{ event "activity" }}

#### secret_read

The `secret_read` data stream contains `security.secret_read` events, rerouted from the activity listener. Each event lists the secrets accessed (`doppler.secret_read.secrets` plus the convenience arrays `secret_names`, `projects`, `environments`, `configs`, and `secret_count`) and the source session, enriched with `source.geo.*`, `source.as.*`, and `user_agent.*` where available.

##### secret_read fields

{{ fields "secret_read" }}

##### secret_read sample event

{{ event "secret_read" }}
