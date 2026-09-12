{{- generatedHeader }}
# ReConfirm Integration for Elastic

## Overview

[ReConfirm](https://reconfirm.com/) is an attack-surface and vulnerability scanning service. The ReConfirm integration for Elastic collects scan result webhooks (assets, open ports, lookalike/typosquat domains, subdomain exposure, and email security posture), normalizes the scan envelope to the Elastic Common Schema (ECS), and ships it to Elasticsearch so security teams can track their external attack surface over time.

### How it works

ReConfirm delivers a scan result by POSTing a single JSON document to a user-configured HTTPS webhook URL when a scan completes. This integration stands up an HTTP endpoint (the Elastic Agent `http_endpoint` input) that receives that document. Incoming requests are authenticated with a static `Authorization` header, then reshaped and mapped to ECS.

The ingest pipeline reshapes dynamically keyed ReConfirm sections, such as assets by IP and subdomains by hostname, into bounded arrays to avoid creating unbounded Elasticsearch fields.

## What data does this integration collect?

The ReConfirm integration collects one family of events:

* **Vulnerability scan results** — one document per completed scan, containing the scan metadata (who triggered it, target domain, start/end/outcome), discovered network assets and their open ports/services, lookalike/typosquat domains found for the target, subdomain exposure (active, offline, and unresolved), and the target domain's email security posture (DKIM/DMARC/SPF/MX).

### Supported use cases

Normalizing ReConfirm scan results to ECS in Elasticsearch makes attack-surface data searchable, visualizable, and correlatable alongside other sources. The collected fields support, for example:

- Attack-surface inventory: which IPs and ports are exposed, and what services/versions are running on them (`reconfirm.assets.*`).
- Brand-protection / typosquat monitoring: lookalike domains registered against the target, and whether they're actively impersonating it (`reconfirm.similar_domains.*`).
- Subdomain exposure tracking: which subdomains are live, offline, or no longer resolving, and which security headers they're missing (`reconfirm.subdomains.*`).
- Email spoofing risk: DKIM/DMARC/SPF/MX posture for the target domain (`reconfirm.email_security.*`).

## What do I need to use this integration?

- An Elastic deployment (self-managed, Elastic Cloud, or Serverless) and an Elastic Agent.
- A ReConfirm account with permission to configure a scan webhook.
- A network path that allows ReConfirm's servers to reach the Agent's HTTPS endpoint (a public ingress, load balancer, or reverse proxy terminating TLS in front of the Agent).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Because ReConfirm requires the destination to be reachable over HTTPS from the public internet, terminate TLS either on the Agent (configure the SSL options on the input) or on a reverse proxy / load balancer placed in front of the Agent that forwards to the listener.

### Set up steps in ReConfirm

1. In the ReConfirm dashboard, open the webhook/notification settings for the scan you want to forward.
2. Set the webhook URL to the public HTTPS URL that reaches the Agent's listener (host/port plus the path configured below, e.g. `https://<your-host>/reconfirm`).
3. Configure an `Authorization` header whose value is a long, random shared secret, e.g. `Bearer <token>`, and configure the same value in Kibana (below).
4. Save and trigger a test scan.

#### Vendor resources

- [ReConfirm webhook implementation](https://reconfirm.com/resources/kb/api-webhook/webhook-implementation)
- [ReConfirm webhook payload schema](https://reconfirm.com/resources/kb/platform-documentation/webhook-payload-schema) — the JSON Schema definition ([raw schema](https://reconfirm.com/schemas/webhook_payload.schema.json)) this integration's ingest pipeline is built against.

### Set up steps in Kibana

1. In Kibana, go to **Management > Integrations**, search for **ReConfirm**, and select **Add ReConfirm**.
2. Configure the **Collect ReConfirm scan results via webhook** input:
   - **Listen Address** and **Listen Port** — the address/port the Agent binds (defaults `0.0.0.0` and port `9023`).
   - **URL** — the request path ReConfirm posts to (e.g. `/reconfirm`); it must match the endpoint set in ReConfirm.
   - **Authorization Token** — the exact value ReConfirm sends in the `Authorization` header, e.g. `Bearer <token>`. The listener fixes the header name to `Authorization`; requests whose header value does not match are rejected with a 401.
   - **Redact Leaked Passwords** — enabled by default. When enabled, leaked plaintext passwords in credential leak findings and `event.original` are replaced with `REDACTED`.
   - **TLS** — provide a certificate and key if the Agent terminates HTTPS directly.
3. Save and deploy the integration to the Agent policy.

### Validation

1. In ReConfirm, trigger a test scan or test webhook delivery.
2. In Kibana, open **Discover** and select the `logs-reconfirm.vulnerability-*` data view to confirm scan results are arriving.
3. Confirm fields such as `reconfirm.scan.target`, `reconfirm.summary.assets_count`, and `reconfirm.summary.similar_domains_count` are populated.

## Troubleshooting

- No data is being collected: Confirm ReConfirm can reach the endpoint over HTTPS from the public internet, that the Agent is healthy, and that the listener address/port/path match the ReConfirm webhook configuration.
- All requests are rejected (401): Verify the Authorization Token in Kibana exactly matches the `Authorization` header value configured in ReConfirm, including the `Bearer ` prefix.
- `reconfirm.associated_domains`, `reconfirm.cred_leaks`, or a `vulns` array is missing from a document: these sections only appear when the corresponding ReConfirm module was enabled and found something during that scan; empty sections are dropped before indexing, so a missing field here does not indicate an ingest issue.

## Performance and scaling

Each event is one full scan result and can be large (hundreds of KB) when a scan finds many assets, lookalike domains, or subdomains. Size the Agent and downstream ILM/retention policy for document size rather than event rate — ReConfirm scans typically complete far less often than most log sources emit events. For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

#### vulnerability

The `vulnerability` data stream contains ReConfirm scan result events — discovered assets, lookalike domains, subdomain exposure, and email security posture. The raw event is preserved (when enabled) in `event.original`, and ReConfirm-specific context is kept under `reconfirm.*`.

##### vulnerability fields

{{ fields "vulnerability" }}

##### vulnerability sample event

{{ event "vulnerability" }}
