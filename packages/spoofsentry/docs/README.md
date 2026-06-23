# SpoofSentry

The SpoofSentry integration collects domain-security events from
[SpoofSentry](https://spoofsentry.com) by DomainSeal and ingests them into Elastic.
SpoofSentry monitors DMARC/SPF/DKIM posture, detects spoofing campaigns, lookalike and
typosquat domains, certificate-transparency activity, and manages takedown cases. This
integration receives those events as a real-time webhook stream.

## Data streams

The integration collects a single data stream:

- **events** — all SpoofSentry security events (`event.dataset: spoofsentry.events`),
  delivered via an HTTP webhook. Each event carries an `event.action` describing what
  happened (for example `SPOOF_ALERT_GENERATED`, `SPOOF_LOOKALIKE_THREAT`,
  `SPOOF_TAKEDOWN_REPORTED`, `SPOOF_DNS_CHANGES_APPLIED`,
  `SPOOF_INTEGRATION_HEALTH_DEGRADED`).

SpoofSentry emits one unified event envelope discriminated by `type`, so a single data
stream represents the full event taxonomy. Event-specific payload is preserved under the
`spoofsentry.event_data` flattened field.

## Requirements

- Elastic Agent managed by Fleet.
- A SpoofSentry account with permission to configure a **Webhook** integration.
- Network reachability from SpoofSentry to the Elastic Agent HTTP listener (consider a
  reverse proxy that terminates TLS in front of the Agent for production use).

## How it works

1. Add this integration to an Elastic Agent policy and configure the HTTP endpoint
   (listen address/port, optional TLS, optional shared-secret header).
2. In SpoofSentry, create a Webhook integration pointing at the Agent listener URL
   (`http(s)://<agent-host>:<listen_port>`).
3. SpoofSentry POSTs each event as JSON. The ingest pipeline normalizes the envelope to
   the Elastic Common Schema (ECS) and stores the original payload under
   `spoofsentry.event_data`.

### Authentication

The listener supports an optional static shared-secret header (**Secret Header** /
**Secret Value**) that must match a header configured on the SpoofSentry webhook.

SpoofSentry additionally signs every request with an HMAC-SHA256 signature in the
`X-Webhook-Signature` header (format `t=<timestamp>,v1=<signature>` over
`<timestamp>.<body>`). This signature is not validated by the HTTP endpoint input and is
intended for verification by consumers that implement the SpoofSentry signing scheme; do
not rely on it for Agent-side authentication. Always restrict network access to the
listener and prefer TLS plus the shared-secret header.

## Field mapping

| Wire field (`json.*`) | ECS / package field |
| --- | --- |
| `type` | `event.action`, `labels.event_type` |
| `eventId` | `event.id` |
| `deduplicationKey` | `event.reference` |
| `id` | `spoofsentry.delivery_id` |
| `tenantId` | `labels.tenant_id` |
| `userId` | `user.id` |
| `entityType` / `entityId` | `spoofsentry.entity.type` / `spoofsentry.entity.id` |
| `occurredAt` | `@timestamp` |
| `data.severity` (or derived from `type`) | `labels.severity`, `event.severity` (0–10) |
| `data.domainName` / `data.targetDomain` / `data.variant` / `data.matchedDomain` | `host.domain` |
| `data.riskScore` | `spoofsentry.risk_score` |
| `data` (full payload) | `spoofsentry.event_data` (flattened) |

When `data.severity` is absent, severity is derived from the event type using the same
mapping SpoofSentry applies on its SIEM delivery path.
