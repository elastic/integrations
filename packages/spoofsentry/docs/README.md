# SpoofSentry

SpoofSentry by DomainSeal monitors your domains for email spoofing, DMARC failures, lookalike domain abuse, and phishing campaigns. This integration receives domain security events via HTTP endpoint for centralized logging, analysis, and alerting in Elastic Security.

## Events

Events include:
- DMARC authentication failures with sender details
- Spoofing campaign detections with IP attribution
- Lookalike domain threats with risk scores
- DNS enforcement changes (SPF, DKIM, DMARC policy)
- Takedown orchestration lifecycle (created, dispatched, escalated, resolved)

## Setup

### In SpoofSentry

1. Log in to [SpoofSentry](https://spoofsentry.com)
2. Go to **Settings > Integrations > SIEM**
3. Select **Elastic Security**
4. Enter your Elasticsearch URL
5. Enter API Key or username/password
6. Click **Test Connection** to verify

### In Elastic

1. Navigate to **Fleet > Integrations**
2. Search for "SpoofSentry"
3. Click **Add SpoofSentry**
4. Configure the HTTP endpoint listen address and port (default: `0.0.0.0:8089`)
5. Set the authentication secret header and value
6. Save and deploy to your agent

Events appear in the `logs-spoofsentry.events-*` data stream.

## ECS Field Mapping

| Source Field | ECS Field | Description |
|---|---|---|
| `eventType` | `event.action` | Event classification |
| `severity` | `event.severity` | Numeric severity (1-10) |
| `domain` | `host.domain` | Target domain |
| `tenantId` | `labels.tenant_id` | Customer tenant |

## Logs Reference

### Events

The `events` data stream collects domain security events from SpoofSentry.

{{fields "events"}}
