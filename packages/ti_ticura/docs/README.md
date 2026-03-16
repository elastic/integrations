# Ticura Threat Intelligence Integration

## Overview

[Ticura](https://www.ticura.io) delivers the industry’s only real-time view of global cyber threat intelligence that is objective, auditable, and continuously optimized to protect each subscriber’s unique environment — at a fraction of the cost of legacy approaches.

Ticura’s threat intelligence feeds are aggregated from hundreds of different public, private, and community sources, enriched using AI, and tailored to your specific needs. The IoC Scoring Algorithm applies a qualitative classification that changes dynamically over time.

This intelligence can be queried through a threat intelligence feed and delivered directly to Firewall, SOAR, SIEM, EDR, and other security platforms e.g. Elastic Security.

---

## Requirements

### Agent based installation

Elastic Agent must be installed. If you have none, check the [Elastic Agent installation instructions](https://www.elastic.co/docs/reference/fleet/install-elastic-agents). You can install only one Elastic Agent per host. Elastic Agent is required to stream data from the REST API or webhook and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

---

## Data Streams

### Threat Intelligence

Each ingested event represents a single indicator of compromise (IOC) and includes metadata such as type, confidence, and scoring information.

### Supported Indicator Types

The integration supports the following indicator types:

- IPv4 addresses
- IPv6 addresses
- Port
- Domains
- URLs
- File hashes

### Indicators of Compromise (IoC) Expiration

All the indicators are retrieved into data streams named `logs-ti_ticura.ecs-{namespace}` and processed via ingest pipelines. 
The ILM Policy triggers rollover every 24 hours to ensure outdated / deleted IoCs disappear from your latest index. 
Warm indicies are deleted after 7 days.

Important: **Ensure your download interval is below 24 hours.** to permanenlty have access to the latest index

If there is need to keep data longer than 24 hours within the hot index or to keep data longer 7 days in warm state please reconfigure the Index Lifecycle Policy (ILM) `logs-ti_ticura.ecs-default_policy`

## Dashboards

Ticura integration provides a dashboard to 

---

## Requirements

To use this integration, you need:

- Access to the Ticura web application
- An active Ticura subscription
- A supported Elastic Stack version with Elastic Security enabled

---

## Setup

### Generate a Ticura Threat Intelligence Feed

1. Register for a Ticura account at:  https://app.ticura.io

2. Create a Threat Intelligence feed based on your requirements and save the provided API Key

---

### Configure the Integration in Elastic

1. Open Kibana and navigate to **Integrations**.
2. Search for **Ticura**.
3. Select **Add Ticura**.
4. Enter your FeedName into Field: **Advanced Options** > **Namespace**
5. Enter your API Key into Field: **Ticura API token**.
6. Select your **Update Intervall**, your **Agent** and klick on **Save and continue** to enable the integration.

After the integration is enabled, indicators are periodically retrieved and ingested into Elastic.

---

## ECS Field Mapping

The Ticura Threat Intelligence integration maps indicators to the Elastic Common Schema (ECS) using the `threat.indicator.*` field set.

### Core Indicator Fields

| ECS Field | Description |
|----------|-------------|
| `threat.indicator.type` | Indicator type (e.g. `ipv4-addr`, `url`, `file-hash`) |
| `threat.indicator.description` | Short description of the indicator |
| `threat.indicator.first_seen` | Time when the indicator was first observed |
| `threat.indicator.last_seen` | Most recent observation time |
| `threat.indicator.confidence` | Confidence level assigned to the indicator |
| `threat.indicator.provider` | Indicator provider (`ticura`) |

---

### Indicator Values

Indicator values are mapped to ECS fields based on type.

| Indicator Type | ECS Field |
|---------------|-----------|
| `threat.indicator.ip` | IPv4 address |
| `threat.indicator.ip` | IPv6 address |
| `threat.indicator.port` | Port |
| `threat.indicator.url.domain` | Domain |
| `threat.indicator.url.full` | URL |
| `threat.indicator.file.hash.*` | File hash |

---

### File Hash Mapping

| ECS Field | Hash Type |
|----------|-----------|
| `threat.indicator.file.hash.md5` | MD5 |
| `threat.indicator.file.hash.sha1` | SHA1 |
| `threat.indicator.file.hash.sha256` | SHA256 |
| `threat.indicator.file.hash.sha512` | SHA512 |
| `threat.indicator.file.hash.ssdeep` | SSDEEP |
| `threat.indicator.file.hash.tlsh` | TLSH |

---

### Scoring and Classification

| ECS Field | Description |
|----------|-------------|
| `threat.indicator.score` | Numeric score representing indicator relevance |
| `threat.indicator.marking.tlp` | Traffic Light Protocol (TLP) marking, if provided |
| `threat.indicator.reference` | Reference or source information |
| `tags` | Tags associated with the indicator |

---

### Metadata Fields

| ECS Field | Description |
|----------|-------------|
| `event.kind` | `enrichment` |
| `event.category` | `threat` |
| `event.type` | `indicator` |
| `event.dataset` | `ti_ticura.ecs` |
| `ecs.version` | `8.17.0` |

---

## Data Access and Security

- Each feed is unique to the subscriber.
- Access is controlled using subscription-specific credentials.
- Feed content reflects the configuration defined during ticura feed setup.

---

## Notes

- Indicator relevance and confidence may change over time.
- The volume of ingested indicators depends on your feed configuration.
- This integration enriches Elastic Security data but does not create detection rules.
