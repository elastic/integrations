# Strider Shield Integration

The Strider Shield integration allows you to ingest threat intelligence indicators from the [Strider Shield REST API](https://www.striderintel.com/shield/) into Elasticsearch. Indicators ingested from Strider Shield can be monitored and explored in [Intelligence → Indicators](https://www.elastic.co/guide/en/security/current/indicators-of-compromise.html) in Kibana.

## Overview

This integration connects to the Strider Shield API to collect threat intelligence indicators—email addresses, domains, and terms—associated with state-sponsored actors. The data is processed into ECS format for use in SIEM and security analysis workflows.

### Compatibility

This integration has been tested with the Strider Shield production API. API reference documentation is not publicly available; access is restricted to paying clients.

### How it works

The integration authenticates with Strider using OAuth2 (client credentials flow) and polls the Shield API at a configurable interval. It fetches three types of indicators: email addresses, email domains, and terms. Data is ingested via the CEL (Common Expression Language) input on Elastic Agent, processed through an ingest pipeline, and stored in Elasticsearch. A transform deduplicates indicators and maintains only active, non-expired entries in a destination index.

## What data does this integration collect?

The Strider Shield integration collects threat intelligence indicators of the following types:

- **Email addresses**: Email indicators associated with state-sponsored actors
- **Email domains**: Domain indicators used in threat campaigns
- **Terms**: Keyword or phrase indicators related to threat activity

Each indicator includes metadata such as primary and secondary names, risk classification, MD5 hash, dates added, and expiration information. Archived indicators expire immediately; active indicators expire 90 days from ingestion.

### Supported use cases

- **Threat detection**: Enrich security events with Strider Shield indicators to identify known malicious emails, domains, or terms
- **Incident response**: Reference threat intelligence when investigating security incidents
- **Compliance and auditing**: Maintain a searchable record of ingested indicators

## What do I need to use this integration?

Before you install the integration, ensure your environment meets the following requirements:

- **Elastic Stack**: Elasticsearch for storing data and Kibana for visualization. You can use Elastic Cloud or self-manage the Elastic Stack.
- **Strider Shield credentials**: Client ID and Client Secret received from your Strider Client Success Manager.
- **Elastic Agent**: This integration is designed to run on [Fleet-managed](https://www.elastic.co/docs/reference/fleet) Elastic Agent.

## How do I deploy this integration?

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

### Onboard and configure

When adding the Strider Shield integration, you must configure:

- **Strider Client ID**: Client ID received from your Strider Client Success Manager
- **Strider Client Secret**: Client Secret received from your Strider Client Success Manager
- **Polling Interval**: How often to poll the API (e.g., `24h`). Permitted units are `s`, `m`, `h`

The API URL and Auth URL default to the Strider production endpoints and typically do not require changes.

### Validation

After deployment, verify the integration is working:

1. Check that the Elastic Agent reports a healthy status in Fleet
2. Query the destination index `logs-ti_strider_latest.indicator` in Kibana Discover
3. Allow up to 5 minutes after each sync for the destination index to populate

## Reference

### IOC expiration and index structure

Indicators are expired based on their status: archived indicators expire immediately; active ones expire 90 days from ingestion. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) deduplicates indicators and maintains only active, non-expired entries.

- **Source indices** (`logs-ti_strider.indicator-*`): Contain raw ingested data, including duplicates and archived IOCs. ILM policy `logs-ti_strider.indicator-default_policy` deletes source data after 7 days.
- **Destination index** (`logs-ti_strider_latest.indicator-1`): Contains deduplicated, active indicators only. Aliased as `logs-ti_strider_latest.indicator`.

To view only Strider Shield indicators in the Intelligence dashboard, filter with:

```
threat.feed.name: "Strider Shield"
```

### Exported fields

{{fields "indicator"}}

### Example event

{{event "indicator"}}
