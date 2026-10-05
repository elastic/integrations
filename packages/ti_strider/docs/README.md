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

- **Source indices** (`logs-ti_strider.indicator-*`): Contain raw ingested data, including duplicates and archived IOCs. See [Data retention](#data-retention) for how long source data is kept.
- **Destination index** (`logs-ti_strider_latest.indicator-1`): Contains deduplicated, active indicators only. Aliased as `logs-ti_strider_latest.indicator`.

### Data retention

Threat indicators are re-collected across polling intervals, and the latest transform keeps the active, deduplicated view in its destination index. The source data streams therefore hold repeated copies of the same indicators.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-ti_strider.indicator-*` | `logs-ti_strider.indicator-default_policy`: roll over after 7d, delete 7d after rollover | delete 7d after ingestion |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies; the data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead: documents are deleted the stated time after they are ingested. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management > Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-ti_strider.indicator-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.

To view only Strider Shield indicators in the Intelligence dashboard, filter with:

```
threat.feed.name: "Strider Shield"
```

### Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Timestamp for the event. | date |
| data_stream.dataset |  | constant_keyword |
| data_stream.namespace |  | constant_keyword |
| data_stream.type |  | constant_keyword |
| ecs.version | ECS version this event adheres to. | keyword |
| event.category | Event category (e.g. threat). | keyword |
| event.type | Event type (e.g. indicator). | keyword |
| input.type | Type of input that generated the event. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| ti_strider.indicator.archive | When 1, the indicator is archived and expires_at is set to ingestion time; otherwise expires_at is set to 90 days from ingestion. | integer |
| ti_strider.indicator.changes | Object describing changes since the IOC was first seen. | keyword |
| ti_strider.indicator.dates_added | Original date when the IOC was added to the source. | date |
| ti_strider.indicator.expires_at | If an IOC is archived from the dataset, we set the expiry to now. For non-archived IOCs we set it 90d ahead of today, which will get reset every day. | date |
| ti_strider.indicator.is_new | Indicates whether this is a newly observed IOC (new for a month after first appearing). | boolean |
| ti_strider.indicator.md5 | MD5 hash associated with the IOC. | keyword |
| ti_strider.indicator.name_primary | Primary name of the IOC. | keyword |
| ti_strider.indicator.name_secondary | List of secondary IOC names and their language. | flattened |
| ti_strider.indicator.risk_signal | Risk classification signal for the IOC. | keyword |
| ti_strider.indicator.type | Type of the IOC (e.g., term, emailDomain, emailAddress). | keyword |


### Example event

An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2026-03-19T13:54:07.446Z",
    "agent": {
        "ephemeral_id": "143eb0eb-57df-4e8d-8b7f-e97113426122",
        "id": "b3eca9d8-21ab-40df-97db-fe337a2f129e",
        "name": "elastic-agent-56621",
        "type": "filebeat",
        "version": "9.1.0"
    },
    "data_stream": {
        "dataset": "ti_strider.indicator",
        "namespace": "96262",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "b3eca9d8-21ab-40df-97db-fe337a2f129e",
        "snapshot": false,
        "version": "9.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "threat",
        "dataset": "ti_strider.indicator",
        "ingested": "2026-03-19T13:54:10Z",
        "kind": "enrichment",
        "type": "indicator"
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_ioc_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "ti_strider-indicator"
    ],
    "ti_strider": {
        "indicator": {
            "changes": "{}",
            "dates_added": "2022-09-20T05:00:00.000Z",
            "expires_at": "2026-06-17T13:54:07.446Z",
            "is_new": false,
            "md5": "2",
            "name_primary": "test@example.com",
            "risk_signal": "GT",
            "type": "emailAddress"
        }
    }
}
```
