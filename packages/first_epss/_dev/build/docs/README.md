# First EPSS

## Overview

The First EPSS integration allows users to retrieve EPSS score from First EPSS API. 

The Exploit Prediction Scoring System (EPSS) is a data-driven effort for estimating the likelihood (probability) that a software vulnerability (CVE) will be exploited in the wild.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data streams

The First EPSS integration collects one type of data stream: `vulnerability`

### EPSS

EPSS scores are retrieved via the First EPSS API (`https://api.first.org/data/v1/epss`).

## Query-time EPSS enrichment (LOOKUP JOIN)

The package ships a `latest` transform that maintains the most recent EPSS score per CVE in the lookup index `logs-first_epss_latest.vulnerability`. The full EPSS catalog is re-ingested on every poll cycle, so the same CVE is re-ingested repeatedly with updated scores; the transform collapses those snapshots into the latest row per CVE, making it the preferred enrichment path.

You can enrich vulnerability findings at query time with the ES|QL [`LOOKUP JOIN`](https://www.elastic.co/docs/reference/query-languages/esql/commands/lookup-join) command on `vulnerability.id`:

```esql
FROM logs-endpoint.vulnerability-*
| LOOKUP JOIN logs-first_epss_latest.vulnerability ON vulnerability.id
| KEEP vulnerability.id, first_epss.vulnerability.epss, first_epss.vulnerability.percentile, first_epss.vulnerability.date
| WHERE first_epss.vulnerability.epss IS NOT NULL
```

## Compatibility

This integration has been tested against the EPSS API v1.


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.


## Data reference

### Vulnerability

This is the `vulnerability` dataset.

#### Example

{{event "vulnerability"}}

{{fields "vulnerability"}}