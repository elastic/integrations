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

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2025-07-08T11:04:54.375Z",
    "agent": {
        "ephemeral_id": "3e6f5925-a6e0-4f02-9f23-4d7dda2c5063",
        "id": "f1f7bf4a-7a17-46e2-9ee4-b93dd07a64de",
        "name": "elastic-agent-64607",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "first_epss.vulnerability",
        "namespace": "63395",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f1f7bf4a-7a17-46e2-9ee4-b93dd07a64de",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "first_epss.vulnerability",
        "ingested": "2025-07-08T11:04:54Z",
        "kind": "enrichment",
        "module": "first_epss",
        "type": [
            "info"
        ]
    },
    "first_epss": {
        "vulnerability": {
            "cve": "CVE-2025-7145",
            "date": "2025-07-07T00:00:00.000Z",
            "epss": 0.0027,
            "percentile": 0.50191
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-64607",
        "ip": [
            "192.168.249.2",
            "192.168.253.6"
        ],
        "mac": [
            "02-42-C0-A8-F9-02",
            "02-42-C0-A8-FD-06"
        ],
        "name": "elastic-agent-64607",
        "os": {
            "family": "",
            "kernel": "3.10.0-1160.92.1.el7.x86_64",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "input": {
        "type": "cel"
    },
    "vulnerability": {
        "id": "CVE-2025-7145",
        "reference": "https://api.first.org/data/v1/epss?pretty=true&cve=CVE-2025-7145"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| first_epss.vulnerability.cve | CVE number. | keyword |
| first_epss.vulnerability.date | Exploit Prediction Scoring System score calculation date. | date |
| first_epss.vulnerability.epss | Exploit Prediction Scoring System score value. | float |
| first_epss.vulnerability.percentile | Exploit Prediction Scoring System percentile value. | float |
| input.type | Type of filebeat input. | keyword |
