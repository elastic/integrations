# First EPSS

## Overview

The First EPSS integration allows users to retrieve EPSS score from First EPSS API. 

The Exploit Prediction Scoring System (EPSS) is a data-driven effort for estimating the likelihood (probability) that a software vulnerability (CVE) will be exploited in the wild.

## Data streams

The First EPSS integration collects one type of data stream: `vulnerability`

### EPSS

EPSS scores are retrieved via the First EPSS API (`https://api.first.org/data/v1/epss`).

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
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| first_epss.vulnerability.cve | CVE number. | keyword |
| first_epss.vulnerability.date | Exploit Prediction Scoring System score calculation date. | date |
| first_epss.vulnerability.epss | Exploit Prediction Scoring System score value. | float |
| first_epss.vulnerability.percentile | Exploit Prediction Scoring System percentile value. | float |
| input.type | Type of filebeat input. | keyword |
