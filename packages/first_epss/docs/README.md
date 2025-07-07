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
    "@timestamp": "2025-05-28T19:29:58.030Z",
    "agent": {
        "ephemeral_id": "18e95b1b-a649-4691-946b-e50d72cbf495",
        "id": "879ba47b-e390-4e0c-b34d-52fa006a0944",
        "name": "elastic-agent-87507",
        "type": "filebeat",
        "version": "9.0.1"
    },
    "data_stream": {
        "dataset": "first_epss.vulnerability",
        "namespace": "75614",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "879ba47b-e390-4e0c-b34d-52fa006a0944",
        "snapshot": false,
        "version": "9.0.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "first_epss.vulnerability",
        "ingested": "2025-05-28T19:29:59Z",
        "kind": "enrichment",
        "module": "first_epss",
        "type": [
            "info"
        ]
    },
    "first_epss": {
        "vulnerability": {
            "cve": "CVE-2025-5298",
            "date": "2025-05-28T00:00:00.000Z",
            "epss": 0.00028,
            "percentile": 0.06335
        }
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-87507",
        "ip": [
            "172.22.0.2",
            "172.21.0.6"
        ],
        "mac": [
            "1E-CA-BA-AD-C0-8F",
            "B2-C4-7F-D7-F4-8F"
        ],
        "name": "elastic-agent-87507",
        "os": {
            "family": "",
            "kernel": "6.10.14-linuxkit",
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
        "id": "CVE-2025-5298",
        "reference": "https://api.first.org/data/v1/epss?pretty=true&cve=CVE-2025-5298"
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
