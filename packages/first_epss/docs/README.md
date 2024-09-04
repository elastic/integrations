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
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.


## Data reference

### Vulnerability

This is the `vulnerability` dataset.

#### Example

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2024-09-04T18:46:10.562Z",
    "agent": {
        "ephemeral_id": "65e2bd60-495a-4955-af00-264b84935a43",
        "id": "043821e5-fd14-4d5c-9733-fa087fc91988",
        "name": "elastic-agent-59786",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "data_stream": {
        "dataset": "first_epss.vulnerability",
        "namespace": "67844",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "043821e5-fd14-4d5c-9733-fa087fc91988",
        "snapshot": false,
        "version": "8.15.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "first_epss.vulnerability",
        "ingested": "2024-09-04T18:46:11Z",
        "kind": "enrichment",
        "type": [
            "info"
        ]
    },
    "first_epss": {
        "vulnerability": {
            "cve": "CVE-2024-8399",
            "date": "2024-09-04T00:00:00.000Z",
            "epss": 0.00043,
            "percentile": 0.09568
        }
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-59786",
        "id": "1e6dd5e4f8a3409dbea97e40111e935a",
        "ip": [
            "172.24.0.2",
            "172.23.0.4"
        ],
        "mac": [
            "02-42-AC-17-00-04",
            "02-42-AC-18-00-02"
        ],
        "name": "elastic-agent-59786",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.10.4-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event"
    ],
    "vulnerability": {
        "id": "CVE-2024-8399",
        "reference": "https://api.first.org/data/v1/epss?pretty=true&cve=CVE-2024-8399"
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
