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
    "input": {
        "type": "cel"
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "8b72fd47-8834-4fb6-8c39-c6bbe8ab8a13",
        "ephemeral_id": "6d478b90-0975-48fa-8437-83e67772c341",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "@timestamp": "2024-08-25T22:05:13.849Z",
    "ecs": {
        "version": "8.11.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "first_epss.vulnerability"
    },
    "elastic_agent": {
        "id": "8b72fd47-8834-4fb6-8c39-c6bbe8ab8a13",
        "version": "8.15.0",
        "snapshot": false
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "6.10.0-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "family": "debian",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.23.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "1e6dd5e4f8a3409dbea97e40111e935a",
        "mac": [
            "02-42-AC-17-00-07"
        ],
        "architecture": "aarch64"
    },
    "first_epss": {
        "vulnerability": {
            "date": "2024-08-25T00:00:00.000Z",
            "cve": "CVE-2024-25593",
            "percentile": 0.09538,
            "epss": 0.00043
        }
    },
    "vulnerability": {
        "reference": "https://api.first.org/data/v1/epss?pretty=true&cve=CVE-2024-25593",
        "id": "CVE-2024-25593"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-08-25T22:05:13Z",
        "kind": "enrichment",
        "category": [
            "vulnerability"
        ],
        "type": [
            "info"
        ],
        "dataset": "first_epss.vulnerability"
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
