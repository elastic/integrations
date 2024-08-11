# First

## Overview

The First EPSS integration allows users to retrieve EPSS score from First EPSS API. 

The Exploit Prediction Scoring System (EPSS) is a data-driven effort for estimating the likelihood (probability) that a software vulnerability (CVE) will be exploited in the wild.

## Data streams

The First EPSS integration collects one type of data stream: `epss`

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


## Logs reference

### EPSS

Retrieves CVEs using the First EPSS API.

An example event for `epss` looks as following:

```json
{
  "_index": ".ds-logs-first.epss-default-2024.08.11-000001",
  "_id": "SmDFQZEBL7kK8upPQ5pd",
  "_version": 1,
  "_score": 0,
  "_source": {
    "input": {
      "type": "cel"
    },
    "agent": {
      "name": "docker-fleet-agent",
      "id": "c884e63b-dea9-403d-86dc-10493c97c4a9",
      "ephemeral_id": "20f70707-53e7-4c22-84ef-d4c049bdf8a6",
      "type": "filebeat",
      "version": "8.14.3"
    },
    "@timestamp": "2024-08-11T14:08:52.538Z",
    "ecs": {
      "version": "8.11.0"
    },
    "data_stream": {
      "namespace": "default",
      "type": "logs",
      "dataset": "first.epss"
    },
    "elastic_agent": {
      "id": "c884e63b-dea9-403d-86dc-10493c97c4a9",
      "version": "8.14.3",
      "snapshot": false
    },
    "vulnerability": {
      "reference": "https://api.first.org/data/v1/epss?pretty=true&cve=CVE-2024-6505",
      "id": "CVE-2024-6505"
    },
    "event": {
      "agent_id_status": "verified",
      "ingested": "2024-08-11T14:08:52Z",
      "kind": "enrichment",
      "category": [
        "vulnerability"
      ],
      "type": [
        "info"
      ],
      "dataset": "first.epss"
    },
    "first": {
      "epss": {
        "date": "2024-08-11",
        "cve": "CVE-2024-6505",
        "percentile": 0.13869,
        "epss": 0.00044
      }
    },
    "tags": [
      "forwarded",
      "first"
    ]
  }
}
```

#### Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| first.epss.cve | CVE number | keyword |
| first.epss.date | Exploit Prediction Scoring System score calculation date | date |
| first.epss.epss | Exploit Prediction Scoring System score value | float |
| first.epss.percentile | Exploit Prediction Scoring System percentile value | float |
| input.type | Input type | keyword |
