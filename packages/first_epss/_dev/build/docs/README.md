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


## Logs reference

### Vulnerability

Retrieves CVEs using the First EPSS API.

An example event for `vulnerability` looks as following:

```json
{
  "_index": ".ds-logs-first_epss.vulnerability-default-2024.08.25-000001",
  "_id": "DKKmi5EBUs3vuMyo3CjX",
  "_version": 1,
  "_score": 0,
  "_source": {
    "input": {
      "type": "cel"
    },
    "agent": {
      "name": "docker-fleet-agent",
      "id": "8b72fd47-8834-4fb6-8c39-c6bbe8ab8a13",
      "type": "filebeat",
      "ephemeral_id": "d503405a-e1a9-4200-baa7-acf87dd9ae70",
      "version": "8.15.0"
    },
    "@timestamp": "2024-08-25T22:27:33.219Z",
    "ecs": {
      "version": "8.11.0"
    },
    "data_stream": {
      "namespace": "default",
      "type": "logs",
      "dataset": "first_epss.vulnerability"
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
    "elastic_agent": {
      "id": "8b72fd47-8834-4fb6-8c39-c6bbe8ab8a13",
      "version": "8.15.0",
      "snapshot": false
    },
    "first_epss": {
      "vulnerability": {
        "date": "2024-08-25T00:00:00.000Z",
        "cve": "CVE-1999-0001",
        "percentile": 0.73458,
        "epss": 0.00383
      }
    },
    "vulnerability": {
      "reference": "https://api.first.org/data/v1/epss?pretty=true&cve=CVE-1999-0001",
      "id": "CVE-1999-0001"
    },
    "event": {
      "agent_id_status": "verified",
      "ingested": "2024-08-25T22:27:34Z",
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
}
```

#### Exported fields

{{fields "vulnerability"}}