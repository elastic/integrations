# Strider Shield

This integration connects with [the REST API provided by Strider Intel](https://www.striderintel.com/shield/) to ingest threat indicators.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

This integration is designed to run on a [Fleet Agent](https://www.elastic.co/docs/reference/fleet)

## Expiration of Indicators of Compromise (IOCs)

Indicators are expired after a certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for a source index to allow only active indicators to be available to the end users. The transform creates a destination index named `logs-ti_strider_latest.indicator*` which only contains active and unexpired indicators. Destination indices are aliased to `logs-ti_strider_latest.indicator`.

### ILM Policy

To facilitate IOC expiration, source datastream-backed indices `logs-ti_strider.indicator-*` are allowed to contain duplicates. ILM policy `logs-ti_strider.indicator-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `7 days` from ingestion date

## Data Streams

### Indicator

The Shield integration collects logs from the API based on a polling interval, 

An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2025-06-11T15:10:15.351Z",
    "agent": {
        "ephemeral_id": "421d9d51-5675-4ee5-801c-d96ab603cd9a",
        "id": "b579255e-b46b-4be7-884d-67f2bd6232e4",
        "name": "elastic-agent-42318",
        "type": "filebeat",
        "version": "8.17.4"
    },
    "data_stream": {
        "dataset": "ti_strider.indicator",
        "namespace": "58899",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "b579255e-b46b-4be7-884d-67f2bd6232e4",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "ti_strider.indicator",
        "ingested": "2025-06-11T15:10:15Z"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-42318",
        "ip": [
            "172.19.0.2",
            "172.18.0.4"
        ],
        "mac": [
            "2E-0B-3E-A0-2B-AA",
            "82-55-19-ED-C0-78"
        ],
        "name": "elastic-agent-42318",
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
    "ioc": {
        "changes": "{}",
        "dates_added": "2022-09-20T05:00:00.000Z",
        "expires_at": "2025-07-10T12:00:00.000Z",
        "is_new": 0,
        "md5": "001259ecf5401350737e51e405954357",
        "name_primary": "abagautdinova@itmo.ru",
        "name_secondary": [],
        "risk_signal": "GT",
        "type": "emailAddress"
    }
}
```
