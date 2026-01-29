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
    "@timestamp": "2025-06-10T17:39:26.680Z",
    "agent": {
        "ephemeral_id": "4b56d09d-0475-40a3-9aeb-5b49a4f82c2b",
        "id": "c00985e3-3268-4a43-92db-ec29f6fc8a77",
        "name": "elastic-agent-68585",
        "type": "filebeat",
        "version": "8.17.4"
    },
    "data_stream": {
        "dataset": "ti_strider.indicator",
        "namespace": "31572",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "c00985e3-3268-4a43-92db-ec29f6fc8a77",
        "snapshot": false,
        "version": "8.17.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "ti_strider.indicator",
        "ingested": "2025-06-10T17:39:27Z"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-68585",
        "ip": [
            "10.10.10.10"
        ],
        "mac": [
            "00-1A-2B-3C-4D-5E."
        ],
        "name": "elastic-agent-68585",
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
        "name_primary": "example@email.address",
        "name_secondary": [
            {
                "name": "辅助名称示例",
                "language": "zn"
            }
        ],
        "risk_signal": "GT",
        "type": "emailAddress"
    }
}
```