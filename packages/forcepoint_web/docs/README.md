# Forcepoint Web Security

This integration allows you to ingest log and event data from Forcepoint Web Security.

NOTE: At present it is limited to ingestion of files exported using the offical Forcepoint Log Export SIEM tool, refer to [this page](https://www.websense.com/content/support/library/web/hosted/admin_guide/siem_script.aspx)

## Data streams

The Forcepoint Web Security integration collects one type of data stream: logs.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.

You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

Start by reading [this page](https://www.websense.com/content/support/library/web/hosted/admin_guide/siem_integration_explain.aspx).

While it is possible to use AWS S3 as BYO storage that Forcepoint Web Security can export logs to, at this point the integration does not support connection to an S3 bucket directly.

Configuration of storage type is [described here](https://www.websense.com/content/support/library/web/hosted/admin_guide/siem_storage.aspx).

A Perl script is provided by Forcepoint to "pull" logs from "Forcepoint" storage and is [described here](https://www.websense.com/content/support/library/web/hosted/admin_guide/siem_script.aspx).

A containerised version of the Forcepoint Log Export SIEM tool is available via this [GitHub repository](https://github.com/colin-stubbs/docker-forcepoint-log_export_siem).

The format of the gzip compressed CSV files that Forcepoint Web Security spits out is configurable, ensure you read and understand [this page](https://www.websense.com/content/support/library/web/hosted/siem_guide/siem_format.aspx).

The default format assumed by this integration is:
```
"%{date}","%{time}","%{user}","%{workstation}","%{category}","%{action}","%{risk_class}","%{policy_name}","%{url}","%{connection_ip}","%{destination_ip}","%{source_ip}","%{threat_type}","%{threat_name}","%{user_agent_string}","%{http_status_code}","%{http_request_method}"
```

The field names (encapsulated in %{}) used in this format will wind up under the `forcepoint_web` field object.

If you choose to export additional fields you may need to expand or change this entirely if you order things differently. It can be customised as part of each integration policy instance. Ensure you escape the double quotes (") in the string as per the default string.

At present those fields are currently mapped as follows,

| Field (under forcepoint_web) | Fields (ECS where possible)                   |
|------------------------------|-----------------------------------------------|
| date + time                  | @timestamp                                    |
| user                         | user.id, user.name, user.domain, related.user |
| workstation                  | host.name, related.hosts                      |
| category                     | -                                             |
| action                       | event.action (lowercase)                      |
| risk_class                   | -                                             |
| policy_name                  | rule.name                                     |
| url                          | url.*                                         |
| connection_ip                | source.nat.ip, related.ip                     |
| destination_ip               | destination.ip, related.ip                    |
| source_ip                    | source.ip, related.ip                         |
| threat_type                  | -                                             |
| threat_name                  | -                                             |
| user_agent_string            | user_agent.*                                  |
| http_status_code             | http.response.status_code                     |
| http_request_method          | http.request.method                           |

## Compatibility

This integration has been tested against Forcepoint Web Security using the Log Export SIEM tool version v2.0.1

Versions above this are expected to work but have not been tested.

## Debugging

If the "Preserve original event" is enabled, this will add the tag `preserve_original_event` to the event. `event.original` will be set with the *original* message contents, which is pre-KV and pre-syslog parsing.

If the "preserve_log" tag is added to an integration input, the `log` object and all fields under it will be preserved.

## Logs reference

### forcepoint_web.logs

The `forcepoint_web.logs` data stream provides events from Forcepoint Web Security.

#### Example

An example event for `forcepoint_web.logs` looks as following:

An example event for `logs` looks as following:

```json
{
    "@timestamp": "2023-01-13T00:30:45.891Z",
    "agent": {
        "ephemeral_id": "07b2ae81-8fca-461c-aba7-9331c2aabc5e",
        "id": "8cc7367b-4069-4535-8545-a477b8c273af",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.1"
    },
    "data_stream": {
        "dataset": "forcepoint_web.logs",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "3.24.198.68"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8cc7367b-4069-4535-8545-a477b8c273af",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "action": "allowed",
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "forcepoint_web.logs",
        "ingested": "2023-01-13T00:30:46Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "forcepoint_web": {
        "action": "Allowed",
        "category": [
            "Reference Materials",
            "Trusted Server Downloads"
        ],
        "connection_ip": "202.4.188.96",
        "date": "16/12/2022",
        "destination_ip": "3.24.198.68",
        "http_request_method": "Connect",
        "http_status_code": "200",
        "policy_name": "Org Internal Server Policy",
        "risk_class": [
            "Business Usage",
            "None"
        ],
        "time": "07:05:25",
        "timestamp": "2022-12-16T07:05:25.000Z",
        "user": "anonymous",
        "user_agent_string": "Java/11.0.6"
    },
    "http": {
        "request": {
            "method": "CONNECT"
        },
        "response": {
            "status_code": 200
        }
    },
    "input": {
        "type": "log"
    },
    "message": "\"16/12/2022\",\"07:05:25\",\"anonymous\",\"Not available\",\"Reference Materials,Trusted Server Downloads\",\"Allowed\",\"Business Usage,None\",\"Org Internal Server Policy\",\"aom-au.nearmap.com:443/\",\"202.4.188.96\",\"3.24.198.68\",\"Not available\",\"None\",\"None\",\"Java/11.0.6\",\"200\",\"Connect\"",
    "related": {
        "ip": [
            "3.24.198.68",
            "202.4.188.96"
        ],
        "user": [
            "anonymous"
        ]
    },
    "rule": {
        "name": "Org Internal Server Policy"
    },
    "source": {
        "nat": {
            "ip": "202.4.188.96"
        }
    },
    "tags": [
        "forwarded"
    ],
    "url": {
        "domain": "aom-au.nearmap.com",
        "original": "https://aom-au.nearmap.com:443/",
        "path": "/",
        "port": 443,
        "registered_domain": "nearmap.com",
        "scheme": "https",
        "subdomain": "aom-au",
        "top_level_domain": "com"
    },
    "user": {
        "id": "anonymous",
        "name": "anonymous"
    },
    "user_agent": {
        "device": {
            "name": "Spider"
        },
        "name": "Java",
        "original": "Java/11.0.6",
        "version": "0.6."
    }
}

```

The following fields may be used by the package:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| forcepoint_web.action |  | keyword |
| forcepoint_web.category |  | keyword |
| forcepoint_web.connection_ip |  | keyword |
| forcepoint_web.date |  | keyword |
| forcepoint_web.destination_ip |  | keyword |
| forcepoint_web.http_request_method |  | keyword |
| forcepoint_web.http_status_code |  | keyword |
| forcepoint_web.policy_name |  | keyword |
| forcepoint_web.risk_class |  | keyword |
| forcepoint_web.source_ip |  | keyword |
| forcepoint_web.time |  | keyword |
| forcepoint_web.timestamp |  | date |
| forcepoint_web.user |  | keyword |
| forcepoint_web.user_agent_string |  | keyword |
| forcepoint_web.workstation |  | keyword |
| input.type |  | keyword |

