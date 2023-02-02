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

{{event "logs"}}

The following fields may be used by the package:

{{fields "logs"}}
