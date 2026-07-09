# Backstage Integration for Elastic

## Overview

The Backstage integration for Elastic collects audit log events emitted by [Backstage](https://backstage.io)'s built-in `auditor` service, giving you visibility into user actions, plugin activity, and catalog operations across your Backstage instance. Events are parsed and normalized into the Elastic Common Schema (ECS) so you can search, alert on, and visualize user and plugin activity across your developer platform.

### Compatibility

This integration is compatible with Backstage backends built on `@backstage/backend-plugin-api` version `1.2.0` or later, the release that introduced the built-in `auditor` core service (implemented by default via `@backstage/backend-defaults`). No additional Backstage plugin is required — every Backstage backend created with `createBackend()` emits audit events through this service automatically.

### How it works

Backstage's `auditor` service formats each audit event as a single JSON log line (message format `<plugin>.<eventId>`) through the root Winston logger, along with fields such as the acting user, HTTP request details, the originating plugin, event status, and severity level. This integration's filestream input reads those JSON lines from a log file — for example, captured container or pod output, or a file the Backstage backend writes to directly — and the ingest pipeline parses and maps them to ECS.

## What data does this integration collect?

The Backstage integration collects audit log events of the following types, depending on which plugins emit `auditor` events in your Backstage instance:
* Catalog operations: entity fetch and catalog query events, including the requested fields and applied filters.
* User and plugin activity: the acting user or service, the plugin and event name, HTTP method and URL, and whether the operation succeeded, failed, or is still in progress.
* Severity-classified events: each event carries a Backstage-assigned severity level (`low`, `medium`, or `high`), mapped to `event.severity`.

### Supported use cases

Integrating Backstage audit logs with the Elastic Stack lets you:
* Monitor user activity: track who accessed or modified catalog entities, and from where.
* Investigate plugin behavior: correlate events by `event.provider` (the Backstage plugin) and `event.code` (the audit event ID) to debug or audit plugin-specific actions.
* Support compliance and security monitoring: maintain a searchable, ECS-normalized record of administrative and catalog actions performed through Backstage.

## What do I need to use this integration?

To use this integration, you'll need the following vendor prerequisites:
- A Backstage backend built with `createBackend()` from `@backstage/backend-defaults` (version `1.2.0` or later), so the `auditor` service is available and emitting events automatically.
- The audit log output written to a location the Elastic Agent can read as a file — for example, captured container/pod logs mounted into the Elastic Agent's filesystem, or a file the Backstage backend logs to directly.

You'll also need the following Elastic prerequisites:
- Elastic Stack (Elasticsearch and Kibana) version `8.19.0` or later.
- An active Elastic Agent installed and enrolled in Fleet, with filesystem access to the Backstage audit log file(s).

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host or container that has access to the Backstage audit log file(s). For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to collect the log file(s) and ship the data to Elastic, where the events are then processed by this integration's ingest pipeline.

### Onboard / configure

1. In Kibana, navigate to **Management → Integrations**.
2. Search for **Backstage** and select the integration.
3. Click **Add Backstage**.
4. Configure **Paths** to point to the location of the Backstage audit log file(s) — for example, a mounted volume or captured container log path. The default is `/var/log/*.log`.
5. (Optional) Configure **Exclude files** to skip rotated or compressed log files. The default already excludes `.gz` files.
6. (Optional) Configure **Parsers** if your Backstage audit log lines are pretty-printed across multiple lines rather than one JSON object per line. See the field's description for `ndjson` and `multiline` examples.
7. Assign the integration to an Elastic Agent policy and click **Save and continue**.

### Validation

After the configuration is complete, follow these steps to verify data is flowing correctly from Backstage to the Elastic Stack:

1. Trigger an audit event in Backstage — for example, browse the Software Catalog to trigger a `catalog.entity-fetch` event.
2. In Kibana, navigate to **Analytics → Discover**.
3. Select the `logs-*` data view.
4. In the search bar, enter the filter: `data_stream.dataset: "backstage.audit_logs"`.
5. Verify that events appear with a non-null `event.action` field, and that `event.provider` reflects the Backstage plugin that generated the event (for example, `catalog`).

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

- **No events collected**: Confirm the Backstage backend is emitting audit events (not every plugin calls the `auditor` service for every operation) and that the configured **Paths** match the actual log file location.
- **Multi-line JSON not parsed**: If your Backstage deployment pretty-prints JSON log lines across multiple lines, enable the `multiline` parser under **Parsers**. Otherwise, partial lines are dropped by the pipeline's `isAuditEvent` check.
- **Events silently dropped**: The ingest pipeline drops any line that doesn't contain an `isAuditEvent` key, so non-audit application logs mixed into the same file are expected to be filtered out.
- **Permission denied reading the log file**: Elastic Agent needs read access to the Backstage audit log file(s). If your environment writes them with restrictive ownership/permissions, deploy Elastic Agent as `root` (or a user with equivalent read access) on that host or container. This is a deployment-time decision, not a setting configurable through this integration.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Inputs used

The following inputs are used by this integration:

These inputs can be used with this integration:
<details>
<summary>filestream</summary>

## Setup

For more details about the Filestream input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream).


### Collecting logs from Filestream

To collect logs via Filestream, select **Collect logs via Filestream** and configure the following parameters:

- Filestream paths: The full path to the related log file.
</details>


### Data streams

#### audit_logs

The `audit_logs` data stream provides audit events from Backstage's `auditor` service, including catalog operations, user activity, and other plugin-specific audit events.

##### audit_logs fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| backstage.meta | Event-specific metadata emitted by the Backstage plugin. Shape varies per event type; stored as `flattened` to preserve arbitrary keys without mapping explosion. Well-known catalog-query keys are promoted to `backstage.query.\*`. | flattened |
| backstage.query.fields | The entity fields requested by the catalog query. | keyword |
| backstage.query.filter | The catalog query filter conditions as key/value pairs. | flattened |
| backstage.query.type | The type of catalog query that was issued (e.g. "all"). | keyword |
| backstage.severity_level | The severity level of the audit log registered by Backstage. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| input.type | Input type. | keyword |
| log.file.device_id | Device ID of the log file this event came from. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset. | long |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The field contains the entire query string, excluding the leading `?` character, such as "q=elasticsearch". If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |


##### audit_logs sample event

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2026-05-22T20:30:05.131Z",
    "agent": {
        "ephemeral_id": "a6024ff8-93af-4093-a415-2fb817831669",
        "id": "a5b33dca-2a73-40bc-8306-73781e65d5b8",
        "name": "elastic-agent-29040",
        "type": "filebeat",
        "version": "9.3.3"
    },
    "backstage": {
        "query": {
            "fields": [
                "metadata",
                "kind",
                "spec.profile"
            ],
            "filter": {
                "kind": "group",
                "relations": {
                    "hasMember": "user:default/guest"
                }
            },
            "type": "all"
        },
        "severity_level": "low"
    },
    "data_stream": {
        "dataset": "backstage.audit_logs",
        "namespace": "34846",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "a5b33dca-2a73-40bc-8306-73781e65d5b8",
        "snapshot": false,
        "version": "9.3.3"
    },
    "event": {
        "action": "entity-fetch:initiated",
        "agent_id_status": "verified",
        "category": [
            "api"
        ],
        "code": "entity-fetch",
        "dataset": "backstage.audit_logs",
        "ingested": "2026-07-09T14:49:59Z",
        "kind": "event",
        "module": "backstage",
        "original": "{\"actor\":{\"hostname\":\"localhost\",\"ip\":\"127.0.0.1\",\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36\"},\"eventId\":\"entity-fetch\",\"isAuditEvent\":true,\"level\":\"info\",\"message\":\"catalog.entity-fetch\",\"meta\":{\"query\":{\"fields\":[\"metadata\",\"kind\",\"spec.profile\"],\"filter\":[\"kind=group,relations.hasMember=user:default/guest\"]},\"queryType\":\"all\"},\"plugin\":\"catalog\",\"request\":{\"method\":\"GET\",\"url\":\"/api/catalog/entities?fields=metadata,kind,spec.profile&filter=kind%3Dgroup%2Crelations.hasMember%3Duser%3Adefault%2Fguest\"},\"service\":\"backstage\",\"severityLevel\":\"low\",\"status\":\"initiated\",\"timestamp\":\"2026-05-22T20:30:05.131Z\"}",
        "outcome": "unknown",
        "provider": "catalog",
        "severity": 3,
        "type": [
            "access",
            "start"
        ]
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-29040",
        "ip": [
            "172.21.0.2",
            "172.18.0.5"
        ],
        "mac": [
            "06-3D-FD-39-9E-43",
            "BE-07-79-AE-71-90"
        ],
        "name": "elastic-agent-29040",
        "os": {
            "family": "",
            "kernel": "6.12.76-linuxkit",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "http": {
        "request": {
            "method": "GET"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "44",
            "inode": "399",
            "path": "/tmp/service_logs/test-audit-events.log"
        },
        "level": "info",
        "offset": 0
    },
    "message": "catalog.entity-fetch",
    "related": {
        "hosts": [
            "localhost"
        ],
        "ip": [
            "127.0.0.1"
        ]
    },
    "source": {
        "ip": "127.0.0.1"
    },
    "tags": [
        "backstage",
        "preserve_original_event"
    ],
    "url": {
        "original": "/api/catalog/entities?fields=metadata,kind,spec.profile&filter=kind%3Dgroup%2Crelations.hasMember%3Duser%3Adefault%2Fguest",
        "path": "/api/catalog/entities",
        "query": "fields=metadata,kind,spec.profile&filter=kind=group,relations.hasMember=user:default/guest"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.15.7",
            "name": "Mac OS X",
            "version": "10.15.7"
        },
        "version": "148.0.0.0"
    }
}
```

### Vendor documentation links

For more information about Backstage's auditor service, refer to:
* [Backstage Auditor Service documentation](https://backstage.io/docs/backend-system/core-services/auditor)
