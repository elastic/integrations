# NVIDIA OpenShell

[NVIDIA OpenShell](https://docs.nvidia.com/openshell/) runs AI agents and other untrusted workloads inside policy-controlled sandboxes. A supervisor inside each sandbox mediates every outbound connection, HTTP request and SSH session against the sandbox policy and records the decision as an [OCSF](https://schema.ocsf.io/) event.

This integration collects the OCSF JSON export written by the OpenShell sandbox supervisor (or the Windows MXC gateway), normalizes it to the Elastic Common Schema (ECS), and keeps the OCSF-specific attributes under `openshell.ocsf.*`. The resulting events let you audit what sandboxed workloads tried to reach, which policy rule decided the outcome, and which process inside the sandbox initiated the activity.

## Data streams

The integration collects one data stream, `ocsf`, which contains every OCSF event class emitted by OpenShell:

| `class_uid` | OCSF class                  | What it records                                                         |
| ----------- | --------------------------- | ----------------------------------------------------------------------- |
| 4001        | Network Activity            | Allowed, denied and failed outbound connections (CONNECT, transparent TCP, DNS policy decisions) |
| 4002        | HTTP Activity               | Layer-7 request decisions for policy-inspected endpoints               |
| 4007        | SSH Activity                | SSH sessions accepted on the supervisor socket                          |
| 1007        | Process Activity            | Process events, when enabled by the supervisor                          |
| 2004        | Detection Finding           | Supervisor findings                                                     |
| 5019        | Device Config State Change  | Policy revisions loaded, published or detected by the supervisor        |
| 6002        | Application Lifecycle       | Supervisor lifecycle events                                             |
| 0           | Base Event                  | Relay open/close notifications and other operational events             |

Every event carries `observer.product: "OpenShell Sandbox Supervisor"`, the sandbox in `container.name` / `container.id`, and `event.code` set to the OCSF `class_uid`. Policy decisions are exposed as `event.action` (`allowed` / `denied`), `event.outcome`, `event.reason` (the OCSF `status_detail`, for example `transparent_tcp_policy_denied`) and `rule.name` / `rule.category` (the matching policy rule). Denied activity is categorized as `event.kind: alert`.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

OpenShell must have OCSF JSON export enabled. The export is opt-in and is written as JSON Lines, one OCSF record per line. Enable it globally or per sandbox:

```shell
openshell settings set --global --key ocsf_json_enabled --value true
# or
openshell settings set my-sandbox --key ocsf_json_enabled --value true
```

The setting takes effect on the next supervisor poll cycle (10 seconds by default). Leave `ocsf_schema_version` unset so records are written at the native OCSF 1.8.0 version; downgraded records are also parsed but lose the `container` object.

## Setup

### Linux sandbox supervisors

The supervisor writes records to `/var/log/openshell-ocsf.YYYY-MM-DD.log` inside the sandbox, rotating daily and keeping the three most recent files. Elastic Agent must be able to read that directory:

- With the Docker driver, mount the sandbox's `/var/log` on a volume that is also mounted into the Elastic Agent container, or run Elastic Agent in a sidecar container that shares the volume.
- With the Kubernetes driver, mount the sandbox pod's `/var/log` on a `hostPath` or shared volume and point the Elastic Agent DaemonSet at it.

Then add the integration to an agent policy and set **Paths** to the mounted location, for example `/var/lib/openshell/logs/*/openshell-ocsf.*.log`. The default path, `/var/log/openshell-ocsf.*.log`, matches an agent running inside the sandbox network namespace.

### Windows MXC gateways

Enable the ETW audit consumer and the durable JSONL sink on the gateway:

```toml
[openshell.drivers.mxc]
etw_audit = true
```

```powershell
$env:OPENSHELL_OCSF_JSON = "1"
$env:OPENSHELL_OCSF_LOG_DIR = "D:\OpenShell\audit"   # optional, defaults to %PROGRAMDATA%\OpenShell\logs
openshell-gateway --drivers mxc --config gateway.toml
```

Set **Paths** to the chosen directory, for example `C:\ProgramData\OpenShell\logs\openshell-ocsf.*.log`.

### Options

- **Preserve original event** keeps the raw JSON record in `event.original`.
- **Preserve duplicate custom fields** keeps the `openshell.ocsf.*` fields that were copied to ECS fields.

## Logs reference

### OCSF events

An example event for `ocsf` looks as following:

```json
{
    "@timestamp": "2026-09-29T13:50:08.267Z",
    "agent": {
        "ephemeral_id": "5f0c4b6a-2c3e-4a8e-9f1d-0b7c2a9e6d41",
        "id": "3b1f9a44-1b1e-4a71-9f0a-6a2a7f1c9d2e",
        "name": "openshell-node-1",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "container": {
        "id": "f5be9de4-94f0-49a0-af70-3262192e50f9",
        "name": "sandbox-a"
    },
    "data_stream": {
        "dataset": "openshell.ocsf",
        "namespace": "default",
        "type": "logs"
    },
    "destination": {
        "ip": "169.254.169.254",
        "port": 80
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "3b1f9a44-1b1e-4a71-9f0a-6a2a7f1c9d2e",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "denied",
        "category": [
            "network"
        ],
        "code": "4001",
        "dataset": "openshell.ocsf",
        "id": "4f8a1500-1048-40f5-bfa8-3c187b086f20",
        "ingested": "2026-09-29T13:50:10Z",
        "kind": "alert",
        "module": "openshell",
        "outcome": "failure",
        "reason": "transparent_tcp_policy_denied",
        "severity": 3,
        "type": [
            "connection",
            "denied"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "openshell-node-1",
        "id": "6f2f9a0b4c1d4e8f9a7b6c5d4e3f2a1b",
        "ip": [
            "10.42.0.31"
        ],
        "mac": [
            "02-42-0A-2A-00-1F"
        ],
        "name": "openshell-node-1",
        "os": {
            "family": "debian",
            "kernel": "6.6.0",
            "name": "Linux",
            "platform": "debian",
            "type": "linux",
            "version": "12 (bookworm)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/var/log/openshell-ocsf.2026-09-29.log"
        },
        "offset": 48213
    },
    "message": "Transparent TCP denied before relay: endpoint 169.254.169.254:80 is not allowed by any policy",
    "network": {
        "direction": "egress",
        "transport": "tcp"
    },
    "observer": {
        "hostname": "docker-desktop",
        "os": {
            "name": "Linux"
        },
        "product": "OpenShell Sandbox Supervisor",
        "vendor": "OpenShell",
        "version": "0.1.2"
    },
    "openshell": {
        "ocsf": {
            "action_id": 2,
            "activity_id": 1,
            "activity_name": "Open",
            "category_name": "Network Activity",
            "category_uid": 4,
            "class_name": "Network Activity",
            "class_uid": 4001,
            "device": {
                "type": "Sandbox",
                "type_id": 99
            },
            "disposition": "Blocked",
            "disposition_id": 2,
            "is_src_dst_assignment_known": true,
            "metadata": {
                "profiles": [
                    "security_control",
                    "network_proxy",
                    "container",
                    "host"
                ],
                "version": "1.8.0"
            },
            "proxy_endpoint": {
                "ip": "127.0.0.1",
                "port": 3128
            },
            "severity": "Medium",
            "status": "Failure",
            "status_id": 2,
            "type_name": "Network Activity: Open",
            "type_uid": 400101
        }
    },
    "process": {
        "executable": "/usr/bin/curl",
        "name": "curl",
        "parent": {
            "executable": "/usr/bin/bash",
            "name": "bash"
        }
    },
    "related": {
        "hosts": [
            "docker-desktop"
        ],
        "ip": [
            "169.254.169.254"
        ]
    },
    "tags": [
        "openshell-ocsf"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| container.id | Unique container id. | keyword |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.status_code | HTTP response status code. | long |
| input.type | Type of filebeat input. | keyword |
| log.file.path | Path of the log file the record was read from. | keyword |
| log.offset | Log offset. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.os.name | Operating system name, without the version. | keyword |
| observer.os.name.text | Multi-field of `observer.os.name`. | match_only_text |
| observer.product | The product name of the observer. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| openshell.ocsf.action | Policy decision applied to the activity (Allowed, Denied). | keyword |
| openshell.ocsf.action_id | Normalized identifier of the action. | long |
| openshell.ocsf.activity_id | Normalized identifier of the activity. | long |
| openshell.ocsf.activity_name | Activity name (Open, Refuse, Fail, Other, Log, Relay open, Relay closed). | keyword |
| openshell.ocsf.actor.process.cmd_line | Command line of the sandbox process that initiated the activity. | keyword |
| openshell.ocsf.actor.process.name | Executable path of the sandbox process that initiated the activity. | keyword |
| openshell.ocsf.actor.process.parent_process.cmd_line | Command line of the parent process. | keyword |
| openshell.ocsf.actor.process.parent_process.name | Executable path of the parent process. | keyword |
| openshell.ocsf.actor.process.parent_process.parent_process.name | Executable path of the grandparent process. | keyword |
| openshell.ocsf.actor.process.parent_process.parent_process.pid | PID of the grandparent process. | long |
| openshell.ocsf.actor.process.parent_process.pid | PID of the parent process. | long |
| openshell.ocsf.actor.process.pid | PID of the sandbox process that initiated the activity. | long |
| openshell.ocsf.category_name | OCSF category name. | keyword |
| openshell.ocsf.category_uid | OCSF category identifier. | long |
| openshell.ocsf.class_name | OCSF event class name. | keyword |
| openshell.ocsf.class_uid | OCSF event class identifier (0, 4001, 4002, 4007, 1007, 2004, 5019, 6002). | long |
| openshell.ocsf.container.name | Sandbox name. | keyword |
| openshell.ocsf.container.uid | Sandbox identifier. | keyword |
| openshell.ocsf.device.hostname | Hostname of the node running the sandbox. | keyword |
| openshell.ocsf.device.os.name | Operating system of the node running the sandbox. | keyword |
| openshell.ocsf.device.type | Device type reported by OpenShell (Sandbox). | keyword |
| openshell.ocsf.device.type_id | Normalized identifier of the device type. | long |
| openshell.ocsf.disposition | Disposition of the security control (Allowed, Blocked). | keyword |
| openshell.ocsf.disposition_id | Normalized identifier of the disposition. | long |
| openshell.ocsf.dst_endpoint.domain | Destination hostname requested by the sandbox. | keyword |
| openshell.ocsf.dst_endpoint.ip | Destination IP address. | ip |
| openshell.ocsf.dst_endpoint.port | Destination port. | long |
| openshell.ocsf.firewall_rule.name | Name of the policy rule that matched the activity. | keyword |
| openshell.ocsf.firewall_rule.type | Type of the policy rule that matched the activity (l7, opa). | keyword |
| openshell.ocsf.http_request.http_method | HTTP request method. | keyword |
| openshell.ocsf.http_request.url.hostname | Hostname component of the request URL. | keyword |
| openshell.ocsf.http_request.url.path | Path component of the request URL. | keyword |
| openshell.ocsf.http_request.url.port | Port component of the request URL. | long |
| openshell.ocsf.http_request.url.scheme | Scheme component of the request URL. | keyword |
| openshell.ocsf.http_response.code | HTTP response status code. | long |
| openshell.ocsf.is_src_dst_assignment_known | Whether the source and destination roles are known. | boolean |
| openshell.ocsf.message | Human-readable description of the event. | keyword |
| openshell.ocsf.metadata.product.name | Product that emitted the record. | keyword |
| openshell.ocsf.metadata.product.vendor_name | Vendor of the product that emitted the record. | keyword |
| openshell.ocsf.metadata.product.version | Version of the product that emitted the record. | keyword |
| openshell.ocsf.metadata.profiles | OCSF profiles applied to the record. | keyword |
| openshell.ocsf.metadata.uid | Unique identifier of the record. | keyword |
| openshell.ocsf.metadata.version | OCSF schema version of the record. | keyword |
| openshell.ocsf.observation_point_id | Normalized identifier of the observation point. | long |
| openshell.ocsf.proxy_endpoint.ip | IP address of the supervisor proxy listener that observed the activity. | ip |
| openshell.ocsf.proxy_endpoint.port | Port of the supervisor proxy listener that observed the activity. | long |
| openshell.ocsf.severity | Severity label. | keyword |
| openshell.ocsf.severity_id | Normalized severity identifier. | long |
| openshell.ocsf.src_endpoint.ip | Source IP address inside the sandbox. | ip |
| openshell.ocsf.src_endpoint.port | Source port inside the sandbox. | long |
| openshell.ocsf.state | Configuration state for Device Config State Change events. | keyword |
| openshell.ocsf.state_id | Normalized identifier of the configuration state. | long |
| openshell.ocsf.status | Outcome status (Success, Failure). | keyword |
| openshell.ocsf.status_detail | Detailed reason for the status, such as the policy decision code. | keyword |
| openshell.ocsf.status_id | Normalized identifier of the status. | long |
| openshell.ocsf.time | Event time. | date |
| openshell.ocsf.type_name | OCSF event type name. | keyword |
| openshell.ocsf.type_uid | OCSF event type identifier. | long |
| openshell.ocsf.unmapped | OpenShell-specific attributes that are not part of the OCSF schema, such as policy generation, mapping identifiers and allowed ports. | flattened |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |

