# Auditd Manager Integration

The Auditd Manager Integration receives audit events from the Linux Audit Framework that
is a part of the Linux kernel.

This integration is available only for Linux.

## How it works

This integration establishes a subscription to the kernel to receive the events
as they occur.

The Linux Audit Framework can send multiple messages for a single auditable
event. For example, a `rename` syscall causes the kernel to send eight separate
messages. Each message describes a different aspect of the activity that is
occurring (the syscall itself, file paths, current working directory, process
title). This integration will combine all of the data from each of the messages
into a single event.

Messages for one event can be interleaved with messages from another event. This
module will buffer the messages in order to combine related messages into a
single event even if they arrive interleaved or out of order.

## Useful commands

When running this integration, you might find that other monitoring tools interfere with it.

For example, you might encounter errors if another process, such as `auditd`, is
registered to receive data from the Linux Audit Framework. You can use these
commands to see if the `auditd` service is running and stop it:

* See if `auditd` is running:

```shell
service auditd status
```

* Stop the `auditd` service:

```shell
service auditd stop
```

* Disable `auditd` from starting on boot:

```shell
chkconfig auditd off
```

To save CPU usage and disk space, you can use this command to stop `journald`
from listening to audit messages:

```shell
systemctl mask systemd-journald-audit.socket
```

## Audit rules

The audit rules are where you configure the activities that are audited. These
rules are configured as either syscalls or files that should be monitored. For
example you can track all `connect` syscalls or file system writes to
`/etc/passwd`.

Auditing a large number of syscalls can place a heavy load on the system so
consider carefully the rules you define and try to apply filters in the rules
themselves to be as selective as possible.

The kernel evaluates the rules in the order in which they were defined so place
the most active rules first in order to speed up evaluation.

You can assign keys to each rule for better identification of the rule that
triggered an event and easier filtering later in Elasticsearch.

Defining any audit rules in the config causes `elastic-agent` to purge all
existing audit rules prior to adding the rules specified in the config.
Therefore it is unnecessary and unsupported to include a `-D` (delete all) rule.

Examples:

```sh
## If you are on a 64 bit platform, everything should be running
## in 64 bit mode. This rule will detect any use of the 32 bit syscalls
## because this might be a sign of someone exploiting a hole in the 32
## bit API.
-a always,exit -F arch=b32 -S all -F key=32bit-abi

## Executions.
-a always,exit -F arch=b64 -S execve,execveat -k exec

## External access (warning: these can be expensive to audit).
-a always,exit -F arch=b64 -S accept,bind,connect -F key=external-access

## Unauthorized access attempts.
-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -k access

# Things that affect identity.
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity

# Unauthorized access attempts to files (unsuccessful).
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
```

An example event for `auditd` looks as following:

```json
{
    "@timestamp": "2022-04-07T15:05:50.500Z",
    "agent": {
        "ephemeral_id": "e0628fc4-1dd1-41be-bd91-933cab7a1f84",
        "id": "0f196a51-65b8-4251-a335-71e4fb500136",
        "name": "auditd-agent",
        "type": "auditbeat",
        "version": "8.2.0"
    },
    "auditd": {
        "data": {
            "audit_backlog_wait_time": "0",
            "old": "0",
            "op": "set"
        },
        "message_type": "config_change",
        "result": "success",
        "sequence": 68938,
        "summary": {
            "actor": {
                "primary": "unset"
            },
            "object": {
                "primary": "set",
                "type": "audit-config"
            }
        }
    },
    "data_stream": {
        "dataset": "auditd_manager.auditd",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "0f196a51-65b8-4251-a335-71e4fb500136",
        "snapshot": true,
        "version": "8.2.0"
    },
    "event": {
        "action": "changed-audit-configuration",
        "agent_id_status": "verified",
        "category": [
            "process",
            "configuration"
        ],
        "dataset": "auditd_manager.auditd",
        "ingested": "2022-04-07T15:05:53Z",
        "kind": "event",
        "module": "auditd",
        "original": [
            "type=CONFIG_CHANGE msg=audit(1649343950.500:68938): op=set audit_backlog_wait_time=0 old=0 auid=4294967295 ses=4294967295 res=1"
        ],
        "outcome": "success",
        "type": [
            "change"
        ]
    },
    "host": {
        "name": "auditd-agent"
    },
    "service": {
        "type": "auditd"
    },
    "tags": [
        "preserve_original_event",
        "auditd_manager-auditd"
    ],
    "user": {}
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| auditd.data.a0 |  | keyword |
| auditd.data.a1 |  | keyword |
| auditd.data.a2 |  | keyword |
| auditd.data.a3 |  | keyword |
| auditd.data.arch |  | keyword |
| auditd.data.argc |  | keyword |
| auditd.data.audit_backlog_wait_time |  | keyword |
| auditd.data.audit_pid |  | keyword |
| auditd.data.auid |  | keyword |
| auditd.data.exit |  | keyword |
| auditd.data.fe |  | keyword |
| auditd.data.fi |  | keyword |
| auditd.data.fp |  | keyword |
| auditd.data.frootid |  | keyword |
| auditd.data.fver |  | keyword |
| auditd.data.old |  | keyword |
| auditd.data.old_pa |  | keyword |
| auditd.data.old_pe |  | keyword |
| auditd.data.old_pi |  | keyword |
| auditd.data.old_pp |  | keyword |
| auditd.data.op |  | keyword |
| auditd.data.pa |  | keyword |
| auditd.data.pe |  | keyword |
| auditd.data.pi |  | keyword |
| auditd.data.pp |  | keyword |
| auditd.data.result |  | keyword |
| auditd.data.ses |  | keyword |
| auditd.data.socket.family |  | keyword |
| auditd.data.socket.saddr |  | keyword |
| auditd.data.syscall |  | keyword |
| auditd.data.tty |  | keyword |
| auditd.message_type |  | keyword |
| auditd.paths |  | keyword |
| auditd.result |  | keyword |
| auditd.sequence |  | long |
| auditd.summary.actor.primary |  | keyword |
| auditd.summary.actor.secondary |  | keyword |
| auditd.summary.how |  | keyword |
| auditd.summary.object.primary |  | keyword |
| auditd.summary.object.type |  | keyword |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.executable | Absolute path to the process executable. | keyword |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| process.working_directory | The working directory of the process. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.effective.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.effective.group.name | Name of the group. | keyword |
| user.effective.id | Unique identifier of the user. | keyword |
| user.effective.name | Short name or login of the user. | keyword |
| user.filesystem.group.id |  | keyword |
| user.filesystem.group.name |  | keyword |
| user.filesystem.id |  | keyword |
| user.filesystem.name |  | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.saved.group.id |  | keyword |
| user.saved.group.name |  | keyword |
| user.saved.id |  | keyword |
| user.saved.name |  | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |

