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

```sh
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
    "@timestamp": "2016-01-03T00:37:51.394Z",
    "agent": {
        "ephemeral_id": "26e35ddc-258e-426f-87cf-40517f808d30",
        "id": "82d0dfd8-3946-4ac0-a092-a9146a71e3f7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "auditd": {
        "log": {
            "proctitle": "bash",
            "sequence": 194438
        }
    },
    "data_stream": {
        "dataset": "auditd.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "82d0dfd8-3946-4ac0-a092-a9146a71e3f7",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "action": "proctitle",
        "agent_id_status": "verified",
        "dataset": "auditd.log",
        "ingested": "2021-12-24T01:30:55Z",
        "kind": "event"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "192.168.224.7"
        ],
        "mac": [
            "02:42:c0:a8:e0:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-41-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/audit.log"
        },
        "offset": 1706
    },
    "tags": [
        "auditd-log"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |

