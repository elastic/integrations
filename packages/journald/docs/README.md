# Journald Input

The journald input integration reads logs from the `journald` system service.
The journald input reads the log data and the metadata associated with it.

The journald input is available on Linux systems with `systemd` installed.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2020-07-22T13:17:10.012Z",
    "agent": {
        "ephemeral_id": "27e2a00a-dab2-4790-8d45-29ad272d0392",
        "id": "bef8099b-68f6-4621-8089-2229b35a669d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.2"
    },
    "data_stream": {
        "dataset": "journald.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "bef8099b-68f6-4621-8089-2229b35a669d",
        "snapshot": false,
        "version": "8.3.2"
    },
    "event": {
        "agent_id_status": "verified",
        "code": "ec387f577b844b8fa948f33cad9a75e6",
        "created": "2022-08-18T18:14:11.588Z",
        "dataset": "journald.log",
        "ingested": "2022-08-18T18:14:15Z",
        "kind": "event"
    },
    "host": {
        "hostname": "sleipnir",
        "id": "505afdafda3b4f33a63749ae39284742"
    },
    "input": {
        "type": "journald"
    },
    "journald": {
        "custom": {
            "available": "0",
            "available_pretty": "0B",
            "current_use": "1023455232",
            "current_use_pretty": "976.0M",
            "disk_available": "6866636800",
            "disk_available_pretty": "6.3G",
            "disk_keep_free": "1466253312",
            "disk_keep_free_pretty": "1.3G",
            "journal_name": "System journal",
            "journal_path": "/var/log/journal/505afdafda3b4f33a63749ae39284742",
            "limit": "977502208",
            "limit_pretty": "932.2M",
            "max_use": "977502208",
            "max_use_pretty": "932.2M"
        },
        "gid": 0,
        "host": {
            "boot_id": "fa3c2e3080dc4cd5be5cb5a43e140d51"
        },
        "pid": 19317,
        "process": {
            "capabilities": "25402800cf",
            "command_line": "/lib/systemd/systemd-journald",
            "executable": "/lib/systemd/systemd-journald",
            "name": "systemd-journal"
        },
        "uid": 0
    },
    "log": {
        "syslog": {
            "facility": {
                "code": 3
            },
            "identifier": "systemd-journald",
            "priority": 6
        }
    },
    "message": "System journal (/var/log/journal/505afdafda3b4f33a63749ae39284742) is 976.0M, max 932.2M, 0B free.",
    "process": {
        "args": [
            "/lib/systemd/systemd-journald"
        ],
        "args_count": 1,
        "command_line": "/lib/systemd/systemd-journald",
        "pid": 19317
    },
    "systemd": {
        "cgroup": "/system.slice/systemd-journald.service",
        "invocation_id": "7c11cda63635437bafe21c92851618a8",
        "slice": "system.slice",
        "transport": "driver",
        "unit": "systemd-journald.service"
    },
    "tags": [
        "forwarded"
    ],
    "user": {
        "group": {
            "id": "0"
        },
        "id": "0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| container.log.tag | User defined tag of a container. Originates from the Docker journald logging driver. | keyword |
| container.partial | A field that flags log integrity when a message is split. The docker journald logging driver splits long message into multiple events. | boolean |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| input.type |  | keyword |
| journald.audit.login_uid | The login UID of the process the journal entry originates from, as maintained by the kernel audit subsystem. | long |
| journald.audit.session | The session of the process the journal entry originates from, as maintained by the kernel audit subsystem. | keyword |
| journald.code.file | The code location generating this message, if known. Contains the source filename. | keyword |
| journald.code.func | The code location generating this message, if known. Contains the function name. | keyword |
| journald.code.line | The code location generating this message, if known. Contains the line number. | long |
| journald.coredump.unit | Used to annotate messages containing coredumps from system units. | keyword |
| journald.coredump.user_unit | Used to annotate messages containing coredumps from user units. | keyword |
| journald.custom | Structured fields added to the log message by the caller. | flattened |
| journald.gid | The group ID of the process the journal entry originates from formatted as a decimal string. Note that entries obtained via "stdout" or "stderr" of forked processes will contain credentials valid for a parent process. | long |
| journald.host.boot_id | The kernel boot ID for the boot the message was generated in, formatted as a 128-bit hexadecimal string. | keyword |
| journald.kernel.device | The kernel device name. If the entry is associated to a block device, contains the major and minor numbers of the device node, separated by ":" and prefixed by "b". Similarly for character devices, but prefixed by "c". For network devices, this is the interface index prefixed by "n". For all other devices, this is the subsystem name prefixed by "+", followed by ":", followed by the kernel device name. | keyword |
| journald.kernel.device_name | The kernel device name as it shows up in the device tree below `/sys/`. | keyword |
| journald.kernel.device_node_path | The device node path of this device in `/dev/`. | keyword |
| journald.kernel.device_symlinks | Additional symlink names pointing to the device node in `/dev/`. This field is frequently set more than once per entry. | keyword |
| journald.kernel.subsystem | The kernel subsystem name. | keyword |
| journald.object.audit.login_uid |  | long |
| journald.object.audit.session |  | long |
| journald.object.gid |  | long |
| journald.object.pid | Privileged programs (currently UID 0) may attach OBJECT_PID= to a message. This will instruct systemd-journald to attach additional `journald.object.\*` on behalf of the caller. These additional fields added automatically by systemd-journald. These additional `journald.object.\*` fields are the same as the equivalent `journald.\*` field except that the process identified by PID is described, instead of the process which logged the message. | long |
| journald.object.process.command_line |  | keyword |
| journald.object.process.executable |  | keyword |
| journald.object.process.name |  | keyword |
| journald.object.systemd.owner_uid |  | long |
| journald.object.systemd.session |  | keyword |
| journald.object.systemd.unit |  | keyword |
| journald.object.systemd.user_unit |  | keyword |
| journald.object.uid |  | long |
| journald.pid | The process ID of the process the journal entry originates from formatted as a decimal string. Note that entries obtained via "stdout" or "stderr" of forked processes will contain credentials valid for a parent process. | long |
| journald.process.capabilities | The effective capabilities(7) of the process the journal entry originates from. | keyword |
| journald.process.command_line | The command line of the process the journal entry originates from. | keyword |
| journald.process.executable | The executable path of the process the journal entry originates from. | keyword |
| journald.process.name | The name of the process the journal entry originates from. | keyword |
| journald.uid | The user ID of the process the journal entry originates from formatted as a decimal string. Note that entries obtained via "stdout" or "stderr" of forked processes will contain credentials valid for a parent process. | long |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.identifier | Identifier (usually process) contained in the syslog header. | keyword |
| log.syslog.pid | PID contained in the syslog header. | long |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.pid | Process id. | long |
| systemd.cgroup | The control group path in the systemd hierarchy. | keyword |
| systemd.invocation_id | The invocation ID for the runtime cycle of the unit the message was generated in, as available to processes of the unit in $INVOCATION_ID. | keyword |
| systemd.owner_uid | The owner UID of the systemd user unit or systemd session (if any) of the process the journal entry originates from. | long |
| systemd.session | The systemd session ID (if any). | keyword |
| systemd.slice | The systemd slice unit name. | keyword |
| systemd.transport | How the entry was received by the journal service. | keyword |
| systemd.unit | The systemd unit name. | keyword |
| systemd.user_slice | The systemd user slice name. | keyword |
| systemd.user_unit | The unit name in the systemd user manager (if any). | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.id | Unique identifier of the user. | keyword |
