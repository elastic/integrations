# Auditd Logs Integration

The Auditd Logs integration collects and parses logs from the audit daemon (`auditd`).

## Compatibility

The integration was tested with logs from `auditd` on OSes like CentOS 6 and CentOS 7.

This integration is not available for Windows.

## Auditd Logs

An example event for `log` looks as following:

```json
{
    "@timestamp": "2008-11-16T22:21:13.147Z",
    "agent": {
        "ephemeral_id": "75aa903f-41e0-4d1d-a447-bac357ac804f",
        "id": "eb088d3b-5a12-4acd-a2e3-f195eee4809e",
        "name": "elastic-agent-55655",
        "type": "filebeat",
        "version": "9.6.0"
    },
    "auditd": {
        "log": {
            "avc": {
                "action": "denied",
                "request": "getattr"
            },
            "dev": "dm-0",
            "ino": "284133",
            "path": "/var/www/html/file1",
            "record_type": "AVC",
            "scontext": "unconfined_u:system_r:httpd_t:s0",
            "sequence": 96,
            "tclass": "file",
            "tcontext": "unconfined_u:object_r:samba_share_t:s0"
        }
    },
    "data_stream": {
        "dataset": "auditd.log",
        "namespace": "34736",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "eb088d3b-5a12-4acd-a2e3-f195eee4809e",
        "snapshot": true,
        "version": "9.6.0"
    },
    "event": {
        "action": "avc",
        "agent_id_status": "verified",
        "dataset": "auditd.log",
        "ingested": "2026-09-07T10:58:39Z",
        "kind": "event",
        "module": "auditd",
        "outcome": "failure"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-55655",
        "ip": [
            "10.89.11.2",
            "fe80::100d:4eff:fe1d:ef0d",
            "10.89.0.175",
            "fe80::a0fa:9eff:fe79:6977"
        ],
        "mac": [
            "12-0D-4E-1D-EF-0D",
            "A2-FA-9E-79-69-77"
        ],
        "name": "elastic-agent-55655",
        "os": {
            "family": "",
            "kernel": "6.17.0-14-generic",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/avc.log"
        },
        "offset": 0
    },
    "process": {
        "name": "httpd",
        "pid": 2465
    },
    "tags": "auditd-log"
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| auditd.log.ARCH |  | keyword |
| auditd.log.AUID |  | keyword |
| auditd.log.EGID |  | keyword |
| auditd.log.EUID |  | keyword |
| auditd.log.FSGID |  | keyword |
| auditd.log.FSUID |  | keyword |
| auditd.log.GID |  | keyword |
| auditd.log.ID |  | keyword |
| auditd.log.SGID |  | keyword |
| auditd.log.SUID |  | keyword |
| auditd.log.SYSCALL |  | keyword |
| auditd.log.UID |  | keyword |
| auditd.log.a0 | The first argument to the system call. | keyword |
| auditd.log.a1 | The second argument to the system call. | keyword |
| auditd.log.a2 | The third argument to the system call. | keyword |
| auditd.log.a3 | The fourth argument to the system call. | keyword |
| auditd.log.addr |  | ip |
| auditd.log.apparmor |  | keyword |
| auditd.log.audit_backlog_limit |  | keyword |
| auditd.log.audit_failure |  | keyword |
| auditd.log.avc.action |  | keyword |
| auditd.log.avc.request |  | keyword |
| auditd.log.capability |  | keyword |
| auditd.log.cipher |  | keyword |
| auditd.log.context |  | keyword |
| auditd.log.data |  | keyword |
| auditd.log.default-context |  | keyword |
| auditd.log.denied_mask |  | keyword |
| auditd.log.dev |  | keyword |
| auditd.log.direction |  | keyword |
| auditd.log.dst_prefixlen |  | long |
| auditd.log.entries |  | long |
| auditd.log.family |  | keyword |
| auditd.log.fe |  | keyword |
| auditd.log.fi |  | keyword |
| auditd.log.format |  | keyword |
| auditd.log.fp |  | keyword |
| auditd.log.fver |  | keyword |
| auditd.log.gpg_res |  | keyword |
| auditd.log.hostname |  | keyword |
| auditd.log.id |  | keyword |
| auditd.log.img-ctx |  | keyword |
| auditd.log.info |  | keyword |
| auditd.log.ino |  | keyword |
| auditd.log.inode |  | keyword |
| auditd.log.item | The item field indicates which item out of the total number of items. This number is zero-based; a value of 0 means it is the first item. | keyword |
| auditd.log.items | The number of items in an event. | keyword |
| auditd.log.kernel |  | keyword |
| auditd.log.key | Records the user defined string associated with a rule that generated a particular event in the Audit log. | keyword |
| auditd.log.key_enforce |  | boolean |
| auditd.log.kind |  | keyword |
| auditd.log.ksize |  | long |
| auditd.log.laddr |  | ip |
| auditd.log.list |  | keyword |
| auditd.log.lport |  | long |
| auditd.log.major |  | keyword |
| auditd.log.minor |  | keyword |
| auditd.log.mode |  | keyword |
| auditd.log.model |  | keyword |
| auditd.log.name |  | keyword |
| auditd.log.new-level |  | keyword |
| auditd.log.new_auid | For login events this is the new audit ID. The audit ID can be used to trace future events to the user even if their identity changes (like becoming root). | keyword |
| auditd.log.new_pe |  | keyword |
| auditd.log.new_pi |  | keyword |
| auditd.log.new_pp |  | keyword |
| auditd.log.new_ses | For login events this is the new session ID. It can be used to tie a user to future events by session ID. | keyword |
| auditd.log.node |  | keyword |
| auditd.log.obj |  | keyword |
| auditd.log.objtype |  | keyword |
| auditd.log.old |  | keyword |
| auditd.log.old-level |  | keyword |
| auditd.log.old_auid | For login events this is the old audit ID used for the user prior to this login. | keyword |
| auditd.log.old_pe |  | keyword |
| auditd.log.old_pi |  | keyword |
| auditd.log.old_pp |  | keyword |
| auditd.log.old_ses | For login events this is the old session ID used for the user prior to this login. | keyword |
| auditd.log.op |  | keyword |
| auditd.log.operation |  | keyword |
| auditd.log.original_field | The original field name if the event was parsed from an enriched format auditd log. | keyword |
| auditd.log.path |  | keyword |
| auditd.log.peer |  | keyword |
| auditd.log.permissive |  | keyword |
| auditd.log.pfs |  | keyword |
| auditd.log.proctitle |  | keyword |
| auditd.log.profile |  | keyword |
| auditd.log.rdev |  | keyword |
| auditd.log.reason |  | keyword |
| auditd.log.record_type |  | keyword |
| auditd.log.request |  | keyword |
| auditd.log.requested_mask |  | keyword |
| auditd.log.reset |  | keyword |
| auditd.log.root_dir |  | keyword |
| auditd.log.rport |  | long |
| auditd.log.saddr |  | keyword |
| auditd.log.saddr_fam |  | keyword |
| auditd.log.sauid |  | keyword |
| auditd.log.scontext |  | keyword |
| auditd.log.selected-context |  | keyword |
| auditd.log.sequence | The audit event sequence number. | long |
| auditd.log.seresult |  | keyword |
| auditd.log.ses |  | keyword |
| auditd.log.sig |  | keyword |
| auditd.log.spid |  | keyword |
| auditd.log.src_prefixlen |  | long |
| auditd.log.subj |  | keyword |
| auditd.log.success |  | boolean |
| auditd.log.sw |  | keyword |
| auditd.log.sw_type |  | keyword |
| auditd.log.syscall |  | keyword |
| auditd.log.table |  | keyword |
| auditd.log.tclass |  | keyword |
| auditd.log.tcontext |  | keyword |
| auditd.log.tty |  | keyword |
| auditd.log.uid |  | keyword |
| auditd.log.unit |  | keyword |
| auditd.log.uuid |  | keyword |
| auditd.log.ver |  | keyword |
| auditd.log.virt |  | keyword |
| auditd.log.vm |  | keyword |
| auditd.log.vm-ctx |  | keyword |
| auditd.log.xdevice |  | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
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
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| process.working_directory | The working directory of the process. | keyword |
| process.working_directory.text | Multi-field of `process.working_directory`. | match_only_text |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.audit.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.audit.group.name | Name of the group. | keyword |
| user.audit.id | One or multiple unique identifiers of the user. | keyword |
| user.audit.name | Short name or login of the user. | keyword |
| user.effective.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.effective.group.name | Name of the group. | keyword |
| user.effective.id | Unique identifier of the user. | keyword |
| user.effective.name | Short name or login of the user. | keyword |
| user.effective.name.text | Multi-field of `user.effective.name`. | match_only_text |
| user.filesystem.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.filesystem.group.name | Name of the group. | keyword |
| user.filesystem.id | One or multiple unique identifiers of the user. | keyword |
| user.filesystem.name | Short name or login of the user. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.group.name | Name of the group. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.owner.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.owner.group.name | Name of the group. | keyword |
| user.owner.id | One or multiple unique identifiers of the user. | keyword |
| user.owner.name | Short name or login of the user. | keyword |
| user.saved.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.saved.group.name | Name of the group. | keyword |
| user.saved.id | One or multiple unique identifiers of the user. | keyword |
| user.saved.name | Short name or login of the user. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |
| user.terminal | Terminal or tty device on which the user is performing the observed activity. | keyword |

