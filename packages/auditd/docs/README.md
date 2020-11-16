# Auditd Integration

The Auditd integration collects and parses logs from the audit daemon (`auditd`).

## Compatibility

The integration was tested with logs from `auditd` on OSes like CentOS 6 and CentOS 7.

This integration is not available for Windows.

## Logs

### Auditd log

This is the Auditd `log` dataset.

An example event for `log` looks as following:

```$json
{
  "@timestamp": "2017-01-31T20:17:14.891Z",
  "auditd": {
    "log": {
      "dst_prefixlen": 16,
      "op": "SPD-delete",
      "sequence": 18877201,
      "ses": "4294967295",
      "src_prefixlen": 24
    }
  },
  "destination": {
    "address": "192.168.0.0"
  },
  "event": {
    "action": "mac_ipsec_event",
    "ingested": "2020-11-16T10:43:43.094510300Z",
    "kind": "event",
    "outcome": "1"
  },
  "source": {
    "address": "192.168.2.0",
    "ip": "192.168.2.0"
  },
  "user": {
    "audit": {
      "id": "4294967295"
    }
  }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| auditd.log.a0 | The first argument to the system call. | keyword |
| auditd.log.addr |  | ip |
| auditd.log.audit_failure |  | keyword |
| auditd.log.cipher |  | keyword |
| auditd.log.data |  | keyword |
| auditd.log.default-context |  | keyword |
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
| auditd.log.inode |  | keyword |
| auditd.log.item | The item field indicates which item out of the total number of items. This number is zero-based; a value of 0 means it is the first item. | keyword |
| auditd.log.items | The number of items in an event. | keyword |
| auditd.log.kernel |  | keyword |
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
| auditd.log.pfs |  | keyword |
| auditd.log.proctitle |  | keyword |
| auditd.log.rdev |  | keyword |
| auditd.log.reason |  | keyword |
| auditd.log.root_dir |  | keyword |
| auditd.log.rport |  | long |
| auditd.log.saddr |  | keyword |
| auditd.log.selected-context |  | keyword |
| auditd.log.sequence | The audit event sequence number. | long |
| auditd.log.ses |  | keyword |
| auditd.log.spid |  | keyword |
| auditd.log.src_prefixlen |  | long |
| auditd.log.subj |  | keyword |
| auditd.log.success |  | boolean |
| auditd.log.sw |  | keyword |
| auditd.log.sw_type |  | keyword |
| auditd.log.syscall |  | keyword |
| auditd.log.table |  | keyword |
| auditd.log.tty |  | keyword |
| auditd.log.unit |  | keyword |
| auditd.log.uuid |  | keyword |
| auditd.log.ver |  | keyword |
| auditd.log.virt |  | keyword |
| auditd.log.vm |  | keyword |
| auditd.log.vm-ctx |  | keyword |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| host.architecture | Operating system architecture. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.executable | Absolute path to the process executable. | keyword |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.pid | Process id. | long |
| process.ppid | Parent process' pid. | long |
| process.working_directory | The working directory of the process. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| user.audit.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.audit.group.name | Name of the group. | keyword |
| user.audit.id | One or multiple unique identifiers of the user. | keyword |
| user.audit.name | Short name or login of the user. | keyword |
| user.effective.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.effective.group.name | Name of the group. | keyword |
| user.effective.id | One or multiple unique identifiers of the user. | keyword |
| user.effective.name | Short name or login of the user. | keyword |
| user.filesystem.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.filesystem.group.name | Name of the group. | keyword |
| user.filesystem.id | One or multiple unique identifiers of the user. | keyword |
| user.filesystem.name | Short name or login of the user. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.owner.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.owner.group.name | Name of the group. | keyword |
| user.owner.id | One or multiple unique identifiers of the user. | keyword |
| user.owner.name | Short name or login of the user. | keyword |
| user.saved.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.saved.group.name | Name of the group. | keyword |
| user.saved.id | One or multiple unique identifiers of the user. | keyword |
| user.saved.name | Short name or login of the user. | keyword |
| user.terminal | Terminal or tty device on which the user is performing the observed activity. | keyword |

