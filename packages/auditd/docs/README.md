# Auditd Logs Integration

The Auditd Logs integration collects and parses logs from the audit daemon (`auditd`).

## Compatibility

The integration was tested with logs from `auditd` on OSes like CentOS 6 and CentOS 7.

This integration is not available for Windows.

## Parser modes

The `parser_mode` setting controls how the Elastic Agent reads auditd log files.
Requires Elastic Agent 9.6.0 or later.

| Mode | Field schema | Use when |
|---|---|---|
| `none` | Raw lines in `message`; no parsing | You pre-process logs elsewhere |
| `parse` | `auditd.log.*` fields per record type | You use existing dashboards or rules on `auditd.log.*` |
| `coalesce` | `auditd.data.*` / ECS fields, one document per syscall group | You want parity with the `auditd_manager` integration |

**Coalesce mode** groups related audit records (SYSCALL, EXECVE, CWD, PATH, …) into a
single document whose field schema matches `logs-auditd_manager.auditd-*`. Switching an
existing policy to `coalesce` means documents no longer contain `auditd.log.*` fields,
so saved searches, visualisations, and detection rules written against `auditd.log.*`
will stop matching.

**Forwarded logs and `resolve_ids`.** The parser resolves numeric UIDs and GIDs to names
using the local `/etc/passwd` and `/etc/group` files. If logs were collected on a
different host, the resolved names will be wrong. There is currently no package-level
option to disable resolution; set `resolve_ids: false` directly in an advanced policy
override if needed.

**`log_format=ENRICHED` in `auditd.conf`.** Without this setting the kernel does not
embed resolved names in the log records, so `auditd.user.audit.name` and similar fields
will be absent. Detection rules that filter on resolved usernames will silently miss
events on hosts without `ENRICHED` logging enabled.

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
| auditd.data.a\* | the arguments to a syscall | keyword |
| auditd.data.acct | a user's account name | keyword |
| auditd.data.acl | access mode of resource assigned to vm | keyword |
| auditd.data.action | netfilter packet disposition | keyword |
| auditd.data.added | number of new files detected | long |
| auditd.data.addr | the remote address that the user is connecting from | keyword |
| auditd.data.apparmor | apparmor event information | keyword |
| auditd.data.arch | the elf architecture flags | keyword |
| auditd.data.argc | the number of arguments to an execve syscall | long |
| auditd.data.audit_backlog_limit | audit system's backlog queue size | keyword |
| auditd.data.audit_backlog_wait_time | audit system's backlog wait time | keyword |
| auditd.data.audit_enabled | audit systems's enable/disable status | keyword |
| auditd.data.audit_failure | audit system's failure mode | keyword |
| auditd.data.audit_pid |  | long |
| auditd.data.auid |  | keyword |
| auditd.data.banners | banners used on printed page | keyword |
| auditd.data.bool | name of SELinux boolean | keyword |
| auditd.data.bus | name of subsystem bus a vm resource belongs to | keyword |
| auditd.data.cap_fe | file assigned effective capability map | keyword |
| auditd.data.cap_fi | file inherited capability map | keyword |
| auditd.data.cap_fp | file permitted capability map | keyword |
| auditd.data.cap_fver | file system capabilities version number | keyword |
| auditd.data.cap_pe | process effective capability map | keyword |
| auditd.data.cap_pi | process inherited capability map | keyword |
| auditd.data.cap_pp | process permitted capability map | keyword |
| auditd.data.capability | posix capabilities | keyword |
| auditd.data.cgroup | path to cgroup in sysfs | keyword |
| auditd.data.changed | number of changed files | long |
| auditd.data.cipher | name of crypto cipher selected | keyword |
| auditd.data.class | resource class assigned to vm | keyword |
| auditd.data.cmd | command being executed | keyword |
| auditd.data.code | seccomp action code | keyword |
| auditd.data.comp | compression algorithm used in crypto session | keyword |
| auditd.data.compat | is_compat_task result | keyword |
| auditd.data.daddr | remote IP address | ip |
| auditd.data.data | TTY text | keyword |
| auditd.data.default_context | default MAC context | keyword |
| auditd.data.dev | network or routing device name | keyword |
| auditd.data.device | device name | keyword |
| auditd.data.dir | directory name | keyword |
| auditd.data.direction | direction of crypto operation | keyword |
| auditd.data.dmac | remote MAC address | keyword |
| auditd.data.dport | remote port number | long |
| auditd.data.dst | routing destination address | keyword |
| auditd.data.dst_prefixlen | routing destination prefix length | keyword |
| auditd.data.enforcing | new MAC enforcement status | keyword |
| auditd.data.entries | number of entries in the netfilter table | long |
| auditd.data.exit | syscall exit code | keyword |
| auditd.data.fam | socket address family | keyword |
| auditd.data.family | netfilter protocol | keyword |
| auditd.data.fd | file descriptor number | keyword |
| auditd.data.fe | file assigned effective capability map | keyword |
| auditd.data.feature | kernel feature being changed | keyword |
| auditd.data.fi | file assigned inherited capability map | keyword |
| auditd.data.file | file name | keyword |
| auditd.data.flags | mmap syscall flags | keyword |
| auditd.data.format | audit log's format | keyword |
| auditd.data.fp | crypto key finger print | keyword |
| auditd.data.frootid |  | keyword |
| auditd.data.fver | file system capabilities version number | keyword |
| auditd.data.gpg_res | GPG verification result | keyword |
| auditd.data.grantors | pam modules approving the action | keyword |
| auditd.data.grp | group name | keyword |
| auditd.data.hook | netfilter hook that packet came from | keyword |
| auditd.data.hostname | the hostname that the user is connecting from | keyword |
| auditd.data.icmp_type | type of icmp message | keyword |
| auditd.data.id | during account changes | keyword |
| auditd.data.igid | ipc object's group ID | keyword |
| auditd.data.img_ctx | the vm's disk image context string | keyword |
| auditd.data.inif | in interface number | keyword |
| auditd.data.ino | inode number | keyword |
| auditd.data.inode_gid | group ID of the inode's owner | keyword |
| auditd.data.inode_uid | user ID of the inode's owner | keyword |
| auditd.data.invalid_context | SELinux context | keyword |
| auditd.data.ioctlcmd | The request argument to the ioctl syscall | keyword |
| auditd.data.ip | network address of a printer | ip |
| auditd.data.ipid | IP datagram fragment identifier | keyword |
| auditd.data.ipx_net | IPX network number | keyword |
| auditd.data.items | the number of path records in the event | long |
| auditd.data.iuid | ipc object's user ID | keyword |
| auditd.data.kernel | kernel's version number | keyword |
| auditd.data.key_enforce | key enforcement mode flag | keyword |
| auditd.data.kind | server or client in crypto operation | keyword |
| auditd.data.ksize | key size for crypto operation | keyword |
| auditd.data.laddr | local network address | keyword |
| auditd.data.len | length | keyword |
| auditd.data.list | the audit system's filter list number | keyword |
| auditd.data.lport | local network port | long |
| auditd.data.mac | crypto MAC algorithm selected | keyword |
| auditd.data.macproto | ethernet packet type ID field | keyword |
| auditd.data.maj | device major number | keyword |
| auditd.data.major | device major number | keyword |
| auditd.data.minor | device minor number | keyword |
| auditd.data.model | security model being used for virt | keyword |
| auditd.data.msg | the payload of the audit record | keyword |
| auditd.data.name | object name | keyword |
| auditd.data.nargs | the number of arguments to a socket call | long |
| auditd.data.net | network MAC address | keyword |
| auditd.data.new | value being set in feature | keyword |
| auditd.data.new_chardev | new character device being assigned to vm | keyword |
| auditd.data.new_disk | disk being added to vm | keyword |
| auditd.data.new_enabled | new TTY audit enabled setting | keyword |
| auditd.data.new_fs | file system being added to vm | keyword |
| auditd.data.new_gid | new group ID being assigned | keyword |
| auditd.data.new_level | new run level | keyword |
| auditd.data.new_lock | new value of feature lock | keyword |
| auditd.data.new_log_passwd | new value for TTY password logging | keyword |
| auditd.data.new_mem | new amount of memory in KB | keyword |
| auditd.data.new_net | MAC address being assigned to vm | keyword |
| auditd.data.new_pe | new process effective capability map | keyword |
| auditd.data.new_pi | new process inherited capability map | keyword |
| auditd.data.new_pp | new process permitted capability map | keyword |
| auditd.data.new_range | new SELinux range | keyword |
| auditd.data.new_rng | device name of rng being added from a vm | keyword |
| auditd.data.new_role | new SELinux role | keyword |
| auditd.data.new_ses | ses value | keyword |
| auditd.data.new_seuser | new SELinux user | keyword |
| auditd.data.new_vcpu | new number of CPU cores | long |
| auditd.data.nlnk_fam | netlink protocol number | keyword |
| auditd.data.nlnk_grp | netlink group number | keyword |
| auditd.data.nlnk_pid | pid of netlink packet sender | long |
| auditd.data.node | The node field from the audit event, set when the kernel was compiled with AUDIT_FEATURE_LOGINUID_IMMUTABLE or when the auditd.conf node_name_format option is set. | keyword |
| auditd.data.oauid | object's login user ID | keyword |
| auditd.data.obj | lspp object context string | keyword |
| auditd.data.obj_gid | group ID of object | keyword |
| auditd.data.obj_uid | user ID of object | keyword |
| auditd.data.ocomm | object's command line name | keyword |
| auditd.data.oflag | open syscall flags | keyword |
| auditd.data.old | old value | keyword |
| auditd.data.old_auid | previous auid value | keyword |
| auditd.data.old_chardev | present character device assigned to vm | keyword |
| auditd.data.old_disk | disk being removed from vm | keyword |
| auditd.data.old_enabled | present TTY audit enabled setting | keyword |
| auditd.data.old_enforcing | old MAC enforcement status | keyword |
| auditd.data.old_fs | file system being removed from vm | keyword |
| auditd.data.old_level | old run level | keyword |
| auditd.data.old_lock | present value of feature lock | keyword |
| auditd.data.old_log_passwd | present value for TTY password logging | keyword |
| auditd.data.old_mem | present amount of memory in KB | keyword |
| auditd.data.old_net | present MAC address assigned to vm | keyword |
| auditd.data.old_pa |  | keyword |
| auditd.data.old_pe | old process effective capability map | keyword |
| auditd.data.old_pi | old process inherited capability map | keyword |
| auditd.data.old_pp | old process permitted capability map | keyword |
| auditd.data.old_prom | network promiscuity flag | keyword |
| auditd.data.old_range | present SELinux range | keyword |
| auditd.data.old_rng | device name of rng being removed from a vm | keyword |
| auditd.data.old_role | present SELinux role | keyword |
| auditd.data.old_ses | previous ses value | keyword |
| auditd.data.old_seuser | present SELinux user | keyword |
| auditd.data.old_val | current value of SELinux boolean | keyword |
| auditd.data.old_vcpu | present number of CPU cores | long |
| auditd.data.op | the operation being performed that is audited | keyword |
| auditd.data.opid | object's process ID | long |
| auditd.data.oses | object's session ID | keyword |
| auditd.data.outif | out interface number | keyword |
| auditd.data.pa |  | keyword |
| auditd.data.parent | the inode number of the parent file | keyword |
| auditd.data.path | file or resource path | keyword |
| auditd.data.pe |  | keyword |
| auditd.data.per | linux personality | keyword |
| auditd.data.perm | the file permission being used | keyword |
| auditd.data.perm_mask | file permission mask that triggered a watch event | keyword |
| auditd.data.permissive | SELinux is in permissive mode | keyword |
| auditd.data.pfs | perfect forward secrecy method | keyword |
| auditd.data.pi |  | keyword |
| auditd.data.port | network port | keyword |
| auditd.data.pp |  | keyword |
| auditd.data.printer | printer name | keyword |
| auditd.data.prom | network promiscuity flag | keyword |
| auditd.data.proto | network protocol | keyword |
| auditd.data.qbytes | ipc objects quantity of bytes | keyword |
| auditd.data.range | user's SE Linux range | keyword |
| auditd.data.reason | text string denoting a reason for the action | keyword |
| auditd.data.removed | number of deleted files | long |
| auditd.data.res | result of the audited operation(success/fail) | keyword |
| auditd.data.reset |  | keyword |
| auditd.data.resrc | resource being assigned | keyword |
| auditd.data.result |  | keyword |
| auditd.data.root_dir | root directory | keyword |
| auditd.data.rport | remote port number | long |
| auditd.data.sauid | sent login user ID | keyword |
| auditd.data.scontext | the subject's context string | keyword |
| auditd.data.selected_context | new MAC context assigned to session | keyword |
| auditd.data.seperm | SELinux permission being decided on | keyword |
| auditd.data.seperms | SELinux permissions being used | keyword |
| auditd.data.seqno | sequence number | long |
| auditd.data.seresult | SELinux AVC decision granted/denied | keyword |
| auditd.data.ses | login session ID | keyword |
| auditd.data.seuser | user's SE Linux user acct | keyword |
| auditd.data.sig | signal number | keyword |
| auditd.data.sigev_signo | signal number | keyword |
| auditd.data.smac | local MAC address | keyword |
| auditd.data.socket.addr | The remote address. | keyword |
| auditd.data.socket.family | The socket family (unix, ipv4, ipv6, netlink). | keyword |
| auditd.data.socket.path | This is the path associated with a unix socket. | keyword |
| auditd.data.socket.port | The port number. | long |
| auditd.data.socket.saddr | The raw socket address structure. | keyword |
| auditd.data.spid | sent process ID | long |
| auditd.data.sport | local port number | long |
| auditd.data.src | routing source address | keyword |
| auditd.data.src_prefixlen | routing source prefix length | keyword |
| auditd.data.state | audit daemon configuration resulting state | keyword |
| auditd.data.subj | lspp subject's context string | keyword |
| auditd.data.subj_category | The SELinux category associated with the subject. It helps further refine the level of access by classifying subjects into categories for multi-level security (MLS). Categories are often used to label data with additional attributes, like "high" or "low," enhancing granularity. | keyword |
| auditd.data.subj_domain | The SELinux domain or type assigned to the subject. The domain specifies the type of resource or process the subject is interacting with, helping enforce domain-based access controls, which are crucial in limiting resource access. | keyword |
| auditd.data.subj_level | The SELinux sensitivity level for the subject. It indicates the security classification level, like `s0` or `s2`, that defines how data or processes are handled based on confidentiality and integrity levels within the system. | keyword |
| auditd.data.subj_role | The SELinux role associated with the subject. The role determines the capabilities a subject has within a given SELinux policy. Roles are used to define higher-level security attributes in the context of the system's security policies. | keyword |
| auditd.data.subj_user | The SELinux user identity. This represents the SELinux user role that is assigned to the subject (user or process) performing an action. It's part of the SELinux security context and is used to enforce policies that restrict what actions a subject can perform. | keyword |
| auditd.data.success | whether the syscall was successful or not | keyword |
| auditd.data.sw | software package name | keyword |
| auditd.data.sw_type | software package type | keyword |
| auditd.data.syscall | syscall number in effect when the event occurred | keyword |
| auditd.data.table | netfilter table name | keyword |
| auditd.data.tclass | target's object classification | keyword |
| auditd.data.tcontext | the target's or object's context string | keyword |
| auditd.data.terminal | terminal name the user is running programs on | keyword |
| auditd.data.tty | tty udevice the user is running programs on | keyword |
| auditd.data.unit | systemd unit | keyword |
| auditd.data.uri | URI pointing to a printer | keyword |
| auditd.data.user | username associated with the event | keyword |
| auditd.data.uuid | a UUID | keyword |
| auditd.data.val | generic value associated with the operation | keyword |
| auditd.data.ver | audit daemon's version number | keyword |
| auditd.data.virt | kind of virtualization being referenced | keyword |
| auditd.data.vm | virtual machine name | keyword |
| auditd.data.vm_ctx | the vm's context string | keyword |
| auditd.data.vm_pid | vm's process ID | long |
| auditd.data.watch | file name in a watch record | keyword |
| auditd.file.selinux.domain | The actor's SELinux domain or type. | keyword |
| auditd.file.selinux.level | The actor's SELinux level. | keyword |
| auditd.file.selinux.role | User's SELinux role | keyword |
| auditd.file.selinux.user | Account submitted for authentication | keyword |
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
| auditd.log.exit | The exit field from a SYSCALL record. Contains a named errno symbol (e.g. EINPROGRESS) when the numeric exit code cannot be converted to process.exit_code. | keyword |
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
| auditd.log.obj_domain |  | keyword |
| auditd.log.obj_level |  | keyword |
| auditd.log.obj_role |  | keyword |
| auditd.log.obj_user |  | keyword |
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
| auditd.log.port |  | keyword |
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
| auditd.log.seperms |  | keyword |
| auditd.log.sequence | The audit event sequence number. | long |
| auditd.log.seresult |  | keyword |
| auditd.log.ses |  | keyword |
| auditd.log.sig |  | keyword |
| auditd.log.spid |  | keyword |
| auditd.log.src_prefixlen |  | long |
| auditd.log.subj |  | keyword |
| auditd.log.subj_category |  | keyword |
| auditd.log.subj_domain |  | keyword |
| auditd.log.subj_level |  | keyword |
| auditd.log.subj_role |  | keyword |
| auditd.log.subj_user |  | keyword |
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
| auditd.message_type | The audit message type (e.g. syscall or apparmor_denied). | keyword |
| auditd.messages | An ordered list of the raw messages received from the kernel that were used to construct this document. This field is present if an error occurred processing the data or if include_raw_message is set in the config. | keyword |
| auditd.paths |  | flattened |
| auditd.paths.dev | Device name as found in /dev | keyword |
| auditd.paths.inode | inode number | keyword |
| auditd.paths.item | Which item is being recorded | keyword |
| auditd.paths.mode | Mode flags on a file | keyword |
| auditd.paths.name | File name in avcs | keyword |
| auditd.paths.nametype | Kind of file operation being referenced | keyword |
| auditd.paths.obj_domain |  | keyword |
| auditd.paths.obj_level |  | keyword |
| auditd.paths.obj_role |  | keyword |
| auditd.paths.obj_type |  | keyword |
| auditd.paths.obj_user |  | keyword |
| auditd.paths.ogid | File owner group ID | keyword |
| auditd.paths.ouid | File owner user ID | keyword |
| auditd.paths.rdev | The device identifier (special files only) | keyword |
| auditd.result | The result of the audited operation (success/fail). | keyword |
| auditd.session | The session ID assigned to a login. All events related to a login session will have the same value. | keyword |
| auditd.summary.action | A description of what action was taken. This is emitted by go-libaudit's aucoalesce normalizations. | keyword |
| auditd.summary.actor.primary | The primary identity of the actor. This is the actor's original login ID. It will not change even if the user changes to another account. | keyword |
| auditd.summary.actor.secondary | The secondary identity of the actor. This is typically the same as the primary, except for when the user has used su. | keyword |
| auditd.summary.how | This describes how the action was performed. Usually this is the exe or command that was being executed that triggered the event. | keyword |
| auditd.summary.object.primary |  | keyword |
| auditd.summary.object.secondary |  | keyword |
| auditd.summary.object.type | A description of the what the "thing" is (e.g. file, socket, user-session). | keyword |
| auditd.user.audit.id |  | keyword |
| auditd.user.audit.name |  | keyword |
| auditd.user.filesystem.group.id |  | keyword |
| auditd.user.filesystem.group.name |  | keyword |
| auditd.user.filesystem.id |  | keyword |
| auditd.user.filesystem.name |  | keyword |
| auditd.user.new_auid.id |  | keyword |
| auditd.user.new_auid.name |  | keyword |
| auditd.user.old_auid.id |  | keyword |
| auditd.user.old_auid.name |  | keyword |
| auditd.user.saved.group.id |  | keyword |
| auditd.user.saved.group.name |  | keyword |
| auditd.user.saved.id |  | keyword |
| auditd.user.saved.name |  | keyword |
| auditd.user.selinux.category | The actor's SELinux category or compartments. | keyword |
| auditd.user.selinux.domain | The actor's SELinux domain or type. | keyword |
| auditd.user.selinux.level | The actor's SELinux level. | keyword |
| auditd.user.selinux.role | User's SELinux role | keyword |
| auditd.user.selinux.user | Account submitted for authentication | keyword |
| auditd.warnings | The warnings generated by the Beat during the construction of the event. These are disabled by default and are used for development and debug purposes only. | keyword |
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
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| file.device | Device that is the source of the file. | keyword |
| file.gid | Primary group ID (GID) of the file. | keyword |
| file.group | Primary group name of the file. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.mode | Mode of the file in octal representation. | keyword |
| file.owner | File owner's username. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.uid | The user ID (UID) or security identifier (SID) of the file owner. | keyword |
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
| log.file.device_id | Device Id of the log file this event came from. | keyword |
| log.file.fingerprint | Fingerprint of the log file. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
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
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| process.working_directory | The working directory of the process. | keyword |
| process.working_directory.text | Multi-field of `process.working_directory`. | match_only_text |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
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
| user.uuid.id | One or multiple unique identifiers of the user. | keyword |
| user.uuid.name | Short name or login of the user. | keyword |

