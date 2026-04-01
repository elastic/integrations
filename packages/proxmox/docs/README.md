# Proxmox VE Integration

The Proxmox VE integration collects metrics and logs from [Proxmox Virtual Environment](https://www.proxmox.com/en/proxmox-virtual-environment/overview) hosts. It polls the Proxmox REST API for cluster and node metrics and reads local log files and systemd journal entries for operational events.

## Compatibility

This integration has been tested with Proxmox VE 8.x and 9.x.

## Setup

1. Create a dedicated monitoring user and API token on your Proxmox host:

```bash
pveum user add monitor@pve
pveum aclmod / -user monitor@pve -role PVEAuditor
pveum user token add monitor@pve elastic --privsep=0
```

2. Install Elastic Agent on the Proxmox host.

3. Add the Proxmox VE integration in Fleet, providing:
   - The Proxmox API URL (for example, `https://192.168.1.1:8006`)
   - The API token ID in `USER@REALM!TOKENID` format (for example, `monitor@pve!elastic`)
   - The API token secret (UUID)

Note: Using `--privsep=0` disables privilege separation, meaning the token inherits all permissions of the user. For tighter security, use `--privsep=1` and grant explicit ACLs to the token.

## Collection architecture

The **cluster** data stream collects summary metrics for all resources (nodes, VMs, containers, storage) from the Proxmox API. A single agent on any node in the cluster is sufficient for cluster-wide visibility.

The **node** data stream collects detailed metrics for the local node only. To get node-level metrics for every node in a multi-node cluster, install Elastic Agent on each node.

The **log data streams** (access, firewall, tasks, auth, cluster_logs) read local files and journals, so they also require an agent on each node.

## Data Streams

### Cluster Metrics

Cluster-wide resource metrics collected from the Proxmox REST API. Includes CPU, memory, disk, and network statistics for all nodes, VMs, containers, and storage pools, along with cluster quorum status and HA resource state.

An example event for `cluster` looks as following:

```json
{
    "event": {
        "dataset": "proxmox.cluster",
        "kind": "metric",
        "module": "proxmox"
    },
    "proxmox": {
        "cluster": {
            "resource": {
                "cpu": 0.0523,
                "maxcpu": 48,
                "type": "node",
                "uptime": 1209600,
                "node": "lab",
                "disk": 18253611008,
                "mem": 17179869184,
                "maxdisk": 107374182400,
                "name": "lab",
                "cgroup_mode": "2",
                "id": "node/lab",
                "maxmem": 270582939648,
                "status": "online"
            }
        }
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud.account.id | Cloud account ID. | keyword |  |  |
| cloud.availability_zone | Cloud availability zone. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Cloud instance ID. | keyword |  |  |
| cloud.provider | Cloud provider name. | keyword |  |  |
| cloud.region | Cloud region. | keyword |  |  |
| container.id | Container ID. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.dataset | Event dataset. | constant_keyword |  |  |
| event.kind | The kind of event. | keyword |  |  |
| event.module | Event module. | constant_keyword |  |  |
| host.containerized | Whether the host is a container. | boolean |  |  |
| host.name | Host name. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| proxmox.cluster.name | Cluster name. | keyword |  |  |
| proxmox.cluster.node.local | Whether this is the local node. | boolean |  |  |
| proxmox.cluster.node.name | Node name from cluster status. | keyword |  |  |
| proxmox.cluster.node.online | Whether the node is online. | boolean |  |  |
| proxmox.cluster.nodes | Number of nodes in the cluster. | long |  | gauge |
| proxmox.cluster.quorate | Whether the cluster has quorum. | boolean |  |  |
| proxmox.cluster.resource.cgroup_mode | Cgroup mode (node only). | keyword |  |  |
| proxmox.cluster.resource.content | Storage content types. | keyword |  |  |
| proxmox.cluster.resource.cpu | CPU usage ratio (0.0 to N). | double |  | gauge |
| proxmox.cluster.resource.disk | Disk usage in bytes. | long | byte | gauge |
| proxmox.cluster.resource.diskread | Disk bytes read. | long | byte | counter |
| proxmox.cluster.resource.diskwrite | Disk bytes written. | long | byte | counter |
| proxmox.cluster.resource.hastate | HA manager state. | keyword |  |  |
| proxmox.cluster.resource.id | Unique resource identifier (for example, qemu/100). | keyword |  |  |
| proxmox.cluster.resource.maxcpu | Number of allocated CPUs. | long |  | gauge |
| proxmox.cluster.resource.maxdisk | Maximum disk size in bytes. | long | byte | gauge |
| proxmox.cluster.resource.maxmem | Maximum memory in bytes. | long | byte | gauge |
| proxmox.cluster.resource.mem | Memory usage in bytes. | long | byte | gauge |
| proxmox.cluster.resource.name | Resource name. | keyword |  |  |
| proxmox.cluster.resource.netin | Network bytes received. | long | byte | counter |
| proxmox.cluster.resource.netout | Network bytes sent. | long | byte | counter |
| proxmox.cluster.resource.node | Node hosting this resource. | keyword |  |  |
| proxmox.cluster.resource.plugintype | Storage plugin type (dir, zfspool, lvmthin). | keyword |  |  |
| proxmox.cluster.resource.pool | Resource pool membership. | keyword |  |  |
| proxmox.cluster.resource.shared | Whether storage is shared. | boolean |  |  |
| proxmox.cluster.resource.status | Resource status (running, stopped, online, offline). | keyword |  |  |
| proxmox.cluster.resource.tags | Resource tags. | keyword |  |  |
| proxmox.cluster.resource.template | Whether this resource is a template. | boolean |  |  |
| proxmox.cluster.resource.type | Resource type (node, qemu, lxc, storage). | keyword |  |  |
| proxmox.cluster.resource.uptime | Uptime in seconds. | long | s | gauge |
| proxmox.cluster.resource.vmid | VM or container ID. | keyword |  |  |
| proxmox.ha.group | HA group name. | keyword |  |  |
| proxmox.ha.max_relocate | Maximum relocate attempts. | long |  | gauge |
| proxmox.ha.max_restart | Maximum restart attempts. | long |  | gauge |
| proxmox.ha.sid | HA service identifier (for example, vm:100). | keyword |  |  |
| proxmox.ha.state | HA resource state (started, stopped, error, migrated). | keyword |  |  |


### Node Metrics

Detailed per-node metrics collected from the Proxmox REST API, including CPU usage, load averages, memory and swap usage, root filesystem usage, and system information.

An example event for `node` looks as following:

```json
{
    "event": {
        "dataset": "proxmox.node",
        "kind": "metric",
        "module": "proxmox"
    },
    "proxmox": {
        "node": {
            "pveversion": "8.3.2",
            "wait": 0.001,
            "memory": {
                "available": 253403070464,
                "total": 270582939648,
                "used": 17179869184,
                "free": 253403070464
            },
            "swap": {
                "total": 8589934592,
                "used": 0,
                "free": 8589934592
            },
            "rootfs": {
                "avail": 89120571392,
                "total": 107374182400,
                "used": 18253611008
            },
            "cpu": 0.0523,
            "loadavg": {
                "5m": 0.38,
                "15m": 0.35,
                "1m": 0.45
            },
            "uptime": 1209600,
            "kversion": "Linux 6.8.12-5-pve",
            "cpuinfo": {
                "model": "AMD EPYC 7543 32-Core Processor",
                "cores": 24,
                "sockets": 2,
                "cpus": 48,
                "mhz": 2794.748
            }
        }
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud.account.id | Cloud account ID. | keyword |  |  |
| cloud.availability_zone | Cloud availability zone. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Cloud instance ID. | keyword |  |  |
| cloud.provider | Cloud provider name. | keyword |  |  |
| cloud.region | Cloud region. | keyword |  |  |
| container.id | Container ID. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.dataset | Event dataset. | constant_keyword |  |  |
| event.kind | The kind of event. | keyword |  |  |
| event.module | Event module. | constant_keyword |  |  |
| host.containerized | Whether the host is a container. | boolean |  |  |
| host.name | Host name. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| proxmox.cluster.name | Proxmox cluster name. | keyword |  |  |
| proxmox.node.cpu | CPU usage ratio (0.0 to 1.0). | double |  | gauge |
| proxmox.node.cpuinfo.cores | Number of CPU cores per socket. | long |  | gauge |
| proxmox.node.cpuinfo.cpus | Total number of CPU threads (cores \* sockets). | long |  | gauge |
| proxmox.node.cpuinfo.mhz | CPU frequency in MHz. | double |  | gauge |
| proxmox.node.cpuinfo.model | CPU model name. | keyword |  |  |
| proxmox.node.cpuinfo.sockets | Number of CPU sockets. | long |  | gauge |
| proxmox.node.kversion | Kernel version string. | keyword |  |  |
| proxmox.node.loadavg.15m | 15-minute load average. | double |  | gauge |
| proxmox.node.loadavg.1m | 1-minute load average. | double |  | gauge |
| proxmox.node.loadavg.5m | 5-minute load average. | double |  | gauge |
| proxmox.node.memory.available | Available memory in bytes. | long | byte | gauge |
| proxmox.node.memory.free | Free memory in bytes. | long | byte | gauge |
| proxmox.node.memory.total | Total memory in bytes. | long | byte | gauge |
| proxmox.node.memory.used | Used memory in bytes. | long | byte | gauge |
| proxmox.node.pveversion | Proxmox VE version string. | keyword |  |  |
| proxmox.node.rootfs.avail | Root filesystem available space in bytes. | long | byte | gauge |
| proxmox.node.rootfs.total | Root filesystem total size in bytes. | long | byte | gauge |
| proxmox.node.rootfs.used | Root filesystem used space in bytes. | long | byte | gauge |
| proxmox.node.swap.free | Free swap in bytes. | long | byte | gauge |
| proxmox.node.swap.total | Total swap in bytes. | long | byte | gauge |
| proxmox.node.swap.used | Used swap in bytes. | long | byte | gauge |
| proxmox.node.uptime | Node uptime in seconds. | long | s | gauge |
| proxmox.node.wait | IO wait ratio. | double |  | gauge |


### Access Logs

HTTP access logs from the Proxmox web proxy (pveproxy). Each entry records the client IP, authenticated user, request method and path, HTTP status code, and response size.

An example event for `access` looks as following:

```json
{
    "observer": {
        "product": "Proxmox VE",
        "type": "virtualization",
        "vendor": "Proxmox"
    },
    "@timestamp": "2026-02-15T14:30:01.000Z",
    "related": {
        "user": [
            "root"
        ],
        "ip": [
            "192.168.2.17"
        ]
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "version": "1.1",
        "response": {
            "body": {
                "bytes": 4523
            },
            "status_code": 200
        }
    },
    "source": {
        "ip": "192.168.2.17"
    },
    "event": {
        "action": "get",
        "category": [
            "web"
        ],
        "type": [
            "access"
        ],
        "kind": "event",
        "outcome": "success"
    },
    "message": "GET /api2/json/cluster/resources 200",
    "user": {
        "name": "root"
    },
    "proxmox": {
        "auth": {
            "realm": "pam"
        }
    },
    "url": {
        "path": "/api2/json/cluster/resources"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. | keyword |
| event.outcome | Event outcome. | keyword |
| event.type | Event type. | keyword |
| host.name | Host name. | keyword |
| http.request.method | HTTP request method. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| message | For log events the message field contains the log message. | match_only_text |
| observer.product | Observer product. | keyword |
| observer.type | Observer type. | keyword |
| observer.vendor | Observer vendor. | keyword |
| proxmox.auth.realm | Authentication realm (pam, pve, ldap). | keyword |
| proxmox.auth.token_id | API token ID if request used token auth. | keyword |
| proxmox.cluster.name | Proxmox cluster name. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.ip | IP address of the source. | ip |
| tags | List of keywords used to tag each event. | keyword |
| url.path | Path of the request. | keyword |
| user.name | Short name or login of the user. | keyword |


### Firewall Logs

Proxmox VE firewall log entries from pve-firewall.log. Each entry records the firewall action (DROP, REJECT, ACCEPT), source and destination IPs, ports, protocol, and packet metadata.

An example event for `firewall` looks as following:

```json
{
    "observer": {
        "product": "Proxmox VE",
        "type": "firewall",
        "vendor": "Proxmox"
    },
    "@timestamp": "2026-02-15T10:15:01.000Z",
    "related": {
        "ip": [
            "172.30.0.1",
            "172.30.255.255"
        ]
    },
    "destination": {
        "port": 138,
        "ip": "172.30.255.255"
    },
    "source": {
        "port": 138,
        "ip": "172.30.0.1"
    },
    "event": {
        "kind": "event",
        "action": "drop",
        "category": [
            "network"
        ],
        "type": [
            "connection",
            "denied"
        ],
        "outcome": "failure"
    },
    "message": "drop 172.30.0.1:138 -> 172.30.255.255:138 udp",
    "proxmox": {
        "firewall": {
            "packet_length": 78,
            "chain": "PVEFW-HOST-OUT"
        }
    },
    "network": {
        "transport": "udp"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| destination.ip | IP address of the destination. | ip |  |
| destination.port | Port of the destination. | long |  |
| ecs.version | ECS version this event conforms to. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.action | The action captured by the event. | keyword |  |
| event.category | Event category. | keyword |  |
| event.dataset | Event dataset. | constant_keyword |  |
| event.kind | The kind of event. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| event.original | Raw text message of entire event. | keyword |  |
| event.outcome | Event outcome. | keyword |  |
| event.type | Event type. | keyword |  |
| host.name | Host name. | keyword |  |
| message | For log events the message field contains the log message. | match_only_text |  |
| network.transport | Protocol Name corresponding to the field `iana_number`. | keyword |  |
| observer.product | Observer product. | keyword |  |
| observer.type | Observer type. | keyword |  |
| observer.vendor | Observer vendor. | keyword |  |
| proxmox.cluster.name | Proxmox cluster name. | keyword |  |
| proxmox.firewall.chain | Firewall chain name (PVEFW-HOST-IN, PVEFW-HOST-OUT, and so on). | keyword |  |
| proxmox.firewall.packet_length | IP packet length in bytes. | long | byte |
| proxmox.firewall.vmid | VM or container ID from the firewall chain. | keyword |  |
| related.ip | All of the IPs seen on your event. | ip |  |
| source.ip | IP address of the source. | ip |  |
| source.port | Port of the source. | long |  |
| tags | List of keywords used to tag each event. | keyword |  |


### Auth Events

Authentication events from the pvedaemon systemd journal. Records successful and failed login attempts with the authenticating user, source IP, and realm.

An example event for `auth` looks as following:

```json
{
    "observer": {
        "product": "Proxmox VE",
        "type": "virtualization",
        "vendor": "Proxmox"
    },
    "related": {
        "user": [
            "root"
        ]
    },
    "event": {
        "category": [
            "authentication"
        ],
        "type": [
            "start"
        ],
        "kind": "event",
        "outcome": "success"
    },
    "message": "Successful authentication for user root@pam",
    "proxmox": {
        "auth": {
            "realm": "pam"
        }
    },
    "user": {
        "name": "root"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | match_only_text |
| event.category | Event category. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. | keyword |
| event.outcome | Event outcome. | keyword |
| event.reason | Event reason. | keyword |
| event.type | Event type. | keyword |
| host.name | Host name. | keyword |
| input.type | Type of Filebeat input. | keyword |
| journald.audit.login_uid | The login UID of the process the journal entry originates from, as maintained by the kernel audit subsystem. | long |
| journald.audit.session | The session of the process the journal entry originates from, as maintained by the kernel audit subsystem. | keyword |
| journald.code.file | The code location generating this message, if known. Contains the source filename. | keyword |
| journald.code.func | The code location generating this message, if known. Contains the function name. | keyword |
| journald.code.line | The code location generating this message, if known. Contains the line number. | long |
| journald.custom | Structured fields added to the log message by the caller. | flattened |
| journald.gid | The group ID of the process the journal entry originates from. | long |
| journald.host.boot_id | The kernel boot ID for the boot the message was generated in. | keyword |
| journald.pid | The process ID of the process the journal entry originates from. | long |
| journald.process.capabilities | The effective capabilities of the process the journal entry originates from. | keyword |
| journald.process.command_line | The command line of the process the journal entry originates from. | keyword |
| journald.process.executable | The executable path of the process the journal entry originates from. | keyword |
| journald.process.name | The name of the process the journal entry originates from. | keyword |
| journald.uid | The user ID of the process the journal entry originates from. | long |
| message | For log events the message field contains the log message. | match_only_text |
| observer.product | Observer product. | keyword |
| observer.type | Observer type. | keyword |
| observer.vendor | Observer vendor. | keyword |
| proxmox.auth.realm | Authentication realm (pam, pve, ldap). | keyword |
| proxmox.cluster.name | Proxmox cluster name. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.ip | IP address of the source. | ip |
| systemd.cgroup | The control group path in the systemd hierarchy. | keyword |
| systemd.invocation_id | The invocation ID for the runtime cycle of the unit the message was generated in. | keyword |
| systemd.slice | The systemd slice unit name. | keyword |
| systemd.transport | How the entry was received by the journal service. | keyword |
| systemd.unit | The systemd unit name. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |


### Cluster Logs

Corosync cluster events from the systemd journal. Records membership changes, quorum transitions, and link state changes.

An example event for `cluster` looks as following:

```json
{
    "observer": {
        "product": "Proxmox VE",
        "type": "virtualization",
        "vendor": "Proxmox"
    },
    "event": {
        "kind": "event",
        "action": "membership_change",
        "category": [
            "configuration"
        ],
        "type": [
            "info"
        ],
        "outcome": "unknown"
    },
    "message": "Members[3]: 1 2 3",
    "proxmox": {
        "corosync": {
            "subsystem": "QUORUM",
            "members": 3
        }
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.action | Event action. | keyword |  |
| event.category | Event category. | keyword |  |
| event.dataset | Event dataset. | constant_keyword |  |
| event.kind | The kind of event. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| event.original | Raw text message of entire event. | keyword |  |
| event.outcome | Event outcome. | keyword |  |
| event.type | Event type. | keyword |  |
| host.name | Host name. | keyword |  |
| input.type | Type of Filebeat input. | keyword |  |
| journald.audit.login_uid | The login UID of the process the journal entry originates from, as maintained by the kernel audit subsystem. | long |  |
| journald.audit.session | The session of the process the journal entry originates from, as maintained by the kernel audit subsystem. | keyword |  |
| journald.code.file | The code location generating this message, if known. Contains the source filename. | keyword |  |
| journald.code.func | The code location generating this message, if known. Contains the function name. | keyword |  |
| journald.code.line | The code location generating this message, if known. Contains the line number. | long |  |
| journald.custom | Structured fields added to the log message by the caller. | flattened |  |
| journald.gid | The group ID of the process the journal entry originates from. | long |  |
| journald.host.boot_id | The kernel boot ID for the boot the message was generated in. | keyword |  |
| journald.pid | The process ID of the process the journal entry originates from. | long |  |
| journald.process.capabilities | The effective capabilities of the process the journal entry originates from. | keyword |  |
| journald.process.command_line | The command line of the process the journal entry originates from. | keyword |  |
| journald.process.executable | The executable path of the process the journal entry originates from. | keyword |  |
| journald.process.name | The name of the process the journal entry originates from. | keyword |  |
| journald.uid | The user ID of the process the journal entry originates from. | long |  |
| message | For log events the message field contains the log message. | match_only_text |  |
| observer.product | Observer product. | keyword |  |
| observer.type | Observer type. | keyword |  |
| observer.vendor | Observer vendor. | keyword |  |
| proxmox.cluster.name | Proxmox cluster name. | keyword |  |
| proxmox.corosync.members | Number of cluster members after a membership change. | long | gauge |
| proxmox.corosync.subsystem | Corosync subsystem (QUORUM, TOTEM, KNET, MAIN). | keyword |  |
| systemd.cgroup | The control group path in the systemd hierarchy. | keyword |  |
| systemd.invocation_id | The invocation ID for the runtime cycle of the unit the message was generated in. | keyword |  |
| systemd.slice | The systemd slice unit name. | keyword |  |
| systemd.transport | How the entry was received by the journal service. | keyword |  |
| systemd.unit | The systemd unit name. | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |


### Tasks

Task completion records from the Proxmox task index. Each entry records the task type, target VM or container, executing user, duration, and outcome.

An example event for `tasks` looks as following:

```json
{
    "observer": {
        "product": "Proxmox VE",
        "type": "virtualization",
        "vendor": "Proxmox"
    },
    "@timestamp": "2026-03-15T20:18:56.000Z",
    "related": {
        "user": [
            "root"
        ]
    },
    "event": {
        "duration": 1000000000,
        "kind": "event",
        "action": "resize",
        "category": [
            "process"
        ],
        "type": [
            "end"
        ],
        "outcome": "success"
    },
    "message": "Task resize on VM 306 completed with status OK",
    "proxmox": {
        "auth": {
            "realm": "pam"
        },
        "task": {
            "upid": "UPID:lab:002C12FB:073B86AD:69B7142F:resize:306:root@pam:",
            "duration_seconds": 1,
            "node": "lab",
            "type": "resize",
            "vmid": "306"
        }
    },
    "user": {
        "name": "root"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.action | Event action. | keyword |  |
| event.category | Event category. | keyword |  |
| event.dataset | Event dataset. | constant_keyword |  |
| event.duration | Duration of the event in nanoseconds. | long |  |
| event.kind | The kind of event. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| event.original | Raw text message of entire event. | keyword |  |
| event.outcome | Event outcome. | keyword |  |
| event.type | Event type. | keyword |  |
| host.name | Host name. | keyword |  |
| message | For log events the message field contains the log message. | match_only_text |  |
| observer.product | Observer product. | keyword |  |
| observer.type | Observer type. | keyword |  |
| observer.vendor | Observer vendor. | keyword |  |
| proxmox.auth.realm | Authentication realm (pam, pve, and so on). | keyword |  |
| proxmox.auth.token_name | API token name, if the task was initiated by a token. | keyword |  |
| proxmox.cluster.name | Proxmox cluster name. | keyword |  |
| proxmox.task.duration_seconds | Task duration in seconds. | long | s |
| proxmox.task.node | Node that ran the task. | keyword |  |
| proxmox.task.type | Task type (vzdump, qmstart, qmstop, vncproxy, and so on). | keyword |  |
| proxmox.task.upid | Unique Process ID (UPID) string. | keyword |  |
| proxmox.task.vmid | Target VM or container ID. | keyword |  |
| related.user | All the user names or other user identifiers seen on the event. | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |
| user.name | Short name or login of the user. | keyword |  |

