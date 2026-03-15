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
   - The node hostname

## Data Streams

### Cluster Metrics

Cluster-wide resource metrics collected from the Proxmox REST API. Includes CPU, memory, disk, and network statistics for all nodes, VMs, containers, and storage pools, along with cluster quorum status and HA resource state.

An example event for `cluster` looks as following:

```json
{
    "@timestamp": "2026-02-21T10:00:00.000Z",
    "event": {
        "ingested": "2026-02-21T10:00:01.000Z",
        "kind": "metric",
        "dataset": "proxmox.cluster",
        "module": "proxmox"
    },
    "proxmox": {
        "cluster": {
            "resource": {
                "type": "qemu",
                "id": "qemu/100",
                "name": "k8s-cp1",
                "node": "lab",
                "vmid": 100,
                "status": "running",
                "cpu": 0.0234,
                "maxcpu": 4,
                "mem": 4294967296,
                "maxmem": 8589934592,
                "disk": 0,
                "maxdisk": 34359738368,
                "netin": 123456789,
                "netout": 987654321,
                "diskread": 555555555,
                "diskwrite": 444444444,
                "uptime": 86400,
                "template": false
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
| proxmox.cluster.resource.cgroup_mode | Cgroup mode (node only). | long |  | gauge |
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
| proxmox.cluster.resource.vmid | VM or container ID. | long |  | gauge |
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
    "@timestamp": "2026-02-21T10:00:00.000Z",
    "event": {
        "ingested": "2026-02-21T10:00:01.000Z",
        "kind": "metric",
        "dataset": "proxmox.node",
        "module": "proxmox"
    },
    "proxmox": {
        "node": {
            "cpu": 0.0523,
            "wait": 0.001,
            "loadavg": {
                "1m": 0.45,
                "5m": 0.38,
                "15m": 0.35
            },
            "memory": {
                "total": 67108864000,
                "used": 8589934592,
                "free": 58518929408,
                "available": 58518929408
            },
            "swap": {
                "total": 8589934592,
                "used": 0,
                "free": 8589934592
            },
            "rootfs": {
                "total": 107374182400,
                "used": 5368709120,
                "avail": 102005473280
            },
            "uptime": 604800,
            "pveversion": "pve-manager/9.1.4/aab1f6c6c1afdb1a",
            "kversion": "Linux 6.17.4-2-pve #1 SMP PREEMPT_DYNAMIC PMX 6.17.4-2 (2026-01-15T12:00:00Z)",
            "cpuinfo": {
                "model": "AMD EPYC 7543 32-Core Processor",
                "cores": 8,
                "sockets": 1
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
    "@timestamp": "2026-02-21T10:05:20.000Z",
    "event": {
        "ingested": "2026-02-21T10:05:21.000Z",
        "kind": "event",
        "category": [
            "web"
        ],
        "type": [
            "access"
        ],
        "outcome": "success",
        "dataset": "proxmox.access",
        "module": "proxmox"
    },
    "source": {
        "ip": "172.30.1.101"
    },
    "user": {
        "name": "csi"
    },
    "proxmox": {
        "auth": {
            "realm": "pve",
            "token_id": "csi-token"
        }
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 200,
            "body": {
                "bytes": 147
            }
        },
        "version": "1.1"
    },
    "url": {
        "path": "/api2/json/nodes/lab/storage/hdd_kubernetes/status"
    },
    "related": {
        "ip": [
            "172.30.1.101"
        ],
        "user": [
            "csi"
        ]
    },
    "observer": {
        "vendor": "Proxmox",
        "product": "Proxmox VE",
        "type": "virtualization"
    },
    "message": "GET /api2/json/nodes/lab/storage/hdd_kubernetes/status 200"
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
    "@timestamp": "2020-07-01T00:42:13.000+02:00",
    "event": {
        "ingested": "2026-02-21T10:05:21.000Z",
        "kind": "event",
        "category": [
            "network"
        ],
        "type": [
            "connection",
            "denied"
        ],
        "action": "drop",
        "outcome": "failure",
        "dataset": "proxmox.firewall",
        "module": "proxmox"
    },
    "source": {
        "ip": "192.168.1.2",
        "port": 23658
    },
    "destination": {
        "ip": "192.168.1.56",
        "port": 443
    },
    "network": {
        "transport": "tcp",
        "bytes": 60
    },
    "proxmox": {
        "firewall": {
            "chain": "PVEFW-HOST-OUT"
        }
    },
    "related": {
        "ip": [
            "192.168.1.2",
            "192.168.1.56"
        ]
    },
    "observer": {
        "vendor": "Proxmox",
        "product": "Proxmox VE",
        "type": "firewall"
    },
    "message": "drop 192.168.1.2:23658 -> 192.168.1.56:443 tcp"
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
| destination.ip | IP address of the destination. | ip |
| destination.port | Port of the destination. | long |
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
| message | For log events the message field contains the log message. | match_only_text |
| network.bytes | Total bytes transferred in both directions. | long |
| network.transport | Protocol Name corresponding to the field `iana_number`. | keyword |
| observer.product | Observer product. | keyword |
| observer.type | Observer type. | keyword |
| observer.vendor | Observer vendor. | keyword |
| proxmox.cluster.name | Proxmox cluster name. | keyword |
| proxmox.firewall.chain | Firewall chain name (PVEFW-HOST-IN, PVEFW-HOST-OUT, and so on). | keyword |
| proxmox.firewall.vmid | VM or container ID from the firewall chain. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.ip | IP address of the source. | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |


### Auth Events

Authentication events from the pvedaemon systemd journal. Records successful and failed login attempts with the authenticating user, source IP, and realm.

An example event for `auth` looks as following:

```json
{
    "@timestamp": "2026-02-21T10:05:20.000Z",
    "event": {
        "ingested": "2026-02-21T10:05:21.000Z",
        "kind": "event",
        "category": [
            "authentication"
        ],
        "type": [
            "info"
        ],
        "outcome": "success",
        "dataset": "proxmox.auth",
        "module": "proxmox"
    },
    "user": {
        "name": "root"
    },
    "proxmox": {
        "auth": {
            "realm": "pam"
        }
    },
    "related": {
        "user": [
            "root"
        ]
    },
    "observer": {
        "vendor": "Proxmox",
        "product": "Proxmox VE",
        "type": "virtualization"
    },
    "message": "Successful authentication for user root@pam"
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
    "event": {
        "ingested": "2026-02-21T10:00:00.000Z",
        "kind": "event",
        "category": [
            "configuration"
        ],
        "type": [
            "info"
        ],
        "action": "membership_change",
        "outcome": "unknown",
        "dataset": "proxmox.cluster_logs",
        "module": "proxmox"
    },
    "proxmox": {
        "corosync": {
            "subsystem": "QUORUM",
            "members": 3
        }
    },
    "observer": {
        "vendor": "Proxmox",
        "product": "Proxmox VE",
        "type": "virtualization"
    },
    "message": "Members[3]: 1 2 3"
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
    "@timestamp": "2021-11-10T19:32:11.000Z",
    "event": {
        "ingested": "2026-02-21T10:00:00.000Z",
        "kind": "event",
        "category": [
            "process"
        ],
        "type": [
            "info"
        ],
        "action": "vzdump",
        "outcome": "success",
        "duration": 230000000000,
        "dataset": "proxmox.tasks",
        "module": "proxmox"
    },
    "proxmox": {
        "task": {
            "node": "lab",
            "type": "vzdump",
            "vmid": "100",
            "upid": "UPID:lab:000AE992:00A21BA7:618C1D55:vzdump:100:root@pam:"
        }
    },
    "user": {
        "name": "root"
    },
    "related": {
        "user": [
            "root"
        ]
    },
    "observer": {
        "vendor": "Proxmox",
        "product": "Proxmox VE",
        "type": "virtualization"
    },
    "message": "Task vzdump on VM 100 completed with status OK"
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
| proxmox.cluster.name | Proxmox cluster name. | keyword |  |
| proxmox.task.duration_seconds | Task duration in seconds. | long | s |
| proxmox.task.node | Node that ran the task. | keyword |  |
| proxmox.task.type | Task type (vzdump, qmstart, qmstop, vncproxy, and so on). | keyword |  |
| proxmox.task.upid | Unique Process ID (UPID) string. | keyword |  |
| proxmox.task.vmid | Target VM or container ID. | keyword |  |
| related.user | All the user names or other user identifiers seen on the event. | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |
| user.name | Short name or login of the user. | keyword |  |

