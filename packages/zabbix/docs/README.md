# Zabbix

The Zabbix integration collects metrics and logs from [Zabbix](https://www.zabbix.com/) monitoring servers. It polls the Zabbix JSON-RPC API for server health statistics, host inventory, active problems, proxy fleet status, HA cluster state, and audit log entries. It can also parse Zabbix server log files directly from disk.

## Compatibility

This integration is compatible with Zabbix 7.0 LTS and later versions.

## Setup

This integration requires a Zabbix API token with read access to the endpoints it polls. The minimum required user role depends on which data streams you enable:

| Data Stream | Required Role | API Method |
|---|---|---|
| Server Health | User or later | `item.get` (internal items) |
| Host Status | User or later | `host.get` |
| Problem | User or later | `problem.get` |
| Proxy Health | Admin or later | `proxy.get` |
| HA Status | User or later | `hanode.get` |
| Audit | Super admin | `auditlog.get` |

To collect all data streams, the token must belong to a **Super admin** user. If you do not need the audit log, an **Admin** role is sufficient.

To create an API token:

1. Log in to the Zabbix frontend.
2. Navigate to **Users > API tokens** (Zabbix 6.4 and later) or **Administration > General > API tokens**.
3. Click **Create API token**.
4. Select the user the token belongs to. This user's role and permissions determine what data the integration can access.
5. Optionally set an expiration date.
6. Click **Add** and copy the generated token value. This is shown only once.
7. Paste the token into the **API Token** field when configuring this integration in Fleet.

For the **log** data stream, the Elastic Agent must run on the Zabbix server host and have filesystem access to the server log file (typically `/var/log/zabbix/zabbix_server.log`). This data stream does not use the API.

## Data Streams

### Server Health

The `server_health` data stream collects internal Zabbix server statistics such as queue depths, cache hit ratios, process utilization, and new values per second (NVPS).

An example event for `server_health` looks as following:

```json
{
    "@timestamp": "2026-04-01T19:26:12.745Z",
    "event": {
        "agent_id_status": "verified",
        "ingested": "2026-04-01T19:26:22Z",
        "kind": "metric"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "opennebula-node2",
        "id": "d8ca343398cc42babf9a8ed1bd5d3c2f",
        "ip": [
            "172.16.100.1",
            "172.30.0.92",
            "fe80::8cf4:9bff:fe15:7173",
            "fe80::be24:11ff:fe86:e78"
        ],
        "mac": [
            "4A-14-E3-EF-26-B2",
            "8E-F4-9B-15-71-73",
            "BC-24-11-86-0E-78"
        ],
        "name": "opennebula-node2",
        "os": {
            "codename": "bookworm",
            "family": "debian",
            "kernel": "6.1.0-44-cloud-amd64",
            "name": "Debian GNU/Linux",
            "platform": "debian",
            "type": "linux",
            "version": "12 (bookworm)"
        }
    },
    "zabbix": {
        "server": {
            "item": {
                "key": "zabbix[process,connector worker,avg,busy]",
                "lastvalue": "0",
                "name": "Utilization of connector worker internal processes, in %"
            },
            "process": {
                "busy": 0.0,
                "name": "connector worker"
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
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.dataset | Event dataset. | constant_keyword |  |  |
| event.kind | The kind of event. | keyword |  |  |
| event.module | Event module. | constant_keyword |  |  |
| zabbix.server.cache.config.pused | Percentage of the configuration cache currently in use. | double | percent | gauge |
| zabbix.server.cache.history.pused | Percentage of the history cache currently in use. | double | percent | gauge |
| zabbix.server.cache.index.pused | Percentage of the history index cache currently in use. | double | percent | gauge |
| zabbix.server.cache.trend.pused | Percentage of the trend cache currently in use. | double | percent | gauge |
| zabbix.server.cache.trend_function.pitems | Percentage of cached items in the trend function cache. | double | percent | gauge |
| zabbix.server.cache.trend_function.pmisses | Percentage of cache misses in the trend function cache. | double | percent | gauge |
| zabbix.server.cache.value.hits | Number of value cache hits per second. | double |  | gauge |
| zabbix.server.cache.value.misses | Number of value cache misses per second. | double |  | gauge |
| zabbix.server.cache.value.mode | Value cache operating mode where 0 indicates normal operation and 1 indicates low memory mode. | long |  | gauge |
| zabbix.server.cache.value.pused | Percentage of the value cache currently in use. | double | percent | gauge |
| zabbix.server.cache.vmware.pused | Percentage of the VMware cache currently in use. | double | percent | gauge |
| zabbix.server.connector_queue | Number of items waiting in the connector queue for external processing. | long |  | gauge |
| zabbix.server.discovery_queue | Number of discovery checks currently waiting in the discovery queue. | long |  | gauge |
| zabbix.server.host.agent.available | Number of hosts where the Zabbix agent interface is available. | long |  | gauge |
| zabbix.server.item.key | Internal item key identifier. | keyword |  |  |
| zabbix.server.item.lastvalue | Raw last value of the item as returned by the Zabbix API. | keyword |  |  |
| zabbix.server.item.name | Human-readable name of the internal item. | keyword |  |  |
| zabbix.server.lld_queue | Number of low-level discovery rules waiting in the LLD queue. | long |  | gauge |
| zabbix.server.preprocessing_queue | Number of values currently waiting in the preprocessing queue. | long |  | gauge |
| zabbix.server.process.busy | Average percentage of time the process type spent in busy state. | double | percent | gauge |
| zabbix.server.process.name | Name of the Zabbix server internal process type. | keyword |  |  |
| zabbix.server.queue.over_10m | Number of items in the queue that have been delayed for more than 10 minutes. | long |  | gauge |
| zabbix.server.queue.total | Total number of items in the queue that are delayed for processing. | long |  | gauge |
| zabbix.server.triggers | Total number of enabled triggers on the Zabbix server. | long |  | gauge |
| zabbix.server.uptime | Number of seconds since the Zabbix server process was started. | long | s | gauge |
| zabbix.server.version | Zabbix server version string. | keyword |  |  |
| zabbix.server.vps.float | Number of float values written per second. | double |  | gauge |
| zabbix.server.vps.log | Number of log values written per second. | double |  | gauge |
| zabbix.server.vps.not_supported | Number of not-supported values written per second. | double |  | gauge |
| zabbix.server.vps.str | Number of string values written per second. | double |  | gauge |
| zabbix.server.vps.text | Number of text values written per second. | double |  | gauge |
| zabbix.server.vps.total | Total number of values processed per second across all value types. | double |  | gauge |
| zabbix.server.vps.uint | Number of unsigned integer values written per second. | double |  | gauge |
| zabbix.server.vps.written | Total number of values written to the database per second. | double |  | gauge |


### Host Status

The `host_status` data stream collects host inventory and availability information, including host groups, maintenance windows, and agent availability.

An example event for `host_status` looks as following:

```json
{
    "@timestamp": "2026-04-01T19:26:12.563Z",
    "event": {
        "agent_id_status": "verified",
        "ingested": "2026-04-01T19:26:18Z",
        "kind": "metric"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "opennebula-lab",
        "id": "d8ca343398cc42babf9a8ed1bd5d3c2f",
        "ip": [
            "172.16.100.1",
            "172.30.0.90",
            "fe80::8cf4:9bff:fe15:7173",
            "fe80::be24:11ff:feb8:a58",
            "fe80::fc00:acff:fe10:6402",
            "fe80::fc00:acff:fe10:6403",
            "fe80::fc00:acff:fe10:6406",
            "fe80::fc00:acff:fe10:6407",
            "fe80::fc00:acff:fe10:6408",
            "fe80::fc00:acff:fe10:6409",
            "fe80::fc00:acff:fe10:640a",
            "fe80::fc00:acff:fe10:640c",
            "fe80::fc00:acff:fe10:640d"
        ],
        "mac": [
            "4A-14-E3-EF-26-B2",
            "8E-F4-9B-15-71-73",
            "BC-24-11-B8-0A-58",
            "FE-00-AC-10-64-02",
            "FE-00-AC-10-64-03",
            "FE-00-AC-10-64-06",
            "FE-00-AC-10-64-07",
            "FE-00-AC-10-64-08",
            "FE-00-AC-10-64-09",
            "FE-00-AC-10-64-0A",
            "FE-00-AC-10-64-0C",
            "FE-00-AC-10-64-0D"
        ],
        "name": "opennebula-lab",
        "os": {
            "codename": "bookworm",
            "family": "debian",
            "kernel": "6.1.0-43-cloud-amd64",
            "name": "Debian GNU/Linux",
            "platform": "debian",
            "type": "linux",
            "version": "12 (bookworm)"
        }
    },
    "zabbix": {
        "host": {
            "active_available": "unknown",
            "groups": "Linux servers",
            "host": "test-unreachable",
            "id": "10680",
            "interface": {
                "available": "unknown",
                "ip": "192.168.99.99",
                "port": "10050",
                "type": "agent"
            },
            "maintenance": {
                "status": "off"
            },
            "monitored_by": "server",
            "name": "test-unreachable",
            "proxy": {
                "id": "0"
            },
            "status": "enabled"
        }
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
| event.dataset | Event dataset. | constant_keyword |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| host.name | Name of the host. | keyword |
| zabbix.host.active_available | Availability of the active agent on this host, one of available, unavailable, or unknown. | keyword |
| zabbix.host.groups | List of host group names this host belongs to. | keyword |
| zabbix.host.host | Technical name of the host used internally by Zabbix. | keyword |
| zabbix.host.id | Unique numeric identifier of the host in Zabbix. | keyword |
| zabbix.host.interface.available | Availability of the primary host interface, one of available, unavailable, or unknown. | keyword |
| zabbix.host.interface.ip | IP address of the primary host interface. | ip |
| zabbix.host.interface.port | Port number of the primary host interface. | keyword |
| zabbix.host.interface.type | Type of the primary host interface, one of agent, snmp, ipmi, or jmx. | keyword |
| zabbix.host.maintenance.status | Whether the host is currently in maintenance, either on or off. | keyword |
| zabbix.host.maintenance.type | Type of maintenance applied to the host, either with_data or without_data. | keyword |
| zabbix.host.monitored_by | Entity responsible for monitoring this host, one of server, proxy, or proxy_group. | keyword |
| zabbix.host.name | Visible display name of the host in the Zabbix frontend. | keyword |
| zabbix.host.proxy.id | Identifier of the proxy monitoring this host, or 0 if monitored directly by the server. | keyword |
| zabbix.host.status | Monitoring status of the host, either enabled or disabled. | keyword |
| zabbix.host.tags | Key-value tags assigned to the host in Zabbix. | flattened |


### Problem

The `problem` data stream collects active problems and trigger events from Zabbix, including severity, acknowledgment status, and suppression state.

An example event for `problem` looks as following:

```json
{
    "observer": {
        "product": "Zabbix Server",
        "vendor": "Zabbix"
    },
    "zabbix": {
        "problem": {
            "severity": "warning",
            "eventid": "103",
            "acknowledged": false,
            "opdata": "Current value: 602",
            "source": "triggers",
            "tags": [
                {
                    "tag": "scope",
                    "value": "availability"
                },
                {
                    "tag": "component",
                    "value": "proxy"
                },
                {
                    "tag": "proxy-name",
                    "value": "lab-proxy-01"
                },
                {
                    "tag": "class",
                    "value": "software"
                },
                {
                    "tag": "target",
                    "value": "server"
                },
                {
                    "tag": "target",
                    "value": "zabbix"
                }
            ],
            "urls": [],
            "r_eventid": "0",
            "severity_number": 2,
            "name": "Zabbix server: Proxy [lab-proxy-01]: Zabbix proxy last seen more than 600 seconds ago",
            "suppressed": false,
            "acknowledges": [],
            "cause_eventid": "0",
            "objectid": "25307",
            "object": "trigger"
        }
    },
    "@timestamp": "2026-04-01T19:09:16.000Z",
    "host": {
        "hostname": "opennebula-lab",
        "os": {
            "kernel": "6.1.0-43-cloud-amd64",
            "codename": "bookworm",
            "name": "Debian GNU/Linux",
            "type": "linux",
            "family": "debian",
            "version": "12 (bookworm)",
            "platform": "debian"
        },
        "containerized": false,
        "ip": [
            "172.30.0.90",
            "fe80::be24:11ff:feb8:a58",
            "172.16.100.1",
            "fe80::8cf4:9bff:fe15:7173",
            "fe80::fc00:acff:fe10:6402",
            "fe80::fc00:acff:fe10:6406",
            "fe80::fc00:acff:fe10:6409",
            "fe80::fc00:acff:fe10:6403",
            "fe80::fc00:acff:fe10:6407",
            "fe80::fc00:acff:fe10:6408",
            "fe80::fc00:acff:fe10:640d",
            "fe80::fc00:acff:fe10:640c",
            "fe80::fc00:acff:fe10:640a"
        ],
        "name": "opennebula-lab",
        "id": "d8ca343398cc42babf9a8ed1bd5d3c2f",
        "mac": [
            "4A-14-E3-EF-26-B2",
            "8E-F4-9B-15-71-73",
            "BC-24-11-B8-0A-58",
            "FE-00-AC-10-64-02",
            "FE-00-AC-10-64-03",
            "FE-00-AC-10-64-06",
            "FE-00-AC-10-64-07",
            "FE-00-AC-10-64-08",
            "FE-00-AC-10-64-09",
            "FE-00-AC-10-64-0A",
            "FE-00-AC-10-64-0C",
            "FE-00-AC-10-64-0D"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "severity": 2,
        "agent_id_status": "verified",
        "ingested": "2026-04-01T19:10:18Z",
        "kind": "event",
        "action": "problem_detected",
        "category": [
            "host"
        ],
        "type": [
            "info"
        ],
        "outcome": "failure"
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
| event.severity | The severity of the event. | long |
| event.type | Event type. | keyword |
| message | For log events the message field contains the log message. | match_only_text |
| observer.product | Observer product. | keyword |
| observer.type | Observer type. | keyword |
| observer.vendor | Observer vendor. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| zabbix.problem.acknowledged | Whether the problem has been acknowledged by a user. | boolean |
| zabbix.problem.acknowledges | List of acknowledgment entries for this problem, each containing user, message, and timestamp. | flattened |
| zabbix.problem.cause_eventid | Identifier of the root cause event if this problem is a symptom of another problem. | keyword |
| zabbix.problem.eventid | Unique identifier of the problem event in Zabbix. | keyword |
| zabbix.problem.name | Name of the problem as defined by the trigger expression. | keyword |
| zabbix.problem.object | Type of object that is related to this problem event. | keyword |
| zabbix.problem.objectid | Identifier of the related object (trigger, item, or LLD rule) that generated this problem. | keyword |
| zabbix.problem.opdata | Operational data string showing current values related to this problem. | keyword |
| zabbix.problem.r_clock | Timestamp when the problem was resolved by the recovery event. | date |
| zabbix.problem.r_eventid | Identifier of the recovery event that resolved this problem, or 0 if unresolved. | keyword |
| zabbix.problem.severity | Severity level of the problem, one of not_classified, information, warning, average, high, or disaster. | keyword |
| zabbix.problem.severity_number | Numeric severity level of the problem from 0 (not classified) to 5 (disaster). | long |
| zabbix.problem.source | Type of the event source that generated this problem. | keyword |
| zabbix.problem.suppressed | Whether the problem is currently suppressed by maintenance or manual suppression. | boolean |
| zabbix.problem.tags | Key-value tags associated with this problem event. | flattened |
| zabbix.problem.urls | List of media type URLs associated with this problem event. | flattened |


### Proxy Health

The `proxy_health` data stream collects status and performance metrics for the Zabbix proxy fleet, including last seen time, host counts, and data queue lengths.

An example event for `proxy_health` looks as following:

```json
{
    "@timestamp": "2026-04-01T19:26:12.560Z",
    "event": {
        "agent_id_status": "verified",
        "ingested": "2026-04-01T19:26:18Z",
        "kind": "metric"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "opennebula-lab",
        "id": "d8ca343398cc42babf9a8ed1bd5d3c2f",
        "ip": [
            "172.16.100.1",
            "172.30.0.90",
            "fe80::8cf4:9bff:fe15:7173",
            "fe80::be24:11ff:feb8:a58",
            "fe80::fc00:acff:fe10:6402",
            "fe80::fc00:acff:fe10:6403",
            "fe80::fc00:acff:fe10:6406",
            "fe80::fc00:acff:fe10:6407",
            "fe80::fc00:acff:fe10:6408",
            "fe80::fc00:acff:fe10:6409",
            "fe80::fc00:acff:fe10:640a",
            "fe80::fc00:acff:fe10:640c",
            "fe80::fc00:acff:fe10:640d"
        ],
        "mac": [
            "4A-14-E3-EF-26-B2",
            "8E-F4-9B-15-71-73",
            "BC-24-11-B8-0A-58",
            "FE-00-AC-10-64-02",
            "FE-00-AC-10-64-03",
            "FE-00-AC-10-64-06",
            "FE-00-AC-10-64-07",
            "FE-00-AC-10-64-08",
            "FE-00-AC-10-64-09",
            "FE-00-AC-10-64-0A",
            "FE-00-AC-10-64-0C",
            "FE-00-AC-10-64-0D"
        ],
        "name": "opennebula-lab",
        "os": {
            "codename": "bookworm",
            "family": "debian",
            "kernel": "6.1.0-43-cloud-amd64",
            "name": "Debian GNU/Linux",
            "platform": "debian",
            "type": "linux",
            "version": "12 (bookworm)"
        }
    },
    "zabbix": {
        "proxy": {
            "compatibility": "current",
            "id": "1",
            "name": "lab-proxy-01",
            "operating_mode": "active",
            "state": "online",
            "version": "70022"
        }
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
| event.dataset | Event dataset. | constant_keyword |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| zabbix.proxy.address | Network address of the proxy. | keyword |
| zabbix.proxy.compatibility | Compatibility status of the proxy version relative to the Zabbix server version. | keyword |
| zabbix.proxy.id | Unique identifier of the proxy in Zabbix. | keyword |
| zabbix.proxy.last_access | Timestamp of the last heartbeat or data received from the proxy. | date |
| zabbix.proxy.name | Display name of the proxy. | keyword |
| zabbix.proxy.operating_mode | Operating mode of the proxy, either active or passive. | keyword |
| zabbix.proxy.port | Port number used for communication with the proxy. | keyword |
| zabbix.proxy.state | Current operational state of the proxy. | keyword |
| zabbix.proxy.version | Version string of the proxy software. | keyword |


### HA Status

The `ha_status` data stream collects high-availability cluster node status, including node roles, last access times, and failover readiness.

An example event for `ha_status` looks as following:

```json
{
    "@timestamp": "2026-04-01T19:26:10.000Z",
    "event": {
        "agent_id_status": "verified",
        "ingested": "2026-04-01T19:26:18Z",
        "kind": "metric"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "opennebula-lab",
        "id": "d8ca343398cc42babf9a8ed1bd5d3c2f",
        "ip": [
            "172.16.100.1",
            "172.30.0.90",
            "fe80::8cf4:9bff:fe15:7173",
            "fe80::be24:11ff:feb8:a58",
            "fe80::fc00:acff:fe10:6402",
            "fe80::fc00:acff:fe10:6403",
            "fe80::fc00:acff:fe10:6406",
            "fe80::fc00:acff:fe10:6407",
            "fe80::fc00:acff:fe10:6408",
            "fe80::fc00:acff:fe10:6409",
            "fe80::fc00:acff:fe10:640a",
            "fe80::fc00:acff:fe10:640c",
            "fe80::fc00:acff:fe10:640d"
        ],
        "mac": [
            "4A-14-E3-EF-26-B2",
            "8E-F4-9B-15-71-73",
            "BC-24-11-B8-0A-58",
            "FE-00-AC-10-64-02",
            "FE-00-AC-10-64-03",
            "FE-00-AC-10-64-06",
            "FE-00-AC-10-64-07",
            "FE-00-AC-10-64-08",
            "FE-00-AC-10-64-09",
            "FE-00-AC-10-64-0A",
            "FE-00-AC-10-64-0C",
            "FE-00-AC-10-64-0D"
        ],
        "name": "opennebula-lab",
        "os": {
            "codename": "bookworm",
            "family": "debian",
            "kernel": "6.1.0-43-cloud-amd64",
            "name": "Debian GNU/Linux",
            "platform": "debian",
            "type": "linux",
            "version": "12 (bookworm)"
        }
    },
    "zabbix": {
        "ha": {
            "address": "localhost",
            "lastaccess": "2026-04-01T19:26:10.000Z",
            "name": "cmmswbbax0001ipws8yn4068f",
            "nodeid": "cmmswbbax0001ipws8yn4068f",
            "port": 10051,
            "status": "active"
        }
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
| event.dataset | Event dataset. | constant_keyword |
| event.kind | The kind of event. | keyword |
| event.module | Event module. | constant_keyword |
| zabbix.ha.address | Network address the HA node is listening on. | keyword |
| zabbix.ha.lastaccess | Timestamp of the last successful heartbeat from the HA node. | date |
| zabbix.ha.name | Display name of the HA cluster node. | keyword |
| zabbix.ha.nodeid | Unique identifier of the HA cluster node. | keyword |
| zabbix.ha.port | Port number the HA node is listening on. | keyword |
| zabbix.ha.status | Current status of the HA node, one of standby, stopped, unavailable, or active. | keyword |


### Audit

The `audit` data stream collects audit log entries from Zabbix, recording user actions such as configuration changes, login events, and API calls.

An example event for `audit` looks as following:

```json
{
    "zabbix": {
        "audit": {
            "resource_cuid": "0",
            "resource_type_name": "user",
            "user_id": "1",
            "action_code": 8,
            "resource_type": 0,
            "resource_id": "1",
            "recordset_id": "cmngfjms00000uxwsqx9mtvsc",
            "id": "cmngfjms00001uxwsrbhycy0i",
            "resource_name": ""
        }
    },
    "source": {
        "ip": "172.30.0.1"
    },
    "observer": {
        "product": "Zabbix Server",
        "vendor": "Zabbix"
    },
    "@timestamp": "2026-04-01T19:19:32.000Z",
    "related": {
        "ip": [
            "172.30.0.1"
        ],
        "user": [
            "Admin"
        ]
    },
    "host": {
        "hostname": "opennebula-lab",
        "os": {
            "kernel": "6.1.0-43-cloud-amd64",
            "codename": "bookworm",
            "name": "Debian GNU/Linux",
            "family": "debian",
            "type": "linux",
            "version": "12 (bookworm)",
            "platform": "debian"
        },
        "containerized": false,
        "ip": [
            "172.30.0.90",
            "fe80::be24:11ff:feb8:a58",
            "172.16.100.1",
            "fe80::8cf4:9bff:fe15:7173",
            "fe80::fc00:acff:fe10:6402",
            "fe80::fc00:acff:fe10:6406",
            "fe80::fc00:acff:fe10:6409",
            "fe80::fc00:acff:fe10:6403",
            "fe80::fc00:acff:fe10:6407",
            "fe80::fc00:acff:fe10:6408",
            "fe80::fc00:acff:fe10:640d",
            "fe80::fc00:acff:fe10:640c",
            "fe80::fc00:acff:fe10:640a"
        ],
        "name": "opennebula-lab",
        "id": "d8ca343398cc42babf9a8ed1bd5d3c2f",
        "mac": [
            "4A-14-E3-EF-26-B2",
            "8E-F4-9B-15-71-73",
            "BC-24-11-B8-0A-58",
            "FE-00-AC-10-64-02",
            "FE-00-AC-10-64-03",
            "FE-00-AC-10-64-06",
            "FE-00-AC-10-64-07",
            "FE-00-AC-10-64-08",
            "FE-00-AC-10-64-09",
            "FE-00-AC-10-64-0A",
            "FE-00-AC-10-64-0C",
            "FE-00-AC-10-64-0D"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2026-04-01T19:20:18Z",
        "kind": "event",
        "action": "login",
        "category": [
            "configuration"
        ],
        "type": [
            "change"
        ],
        "outcome": "success"
    },
    "user": {
        "name": "Admin",
        "id": "1"
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
| message | For log events the message field contains the log message. | match_only_text |
| observer.product | Observer product. | keyword |
| observer.type | Observer type. | keyword |
| observer.vendor | Observer vendor. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.ip | IP address of the source. | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| zabbix.audit.action_code | Raw numeric action code from the Zabbix audit log. | long |
| zabbix.audit.details | Detailed changes made during the audit action, containing before and after values. | flattened |
| zabbix.audit.id | Unique identifier of the audit log entry. | keyword |
| zabbix.audit.recordset_id | Identifier linking multiple audit entries that belong to the same operation. | keyword |
| zabbix.audit.resource_cuid | Compound unique identifier of the resource that was affected by the action. | keyword |
| zabbix.audit.resource_id | Identifier of the resource that was affected by the action. | keyword |
| zabbix.audit.resource_name | Display name of the resource that was affected by the action. | keyword |
| zabbix.audit.resource_type | Raw numeric type identifier of the resource that was affected by the action. | long |
| zabbix.audit.resource_type_name | Human-readable name of the affected resource type (derived from resource_type code). | keyword |
| zabbix.audit.user_id | Identifier of the user who performed the action. | keyword |


### Log

The `log` data stream parses Zabbix server log files, capturing startup messages, error conditions, slow queries, and other operational events.

An example event for `log` looks as following:

```json
{
    "observer": {
        "product": "Zabbix Server",
        "vendor": "Zabbix"
    },
    "process": {
        "pid": 1
    },
    "@timestamp": "2026-03-14T10:50:41.851Z",
    "message": "Starting Zabbix Server. Zabbix 7.0.24 (revision 36bdd34).",
    "event": {
        "original": "     1:20260314:105041.851 Starting Zabbix Server. Zabbix 7.0.24 (revision 36bdd34).",
        "category": [
            "process"
        ],
        "kind": "event"
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
| event.category | Event category. | keyword |  |
| event.dataset | Event dataset. | constant_keyword |  |
| event.kind | The kind of event. | keyword |  |
| event.module | Event module. | constant_keyword |  |
| event.original | Raw text message of entire event. | keyword |  |
| event.type | Event type. | keyword |  |
| message | For log events the message field contains the log message. | match_only_text |  |
| observer.product | Observer product. | keyword |  |
| observer.type | Observer type. | keyword |  |
| observer.vendor | Observer vendor. | keyword |  |
| process.pid | Process id. | long |  |
| tags | List of keywords used to tag each event. | keyword |  |
| zabbix.log.slow_query.detected | Whether a slow database query was detected in this log line. | boolean |  |
| zabbix.log.slow_query.duration | Duration of a slow database query in seconds, extracted when a slow query is detected in the log. | double | s |

