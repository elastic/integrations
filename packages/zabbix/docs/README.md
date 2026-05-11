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

When configuring this integration in Fleet, the **Zabbix URL** field (`zabbix_url`) must point to the base URL of your Zabbix frontend, including the JSON-RPC endpoint path. For example: `http://zabbix.example.com/api_jsonrpc.php`.

For the **log** data stream, the Elastic Agent must run on the Zabbix server host and have filesystem access to the server log file (typically `/var/log/zabbix/zabbix_server.log`). This data stream does not use the API.

## Data Streams

### Server Health

The `server_health` data stream collects internal Zabbix server statistics such as queue depths, cache hit ratios, process utilization, and new values per second (NVPS).

An example event for `server_health` looks as following:

```json
{
    "event": {
        "dataset": "zabbix.server_health",
        "kind": "metric",
        "module": "zabbix"
    },
    "zabbix": {
        "server": {
            "item": {
                "name": "Utilization of history syncer internal processes, in %",
                "key": "zabbix[process,history syncer,avg,busy]",
                "lastvalue": "0.21163125370354693"
            },
            "process": {
                "name": "history syncer",
                "busy": 0.21163125370354693
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
| zabbix.server.preprocessing.throughput.direct | Number of items preprocessed directly per second (bypassing the queue). | double |  | gauge |
| zabbix.server.preprocessing.throughput.queued | Number of items preprocessed through the queue per second. | double |  | gauge |
| zabbix.server.preprocessing.vps.direct | Number of values preprocessed directly per second. | double |  | gauge |
| zabbix.server.preprocessing.vps.queued | Number of values preprocessed through the queue per second. | double |  | gauge |
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
    "host": {
        "name": "test-audit-host"
    },
    "zabbix": {
        "host": {
            "proxy": {
                "id": "0"
            },
            "monitored_by": "server",
            "host": "test-audit-host",
            "name": "test-audit-host",
            "groups": [
                "Linux servers"
            ],
            "id": "10680",
            "active_available": "unknown",
            "interface": {
                "available": "unknown",
                "type": "agent",
                "port": "10050",
                "ip": "192.168.1.100"
            },
            "maintenance": {
                "status": "off"
            },
            "status": "enabled",
            "tags": {}
        }
    },
    "related": {
        "hosts": [
            "test-audit-host"
        ]
    },
    "event": {
        "dataset": "zabbix.host_status",
        "kind": "metric",
        "module": "zabbix"
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
| related.hosts | All hostnames or other host identifiers seen on your event. | keyword |
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
            "severity": "average",
            "eventid": "18",
            "acknowledged": false,
            "opdata": "",
            "source": "triggers",
            "tags": [
                {
                    "value": "os",
                    "tag": "class"
                },
                {
                    "value": "system",
                    "tag": "component"
                },
                {
                    "value": "availability",
                    "tag": "scope"
                },
                {
                    "value": "linux",
                    "tag": "target"
                }
            ],
            "urls": [],
            "r_eventid": "0",
            "severity_number": 3,
            "name": "Linux: Zabbix agent is not available (for 3m)",
            "suppressed": false,
            "acknowledges": [],
            "cause_eventid": "0",
            "objectid": "22391",
            "object": "trigger"
        }
    },
    "@timestamp": "2026-03-14T10:49:26.000Z",
    "event": {
        "severity": 3,
        "kind": "event",
        "module": "zabbix",
        "action": "problem_detected",
        "category": [
            "host"
        ],
        "type": [
            "error"
        ],
        "dataset": "zabbix.problem",
        "outcome": "failure"
    },
    "message": "Linux: Zabbix agent is not available (for 3m)"
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
    "zabbix": {
        "proxy": {
            "last_access": "2024-03-14T14:04:42.000Z",
            "address": "192.168.1.10",
            "port": "10051",
            "name": "proxy-dc1",
            "operating_mode": "active",
            "id": "10001",
            "state": "online",
            "version": "7.0.24",
            "compatibility": "current"
        }
    },
    "@timestamp": "2024-03-14T14:04:42.000Z",
    "event": {
        "dataset": "zabbix.proxy_health",
        "kind": "metric",
        "module": "zabbix"
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
    "zabbix": {
        "ha": {
            "lastaccess": "2026-03-14T12:24:46.000Z",
            "address": "localhost",
            "port": "10051",
            "name": "cmmq7d3zg00016zp837hqd44s",
            "nodeid": "cmmq7d3zg00016zp837hqd44s",
            "status": "active"
        }
    },
    "@timestamp": "2026-03-14T12:24:46.000Z",
    "event": {
        "dataset": "zabbix.ha_status",
        "kind": "metric",
        "module": "zabbix"
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
    "observer": {
        "product": "Zabbix Server",
        "vendor": "Zabbix"
    },
    "zabbix": {
        "audit": {
            "resource_cuid": "0",
            "resource_type_name": "host_group",
            "user_id": "1",
            "action_code": 1,
            "resource_type": 14,
            "resource_id": "2",
            "recordset_id": "cmmq8uzaj00020wp9uuaac9ue",
            "details": {
                "hostgroup.hosts[677].hostid": [
                    "add",
                    "10680"
                ],
                "hostgroup.hosts[677].hostgroupid": [
                    "add",
                    "677"
                ],
                "hostgroup.hosts[677]": [
                    "add"
                ]
            },
            "id": "cmmq8uzak00030wp9m31buxgh",
            "resource_name": "Linux servers"
        }
    },
    "@timestamp": "2026-03-14T11:30:24.000Z",
    "related": {
        "user": [
            "Admin"
        ],
        "ip": [
            "172.18.2.1"
        ]
    },
    "source": {
        "ip": "172.18.2.1"
    },
    "event": {
        "kind": "event",
        "module": "zabbix",
        "action": "update",
        "category": [
            "configuration"
        ],
        "type": [
            "change"
        ],
        "dataset": "zabbix.audit",
        "outcome": "success"
    },
    "message": "update host_group Linux servers",
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
        "type": [
            "info"
        ],
        "dataset": "zabbix.log",
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

