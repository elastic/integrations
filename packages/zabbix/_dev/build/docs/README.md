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

{{event "server_health"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "server_health"}}

### Host Status

The `host_status` data stream collects host inventory and availability information, including host groups, maintenance windows, and agent availability.

{{event "host_status"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "host_status"}}

### Problem

The `problem` data stream collects active problems and trigger events from Zabbix, including severity, acknowledgment status, and suppression state.

{{event "problem"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "problem"}}

### Proxy Health

The `proxy_health` data stream collects status and performance metrics for the Zabbix proxy fleet, including last seen time, host counts, and data queue lengths.

{{event "proxy_health"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "proxy_health"}}

### HA Status

The `ha_status` data stream collects high-availability cluster node status, including node roles, last access times, and failover readiness.

{{event "ha_status"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "ha_status"}}

### Audit

The `audit` data stream collects audit log entries from Zabbix, recording user actions such as configuration changes, login events, and API calls.

{{event "audit"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "audit"}}

### Log

The `log` data stream parses Zabbix server log files, capturing startup messages, error conditions, slow queries, and other operational events.

{{event "log"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "log"}}
