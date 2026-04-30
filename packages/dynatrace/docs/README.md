# Dynatrace

The [Dynatrace](https://www.dynatrace.com/) integration collects observability and audit-related data from **Dynatrace SaaS** and **Dynatrace Managed** into Elasticsearch using the Elastic Agent [CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html). Use it to centralize problems (alerts), audit actions, cluster inventory, license usage, and related signals alongside the rest of your Elastic data.

:::{note}
This package is **community-supported** and ships as a **technical preview**: each data stream sets `release: experimental`, which surfaces as the technical preview badge in the Elastic Integrations UI. It is not authored or endorsed by Dynatrace as an official Elastic integration. The icon uses Dynatrace brand artwork for recognition.
:::

## Overview

Two Fleet policy templates are available:

- **Dynatrace SaaS** — single-tenant Environment API access (`problems`, `audit_logs`, `cluster_version`).
- **Dynatrace Managed** — Cluster API v2 for fleet and licensing data, plus per-tenant Problems API via `/e/<environmentId>/...` (`activegates`, `license_usage`, `environments`, `tenant_problems`).

### How it works

On each interval the CEL program issues HTTPS GET requests to Dynatrace REST endpoints with `Authorization: Api-Token <token>`. Paginated endpoints use Dynatrace `nextPageKey` cursors; state is persisted per data stream so later runs advance from the last watermark. For **tenant problems**, the collector refreshes the environments list, caps optional batching with **Max tenants per cycle**, and maintains separate cursors per tenant.

### Compatibility

- **Dynatrace SaaS** — Environment API v1/v2 as used by the implemented paths (problems v2, audit logs v2, cluster version v1).
- **Dynatrace Managed** — Cluster API v2 (`/api/cluster/v2/...`) and per-tenant Environment API v2 under `/e/<environmentId>/api/v2/...`.

API references:

- [Problems v2](https://docs.dynatrace.com/docs/dynatrace-api/environment-api/problems-v2)
- [Audit logs](https://docs.dynatrace.com/managed/dynatrace-api/environment-api/audit-logs/get-log)
- [Cluster version](https://docs.dynatrace.com/docs/dynatrace-api/environment-api/cluster-information)
- [ActiveGates](https://docs.dynatrace.com/managed/dynatrace-api/cluster-api/cluster-api-v2/activegate/get-activegates)
- [Cluster license usage](https://docs.dynatrace.com/managed/dynatrace-api/cluster-api/cluster-api-v2/cluster-license/get-cluster-license-usage)
- [List managed environments](https://docs.dynatrace.com/managed/dynatrace-api/cluster-api/cluster-api-v2/environments/list-managed-environments)

## Data streams

**Dynatrace SaaS**

| Dataset | Description |
| --------| ----------- |
| `problems` | Problems from the Problems v2 API (`/api/v2/problems`). |
| `audit_logs` | Audit log entries from `/api/v2/auditlogs`. |
| `cluster_version` | Cluster version snapshot from `/api/v1/config/clusterversion`. |

**Dynatrace Managed**

| Dataset | Description |
| --------| ----------- |
| `activegates` | ActiveGate rows from `/api/cluster/v2/activeGates`. |
| `license_usage` | Cluster license and usage from `/api/cluster/v2/clusterLicense` (**metrics** data stream). |
| `environments` | Tenant list from `/api/cluster/v2/environments` using `pageSize`, optional `filter`, `includeConsumptionInfo` / `includeStorageInfo` (when not paginating with `nextPageKey`), and `nextPageKey` pagination. |
| `tenant_problems` | Problems per tenant from `/e/<environmentId>/api/v2/problems`. |

## Requirements

- Elastic Agent enrolled in Fleet (or agentless where supported). See the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).
- Network path from the agent (or agentless runner) to your Dynatrace SaaS URL or Managed cluster URL.
- **SaaS API token** — scopes such as `problems.read`, `auditLogs.read`, and `DataExport` as documented in the integration UI.
- **Managed cluster API token** — Cluster API access with **Service Provider API** (`ServiceProviderAPI`) for cluster endpoints.
- **Managed tenant problems (optional)** — A separate tenant token with `problems.read` and `DataExport` may be used; otherwise the cluster token is reused and must allow tenant problem reads.

## Agentless-enabled integration

Agentless integrations collect data without managing Elastic Agent on your hosts where the platform supports it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Beta or preview limitations may apply; see Elastic documentation for current support.

## Setup

### Dynatrace

1. Sign in to Dynatrace SaaS or the Managed cluster as an administrator.
2. Create an API token with the scopes or permissions required for the policy template you use (see **Requirements**).
3. Copy the **environment base URL** (SaaS) or **cluster base URL** (Managed) with no trailing API path.

### Enable the integration in Elastic

1. In Kibana open **Management → Integrations**.
2. Search for **Dynatrace** and choose **Add Dynatrace**.
3. Select **Dynatrace SaaS** or **Dynatrace Managed** and attach the integration to an agent policy.
4. Enter **Environment URL** + **API Token** (SaaS), or **Cluster URL**, **Cluster API Token**, and optional **Tenant API Token** (Managed).
5. Enable individual data streams and tune **Interval**, **Initial lookback**, **Page size**, and (Managed tenant problems) **Max tenants per cycle** as needed.
6. Save the policy and confirm data appears in Discover (`event.module: dynatrace`).

### Validation

Use `data_stream.dataset` filters, for example:

- `dynatrace.problems`, `dynatrace.audit_logs`, `dynatrace.cluster_version`
- `dynatrace.activegates`, `dynatrace.license_usage`, `dynatrace.environments`, `dynatrace.tenant_problems`

License usage indexes follow the metrics naming pattern `metrics-dynatrace.license_usage-*`; other datasets use `logs-dynatrace.*-*`.

## Troubleshooting

For Fleet and agent issues see [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

- **401 / 403** — Token missing required scopes (`problems.read`, `auditLogs.read`, `DataExport`, or `ServiceProviderAPI` for cluster calls).
- **No tenant problems** — Verify cluster URL, cluster token permissions, and that environments list requests succeed (`dynatrace.environments`).
- **429 Too Many Requests** — Reduce page sizes or increase the collection interval; the CEL programs stop advancing for that interval on HTTP 429 and retry later.
- **Resetting cursors** — Removing and re-adding the integration (or policy) resets persisted CEL state; use when you intentionally need a full replay.

## Performance and scaling

See [Ingest architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) for Elastic-side guidance.

- Pagination is drained up to **Maximum pages per interval** per data stream where configured.
- Larger **Page size** improves throughput until Dynatrace rate limits apply.
- **Tenant problems** uses an internal work list; **Max tenants per cycle** spreads large tenant counts across intervals.

## Logs and metrics reference

### problems

This is the `problems` dataset (SaaS).

#### Example

An example event for `problems` looks as following:

```json
{
    "@timestamp": "2024-04-15T19:47:21.565Z",
    "agent": {
        "ephemeral_id": "486828a1-d4df-4297-b973-862f20836d5f",
        "id": "4f82ead5-acc7-43ef-8529-68b1286c0acb",
        "name": "elastic-agent-001",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "dynatrace.problems",
        "namespace": "default",
        "type": "logs"
    },
    "dynatrace": {
        "problems": {
            "affected_entities": [
                {
                    "entityId": {
                        "id": "HOST-0000000000000001",
                        "type": "HOST"
                    },
                    "name": "web-01"
                }
            ],
            "display_id": "P-2403-12345",
            "impact_level": "INFRASTRUCTURE",
            "problem_id": "9032023145246800162_1712430000000V2",
            "root_cause_entity": {
                "entityId": {
                    "id": "PROCESS_GROUP_INSTANCE-AAAAAAAAAAAAAAAA",
                    "type": "PROCESS_GROUP_INSTANCE"
                },
                "name": "java"
            },
            "severity_level": "ERROR",
            "start_time": 1712430000000,
            "status": "OPEN",
            "title": "High CPU saturation"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "network",
            "host"
        ],
        "dataset": "dynatrace.problems",
        "id": "9032023145246800162_1712430000000V2",
        "kind": "alert",
        "module": "dynatrace",
        "severity": "ERROR",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "forwarded",
        "dynatrace-problems"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dynatrace.problems.affected_entities | Entities affected by the problem. | flattened |
| dynatrace.problems.display_id | Human-readable problem identifier displayed in the Dynatrace UI. | keyword |
| dynatrace.problems.end_time | End time of the problem (UTC milliseconds). Only set for closed problems. | date |
| dynatrace.problems.entity_tags | Tags applied to entities involved in the problem. | flattened |
| dynatrace.problems.evidence_details | Evidence collected by Davis AI to support the problem. | flattened |
| dynatrace.problems.impact_level | Impact level reported by Dynatrace (e.g. `INFRASTRUCTURE`, `SERVICE`, `APPLICATION`). | keyword |
| dynatrace.problems.impacted_entities | Entities impacted by the problem. | flattened |
| dynatrace.problems.linked_problem_info | Information about linked problems. | flattened |
| dynatrace.problems.management_zones | Management zones associated with the problem. | flattened |
| dynatrace.problems.problem_id | Unique problem identifier. | keyword |
| dynatrace.problems.recent_comments | Recent comments made on the problem. | flattened |
| dynatrace.problems.root_cause_entity | Root cause entity reported by Davis AI. | flattened |
| dynatrace.problems.severity_level | Severity level reported by Dynatrace (e.g. `AVAILABILITY`, `ERROR`, `PERFORMANCE`). | keyword |
| dynatrace.problems.start_time | Start time of the problem (UTC milliseconds). | date |
| dynatrace.problems.status | Current status of the problem (`OPEN`, `CLOSED`). | keyword |
| dynatrace.problems.title | Title of the problem. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| tags | Tags applied by the agent. | keyword |


### audit_logs

This is the `audit_logs` dataset (SaaS).

#### Example

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2024-04-15T05:01:28.445Z",
    "agent": {
        "ephemeral_id": "486828a1-d4df-4297-b973-862f20836d5f",
        "id": "4f82ead5-acc7-43ef-8529-68b1286c0acb",
        "name": "elastic-agent-001",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "dynatrace.audit_logs",
        "namespace": "default",
        "type": "logs"
    },
    "dynatrace": {
        "audit_logs": {
            "category": "CONFIG",
            "entity_id": "MOBILE_RUM:MOBILE_APPLICATION-752C223D59734CD2",
            "environment_id": "prod-env-13",
            "event_type": "UPDATE",
            "log_id": "197425568800060000",
            "patch": [
                {
                    "oldValue": 20000,
                    "op": "replace",
                    "path": "/refreshTimeIntervalMillis",
                    "value": 30000
                }
            ],
            "success": true,
            "user_origin": "webui (192.168.0.2)",
            "user_type": "USER_NAME"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "UPDATE",
        "category": [
            "configuration"
        ],
        "dataset": "dynatrace.audit_logs",
        "kind": "event",
        "module": "dynatrace",
        "outcome": "success",
        "type": [
            "change"
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "forwarded",
        "dynatrace-audit-logs"
    ],
    "user": {
        "id": "test.user@company.com",
        "name": "test.user@company.com"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dynatrace.audit_logs.category | Category of the recorded operation (`CONFIG`, `WEB_UI`, `TOKEN`, `ACTIVEGATE_TOKEN`, etc.). | keyword |
| dynatrace.audit_logs.entity_id | ID of an entity from the operation's category (e.g. config ID, token ID). | keyword |
| dynatrace.audit_logs.environment_id | Dynatrace environment where the operation occurred. | keyword |
| dynatrace.audit_logs.event_type | Type of the recorded operation (`CREATE`, `UPDATE`, `DELETE`, `LOGIN`, `LOGOUT`, etc.). | keyword |
| dynatrace.audit_logs.log_id | ID of the audit log entry. | keyword |
| dynatrace.audit_logs.patch | JSON patch describing the change (RFC 6902-like, with `oldValue`). | flattened |
| dynatrace.audit_logs.settings.key | Key of the affected setting object. | keyword |
| dynatrace.audit_logs.settings.object_id | ID of the affected object. | keyword |
| dynatrace.audit_logs.settings.object_summary | Human-readable summary of the change. | text |
| dynatrace.audit_logs.settings.schema_id | The schema ID for entries of category `CONFIG`. | keyword |
| dynatrace.audit_logs.settings.scope_id | The persistence scope for `CONFIG` entries. | keyword |
| dynatrace.audit_logs.settings.scope_name | Display name of the scope for `CONFIG` entries. | keyword |
| dynatrace.audit_logs.success | Whether the recorded operation was successful. | boolean |
| dynatrace.audit_logs.user_origin | Origin and IP address of the user who performed the operation. | keyword |
| dynatrace.audit_logs.user_type | Authentication type of the user (`USER_NAME`, `TOKEN_HASH`, `SERVICE_NAME`, `PUBLIC_TOKEN_IDENTIFIER`). | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| tags | Tags applied by the agent. | keyword |


### cluster_version

This is the `cluster_version` dataset (SaaS).

#### Example

An example event for `cluster_version` looks as following:

```json
{
    "@timestamp": "2024-04-15T19:47:21.565Z",
    "agent": {
        "ephemeral_id": "486828a1-d4df-4297-b973-862f20836d5f",
        "id": "4f82ead5-acc7-43ef-8529-68b1286c0acb",
        "name": "elastic-agent-001",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "dynatrace.cluster_version",
        "namespace": "default",
        "type": "logs"
    },
    "dynatrace": {
        "cluster_version": {
            "version": "1.247.0.20220707-181710"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "dynatrace.cluster_version",
        "kind": "state",
        "module": "dynatrace"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "forwarded",
        "dynatrace-cluster-version"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dynatrace.cluster_version.version | The current version of the Dynatrace cluster. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| tags | Tags applied by the agent. | keyword |


### activegates

This is the `activegates` dataset (Managed).

#### Example

An example event for `activegates` looks as following:

```json
{
    "@timestamp": "2024-04-15T19:47:21.565Z",
    "agent": {
        "ephemeral_id": "486828a1-d4df-4297-b973-862f20836d5f",
        "id": "4f82ead5-acc7-43ef-8529-68b1286c0acb",
        "name": "elastic-agent-001",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "dynatrace.activegates",
        "namespace": "default",
        "type": "logs"
    },
    "dynatrace": {
        "activegates": {
            "auto_update_effective": "ENABLED",
            "auto_update_setting": "ENABLED",
            "auto_update_status": "UP2DATE",
            "connected_hosts": 3,
            "containerized": false,
            "group": "default",
            "hostname": "abc.efg-hij.org",
            "id": "0xe12f4b4e",
            "load_balancer_addresses": [
                "172.18.149.164"
            ],
            "modules": [
                {
                    "attributes": {},
                    "enabled": true,
                    "misconfigured": false,
                    "type": "AWS",
                    "version": null
                }
            ],
            "network_addresses": [
                "abc.efg-hij.org",
                "172.18.149.164"
            ],
            "network_zone": "ab-cde-xyz",
            "os_architecture": "X86",
            "os_bitness": "64",
            "os_type": "LINUX",
            "type": "CLUSTER",
            "version": "1.247.0.20220707-181710"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "dynatrace.activegates",
        "kind": "state",
        "module": "dynatrace"
    },
    "host": {
        "id": "0xe12f4b4e",
        "ip": [
            "abc.efg-hij.org",
            "172.18.149.164"
        ],
        "name": "abc.efg-hij.org",
        "os": {
            "platform": "linux",
            "type": "linux"
        }
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "forwarded",
        "dynatrace-activegates"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dynatrace.activegates.auto_update_effective | Effective auto-update setting (`ENABLED`, `DISABLED`). | keyword |
| dynatrace.activegates.auto_update_setting | Auto-update setting (`ENABLED`, `DISABLED`, `INHERITED`). | keyword |
| dynatrace.activegates.auto_update_status | Auto-update status (`UP2DATE`, `OUTDATED`, `UPDATE_PENDING`, etc.). | keyword |
| dynatrace.activegates.connected_hosts | Number of hosts currently connected to the ActiveGate. | long |
| dynatrace.activegates.containerized | Whether the ActiveGate is deployed in a container. | boolean |
| dynatrace.activegates.environments | Environment IDs the ActiveGate can connect to. | keyword |
| dynatrace.activegates.fips_mode | Whether the ActiveGate runs in FIPS-compliant mode. | boolean |
| dynatrace.activegates.group | ActiveGate group. | keyword |
| dynatrace.activegates.hostname | Hostname of the ActiveGate. | keyword |
| dynatrace.activegates.id | ID of the ActiveGate (hexadecimal node ID). | keyword |
| dynatrace.activegates.load_balancer_addresses | Load Balancer addresses of the ActiveGate. | keyword |
| dynatrace.activegates.main_environment | Main environment ID for multi-environment ActiveGates. | keyword |
| dynatrace.activegates.modules | Modules of the ActiveGate (type, enabled, version, attributes). | flattened |
| dynatrace.activegates.network_addresses | Network addresses of the ActiveGate. | keyword |
| dynatrace.activegates.network_zone | Network zone of the ActiveGate. | keyword |
| dynatrace.activegates.offline_since | Epoch milliseconds since the ActiveGate went offline; omitted when online (`offlineSince` is null in the API). | long |
| dynatrace.activegates.os_architecture | OS architecture (`X86`, `S390`, `ARM`, `PPCLE`). | keyword |
| dynatrace.activegates.os_bitness | OS bitness (e.g. `64`). | keyword |
| dynatrace.activegates.os_type | OS type (`LINUX`, `WINDOWS`). | keyword |
| dynatrace.activegates.tokens | Tokens registered against the ActiveGate. | flattened |
| dynatrace.activegates.type | ActiveGate type (`CLUSTER`, `ENVIRONMENT`, `ENVIRONMENT_MULTI`). | keyword |
| dynatrace.activegates.version | ActiveGate software version. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| tags | Tags applied by the agent. | keyword |


### license_usage

This is the `license_usage` dataset (Managed, **metrics**).

#### Example

An example event for `license_usage` looks as following:

```json
{
    "@timestamp": "2024-04-15T19:47:21.565Z",
    "agent": {
        "ephemeral_id": "486828a1-d4df-4297-b973-862f20836d5f",
        "id": "4f82ead5-acc7-43ef-8529-68b1286c0acb",
        "name": "elastic-agent-001",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "dynatrace.license_usage",
        "namespace": "default",
        "type": "metrics"
    },
    "dynatrace": {
        "license_usage": {
            "account_name": "Acme",
            "cluster_id": "cluster-1",
            "contact_email": "ops@acme.example",
            "ddu": {
                "quota": 100000,
                "remaining": 75000,
                "remaining_percent": 75,
                "status": "USING_QUOTA",
                "usage": 25000,
                "usage_percent": 25
            },
            "host_units": {
                "quota": 100,
                "remaining": 30,
                "remaining_percent": 30,
                "status": "USING_QUOTA",
                "usage": 70,
                "usage_percent": 70
            },
            "license_name": "Enterprise",
            "license_status": "ACTIVE",
            "license_type": "DPS",
            "product_version": "1.247.0"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "dynatrace.license_usage",
        "kind": "metric",
        "module": "dynatrace"
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "forwarded",
        "dynatrace-license-usage"
    ]
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset name. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| dynatrace.license_usage.account_name | License account name. | keyword |  |
| dynatrace.license_usage.cluster_id | Cluster ID. | keyword |  |
| dynatrace.license_usage.contact_email | Contact email address. | keyword |  |
| dynatrace.license_usage.ddu.overage | Overage usage details. | flattened |  |
| dynatrace.license_usage.ddu.quota | License quota. | long |  |
| dynatrace.license_usage.ddu.remaining | Remaining usage of quota. | double | gauge |
| dynatrace.license_usage.ddu.remaining_percent | Remaining usage of quota as percentage. | double | gauge |
| dynatrace.license_usage.ddu.status | Current license usage status. | keyword |  |
| dynatrace.license_usage.ddu.usage | Current usage of quota. | double | gauge |
| dynatrace.license_usage.ddu.usage_percent | Current usage of quota as percentage. | double | gauge |
| dynatrace.license_usage.dem.overage | Overage usage details. | flattened |  |
| dynatrace.license_usage.dem.quota | License quota. | long |  |
| dynatrace.license_usage.dem.remaining | Remaining usage of quota. | double | gauge |
| dynatrace.license_usage.dem.remaining_percent | Remaining usage of quota as percentage. | double | gauge |
| dynatrace.license_usage.dem.status | Current license usage status. | keyword |  |
| dynatrace.license_usage.dem.usage | Current usage of quota. | double | gauge |
| dynatrace.license_usage.dem.usage_percent | Current usage of quota as percentage. | double | gauge |
| dynatrace.license_usage.host_units.overage | Overage usage details. | flattened |  |
| dynatrace.license_usage.host_units.quota | License quota. | long |  |
| dynatrace.license_usage.host_units.remaining | Remaining usage of quota. | double | gauge |
| dynatrace.license_usage.host_units.remaining_percent | Remaining usage of quota as percentage. | double | gauge |
| dynatrace.license_usage.host_units.status | Current license usage status. | keyword |  |
| dynatrace.license_usage.host_units.usage | Current usage of quota. | double | gauge |
| dynatrace.license_usage.host_units.usage_percent | Current usage of quota as percentage. | double | gauge |
| dynatrace.license_usage.last_billing_time | Last time billing data was refreshed (parsed for time-range queries). | date |  |
| dynatrace.license_usage.license_expiration_time | License expiration time from the Dynatrace API (parsed for time-range queries). | date |  |
| dynatrace.license_usage.license_key | License key. | keyword |  |
| dynatrace.license_usage.license_name | License name. | keyword |  |
| dynatrace.license_usage.license_status | License status. | keyword |  |
| dynatrace.license_usage.license_type | License type. | keyword |  |
| dynatrace.license_usage.product_version | Current Dynatrace product version. | keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| input.type | Type of Filebeat input. | keyword |  |
| tags | Tags applied by the agent. | keyword |  |


### environments

This is the `environments` dataset (Managed).

#### Example

An example event for `environments` looks as following:

```json
{
    "@timestamp": "2024-04-15T19:47:21.565Z",
    "agent": {
        "ephemeral_id": "486828a1-d4df-4297-b973-862f20836d5f",
        "id": "4f82ead5-acc7-43ef-8529-68b1286c0acb",
        "name": "elastic-agent-001",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "dynatrace.environments",
        "namespace": "default",
        "type": "logs"
    },
    "dynatrace": {
        "environments": {
            "creation_date": "2021-02-09T11:03:17.732Z",
            "id": "be22c776-1414-00e0-a00a-00b0dcf56443321",
            "name": "AndroidApps",
            "state": "ENABLED",
            "tags": [],
            "trial": false
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "dynatrace.environments",
        "kind": "state",
        "module": "dynatrace"
    },
    "input": {
        "type": "cel"
    },
    "organization": {
        "id": "be22c776-1414-00e0-a00a-00b0dcf56443321",
        "name": "AndroidApps"
    },
    "tags": [
        "forwarded",
        "dynatrace-environments"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dynatrace.environments.creation_date | Creation date of the environment. | date |
| dynatrace.environments.id | Environment ID. | keyword |
| dynatrace.environments.name | Environment display name. | keyword |
| dynatrace.environments.quotas | Environment level consumption and quotas information. | flattened |
| dynatrace.environments.state | Whether the environment is `ENABLED` or `DISABLED`. | keyword |
| dynatrace.environments.storage | Environment level storage usage and limits. | flattened |
| dynatrace.environments.tags | Tags assigned to this environment. | keyword |
| dynatrace.environments.trial | Whether the environment is a trial environment. | boolean |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| tags | Tags applied by the agent. | keyword |


### tenant_problems

This is the `tenant_problems` dataset (Managed).

#### Example

An example event for `tenant_problems` looks as following:

```json
{
    "@timestamp": "2024-04-15T19:47:21.565Z",
    "agent": {
        "ephemeral_id": "486828a1-d4df-4297-b973-862f20836d5f",
        "id": "4f82ead5-acc7-43ef-8529-68b1286c0acb",
        "name": "elastic-agent-001",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "dynatrace.tenant_problems",
        "namespace": "default",
        "type": "logs"
    },
    "dynatrace": {
        "tenant_problems": {
            "display_id": "P-2403-12345",
            "impact_level": "INFRASTRUCTURE",
            "problem_id": "9032023145246800162_1712430000000V2",
            "severity_level": "ERROR",
            "start_time": 1712430000000,
            "status": "OPEN",
            "tenant_id": "prod-env-13",
            "tenant_name": "Production",
            "title": "High CPU saturation"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "dynatrace.tenant_problems",
        "id": "9032023145246800162_1712430000000V2",
        "kind": "alert",
        "module": "dynatrace",
        "severity": "ERROR",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "organization": {
        "id": "prod-env-13",
        "name": "Production"
    },
    "tags": [
        "forwarded",
        "dynatrace-tenant-problems"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dynatrace.tenant_problems.affected_entities | Entities affected by the problem. | flattened |
| dynatrace.tenant_problems.display_id | Human-readable problem identifier displayed in the Dynatrace UI. | keyword |
| dynatrace.tenant_problems.end_time | End time of the problem (UTC milliseconds). Only set for closed problems. | date |
| dynatrace.tenant_problems.impact_level | Impact level reported by Dynatrace. | keyword |
| dynatrace.tenant_problems.impacted_entities | Entities impacted by the problem. | flattened |
| dynatrace.tenant_problems.management_zones | Management zones associated with the problem. | flattened |
| dynatrace.tenant_problems.problem_id | Unique problem identifier. | keyword |
| dynatrace.tenant_problems.root_cause_entity | Root cause entity reported by Davis AI. | flattened |
| dynatrace.tenant_problems.severity_level | Severity level reported by Dynatrace. | keyword |
| dynatrace.tenant_problems.start_time | Start time of the problem (UTC milliseconds). | date |
| dynatrace.tenant_problems.status | Current status of the problem (`OPEN`, `CLOSED`). | keyword |
| dynatrace.tenant_problems.tenant_id | ID of the Dynatrace environment (tenant) that produced the problem. | keyword |
| dynatrace.tenant_problems.tenant_name | Display name of the Dynatrace environment (tenant), if known. | keyword |
| dynatrace.tenant_problems.title | Title of the problem. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| tags | Tags applied by the agent. | keyword |


## Reference

- [ECS field reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)
- [Filebeat CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html)
