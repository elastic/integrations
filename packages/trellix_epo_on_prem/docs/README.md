# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization.

The Trellix ePO On-Prem integration for Elastic collects endpoint compliance history and managed system (endpoint) records through the **Web API** using the Elastic Agent CEL input.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with Web API support enabled.

### How it works

This integration polls the Trellix ePO Web API at a configurable interval using the Elastic Agent CEL input.

The `compliance_history` data stream retrieves records from the `EpoComplianceHistory` query target. It uses `TheTimestamp` as an inclusive, ascending cursor for incremental collection. Overlapping records at the cursor boundary are deduplicated by the ingest pipeline.

The `system` data stream retrieves managed system (endpoint) records from the `EPOLeafNode` query target. It uses `LastUpdate` as an inclusive, ascending cursor. Because ePO returns `LastUpdate` with the server's UTC offset while interpreting a bare timestamp in a query as UTC, the cursor is adjusted by the configured **Timezone Offset** so records are not skipped or re-read on every poll. Overlapping records at the cursor boundary are deduplicated by the ingest pipeline.

Each response record is mapped to Elastic Common Schema (ECS) and indexed under the integration namespace.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following data:

| Data stream | Description | Source |
|---|---|---|
| `compliance_history` | Historical endpoint compliance snapshots, including evaluated, compliant, and noncompliant computer counts and compliance percentages. | `/remote/core.executeQuery` API |
| `system` | Managed system (endpoint) records, including node name, path, and type; agent GUID and version; managed and communication state; and tenant, tag, and sequence metadata. | `/remote/core.executeQuery` API |

### Supported use cases

The compliance history data stream supports:

- Tracking endpoint compliance posture over time.
- Comparing compliant and noncompliant computer counts.
- Monitoring changes in policy compliance percentages.
- Identifying gaps in compliance reporting tasks.
- Building compliance reports and alerts in Kibana.

The system data stream supports:

- Maintaining an inventory of endpoints managed by ePO.
- Monitoring agent version, communication health, and managed state.
- Reviewing System Tree placement and tag-based grouping of endpoints.
- Investigating unmanaged, stale, or misconfigured endpoints in Kibana.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data through the Web API, you need:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with Web API support enabled.
2. **User account**: A Trellix ePO user account with:
   - Permission to query the `EpoComplianceHistory` and/or `EPOLeafNode` targets.
   - Permission to execute queries through the Web API.
3. **API credentials**: Username and password for HTTP Basic authentication.
4. **Server URL**: Base URL of the Trellix ePO server, for example `https://epo.example.com:8443`.
5. **Network access**: The Elastic Agent must have outbound HTTPS access to the Trellix ePO server.
6. **Compliance history data**: To collect the `compliance_history` data stream, the relevant Trellix ePO compliance history reporting task must be configured and producing records.

For more information about configuring Web API access, refer to the [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html).

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without managing Elastic Agent infrastructure. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are supported in Elastic Serverless and Elastic Cloud environments.

### Agent-based installation

Elastic Agent must be installed. For more details, refer to the [Elastic Agent installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

### Configure

1. In Kibana, search for **Integrations**.
2. Search for **Trellix ePO On-Prem**.
3. Select the integration and choose **Add Trellix ePO On-Prem**.
4. Enable and configure the data streams you need:
   - For **compliance history** logs, enable **Collect Trellix ePO On-Prem logs** and configure the `compliance_history` data stream:
     - Set **Initial Interval** to the historical lookback used on the first request. The default is `24h`.
     - Set **Interval** to the polling frequency. The default is `24h`.
     - Set **Page Size** to the number of records retrieved per API request. The default is `500`.
   - For **system** logs, enable the `system` data stream:
     - Set **Initial Interval** to the historical lookback used on the first request. The default is `24h`.
     - Set **Interval** to the polling frequency. The default is `5m`.
     - Set **Timezone Offset** to the UTC offset of the ePO server, for example `+05:30`, so cursor timestamps are interpreted correctly.
     - Set **Page Size** to the number of records retrieved per API request. The default is `500`.
5. Common settings:
   - Set **Trellix ePO URL** to the base URL of the Trellix ePO server, for example `https://epo.example.com:8443`.
   - Set **Username** and **Password** for an account permitted to query the required targets.
   - Optionally configure the HTTP client timeout, proxy, and SSL settings.
6. Select **Save and continue**.

## Troubleshooting

- **No data collected**: Verify the ePO URL, credentials, network access, and permission to query `EpoComplianceHistory` and/or `EPOLeafNode`. For compliance history, confirm the compliance history reporting task has generated records.
- **Authentication failures**: Confirm the API account is active and has sufficient Web API permissions.
- **Table or target not found**: Use the local API targets `EpoComplianceHistory` and `EPOLeafNode`; do not use rollup targets unless a rollup database is configured.
- **Incomplete records**: Confirm the API account can select all fields requested by the CEL input.
- **Pagination issues (compliance history)**: Verify every returned record includes `TheTimestamp` and that ePO permits filtering and ordering on this field.
- **Pagination issues (system)**: Verify every returned record includes `LastUpdate` and that ePO permits filtering and ordering on this field. Confirm that **Timezone Offset** matches the ePO server's UTC offset — an incorrect offset can cause the cursor to skip past unread records or re-read the same window on every poll.
- **Collection timeouts**: Increase **HTTP Client Timeout** or reduce **Page Size**.
- **SSL certificate errors**: Configure the private certificate authority or appropriate SSL verification settings.
- **Missing historical records**: Increase **Initial Interval**.

For help with Elastic ingest tools, refer to [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In Kibana, search for **Dashboards**.
2. Search for **Trellix ePO On-Prem** and verify the dashboard information is populated.
3. Open the **[Logs Trellix ePO On-Prem] System** dashboard and verify that managed system data is populated.

#### Discover

1. In Kibana, open **Discover**.
2. Select the `logs-trellix_epo_on_prem.compliance_history-*` or `logs-trellix_epo_on_prem.system-*` data view.
3. Confirm that documents contain `@timestamp` and the expected data stream fields.

## Scaling

For more information on scaling architectures, refer to [Ingest architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures).

## Reference

### Vendor documentation links

- [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html)
- [Trellix ePO Web API Query Language](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-cd01321d-b19b-5095-c79b-eabc7c0726bb.html)
- [Trellix ePO 5.10.0 Product Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-5.10.0-product-guide/page/UUID-3946078c-6e32-df76-6296-216ee05a2176.html)

### Compliance history

The `compliance_history` data stream provides historical Trellix ePO endpoint compliance snapshots collected from the Web API.

#### Compliance history fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.chart_name | Name of the chart that generated the compliance history record. | keyword |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.count_compliant | Number of computers recorded as compliant. | long |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.count_computers | Total number of computers evaluated by the compliance query. | long |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.count_non_compliant | Number of computers recorded as noncompliant. | long |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.percent_compliant | Percentage of evaluated computers recorded as compliant. | double |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.percent_non_compliant | Percentage of evaluated computers recorded as noncompliant. | double |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.task_name | Name of the server task that generated the compliance history record. | keyword |
| trellix_epo_on_prem.compliance_history.epo_compliance_history.tenant_id | Tenant identifier associated with the compliance history record. | keyword |


### Example event

#### Compliance history

An example event for `compliance_history` looks as following:

```json
{
    "@timestamp": "2026-08-01T19:30:20.000Z",
    "agent": {
        "ephemeral_id": "84b7a05d-35f0-48ca-9b35-875e6eac5f2e",
        "id": "92824ee0-912e-4619-ab3f-aaed676cd6ee",
        "name": "elastic-agent-53476",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.compliance_history",
        "namespace": "82849",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "92824ee0-912e-4619-ab3f-aaed676cd6ee",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "trellix_epo_on_prem.compliance_history",
        "id": "4",
        "ingested": "2026-07-31T12:13:36Z",
        "kind": "state",
        "original": "{\"EpoComplianceHistory.AutoId\":4,\"EpoComplianceHistory.ChartName\":\"Trellix Agent Compliance Summary\",\"EpoComplianceHistory.CountCompliant\":4,\"EpoComplianceHistory.CountComputers\":5,\"EpoComplianceHistory.CountNonCompliant\":1,\"EpoComplianceHistory.PercentCompliant\":80,\"EpoComplianceHistory.PercentNonCompliant\":20,\"EpoComplianceHistory.TaskName\":\"Generate Records for Trellix Agent Compliance History Reporting\",\"EpoComplianceHistory.TenantId\":0,\"EpoComplianceHistory.TheTimestamp\":\"2026-08-02T01:00:20+05:30\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-compliance_history"
    ],
    "trellix_epo_on_prem": {
        "compliance_history": {
            "epo_compliance_history": {
                "chart_name": "Trellix Agent Compliance Summary",
                "count_compliant": 4,
                "count_computers": 5,
                "count_non_compliant": 1,
                "percent_compliant": 80,
                "percent_non_compliant": 20,
                "task_name": "Generate Records for Trellix Agent Compliance History Reporting",
                "tenant_id": "0"
            }
        }
    }
}
```

### System

The `system` data stream provides Trellix ePO On-Prem managed system (endpoint) records collected from the Web API.

#### System fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date and time when the event occurred. | date |
| data_stream.dataset | Dataset name associated with the data stream. | constant_keyword |
| data_stream.namespace | Namespace used to group related data streams. | constant_keyword |
| data_stream.type | Type of data stream, such as logs or metrics. | constant_keyword |
| event.dataset | Event Dataset. | constant_keyword |
| event.module | Module that generated the event. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| observer.product | Product name of the observer that generated the event. | constant_keyword |
| observer.vendor | Vendor name of the observer that generated the event. | constant_keyword |
| trellix_epo_on_prem.system.epo_leaf_node.agent_version | Version string of the managed Trellix agent installed on the system. | keyword |
| trellix_epo_on_prem.system.epo_leaf_node.excluded_tags | Comma-separated tags excluded from the managed system node.' | keyword |
| trellix_epo_on_prem.system.epo_leaf_node.last_comm_secure | Source code indicating whether the system’s last communication was secure. | keyword |
| trellix_epo_on_prem.system.epo_leaf_node.managed_state | Numeric managed-state code associated with the system node. | long |
| trellix_epo_on_prem.system.epo_leaf_node.node_path | Hierarchical path of the managed system node. | keyword |
| trellix_epo_on_prem.system.epo_leaf_node.parent_id | Numeric identifier of the parent object in the ePO system hierarchy. | long |
| trellix_epo_on_prem.system.epo_leaf_node.sequence_error_count | Number of sequence errors recorded for the managed system node. | long |
| trellix_epo_on_prem.system.epo_leaf_node.sequence_error_count_last_update | Date and time when the sequence-error count was last updated. | date |
| trellix_epo_on_prem.system.epo_leaf_node.server_key_hash | Base64-encoded cryptographic hash associated with the ePO server key. | keyword |
| trellix_epo_on_prem.system.epo_leaf_node.tenant_id | Numeric tenant identifier associated with the system node. | long |
| trellix_epo_on_prem.system.epo_leaf_node.transfer_site_lists_id | Boolean flag associated with transferring site-list identifiers for the system node. | boolean |
| trellix_epo_on_prem.system.epo_leaf_node.type | Numeric type code assigned to the managed system node. | long |


### Example event

#### System

An example event for `system` looks as following:

```json
{
    "@timestamp": "2026-08-03T07:01:28.000Z",
    "agent": {
        "ephemeral_id": "79a9dd7e-9312-4418-b4f9-d9ca380af37e",
        "id": "a55de640-a6c2-473f-8c11-f90c1fa451ff",
        "name": "elastic-agent-88753",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.system",
        "namespace": "18303",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "a55de640-a6c2-473f-8c11-f90c1fa451ff",
        "snapshot": false,
        "version": "8.19.0"
    },
    "entity": {
        "id": "65E387D4-DD78-406F-9765-2A3AAC1DF958",
        "name": "DESKTOP-B9TTHQE",
        "type": [
            "host"
        ]
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "trellix_epo_on_prem.system",
        "id": "3",
        "ingested": "2026-09-02T05:26:09Z",
        "kind": "asset",
        "original": "{\"EPOLeafNode.AgentGUID\":\"65E387D4-DD78-406F-9765-2A3AAC1DF958\",\"EPOLeafNode.AgentVersion\":\"5.8.6.185\",\"EPOLeafNode.AutoID\":3,\"EPOLeafNode.ExcludedTags\":\"\",\"EPOLeafNode.LastCommSecure\":\"1\",\"EPOLeafNode.LastUpdate\":\"2026-08-03T12:31:28+05:30\",\"EPOLeafNode.ManagedState\":1,\"EPOLeafNode.NodeName\":\"DESKTOP-B9TTHQE\",\"EPOLeafNode.NodePath\":null,\"EPOLeafNode.ParentID\":2,\"EPOLeafNode.SequenceErrorCount\":0,\"EPOLeafNode.SequenceErrorCountLastUpdate\":null,\"EPOLeafNode.ServerKeyHash\":\"zCpCbtDGJO5y9CB7kjIW+lY9lEPxhJhunES4S5Aayao=\",\"EPOLeafNode.Tags\":\"Escalated, Workstation\",\"EPOLeafNode.TenantId\":1,\"EPOLeafNode.TransferSiteListsID\":false,\"EPOLeafNode.Type\":1}",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "DESKTOP-B9TTHQE",
        "id": "65E387D4-DD78-406F-9765-2A3AAC1DF958",
        "name": "DESKTOP-B9TTHQE"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hash": [
            "zCpCbtDGJO5y9CB7kjIW+lY9lEPxhJhunES4S5Aayao="
        ],
        "hosts": [
            "65E387D4-DD78-406F-9765-2A3AAC1DF958",
            "DESKTOP-B9TTHQE"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-system",
        "Escalated, Workstation"
    ],
    "trellix_epo_on_prem": {
        "system": {
            "epo_leaf_node": {
                "agent_version": "5.8.6.185",
                "last_comm_secure": "1",
                "managed_state": 1,
                "parent_id": 2,
                "sequence_error_count": 0,
                "server_key_hash": "zCpCbtDGJO5y9CB7kjIW+lY9lEPxhJhunES4S5Aayao=",
                "tenant_id": 1,
                "transfer_site_lists_id": false,
                "type": 1
            }
        }
    }
}
```

### Inputs used

This integration uses the following input:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

Both data streams call `/remote/core.executeQuery`:

- The `compliance_history` data stream uses target `EpoComplianceHistory`. It requests timestamp-ordered pages and uses `TheTimestamp` as the incremental cursor.
- The `system` data stream uses target `EPOLeafNode`. It requests `LastUpdate`-ordered pages and uses `LastUpdate` (adjusted by the configured timezone offset) as the incremental cursor.
