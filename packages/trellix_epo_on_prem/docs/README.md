# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization. It provides visibility into endpoint security operations and Data Loss Prevention (DLP) incidents across hybrid endpoint deployments.

The Trellix ePO On-Prem integration for Elastic collects DLP incident records using the **Web API** through the Elastic Agent CEL input and visualizes them in Kibana.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with Web API support enabled.

### How it works

This integration uses the Elastic Agent CEL input to poll the Trellix ePO Web API at configurable intervals. It retrieves DLP incident records from the `UDLP_EPD_Incidents` table and implements keyset-based pagination using `LastUpdateTimestamp` as the cursor. Each DLP incident is mapped to Elastic Common Schema (ECS) and ingested as an individual event for processing by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following type of data:

| Data stream | Description | Source |
|---|---|---|
| `dlp_incident` | Trellix ePO DLP incidents, including violation times, severity, status, evidence counts, classifications, matched rules, actions, and reviewer information. | `/remote/core.executeQuery` API |

### Supported use cases

Integrating Trellix ePO with Elastic provides centralized visibility into DLP policy violations and sensitive-data activity across managed endpoints. It supports incident investigation, policy effectiveness analysis, compliance reporting, and monitoring of classifications, matched rules, actions, severity, and reviewer activity in Kibana.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data through the Web API, you need the following:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with Web API support enabled.
2. **User account**: A Trellix ePO user account with:
   - Query permissions for the `UDLP_EPD_Incidents` table.
   - Sufficient role permissions to execute queries through the Web API.
3. **API credentials**: Username and password for HTTP Basic authentication.
4. **Server URL**: Base URL of the Trellix ePO server, for example `https://epo.example.com:8443`.
5. **Network access**: The Elastic Agent must have outbound HTTPS access to the Trellix ePO server.

For more information about configuring Web API access, refer to the [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html).

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Trellix ePO On-Prem**.
3. Select the **Trellix ePO On-Prem** integration from the search results.
4. Select **Add Trellix ePO On-Prem** to add the integration.
5. Enable and configure **Collect Trellix ePO DLP incident logs**.

   - Set **Trellix ePO URL** to the base URL of the Trellix ePO server, for example `https://epo.example.com:8443`.
   - Set **Username** and **Password** for an account with permission to query DLP incidents.
   - Set **Initial Interval** to the lookback period used for the first API request. The default is `168h`.
   - Set **Interval** to the polling frequency. The default is `5m`.
   - Set **Page Size** to the number of DLP incidents retrieved per API request. The default is `500`.
   - Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.

6. Select **Save and continue** to save the integration.

## Troubleshooting

- **No data collected**: Verify that the Trellix ePO URL is correct, the credentials are valid, and the Elastic Agent has network access to the ePO server. Confirm that the user account can query `UDLP_EPD_Incidents`.
- **Authentication failures**: Ensure the username and password are correct and that the user account is active and has sufficient Web API permissions.
- **Incomplete or missing fields**: Confirm that the ePO account can access all DLP incident fields requested by the CEL input.
- **Pagination issues**: If collection does not advance, verify that `LastUpdateTimestamp` is present in every returned incident and that records are ordered by this field.
- **Collection timeouts**: Increase **HTTP Client Timeout** or reduce **Page Size**.
- **SSL certificate errors**: If the ePO server uses a private certificate authority, configure the issuing CA certificate in the integration's SSL settings.
- **Missing historical incidents**: Increase **Initial Interval** so that the first request covers the required lookback period.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Prem**, and verify that the dashboard is listed.
3. Open the **[Logs Trellix ePO On-Prem] DLP Incident Overview** dashboard and verify that DLP incident data is populated.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Vendor documentation links

- [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html)
- [Trellix ePO Web API Query Language](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-cd01321d-b19b-5095-c79b-eabc7c0726bb.html)
- [Trellix ePO 5.10.0 Product Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-5.10.0-product-guide/page/UUID-3946078c-6e32-df76-6296-216ee05a2176.html)

### DLP incident

The `dlp_incident` data stream provides Trellix ePO On-Prem DLP incident records collected from the Web API.

#### DLP incident fields

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
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ActualAction | Numeric identifier of the action actually taken for the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ClassificationsToDisplay | Display label for the data classification associated with the DLP incident. | keyword |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ConnectivityState | Numeric connectivity-state code associated with the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.DlpAgentVersion | Version string of the DLP agent associated with the incident. | keyword |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.EvidenceCount | Number of evidence items associated with the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ExpectedAction | Numeric identifier of the action expected for the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.FailureReason | Numeric failure-reason code associated with the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.LastUpdateTimestamp | Date and time when the DLP incident record was last updated. | date |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.McAfeeAgentGuid | GUID identifying a McAfee agent associated with the DLP incident. | keyword |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.OriginalIncidentId | Numeric identifier of an original incident related to the current DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ReportingProduct | Numeric identifier of the product that reported the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ResolutionId | Numeric identifier of the DLP incident resolution. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.Severity | Numeric severity level associated with the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ShortMatchString | Short content excerpt associated with a DLP rule match. | keyword |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.StatusId | Numeric identifier of the DLP incident status. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.TotalContentSize | Total content size recorded for the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.TotalMatchCount | Total number of matches recorded for the DLP incident. | long |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ViolationCustomTime | Custom date and time representation associated with the DLP violation. | date |
| trellix_epo_on_prem.dlp_incident.UDLP_EPD_Incidents.ViolationLocalTime | Local date and time when the DLP violation occurred. | date |


### Example event

#### DLP incident

An example event for `dlp_incident` looks as following:

```json
{
    "@timestamp": "2026-01-15T10:00:05.000Z",
    "agent": {
        "ephemeral_id": "d6443151-0c82-49ca-9236-7b0bd710fefc",
        "id": "4e957d46-eb1f-4b06-8a17-a1270117278b",
        "name": "elastic-agent-94815",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.dlp_incident",
        "namespace": "17523",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "4e957d46-eb1f-4b06-8a17-a1270117278b",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "code": "1",
        "dataset": "trellix_epo_on_prem.dlp_incident",
        "id": "100006",
        "ingested": "2026-07-29T18:09:32Z",
        "kind": "alert",
        "original": "{\"UDLP_EPD_Incidents.ActualAction\":2,\"UDLP_EPD_Incidents.ClassificationsToDisplay\":\"Restricted Data\",\"UDLP_EPD_Incidents.ConnectivityState\":1,\"UDLP_EPD_Incidents.DlpAgentVersion\":\"11.10.0.456\",\"UDLP_EPD_Incidents.EvidenceCount\":1,\"UDLP_EPD_Incidents.ExpectedAction\":2,\"UDLP_EPD_Incidents.FailureReason\":0,\"UDLP_EPD_Incidents.IncidentId\":100006,\"UDLP_EPD_Incidents.IncidentType\":1,\"UDLP_EPD_Incidents.LastUpdateTimestamp\":\"2026-01-15T10:00:05Z\",\"UDLP_EPD_Incidents.McAfeeAgentGuid\":\"89a1d5c1-2b3e-4f67-8a9b-0c1d2e3f4a5b\",\"UDLP_EPD_Incidents.OriginalIncidentId\":100005,\"UDLP_EPD_Incidents.ReportingProduct\":1,\"UDLP_EPD_Incidents.ResolutionId\":0,\"UDLP_EPD_Incidents.Reviewer\":\"reviewer@example.com\",\"UDLP_EPD_Incidents.RuleSetToDisplay\":\"Endpoint DLP Rules\",\"UDLP_EPD_Incidents.RulesToDisplay\":\"Block restricted upload\",\"UDLP_EPD_Incidents.Severity\":2,\"UDLP_EPD_Incidents.ShortMatchString\":\"Sample restricted identifier: ***-**-5678\",\"UDLP_EPD_Incidents.StatusId\":1,\"UDLP_EPD_Incidents.TotalContentSize\":2048,\"UDLP_EPD_Incidents.TotalMatchCount\":1,\"UDLP_EPD_Incidents.ViolationCustomTime\":\"2026-01-15T15:30:05+05:30\",\"UDLP_EPD_Incidents.ViolationLocalTime\":\"2026-01-15T15:30:05+05:30\",\"UDLP_EPD_Incidents.ViolationTimezone\":\"Asia/Kolkata\",\"UDLP_EPD_Incidents.ViolationUTCTime\":\"2026-01-15T10:00:05Z\"}",
        "timezone": "Asia/Kolkata"
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "reviewer@example.com"
        ]
    },
    "rule": {
        "name": "Block restricted upload",
        "ruleset": "Endpoint DLP Rules"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-dlp_incident"
    ],
    "trellix_epo_on_prem": {
        "dlp_incident": {
            "UDLP_EPD_Incidents": {
                "ActualAction": 2,
                "ClassificationsToDisplay": "Restricted Data",
                "ConnectivityState": 1,
                "DlpAgentVersion": "11.10.0.456",
                "EvidenceCount": 1,
                "ExpectedAction": 2,
                "FailureReason": 0,
                "LastUpdateTimestamp": "2026-01-15T10:00:05.000Z",
                "McAfeeAgentGuid": "89a1d5c1-2b3e-4f67-8a9b-0c1d2e3f4a5b",
                "OriginalIncidentId": 100005,
                "ReportingProduct": 1,
                "ResolutionId": 0,
                "Severity": 2,
                "ShortMatchString": "Sample restricted identifier: ***-**-5678",
                "StatusId": 1,
                "TotalContentSize": 2048,
                "TotalMatchCount": 1,
                "ViolationCustomTime": "2026-01-15T10:00:05.000Z",
                "ViolationLocalTime": "2026-01-15T10:00:05.000Z"
            }
        }
    },
    "user": {
        "domain": "example.com",
        "email": "reviewer@example.com",
        "name": "reviewer"
    }
}
```

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following API:

- **DLP incident**: Collects DLP incident records through the **Trellix ePO executeQuery API** at `/remote/core.executeQuery`. Records are queried from `UDLP_EPD_Incidents` using keyset-based pagination with `LastUpdateTimestamp` as the cursor.
