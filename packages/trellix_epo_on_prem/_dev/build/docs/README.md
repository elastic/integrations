# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization.

The Trellix ePO On-Prem integration for Elastic collects endpoint compliance history records through the **Web API** using the Elastic Agent CEL input.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with Web API support enabled.

### How it works

This integration polls the Trellix ePO Web API at a configurable interval and retrieves records from the `EpoComplianceHistory` query target. It uses `TheTimestamp` as an inclusive, ascending cursor for incremental collection. Overlapping records at the cursor boundary are deduplicated by the ingest pipeline.

Each response record is mapped to Elastic Common Schema (ECS) and indexed as a compliance state document. Compliance counts and percentages remain available under the integration namespace.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following data:

| Data stream | Description | Source |
|---|---|---|
| `compliance_history` | Historical endpoint compliance snapshots, including evaluated, compliant, and noncompliant computer counts and compliance percentages. | `/remote/core.executeQuery` API |

### Supported use cases

The compliance history data stream supports:

- Tracking endpoint compliance posture over time.
- Comparing compliant and noncompliant computer counts.
- Monitoring changes in policy compliance percentages.
- Identifying gaps in compliance reporting tasks.
- Building compliance reports and alerts in Kibana.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect compliance history through the Web API, you need:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with Web API support enabled.
2. **User account**: A Trellix ePO user account with:
   - Permission to query the `EpoComplianceHistory` target.
   - Permission to execute queries through the Web API.
3. **API credentials**: Username and password for HTTP Basic authentication.
4. **Server URL**: Base URL of the Trellix ePO server, for example `https://epo.example.com:8443`.
5. **Network access**: The Elastic Agent must have outbound HTTPS access to the Trellix ePO server.
6. **Compliance history data**: The relevant Trellix ePO compliance history reporting task must be configured and producing records.

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
4. Enable **Collect Trellix ePO compliance history logs**.
5. Configure the integration:
   - Set **Trellix ePO URL** to the base URL of the Trellix ePO server, for example `https://epo.example.com:8443`.
   - Set **Username** and **Password** for an account permitted to query compliance history.
   - Set **Initial Interval** to the historical lookback used on the first request. The default is `168h`.
   - Set **Interval** to the polling frequency. The default is `5m`.
   - Set **Page Size** to the number of records retrieved per API request. The default is `500`.
   - Optionally configure the HTTP client timeout, proxy, and SSL settings.
6. Select **Save and continue**.

## Troubleshooting

- **No data collected**: Verify the ePO URL, credentials, network access, and permission to query `EpoComplianceHistory`. Confirm the compliance history reporting task has generated records.
- **Authentication failures**: Confirm the API account is active and has sufficient Web API permissions.
- **Table or target not found**: Use the local API target `EpoComplianceHistory`; do not use the rollup target unless a rollup database is configured.
- **Incomplete records**: Confirm the API account can select all fields requested by the CEL input.
- **Pagination issues**: Verify every returned record includes `TheTimestamp` and that ePO permits filtering and ordering on this field.
- **Collection timeouts**: Increase **HTTP Client Timeout** or reduce **Page Size**.
- **SSL certificate errors**: Configure the private certificate authority or appropriate SSL verification settings.
- **Missing historical records**: Increase **Initial Interval**.

For help with Elastic ingest tools, refer to [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

After data collection starts:

1. In Kibana, open **Discover**.
2. Select the `logs-trellix_epo_on_prem.compliance_history-*` data view.
3. Confirm that compliance history state documents contain `@timestamp`, `event.id`, and the compliance count and percentage fields.

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

{{ fields "compliance_history" }}

### Example event

#### Compliance history

{{ event "compliance_history" }}

### Inputs used

This integration uses the following input:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

The `compliance_history` data stream calls `/remote/core.executeQuery` with target `EpoComplianceHistory`. It requests timestamp-ordered pages and uses `TheTimestamp` as the incremental cursor.
