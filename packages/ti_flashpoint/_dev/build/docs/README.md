# Flashpoint Integration for Elastic

## Overview

[Flashpoint](https://flashpoint.io/) is a comprehensive threat intelligence platform that delivers actionable insights from dark web, deep web, and technical sources. It combines human-curated intelligence with automated collection to help organizations identify emerging threats, monitor adversary activity, and assess cyber risk with enriched context.

The Flashpoint integration for Elastic collects vulnerabilities from the **Flashpoint Ignite API** and visualizes them in Kibana.

### Compatibility

The Flashpoint integration is compatible with Ignite API version **1.2**.

### How it works

This integration periodically queries the Flashpoint Ignite API to retrieve logs.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Vulnerabilities`: Collects `vulnerability` logs from the Flashpoint Ignite API (endpoint: `/vulnerability-intelligence/v1/vulnerabilities`),

### Supported use cases

Integrating Flashpoint Vulnerabilities with Elastic SIEM provides centralized visibility into vulnerability risk and exposure.

Dashboards display `Total Vulnerabilities` and include tables for `Top Classifications`,` Vulnerability Names`, `Products`, and `Vendors`. Pie charts show `vulnerabilities by Ransomware Score`, `Severity`, and `Status`, while a line chart tracks `Vulnerabilities by Severity over Time`.

A control panel allows filtering by `Status`, `Severity` and `Ransomware Score`. A saved searches for `CVSS v2`, `v3`, and `v4` details support deeper vulnerability analysis and prioritization.

## What do I need to use this integration?

### From Flashpoint

To collect data through the Flashpoint Ignite API, you need to provide an **API Token**. Authentication is handled using the **API Token**, which serves as the required credential.

#### Retrieve an API Token:

1. Log in to the **Flashpoint** Instance.
2. Click on your profile icon in the top-right corner and select **Manage API Tokens**.
3. Click **Generate Token**.
4. Enter a name for the API token and click **Generate Token**.
5. Copy and securely store the generated API token for use in the integration configuration.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.


### configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Flashpoint**.
3. Select the **Flashpoint** integration from the search results.
4. Select **Add Flashpoint** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs from Flashpoint API**, you'll need to:

        - Configure **API Token**.
        - Adjust the integration configuration parameters if required, including the **Initial Interval**, **Interval**, **Page Size** etc. to enable data collection.

6. Select **Save and continue** to save the integration.

## Troubleshooting

1. If vulnerability data collection is slow or fails with `context deadline exceeded`, reduce the `Page Size` and increase the `HTTP Client Timeout`.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Flashpoint**, and verify the dashboard information is populated.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Vulnerability

{{fields "vulnerability"}}

### Example event

#### Vulnerability

{{event "vulnerability"}}


### Inputs used

These input is used in the integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)


### API usage

This integration dataset uses the following API:

* List Vulberabilities (endpoint: `/vulnerability-intelligence/v1/vulnerabilities`)
