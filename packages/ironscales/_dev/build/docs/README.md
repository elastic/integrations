# IRONSCALES Integration for Elastic

## Overview

[IRONSCALES](https://ironscales.com/) is an advanced anti-phishing detection and response platform that combines human intelligence with machine learning to protect organizations from evolving email threats. It prevents, detects, and remediates phishing attacks directly at the mailbox level using a multi-layered and automated approach.

The IRONSCALES integration for Elastic allows you to collect email security event data using the IRONSCALES API, then visualize the data in Kibana.

### Compatibility

The IRONSCALES integration is compatible with product version **25.10.1**.

### How it works

This integration periodically queries the IRONSCALES API to retrieve logs.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Incident`: collect incident records from the Incident List(endpoint: `/appapi/incident/{company_id}/list/`) and Incident Details(endpoint: `/appapi/incident/{company_id}/details/{incident_id}`) endpoints, with detailed incident data enriched to provide additional context.

### Supported use cases

Integrating IRONSCALES with Elastic SIEM provides centralized visibility into email security incidents and their underlying context. Kibana dashboards track incident classifications and types, with key metrics highlighting the total affected mailboxes and total incidents for a quick overview of the threat landscape.

Pie and bar charts visualize incident classifications, sender reputation, and incident types, helping analysts identify emerging phishing patterns and attack sources. Tables display the top recipient emails, recipient names, assignees, sender emails, and sender names to support in-depth investigation.

Saved searches include detailed incident reports and attachment information to enrich investigations with essential context. These insights enable analysts to monitor email threat activity, identify high-risk users, and accelerate phishing detection and response workflows.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From IRONSCALES

To collect data through the IRONSCALES APIs, you need to provide an **API Token** and **Company ID**. Authentication is handled using the **API Token**, which serves as the required credential.

#### Retrieve an API Token and Company ID:

1. Log in to the **IRONSCALES** instance.
2. Navigate to **Settings > Account Settings > General & Security**.
3. Locate the **APP API Token** and **Company ID** values in this section.
4. Copy both values and store them securely for use in the Integration configuration.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.


## configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **IRONSCALES**.
3. Select the **IRONSCALES** integration from the search results.
4. Select **Add IRONSCALES** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs from IRONSCALES API**, you'll need to:

        - Configure **URL**, **API Token** and **Company ID**.
        - Adjust the integration configuration parameters if required, including the Interval, Page Size etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **IRONSCALES**, and verify the dashboard information is populated.

#### Transform healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **ironscales**.
4. Transform from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Incident

{{fields "incident"}}

### Example event

#### Incident

{{event "incident"}}

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following API:

* Incident List (endpoint: `/appapi/incident/{company_id}/list/`)
* Incident Details (endpoint: `/appapi/incident/{company_id}/details/{incident_id}`)

#### ILM Policy

To facilitate incident data, source data stream-backed indices `.ds-logs-ironscales.incident-*` is allowed to contain duplicates from each polling interval. ILM policy `logs-ironscales.incident-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
