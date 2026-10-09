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


### configure

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

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following API:

* Incident List (endpoint: `/appapi/incident/{company_id}/list/`)
* Incident Details (endpoint: `/appapi/incident/{company_id}/details/{incident_id}`)

#### Data retention

The data streams below collect a full snapshot of IRONSCALES incidents on every polling interval, so their backing indices hold one copy of each record per interval.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-ironscales.incident-*` | `logs-ironscales.incident-default_policy`: roll over after 15d, delete 15d after rollover | delete 30d after rollover |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies. The data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead. It also works per backing index: Elasticsearch [rolls the write index over automatically](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/data-stream-lifecycle-settings#cluster-lifecycle-default-rollover) on age, size, or document count, and [deletes a backing index once the retention has passed since it rolled over](https://www.elastic.co/docs/manage-data/lifecycle/data-stream#data-streams-lifecycle-how-it-works). A document therefore stays for the retention plus up to one rollover interval. The rollover age is derived from the retention and is an implementation detail that Elasticsearch may change. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management → Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-ironscales.incident-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.
