# JupiterOne Integration for Elastic

## Overview

[JupiterOne](https://www.jupiterone.com/) provides continuous monitoring to surface problems impacting critical assets and infrastructure. Secure your attack surface with continuous asset discovery and attack path analysis. Reduce risk, triage incidents, and prioritize vulnerability findings with greater clarity and 85% fewer SecOps resources.

The JupiterOne integration for Elastic allows you to collect logs using [JupiterOne API](https://docs.jupiterone.io/reference), then visualise the data in Kibana.

### Compatibility

The JupiterOne integration uses the GraphQL endpoint to collect assests.

### How it works

This integration periodically queries the JupiterOne API to retrieve details for assets of class alert, vulnerability, and finding.

## What data does this integration collect?

This integration collects assets of the following classes:

- [`Alert`](https://docs.jupiterone.io/data-model/schemas/Alert).
- [`Vulnerability`](https://docs.jupiterone.io/data-model/schemas/Vulnerability).
- [`Finding`](https://docs.jupiterone.io/data-model/schemas/Finding).

### Supported use cases

Integrating JupiterOne Alert, Finding, and Vulnerability data with SIEM dashboards delivers unified visibility into risk signals, asset classifications, and security posture across the environment. Dashboards summarize asset class, type, and source distributions, highlight classification and status trends, and surface key risk attributes such as category, level, and severity. Time-based severity trends, MITRE mappings, and product or device-based breakdowns help analysts understand threat patterns and prioritize response. Metrics for open alerts, closed alerts, open vulnerabilities, and affected entities provide quick operational insight, while tables of top device IPs and product versions add valuable investigative context. Together, these visualizations enable teams to track risks, monitor asset health, and strengthen overall detection and remediation efforts.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From JupiterOne

To collect data from JupiterOne, Authentication is handled using a `API Token` and `Account ID`, which serve as the required credentials.

#### Generate an `API Token`:

1. Log in to the account you want to manage.
2. Go to **Settings > Account Management**.
3. In the left panel, click the **Key Icon**.
4. In the User API Keys page, click **Add**.
5. In the API Keys modal, enter the name of the key and the number of days before it expires, and click **Create**.

For more details, check [Documentation](https://docs.jupiterone.io/api/authentication#create-account-level-api-keys).


## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **JupiterOne**.
3. Select the **JupiterOne** integration from the search results.
4. Select **Add JupiterOne** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect assets from JupiterOne API**, you'll need to:

        - Configure **URL**, **Account ID** and **API Token**.
        - Enable the dataset.
        - Adjust the integration configuration parameters if required, including the Interval, etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **jupiter_one**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **jupiter_one**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Risks and Alerts

{{fields "risks_and_alerts"}}

### Inputs used

These inputs can be used in this integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following API:

- `Asset`: [JupiterOne API](https://docs.jupiterone.io/api/entity-relationship-queries).

#### Data retention

The data streams below collect a full snapshot of JupiterOne risks and alerts on every polling interval, so their backing indices hold one copy of each record per interval.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-jupiter_one.risks_and_alerts-*` | `logs-jupiter_one.risks_and_alerts-default_policy`: roll over after 30d, delete 30d after rollover | delete 30d after rollover |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies. The data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead. It also works per backing index: Elasticsearch [rolls the write index over automatically](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/data-stream-lifecycle-settings#cluster-lifecycle-default-rollover) on age, size, or document count, and [deletes a backing index once the retention has passed since it rolled over](https://www.elastic.co/docs/manage-data/lifecycle/data-stream#data-streams-lifecycle-how-it-works). A document therefore stays for the retention plus up to one rollover interval. The rollover age is derived from the retention and is an implementation detail that Elasticsearch may change. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management → Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-jupiter_one.risks_and_alerts-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.
