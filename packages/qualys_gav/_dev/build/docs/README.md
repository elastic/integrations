# Qualys Global AssetView (GAV)

## Overview

[Qualys GAV](https://docs.qualys.com/en/gav/latest/) helps you to accurately assess complex IT infrastructure and quickly identify and remediate risk. Using a combination of Qualys sensors — Cloud Agents, scanners and passive network sensors — GAV collects and analyzes data about assets across hybrid environments, and delivers up-to-date, comprehensive and continuous information about those assets as well as their security and compliance posture.

The Qualys GAV integration collect assets via REST API.

## Data streams

The Qualys GAV integration collects logs of the following type:

1. **Asset:** This data stream will collect details of all assets.

>**Note**: For the **Asset** Dashboard, ensure that the time range is aligned with the configured interval parameter to display accurate and consistent data.

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Compatibility

For Rest API, this module has been tested against the **2.0** API version.

## Setup

### Collect data from the Qualys GAV API:

- The base URL corresponds to the API Gateway URL of the respective Qualys GAV instance. For reference, see: [Qualys Platform Identification](https://www.qualys.com/platform-identification/#:~:text=apps.qualysksa.com-,API%20URLs,-Use%20API%20Gateway).
- The same username and password used for logging into the Qualys instance are required for authentication when fetching logs through the integration.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Qualys GAV**.
3. Select the **Qualys GAV** integration and add it.
4. Add all the required integration configuration parameters: URL, Username and Password.
5. Save the integration.

### Query-time asset enrichment (LOOKUP JOIN)

When the integration is installed, a transform maintains the latest asset inventory per host in a lookup index (`logs-qualys_gav_latest.asset`). You can enrich other Qualys or security data with GAV asset metadata at query time using ES|QL [`LOOKUP JOIN`](https://www.elastic.co/docs/reference/query-languages/esql/commands/lookup-join) on `host.id`.

Example enriching Qualys VMDR vulnerability data with GAV asset inventory:

```esql
FROM security_solution-qualys_vmdr.vulnerability_latest
| LOOKUP JOIN logs-qualys_gav_latest.asset ON host.id
```

**Elasticsearch 9.1+** is required for `LOOKUP JOIN` against a lookup index. On releases before 9.1, `LOOKUP JOIN` must target the concrete transform destination index instead: in Kibana go to **Stack Management** → **Transforms**, open the Qualys GAV latest asset transform, and use the **destination_index** name shown there (that name can change with the integration version).

## Data retention

The data streams below collect a full snapshot of Qualys Global AssetView assets on every polling interval, so their backing indices hold one copy of each record per interval. The `latest_asset` transform maintains the current view of each asset.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-qualys_gav.asset-*` | `logs-qualys_gav.asset-default_policy`: roll over after 30d, delete 30d after rollover | delete 30d after ingestion |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies; the data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead: documents are deleted the stated time after they are ingested. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management > Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-qualys_gav.asset-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.

## Logs reference

### Asset

This is the `Asset` dataset.

#### Example

{{event "asset"}}

{{fields "asset"}}