# ThreatConnect

ThreatConnect is a widely used Threat Intelligence Platform (TIP) designed to assist organizations in aggregating, analyzing, and sharing information related to cybersecurity threats. The platform provides tools and features that enable security teams to collaborate on threat intelligence, manage incidents, and make informed decisions to enhance their overall cybersecurity posture. This ThreatConnect integration enables you to consume and analyze ThreatConnect data within Elastic Security, including indicator events, providing you with visibility and context for your cloud environments within Elastic Security.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data stream

The ThreatConnect Integration collects indicators as the primary data type. Associated groups and associated indicators are brought in via Elastic custom mapping fields.

An **Indicator** inside [ThreatConnect](https://docs.threatconnect.com/en/latest/rest_api/v3/indicators/indicators.html) represents an atomic piece of information that has some intelligence value.

Reference for [REST APIs](https://docs.threatconnect.com/en/latest/rest_api/rest_api.html#getting-started) of ThreatConnect.

## Compatibility

This module has been tested against the **ThreatConnect API Version v3**.
The minimum required ThreatConnect Platform version is **7.3.1**.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

To collect data from ThreatConnect, the following parameters from your ThreatConnect instance are required:

- Access Id
- Secret Key
- URL

To create an API user account, refer to this [article](https://knowledge.threatconnect.com/docs/creating-user-accounts).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **ThreatConnect**.
3. Select the **ThreatConnect** integration and add it.
4. Configure all required integration parameters, including Access Id, Secret Key, and URL, to enable data collection from the ThreatConnect REST API.
5. Save the integration.

## Indicator expiration

The ingested indicators expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to facilitate only active indicators be available to the end users. Since we want to retain only valuable information and avoid duplicated data, the ThreatConnect Elastic integration forces the intel indicators to rotate into a custom index called: `logs-ti_threatconnect_latest.dest_indicator-*`.
**Please, refer to this index in order to set alerts and so on.**

#### Handling orphaned indicators

To prevent orphaned indicators that may never expire in the destination index, you can configure IOC Expiration Duration parameter while setting up the integration. This parameter deletes all data inside the destination index logs-ti_threatconnect_latest.dest_indicator after this specified duration is reached.

### How it works

This is possible thanks to a transform rule installed along with the integration. The transform rule parses the data stream content that is pulled from ThreatConnect and only adds new indicators.
Both the data stream and the latest index have applied expiration through ILM and a retention policy in the transform respectively. See [Data retention](#data-retention).

### Data retention

Threat indicators are re-collected across polling intervals, and the latest transform keeps the active, deduplicated view in its destination index. The source data streams therefore hold repeated copies of the same indicators.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-ti_threatconnect.indicator-*` | `logs-ti_threatconnect.indicator-default_policy`: roll over after 1d, delete 2d after rollover | delete 5d after ingestion |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies; the data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead: documents are deleted the stated time after they are ingested. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management > Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-ti_threatconnect.indicator-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.

## Logs reference

### Indicator

This is the `Indicator` dataset.

#### Example

{{event "indicator"}}

{{fields "indicator"}}
