# ThreatConnect

ThreatConnect is a widely used Threat Intelligence Platform (TIP) designed to assist organizations in aggregating, analyzing, and sharing information related to cybersecurity threats. The platform provides tools and features that enable security teams to collaborate on threat intelligence, manage incidents, and make informed decisions to enhance their overall cybersecurity posture. This ThreatConnect integration enables you to consume and analyze ThreatConnect data within Elastic Security, including indicator events, providing you with visibility and context for your cloud environments within Elastic Security.

## Data stream

The ThreatConnect Integration collects indicators as the primary data type. Associated groups and associated indicators are brought in via Elastic custom mapping fields.

An **Indicator** inside [ThreatConnect](https://docs.threatconnect.com/en/latest/rest_api/v3/indicators/indicators.html) represents an atomic piece of information that has some intelligence value.

Reference for [REST APIs](https://docs.threatconnect.com/en/latest/rest_api/rest_api.html#getting-started) of ThreatConnect.

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Versions

The minimum required versions for the Elastic Stack is **8.12.0**.

The minimum required ThreatConnect Platform version is 7.3.1 This integration module uses the ThreatConnect V3 API.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.11.0**.
This module has been tested against the **ThreatConnect API Version v3**.
The minimum required ThreatConnect Platform version needs to be **7.3.1**.

## Setup

### To collect data from ThreatConnect, the following parameters from your ThreatConnect instance are required:

1. Access Id
2. Secret Key
3. URL

To create an API user account, please refer to [this](https://knowledge.threatconnect.com/docs/creating-user-accounts) article.

### Enabling the integration in Elastic:
1. In Kibana, go to Management > Integrations.
2. In the "Search for integrations" search bar, type ThreatConnect.
3. Click on the "ThreatConnect" integration from the search results.
4. Click on the "Add ThreatConnect" button to add the integration.
5. Configure all required integration parameters, including Access Id, Secret Key, and URL, to enable data collection from the ThreatConnect REST API.
6. Save the integration.

## Indicators Expiration

The ingested indicators expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to facilitate only active indicators be available to the end users. Since we want to retain only valuable information and avoid duplicated data, the ThreatConnect Elastic integration forces the intel indicators to rotate into a custom index called: `logs-ti_threatconnect_latest.dest_indicator-*`.
**Please, refer to this index in order to set alerts and so on.**

#### Handling Orphaned Indicators

In order to prevent orphaned indicators that may never expire in the destination index users can configure IOC Expiration Duration parameter while setting up the integration. This parameter deletes all data inside the destination index logs-ti_threatconnect_latest.dest_indicator after this specified duration is reached.

### How it works

This is possible thanks to a transform rule installed along with the integration. The transform rule parses the data stream content that is pulled from ThreatConnect and only adds new indicators.

Both the data stream and the latest index have applied expiration through ILM and a retention policy in the transform respectively.

## Logs Reference

### Indicator

This is the `Indicator` dataset.

#### Example

{{event "indicator"}}

{{fields "indicator"}}
