# Armis

[Armis](https://www.armis.com/) is an enterprise-class security platform designed to provide visibility and protection for managed, unmanaged, and IoT devices. It enables organizations to detect threats, manage vulnerabilities, and enforce security policies across their network.

Use this integration to collect and parse data from your Armis instance.

## Compatibility

This module has been tested against the Armis API version **v1**.

## Data Streams

The Armis integration collects three types of logs.

- **Devices** : Fetches the latest updates for all devices monitored by Armis.
- **Alerts** : Gathers alerts associated with all devices monitored by Armis.
- **Vulnerabilities** : Retrieves detected vulnerabilities and possible mitigation steps across all devices monitored by Armis.

**Note** :

1. The **vulnerability data stream** retrieves information by first fetching vulnerabilities and then identifying the devices where these vulnerabilities were detected, using a chained call between the vulnerability search and vulnerability match endpoints.

## Requirements

### Agentless Enabled Integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent Based Installation
- Elastic Agent must be installed
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the GCP Pub/Sub or REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

#### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

#### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

#### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

#### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### To collect logs through REST API, follow the below steps:

1. Log in to your Armis portal.
2. Navigate to the **Settings** tab.
3. Select **Asset Management & Security**.
4. Go to **API Management** and generate a **Secret Key**.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Armis`.
3. Select the "Armis" integration from the search results.
4. Select "Add Armis" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Secret Key to enable data collection.
6. Select "Save and continue" to save the integration.

## Limitations

1. In the **alert data stream**, based on the documentation, we initially expected to use the `statusChangeTime` field for filtering updates. However, the `"after"` filter applies only to the primary `time` field from the alert endpoint and does not support filtering based on `statusChangeTime`. As a result, when an alert's status changes, the data collection process does not capture these updates.

2. In the **vulnerability data stream**, our filtering mechanism for the **vulnerability search API** relies specifically on the `lastDetected` field. This means that when a user takes action on a vulnerability and `lastDetected` updates, only then will the event for that vulnerability be retrieved. Initially, we assumed this field would always have a value and could be used as a cursor timestamp for fetching data between intervals. However, due to inconsistencies in the API response, we observed cases where `lastDetected` is `null`.

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

An example event for `alert` looks as following:

{{event "alert"}}

#### Exported fields

{{fields "alert"}}

### Device

This is the `device` dataset.

#### Example

An example event for `device` looks as following:

{{event "device"}}

#### Exported fields

{{fields "device"}}

### Vulnerability

This is the `vulnerability` dataset.

#### Example

An example event for `vulnerability` looks as following:

{{event "vulnerability"}}

#### Exported fields

{{fields "vulnerability"}}
