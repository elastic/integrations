# Microsoft Defender for Cloud

The [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction) integration allows you to monitor security alert events. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for analyzing the resources and services that users are protecting through Microsoft Defender.

Use the Microsoft Defender for Cloud integration to collect and parse data from **Azure Event Hub** and then visualize that data in Kibana.

## Data streams

The Microsoft Defender for Cloud integration collects one type of data: event.

**Event** allows users to preserve a record of security events that occurred on the subscription, which includes real-time events that affect the security of the user's environment. For further information connected to security alerts and type, Refer to the page [here](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference).

## Prerequisites

To get started with Defender for Cloud, user must have a subscription to Microsoft Azure.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the **Azure Event Hub** and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.3.0**.

## Setup

### To collect data from Microsoft Azure Event Hub, follow the below steps:

- Configure the Microsoft Defender for Cloud on Azure subscription. For more detail, refer to the link [here](https://learn.microsoft.com/en-us/azure/defender-for-cloud/get-started).

### Enabling the integration in Elastic:

1. In Kibana, go to Management > Integrations.
2. In the "Search for integrations" search bar, type Microsoft Defender for Cloud.
3. Click on the "Microsoft Defender for Cloud" integration from the search results.
4. Click on the Add Microsoft Defender for Cloud Integration button to add the integration.
5. While adding the integration, if you want to collect logs via **Azure Event Hub**, then you have to put the following details:
   - eventhub
   - consumer_group
   - connection_string
   - storage_account
   - storage_account_key
   - storage_account_container (optional)
   - resource_manager_endpoint (optional)

## Logs reference

### Event

This is the `Event` dataset.

#### Example

{{fields "event"}}
