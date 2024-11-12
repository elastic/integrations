# Microsoft Sentinel

## Overview

[Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/overview?tabs=azure-portal) is a scalable, cloud-native security information and event management (SIEM) system that delivers an intelligent and comprehensive solution for SIEM and security orchestration, automation, and response (SOAR). Microsoft Sentinel provides cyberthreat detection, investigation, response, and proactive hunting, with a bird's-eye view across your enterprise.

Use the Microsoft Sentinel integration to collect and parse Alerts and Incidents from Microsoft Sentinel REST API and Events from the Microsoft Azure Event Hub, then visualise the data in Kibana.

## Data streams

The Microsoft Sentinel integration collects logs for three types of events: Alert, Event and Incident.

**Alert:** [Alert](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-alerts?view=rest-securityinsights-2024-03-01&tabs=HTTP) allows collecting all alerts for an incident via API.

**Incident:** [Incident](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list?view=rest-securityinsights-2024-03-01&tabs=HTTP) allows collecting all incidents via API.

**Event:** [Event](https://learn.microsoft.com/en-us/azure/sentinel/security-alert-schema) allows collecting all alerts for an incident streamed to an Azure Event Hub.  

## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).

## Compatibility

For Rest API, this module has been tested against the **2024-03-01** version.  

## Setup

### To collect data from Microsoft Azure Event Hub, follow the below steps:  

1. **Navigate to Log Analytics Workspace:** From the Azure Portal's navigation menu, locate and select **Log Analytics workspaces**.
2. **Select your Workspace:** Choose the Log Analytics workspace associated with your Azure Sentinel deployment.
3. **Navigate to Data Export:** Within the Log Analytics workspace, locate and select the `Data Export` option. This is usually found in the settings menu.
4. **New Export Rule:** Within Data export click on `New export rule` to create a new rule.
5. **Under Basic section:** Provide a rule name for the data export rule.
6. **Under Source section:** Select the tables you want to export data to storage account.
7. **Under Destination section:** Provide the destination details like the `Subscription` name and `Storage account` name to which you want to export data.
8. **Review + Create:** In the `review + create` section, select `Create`.

### To collect data from Microsoft Sentinel REST API, follow the below steps:

1. Open [Azure Portal](https://portal.azure.com/) and [Register a new Azure Application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=certificate).
2. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for data collection.
3. To get **Workspace Name, Subscription ID, and Resource Group** navigate to **Microsoft Sentinel** and select desired workspace among the list.
4. Go to **Manage > API permissions** in your portal, then add the following permissions for **Microsoft Graph**:
    - **SecurityAlert.Read.All** with both **Application** and **Delegated** permission types.
    - **User.Read** with the **Delegated** permission type.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Microsoft Sentinel`.
3. Select the "Microsoft Sentinel" integration from the search results.
4. Select "Add Microsoft Sentinel" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Login URL, Client ID, Client Secret, Tenant Id, Resource Group Name, Subscription ID, Workspace Name, Interval, and Initial Interval, to enable data collection for REST API input type and Azure Event Hub, Consumer Group, Connection String, Storage Account and Storage Account Key for Azure Event Hub input type.
6. Select "Save and continue" to save the integration.

## Logs reference

### Alert

This is the `Alert` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}

### Event

This is the `Event` dataset.

#### Example

{{fields "event"}}

### Incident

This is the `Incident` dataset.

#### Example

{{event "incident"}}

{{fields "incident"}}
