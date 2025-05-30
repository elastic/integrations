# Microsoft Sentinel

## Overview

[Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/overview?tabs=azure-portal) is a scalable, cloud-native security information and event management (SIEM) system that delivers an intelligent and comprehensive solution for SIEM and security orchestration, automation, and response (SOAR). Microsoft Sentinel provides cyberthreat detection, investigation, response, and proactive hunting, with a bird's-eye view across your enterprise.

Use the Microsoft Sentinel integration to collect and parse Alerts and Incidents from Microsoft Sentinel REST API and Events from the Microsoft Azure Event Hub, then visualise the data in Kibana.

## Agentless Enabled Integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data streams

The Microsoft Sentinel integration collects logs for three types of events: Alert, Event and Incident.

**Alert:** [Alert](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-alerts?view=rest-securityinsights-2024-03-01&tabs=HTTP) allows collecting all alerts for an incident via API.

**Incident:** [Incident](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list?view=rest-securityinsights-2024-03-01&tabs=HTTP) allows collecting all incidents via API.

**Event:** [Event](https://learn.microsoft.com/en-us/azure/sentinel/security-alert-schema) allows collecting all alerts for an incident streamed to an Azure Event Hub.  

## Requirements

Unless you choose `Agentless` deployment, the Elastic Agent must be installed. Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Compatibility

For Rest API, this module has been tested against the **2024-03-01** version.  

## Setup

### Collect data from Microsoft Azure Event Hub

1. **Navigate to Log Analytics Workspace:** From the Azure Portal's navigation menu, locate and select **Log Analytics workspaces**.
2. **Select your Workspace:** Choose the Log Analytics workspace associated with your Azure Sentinel deployment.
3. **Navigate to Data Export:** Within the Log Analytics workspace, locate and select the `Data Export` option. This is usually found in the settings menu.
4. **New Export Rule:** Within Data export click on `New export rule` to create a new rule.
5. **Under Basic section:** Provide a rule name for the data export rule.
6. **Under Source section:** Select the tables you want to export data to storage account.
7. **Under Destination section:** Provide the destination details like the `Subscription` name and `Storage account` name to which you want to export data.
8. **Review + Create:** In the `review + create` section, select `Create`.

### Collect data from Microsoft Sentinel REST API

1. Open [Azure Portal](https://portal.azure.com/) and [Register a new Azure Application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=certificate).
2. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for data collection.
3. To get **Workspace Name, Subscription ID, and Resource Group** navigate to **Microsoft Sentinel** and select desired workspace among the list.
4. Go to **Manage > API permissions** in your portal, then add the following permissions for **Microsoft Graph**:
    - **SecurityAlert.Read.All** with both **Application** and **Delegated** permission types.
    - **User.Read** with the **Delegated** permission type.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Microsoft Sentinel**.
3. Select the **Microsoft Sentinel** integration and add it.
4. Add all the required integration configuration parameters, including the URL, Login URL, Client ID, Client Secret, Tenant Id, Resource Group Name, Subscription ID, Workspace Name, Interval, and Initial Interval, to enable data collection for REST API input type and Azure Event Hub, Consumer Group, Connection String, Storage Account and Storage Account Key for Azure Event Hub input type.
5. Save the integration.

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