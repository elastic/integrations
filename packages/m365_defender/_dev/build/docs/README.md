# M365 Defender integration

## Overview

The [Microsoft 365 Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender) integration allows you to monitor Alert, Incident (Microsoft Graph Security API) and Event (Streaming API) Logs. Microsoft 365 Defender is a unified pre and post-breach enterprise defense suite that natively coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated protection against sophisticated attacks.

Use the Microsoft 365 Defender integration to collect and parse data from the Microsoft Azure Event Hub, and the Microsoft Graph Security v1.0 REST API. Then visualise that data in Kibana.

For example, you could use the data from this integration to consolidate and correlate security alerts from multiple sources. Also, by looking into the alert and incident, a user can take an appropriate action in the Microsoft 365 Defender Portal.

## Agentless Enabled Integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data streams

The Microsoft 365 Defender integration collects logs for three types of events: Alert, Event, and Incident.

**Alert:** This data streams leverages the [Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0) to collect alerts including suspicious activities in a customer's tenant that Microsoft or partner security providers have identified and flagged for action.

**Event (Recommended):** This data stream leverages the [M365 Defender Streaming API](https://learn.microsoft.com/en-us/microsoft-365/security/defender/streaming-api?view=o365-worldwide) to collect Alert, Device, Email, App and Identity Events. Events are streamed to an Azure Event Hub. For a list of Supported Events exposed by the Streaming API and supported by Elastic's integration, please see Microsoft's documentation [here](https://learn.microsoft.com/en-us/microsoft-365/security/defender/supported-event-types?view=o365-worldwide).

**Incidents and Alerts (Recommended):** This data streams leverages the [Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0) to ingest a collection of correlated alert instances and associated metadata that reflects the story of an attack in M365D. Incidents stemming from Microsoft 365 Defender, Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Identity, Microsoft Defender for Cloud Apps, and Microsoft Purview Data Loss Prevention are supported by this integration.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has used **Microsoft Azure Event Hub** for Streaming Event, and **Microsoft Graph Security v1.0 REST API** for Incident data stream.

For **Event**, using filebeat's [Azure Event Hub](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-eventhub.html) input, state such as leases on partitions and checkpoints in the event stream are shared between receivers using an Azure Storage container. For this reason, as a prerequisite to using this input, users will have to create or use an existing storage account.

## Compatibility

- Supported Microsoft 365 Defender streaming event types have been supported in the current integration version:

  | Resource types            | Description               |
  |---------------------------|---------------------------|
  | AlertEvidence             | Files, IP addresses, URLs, users, or devices associated with alerts. |
  | AlertInfo                 | Alerts from M365 Defender XDR services, including severity and threat categorization. |
  | DeviceEvents              | Event types, including events triggered by security controls. |
  | DeviceFileCertificateInfo | Certificate information of signed files obtained from certificate verification events on endpoints. |
  | DeviceFileEvents          | File creation, modification, and other file system events. |
  | DeviceImageLoadEvents     | DLL loading events. |
  | DeviceInfo                | Machine information, including OS information. |
  | DeviceLogonEvents         | Sign-ins and other authentication events on devices. |
  | DeviceNetworkEvents       | Network connection and related events. |
  | DeviceNetworkInfo         | Network properties of devices, as well as connected networks and domains. |
  | DeviceProcessEvents       | Process creation and related events. |
  | DeviceRegistryEvents      | Creation and modification of registry entries. |
  | EmailAttachmentInfo       | Information about files attached to emails. |
  | EmailEvents               | Microsoft 365 email events, including email delivery and blocking events. |
  | EmailPostDeliveryEvents   | Security events that occur post-delivery, after Microsoft 365 delivers the emails to the recipient mailbox. |
  | EmailUrlInfo              | Information about URLs in emails. |
  | IdentityInfo              | Account information from various sources, including Microsoft Entra ID. |
  | IdentityLogonEvents       | Authentication events on Active Directory and Microsoft online services. |
  | IdentityQueryEvents       | Queries for Active Directory objects, such as users, groups, devices, and domains. |
  | IdentityDirectoryEvents   | Events involving an on-premises domain controller running Active Directory (AD). This table covers a range of identity-related events and system events on the domain controller. |
  | CloudAppEvents            | Events involving accounts and objects in Office 365 and other cloud apps and services. |
  | UrlClickEvent             | Safe Links clicks from email messages, Teams, and Office 365 apps. |

## Setup

### To collect data from Microsoft Azure Event Hub, follow the below steps:
1. [Configure Microsoft 365 Defender to stream Advanced Hunting events to your Azure Event Hub](https://learn.microsoft.com/en-us/microsoft-365/security/defender/streaming-api-event-hub?view=o365-worldwide).

### To collect data from Microsoft Graph Security v1.0 REST API, follow the below steps:

1. [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
2. Permission required for accessing Incident API would be **SecurityIncident.Read.All**. See more details [here](https://learn.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0)
3. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for alert and incident data collection.

## Alert severity mapping

The values used in `event.severity` are consistent with Elastic Detection Rules.

| Severity Name          | `event.severity` |
|------------------------|:----------------:|
| Low (or Informational) | 21               |
| Medium                 | 47               |
| High                   | 73               |
| Critical               | 99               |

## Logs reference

### alert

This is the `alert` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}

### event

This is the `event` dataset.

#### Example

{{fields "event"}}

### incident

This is the `incident` dataset.

#### Example

{{event "incident"}}

{{fields "incident"}}
