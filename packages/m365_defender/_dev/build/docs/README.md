# Microsoft Defender XDR integration

## Overview

The [Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/) integration allows you to monitor Alert, Incident (Microsoft Graph Security API), Event (Streaming API) Logs, and Vulnerability (Microsoft Defender for Endpoint API) Logs. Microsoft Defender XDR is a unified pre and post-breach enterprise defense suite that natively coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated protection against sophisticated attacks.

Use the Microsoft Defender XDR integration to collect and parse data from the Microsoft Azure Event Hub, Microsoft Graph Security v1.0 REST API, and the Microsoft Defender Endpoint API. Then visualise that data in Kibana.

For example, you could use the data from this integration to consolidate and correlate security alerts from multiple sources. Also, by looking into the alert, incident, and vulnerability a user can take an appropriate action in the Microsoft Defender XDR Portal.

## Data streams

The Microsoft Defender XDR integration collects logs for four types of events: Alert, Event, Incident, and Vulnerability.

**Alert:** This data streams leverages the [Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0) to collect alerts including suspicious activities in a customer's tenant that Microsoft or partner security providers have identified and flagged for action.

**Event (Recommended):** This data stream leverages the [M365 Defender Streaming API](https://learn.microsoft.com/en-us/defender-xdr/streaming-api?view=o365-worldwide) to collect Alert, Device, Email, App and Identity Events. Events are streamed to an Azure Event Hub. For a list of Supported Events exposed by the Streaming API and supported by Elastic's integration, please see Microsoft's documentation [here](https://learn.microsoft.com/en-us/defender-xdr/supported-event-types?view=o365-worldwide).

**Incidents and Alerts (Recommended):** This data streams leverages the [Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0) to ingest a collection of correlated alert instances and associated metadata that reflects the story of an attack in Microsoft Defender XDR. Incidents stemming from Microsoft Defender XDR, Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Identity, Microsoft Defender for Cloud Apps, and Microsoft Purview Data Loss Prevention are supported by this integration.

**Vulnerability:** This data stream uses the [Microsoft Defender for Endpoint API](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list) to gather vulnerability details by fetching data from three different endpoints — [vulnerabilities](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities), [machines](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines), and [software/products](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities-by-machines). The collected data is then correlated and mapped to generate a single, enriched log per vulnerability, providing a clear view of risks across machines and installed software in your environment.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has used **Microsoft Azure Event Hub** for Streaming Event, **Microsoft Graph Security v1.0 REST API** for Incident data stream and **Microsoft Defender for Endpoint API** for Vulnerability data stream.

For **Event**, using filebeat's [Azure Event Hub](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-eventhub.html) input, state such as leases on partitions and checkpoints in the event stream are shared between receivers using an Azure Storage container. For this reason, as a prerequisite to using this input, users will have to create or use an existing storage account.

### Agentless enabled integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Compatibility
###  This integration supports below API versions to collect data.
  - [Microsoft Graph Security v1.0 REST API](https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0)
  - [M365 Defender Streaming API](https://learn.microsoft.com/en-us/defender-xdr/streaming-api?view=o365-worldwide)
    Supported Microsoft Defender XDR streaming event types:
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
  - [Microsoft Defender for Endpoint API](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list)
    - [Vulnerabilities API](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities) (Last updated On 04/25/2024)
    - [Machines API](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines) (Last updated On 03/01/2025)
    - [software/products API](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities-by-machines) (Last updated On 04/25/2024)

## Setup

### Follow the steps below to configure data collection from Microsoft sources:

### 1. Collecting Data from Microsoft Azure Event Hub
- [Configure Microsoft Defender XDR to stream Advanced Hunting events to your Azure Event Hub](https://learn.microsoft.com/en-us/defender-xdr/streaming-api-event-hub?view=o365-worldwide).

### 2. Collecting Data from Microsoft Graph Security v1.0 REST API (for Incidents & Alerts)
- [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
- Assign the required permission: **SecurityIncident.Read.All**. See more details [here](https://learn.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0).
- Once the application is registered, note the following values for use during configuration:
  - Client ID
  - Client Secret
  - Tenant ID

### 3. Collecting Data from Microsoft Defender for Endpoint API (for Vulnerabilities)
- [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
- Assign the required permissions: 
  - **Vulnerability.Read.All** See more details [here](https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities#permissions).
  - **Machine.Read.All** See more details [here](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines#permissions).
- After registration, retrieve the following credentials needed for configuration:
  - Client ID
  - Client Secret
  - Tenant ID

### Data Retention and ILM Configuration
A full sync pulls in a large volume of data, which can lead to storage issues or index overflow over time. To avoid this, we’ve set up an Index Lifecycle Management (ILM) policy that automatically deletes data older than 7 days. This helps keep storage usage under control.

> **Note:** The user or service account associated with the integration must have the following **index privileges** on the relevant index have the following permissions `delete`, `delete_index`

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

### vulnerability

This is the `vulnerability` dataset.

#### Example

{{event "vulnerability"}}

{{fields "vulnerability"}}
