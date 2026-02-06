# Microsoft Defender XDR integration

## Overview

The [Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/) integration allows you to monitor Alert, Incident (Microsoft Graph Security API), Event (Streaming API) Logs, and Vulnerability (Microsoft Defender for Endpoint API) Logs. Microsoft Defender XDR is a unified pre and post-breach enterprise defense suite that natively coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated protection against sophisticated attacks.

### How it works

The integration works by collecting data from the Microsoft Azure Event Hub, Microsoft Graph Security REST API, and the Microsoft Defender Endpoint API.

### Compatibility

This integration supports below API versions to collect data.
  - [Microsoft Graph Security REST API v1.0](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0)
    - [Alerts](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0)
    - [Incidents](https://learn.microsoft.com/en-us/graph/api/security-list-incidents?view=graph-rest-1.0)
  - [Microsoft Defender for Endpoint API v1.0](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list)
    - [Vulnerabilities](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities#2-export-software-vulnerabilities-assessment-via-files)
  - [Microsoft Defender XDR Streaming API](https://learn.microsoft.com/en-us/defender-xdr/streaming-api?view=o365-worldwide)
    - Supported Microsoft Defender XDR Streaming event types are listed below. For more details on all available event types, see [documentation](https://learn.microsoft.com/en-us/defender-xdr/supported-event-types).
        | Resource types            | Description                                                                                                                                                                       |
        | ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
        | AlertEvidence             | Files, IP addresses, URLs, users, or devices associated with alerts.                                                                                                              |
        | AlertInfo                 | Alerts from M365 Defender XDR services, including severity and threat categorization.                                                                                             |
        | CloudAppEvents            | Events involving accounts and objects in Office 365 and other cloud apps and services.                                                                                            |
        | DeviceEvents              | Event types, including events triggered by security controls.                                                                                                                     |
        | DeviceFileCertificateInfo | Certificate information of signed files obtained from certificate verification events on endpoints.                                                                               |
        | DeviceFileEvents          | File creation, modification, and other file system events.                                                                                                                        |
        | DeviceImageLoadEvents     | DLL loading events.                                                                                                                                                               |
        | DeviceInfo                | Machine information, including OS information.                                                                                                                                    |
        | DeviceLogonEvents         | Sign-ins and other authentication events on devices.                                                                                                                              |
        | DeviceNetworkEvents       | Network connection and related events.                                                                                                                                            |
        | DeviceNetworkInfo         | Network properties of devices, as well as connected networks and domains.                                                                                                         |
        | DeviceProcessEvents       | Process creation and related events.                                                                                                                                              |
        | DeviceRegistryEvents      | Creation and modification of registry entries.                                                                                                                                    |
        | EmailAttachmentInfo       | Information about files attached to emails.                                                                                                                                       |
        | EmailEvents               | Microsoft 365 email events, including email delivery and blocking events.                                                                                                         |
        | EmailPostDeliveryEvents   | Security events that occur post-delivery, after Microsoft 365 delivers the emails to the recipient mailbox.                                                                       |
        | EmailUrlInfo              | Information about URLs in emails.                                                                                                                                                 |
        | IdentityInfo              | Account information from various sources, including Microsoft Entra ID.                                                                                                           |
        | IdentityLogonEvents       | Authentication events on Active Directory and Microsoft online services.                                                                                                          |
        | IdentityQueryEvents       | Queries for Active Directory objects, such as users, groups, devices, and domains.                                                                                                |
        | IdentityDirectoryEvents   | Events involving an on-premises domain controller running Active Directory (AD). This table covers a range of identity-related events and system events on the domain controller. |
        | CloudAppEvents            | Events involving accounts and objects in Office 365 and other cloud apps and services.                                                                                            |
        | UrlClickEvent             | Safe Links clicks from email messages, Teams, and Office 365 apps.                                                                                                                |

## What data does this integration collect?

The Microsoft Defender XDR integration collects logs for four types of events: Alerts, Events, Incidents, and Vulnerabilities.

**Alerts:** This data streams uses the [Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0)'s [`/security/alerts_v2`](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0) endpoint to collect alerts including suspicious activities in a customer's tenant that Microsoft or partner security providers have identified and flagged for action.

**Events:** This data stream uses the [Microsoft Defender XDR Streaming API](https://learn.microsoft.com/en-us/defender-xdr/streaming-api?view=o365-worldwide) to collect Alert, Device, Email, App and Identity Events. Events are streamed to an Azure Event Hub. For a list of supported events exposed by the Streaming API and supported by Elastic's integration, please see Microsoft's documentation [here](https://learn.microsoft.com/en-us/defender-xdr/supported-event-types?view=o365-worldwide).

**Incidents and Alerts:** This data streams uses the [Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0)'s [`/security/incidents`](https://learn.microsoft.com/en-us/graph/api/security-list-incidents?view=graph-rest-1.0) endpoint to ingest a collection of correlated alert instances and associated metadata that reflects the story of an attack in Microsoft Defender XDR. Incidents stemming from Microsoft Defender XDR, Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Identity, Microsoft Defender for Cloud Apps, and Microsoft Purview Data Loss Prevention are supported by this integration.

**Vulnerabilities:** This data stream uses the [Microsoft Defender for Endpoint API](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list)'s [`/api/machines/SoftwareVulnerabilitiesExport`](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities#2-export-software-vulnerabilities-assessment-via-files) endpoint to collect vulnerability assessments.

**Note:** **Alerts** data stream ingests individual detection events surfaced by Microsoft and partner security providers, while **Incidents and Alerts** data stream ingests correlated collections of alerts that represent a broader attack.

### Supported Use Cases

Use the data from this integration to consolidate and correlate security alerts from multiple sources. Also, by looking into the alert, incident, and vulnerability a user can take an appropriate action in the Microsoft Defender XDR Portal.

## What do I need to use this integration?

### From Elastic

Version `4.0.0` of the Microsoft Defender XDR integration adds [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Microsoft Defender XDR
Follow the steps below to configure data collection from Microsoft sources.

#### 1. Collecting Data via Azure Event Hub

- [Configure Microsoft Defender XDR to stream Advanced Hunting events to your Azure Event Hub](https://learn.microsoft.com/en-us/defender-xdr/streaming-api-event-hub?view=o365-worldwide).
- A Blob Storage account is required in order to store/retrieve/update the offset or state of the eventhub messages. This means that after stopping filebeat it can start back up at the spot that it stopped processing messages.

#### 2. Collecting Data via Microsoft Graph Security REST API (for Incidents & Alerts)

- [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
- Assign the required permission: **SecurityIncident.Read.All**. See more details [here](https://learn.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0).
- Once the application is registered, note the following values for use during configuration:
  - Client ID
  - Client Secret
  - Tenant ID

#### 3. Collecting Data via Microsoft Defender for Endpoint API (for Vulnerabilities)

- [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
- Assign the required permissions: **Vulnerability.Read.All**. See more details [here](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities#22-permissions).
- After registration, retrieve the following credentials needed for configuration:
  - Client ID
  - Client Secret
  - Tenant ID

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Microsoft Defender XDR**.
3. Select the **Microsoft Defender XDR** integration from the search results.
4. Select **Add Microsoft Defender XDR** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect alerts and incidents via Microsoft Graph Security API**, you'll need to:

        - Configure **Client ID**, **Client Secret** and **Tenant ID**.
    * To **Collect vulnerabilities via Microsoft Defender for Endpoint API**, you'll need to:

        - Configure **Client ID**, **Client Secret** and **Tenant ID**. Configure either **Subscription ID** or **Management Group Name** as the scope.
    * To **Collect events via Azure Event Hub**, you'll need to:

        - Configure **Azure Event Hub**, **Connection String**, **Storage Account**, and **storage_account_key**.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Microsoft Defender XDR**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **m365_defender**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

### Data Retention and ILM Configuration

A full sync pulls in a large volume of data, which can lead to storage issues or index overflow over time. To avoid this, we have set up an Index Lifecycle Management (ILM) policy that automatically deletes data older than 7 days. This helps keep storage usage under control.

> **Note:** The user or service account associated with the integration must have the following **index privileges** on the relevant index have the following permissions `delete`, `delete_index`.

## Alert severity mapping

The values used in `event.severity` are consistent with Elastic Detection Rules.

| Severity Name          | `event.severity` |
|------------------------|:----------------:|
| Low (or Informational) | 21               |
| Medium                 | 47               |
| High                   | 73               |
| Critical               | 99               |

## Troubleshooting

- Expiring SAS URLs: The option `SAS Valid Hours` in `vulnerability` data stream controls the duration that the `Shared Access Signature (SAS)` download URLs are valid for. The default value of this option is `1h` i.e., 1 hour, and the maximum allowed value is `6h` i.e., 6 hours. Increase the value of the option `SAS Valid Hours` when you see `error.message` indicates signatures are invalid, or when you notice invalid signature errors inside CEL trace logs.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### log

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

### Inputs used

These inputs are used in this integration:

- [azure-eventhub](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-azure-eventhub)
- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)
- [httpjson](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-httpjson)

### API usage

This integration dataset uses the following APIs:

- `Alerts`: [List alerts_v2](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0&tabs=http) endpoint from [Microsoft Graph Security REST API v1.0](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0)
- `Events`: [Microsoft Defender XDR Streaming API](https://learn.microsoft.com/en-us/defender-xdr/streaming-api?view=o365-worldwide)
- `Incidents`: [List incidents](https://learn.microsoft.com/en-us/graph/api/security-list-incidents?view=graph-rest-1.0&tabs=http) endpoint from [Microsoft Graph Security REST API v1.0](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0)
- `Vulnerabilities`: [Get software vulnerabilities](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities#2-export-software-vulnerabilities-assessment-via-files) endpoint from [Microsoft Defender for Endpoint API v1.0](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list)
