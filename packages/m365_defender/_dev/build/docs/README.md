# Microsoft Defender XDR integration

## Overview

The [Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/) integration allows you to monitor Alert, Incident (Microsoft Graph Security API), Event (Streaming API) Logs, and Vulnerability (Microsoft Defender for Endpoint API) Logs. Microsoft Defender XDR is a unified pre and post-breach enterprise defense suite that natively coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated protection against sophisticated attacks.

### How it works

The integration works by collecting data from the Microsoft Azure Event Hub, Microsoft Graph Security REST API, and the Microsoft Defender Endpoint API.

For a demo, refer to the following video (click to view).

[![Microsoft Defender XDR integration video](https://play.vidyard.com/fsxgbbf7qarpgx345x28v5.jpg)](https://videos.elastic.co/watch/fSxgBbf7QArpgX345x28v5)

### Compatibility

This integration supports below API versions to collect data.
  - [Microsoft Graph Security REST API v1.0](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0)
    - [Alerts](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0)
    - [Incidents](https://learn.microsoft.com/en-us/graph/api/security-list-incidents?view=graph-rest-1.0)
  - [Microsoft Defender for Endpoint API v1.0](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list)
    - [Vulnerabilities](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities)
  - [Microsoft Defender XDR Streaming API](https://learn.microsoft.com/en-us/defender-xdr/streaming-api?view=o365-worldwide)
    - Supported Microsoft Defender XDR Streaming event types are in the following table. For more details on all available event types, refer to [documentation](https://learn.microsoft.com/en-us/defender-xdr/supported-event-types).

| Resource types | Description |
| --- | --- |
| AlertEvidence | Files, IP addresses, URLs, users, or devices associated with alerts. |
| AlertInfo | Alerts from M365 Defender XDR services, including severity and threat categorization. |
| BehaviorEntities | Information about entities (file, process, device, user, and others) that are involved in a behavior. |
| BehaviorInfo | Information about behaviors from Microsoft Defender for Cloud Apps and User and Entity Behavior Analytics (UEBA). |
| CloudAppEvents | Events involving accounts and objects in Office 365 and other cloud apps and services. |
| CloudAuditEvents | Information about cloud audit events for various cloud platforms protected by the organization's Microsoft Defender for Cloud. |
| CloudProcessEvents | Information about process events in multicloud hosted environments protected by the organization's Microsoft Defender for Cloud. |
| CloudStorageAggregatedEvents | Information about storage activity and related events. |
| DeviceEvents | Event types, including events triggered by security controls. |
| DeviceFileCertificateInfo | Certificate information of signed files obtained from certificate verification events on endpoints. |
| DeviceFileEvents | File creation, modification, and other file system events. |
| DeviceImageLoadEvents | DLL loading events. |
| DeviceInfo | Machine information, including OS information. |
| DeviceLogonEvents | Sign-ins and other authentication events on devices. |
| DeviceNetworkEvents | Network connection and related events. |
| DeviceNetworkInfo | Network properties of devices, as well as connected networks and domains. |
| DeviceProcessEvents | Process creation and related events. |
| DeviceRegistryEvents | Creation and modification of registry entries. |
| EmailAttachmentInfo | Information about files attached to emails. |
| EmailEvents | Microsoft 365 email events, including email delivery and blocking events. |
| EmailPostDeliveryEvents | Security events that occur post-delivery, after Microsoft 365 delivers the emails to the recipient mailbox. |
| EmailUrlInfo | Information about URLs in emails. |
| IdentityInfo | Account information from various sources, including Microsoft Entra ID. |
| IdentityLogonEvents | Authentication events on Active Directory and Microsoft online services. |
| IdentityQueryEvents | Queries for Active Directory objects, such as users, groups, devices, and domains. |
| IdentityDirectoryEvents | Events involving an on-premises domain controller running Active Directory (AD). This table covers a range of identity-related events and system events on the domain controller. |
| MessageEvents | Details about messages sent and received within your organization at the time of delivery. |
| MessagePostDeliveryEvents | Information about security events that occurred after the delivery of a Microsoft Teams message in your organization. |
| MessageUrlInfo | Information about URLs sent through Microsoft Teams messages in your organization. |
| UrlClickEvent | Safe Links clicks from email messages, Teams, and Office 365 apps. |


## What data does this integration collect?

The Microsoft Defender XDR integration collects logs for four types of events: Alerts, Events, Incidents, and Vulnerabilities.

**Incidents:** This data streams uses the [Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0)'s [`/security/incidents`](https://learn.microsoft.com/en-us/graph/api/security-list-incidents?view=graph-rest-1.0) endpoint to ingest a collection of correlated alert instances and associated metadata that reflects the story of an attack in Microsoft Defender XDR. Incidents stemming from Microsoft Defender XDR, Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Identity, Microsoft Defender for Cloud Apps, and Microsoft Purview Data Loss Prevention are supported by this integration. This is recommended over **Alerts** because it fetches correlated incidents including all associated alerts and evidence.

**Alerts:** This data streams uses the [Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0)'s [`/security/alerts_v2`](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0) endpoint to collect alerts including suspicious activities in a customer's tenant that Microsoft or partner security providers have identified and flagged for action. **Incidents** is recommended over **Alerts** if you want to fetch correlated incidents including all associated alerts and evidence.

**Events:** This data stream uses the [Microsoft Defender XDR Streaming API](https://learn.microsoft.com/en-us/defender-xdr/streaming-api?view=o365-worldwide) to collect Alert, Device, Email, App and Identity Events. Events are streamed to an Azure Event Hub. For a list of supported events exposed by the Streaming API and supported by Elastic's integration, please refer to Microsoft's documentation [here](https://learn.microsoft.com/en-us/defender-xdr/supported-event-types?view=o365-worldwide).

**Vulnerabilities:** This data stream uses the [Microsoft Defender for Endpoint API](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list)'s [`/api/machines/SoftwareVulnerabilityChangesByMachine`](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities) delta endpoint to collect vulnerability change events (new, updated, and fixed vulnerabilities).

**Note:** The **Alerts** data stream ingests individual detection events surfaced by Microsoft and partner security providers, while **Incidents** data stream ingests correlated collections of alerts that represent a broader attack.

### Supported Use Cases

Use the data from this integration to consolidate and correlate security alerts from multiple sources. Also, by looking into the alert, incident, and vulnerability a user can take an appropriate action in the Microsoft Defender XDR Portal.

## What do I need to use this integration?

### From Elastic

Version `4.0.0` of the Microsoft Defender XDR integration adds [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, refer to the Transform setup and requirements [documentation](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup).

### From Microsoft Defender XDR
Follow the steps below to configure data collection from Microsoft sources.

#### 1. Collecting Data using Azure Event Hub

- [Configure Microsoft Defender XDR to stream Advanced Hunting events to your Azure Event Hub](https://learn.microsoft.com/en-us/defender-xdr/streaming-api-event-hub?view=o365-worldwide).
- A Blob Storage account is required in order to store/retrieve/update the offset or state of the eventhub messages. This means that after stopping filebeat it can start back up at the spot that it stopped processing messages.

**Authentication:** The Event Hub input supports two authentication methods: **connection string** (default) and **client secret** (Microsoft Entra ID). For setup steps, required RBAC roles (Azure Event Hubs Data Receiver, Storage Blob Data Contributor), and configuration options, see the [Azure Logs integration](https://docs.elastic.co/integrations/azure) or [Filebeat azure-eventhub input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-eventhub.html) documentation.

#### 2. Collecting Data using Microsoft Graph Security REST API (for Incidents & Alerts)

- [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
- Assign the required permission: **SecurityIncident.Read.All**. Refer to [this documentation](https://learn.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0&tabs=http#step-1-configure-permissions-for-microsoft-graph) on how to configure permissions. Refer to [documentation](https://learn.microsoft.com/en-us/graph/api/security-list-incidents?view=graph-rest-1.0&tabs=http#permissions) on required permissions for incidents and alerts.
- Once the application is registered, note the following values for use during configuration:
  - Client ID
  - Client Secret
  - Tenant ID

#### 3. Collecting Data using Microsoft Defender for Endpoint API (for Vulnerabilities)

- [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
- Assign the required permissions: **Vulnerability.Read.All**. Refer to [this documentation](https://learn.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0&tabs=http#step-1-configure-permissions-for-microsoft-graph) on how to configure permissions. Refer to [this documentation](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities#22-permissions) on required permissions for vulnerability.
- After registration, retrieve the following credentials needed for configuration:
  - Client ID
  - Client Secret
  - Tenant ID

## How do I deploy this integration?

This integration supports both Elastic Managed and Agent-based installations.

### Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Microsoft Defender XDR**.
3. Select the **Microsoft Defender XDR** integration from the search results.
4. Select **Add Microsoft Defender XDR** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect alerts and incidents using Microsoft Graph Security API**, you'll need to:

        - Configure **Client ID**, **Client Secret** and **Tenant ID**.
    * To **Collect vulnerabilities using Microsoft Defender for Endpoint API**, you'll need to:

        - Configure **Client ID**, **Client Secret** and **Tenant ID**.
    * To **Collect events using Azure Event Hub**, you'll need to:

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

The Vulnerabilities data stream performs a full sync that pulls in a large volume of data, which can lead to storage issues or index overflow over time. To avoid this, it ships an Index Lifecycle Management (ILM) policy that automatically deletes data older than 7 days, keeping storage usage under control. The other data streams do not define a custom ILM policy and follow the default index lifecycle for their destination indices.

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

Most issues fall into one of the scenarios below. To confirm the integration is working end to end, see [Validation](#validation). For how long collected data is kept, see [Data Retention and ILM Configuration](#data-retention-and-ilm-configuration).

### Enabling request tracing

When debugging a permissions issue or unexpected API responses on the Alerts, Incidents, or Vulnerabilities data streams, enable request tracing and inspect the request trace logs to see the interaction with the server. (The Events data stream is collected over Azure Event Hub and does not offer request tracing.) OAuth2 token values can be decoded using [https://jwt.ms/](https://jwt.ms/) and should include a `roles` section listing the configured permissions.

**Security warning:** request trace files are not redacted. They contain the `Authorization` header and, during OAuth2 token exchange, the client secret in clear text. Only enable request tracing in a controlled debugging session, restrict access to the trace files, disable it as soon as you are finished, and rotate the client secret if a trace file that may contain it was exposed. On agentless deployments this setting is not user-configurable.

### Authentication failures

The Alerts, Incidents, and Vulnerabilities data streams authenticate to Microsoft with OAuth2 client credentials. If the integration reports a degraded status in Fleet and logs OAuth2 token errors, confirm that the client secret has not expired, that the Tenant ID and Client ID are correct, and that admin consent is still granted for the application. Generate a new client secret and update the integration if needed. The degraded status will clear on the next successful poll.

The Events data stream authenticates to Azure Event Hub with a connection string or Microsoft Entra client secret. For those errors, verify the connection string, the storage account, and the RBAC role assignments (Azure Event Hubs Data Receiver and Storage Blob Data Contributor).

### Missing permissions

A `403 Forbidden` response means the Azure application is missing a required API permission. Alerts and Incidents require `SecurityIncident.Read.All`; Vulnerabilities require `Vulnerability.Read.All`. Add the permission, grant admin consent, and wait for the next poll.

### No data is collected

If the integration is healthy but no data appears, confirm that the collection method for the data stream you expect is enabled, and that there is activity in the tenant for that data stream and time window. For the Events data stream, also confirm that the Azure Event Hub and its Blob Storage account are reachable and that Microsoft Defender XDR is configured to stream events to that Event Hub. Check the logs for successful polls or Event Hub reads, then see [Validation](#validation).

### Recovering after an outage

Each data stream saves its position and resumes from there when the agent restarts, so a short outage backfills automatically on the following polls:

- Alerts and Incidents resume from the last `lastUpdateDateTime` cursor and page forward through the backlog. Overlapping records are de-duplicated during ingest (a stable document `_id` is derived from each record), so a resume does not create duplicates.
- Vulnerabilities resume from the saved delta link, so only changes since the last successful run are fetched.
- Events resume from the offset stored in the configured Blob Storage account.

The Vulnerabilities data stream applies an ILM policy that deletes data after 7 days (see [Data Retention and ILM Configuration](#data-retention-and-ilm-configuration)); the other data streams follow the default index lifecycle for their destination indices. This governs how long ingested data is kept in Elasticsearch and is separate from how far back the source APIs can backfill.

### Rate limiting

Repeated `429` responses mean the Microsoft Graph or Defender for Endpoint per-tenant throttling limit has been reached. The affected request fails and the integration retries on the next scheduled interval, so collection catches up once the limit resets. Persistent throttling for many tenants that share one Azure application registration can mean the application is over-subscribed; consider using a separate application registration per tenant.

### Unhealthy transforms

If the Microsoft Defender XDR transforms do not show **Healthy** (see [Validation](#validation)), open the transform to check its messages for the underlying error (for example, permissions or mapping conflicts). Resolve the error, then stop and restart the transform and confirm that it returns to **Healthy**.

### Vulnerability data stream: Fixed vulnerabilities appearing on the Findings page

The vulnerability data stream uses Microsoft Defender for Endpoint's delta API, which returns change events including remediated (`Fixed`) vulnerabilities. Each record carries a `vulnerability.status` field with one of the following values: `open`, `fixed`, or `unknown`.

Until the Kibana Vulnerability Findings page adds a default filter on this field, remediated vulnerabilities will appear alongside open findings. To exclude them, add the following filter to the Findings page or any saved search:

```
NOT vulnerability.status: fixed
```

This is equivalent to showing only currently active vulnerabilities.

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
- `Vulnerabilities`: [SoftwareVulnerabilityChangesByMachine](https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities) delta endpoint from [Microsoft Defender for Endpoint API v1.0](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list)