# M365 Defender integration

## Overview

The [Microsoft 365 Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender) integration allows you to monitor Incident (Microsoft Graph Security API) and Event (Streaming API) Logs. Microsoft 365 Defender is a unified pre and post-breach enterprise defense suite that natively coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated protection against sophisticated attacks.

Use the Microsoft 365 Defender integration to collect and parse data from the Microsoft Azure Event Hub, Microsoft Graph Security v1.0 REST API and Microsoft 365 Defender API. Then visualise that data in Kibana.

For example, you could use the data from this integration to consolidate and correlate security alerts from multiple sources. Also, by looking into the alert and incident, a user can take an appropriate action in the Microsoft 365 Defender Portal.

## Data streams

The Microsoft 365 Defender integration collects logs for three types of events: Event, Incident and Log.

**Event (Recommended)** in Microsoft 365 Defender collects Alert, Device, Email and App & Identity Events. It uses the Microsoft Azure Event Hub to collect data. See [Supported Streaming Event Types](https://learn.microsoft.com/en-us/microsoft-365/security/defender/supported-event-types?view=o365-worldwide).

**Incident (Recommended)** in Microsoft 365 Defender is a collection of correlated alert instances and associated metadata that reflects the story of an attack in a tenant. It uses the Microsoft Graph Security v1.0 REST API to collect data. See Example Schema [here](https://learn.microsoft.com/en-us/graph/api/resources/security-incident?view=graph-rest-1.0#properties).

**Log** incidents API allows you to sort through incidents to create an informed cybersecurity response. It exposes a collection of incidents that were flagged in your network, within the time range you specified in your environmental retention policy. The most recent incidents are displayed at the top of the list. Each incident contains an array of related alerts and their related entities. It uses the Microsoft 365 Defender API to collect data. See Example Schema [here](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-list-incidents?view=o365-worldwide#schema-mapping).

## Requirements

**Note:**
  - As per the Microsoft 365 Defender documentation [Here](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-siem?view=o365-worldwide#use-the-new-microsoft-365-defender-api-for-all-your-alerts), the SIEM API will be deprecated. Therefore, we recommend using the new Incident data stream with the latest Security Graph API.
  - **log** and **incident** data streams have the same events, so we recommend using one data stream at a time.

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has used **Microsoft Azure Event Hub** for Streaming Event, **Microsoft Graph Security v1.0 REST API** for Incident and **Microsoft 365 Defender API** for Log data streams.

For **Event**, in filebeat [Azure Event Hub](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-eventhub.html) input, state such as leases on partitions and checkpoints in the event stream are shared between receivers using an Azure Storage container. For this reason, as a prerequisite to using this input, users will have to create or use an existing storage account.

## Compatibility

- Supported Microsoft 365 Defender streaming event types have been supported in the current integration version:

  | Sr. No. | Resource types            |
  |---------|---------------------------|
  |    1    | AlertEvidence             |
  |    2    | AlertInfo                 |
  |    3    | DeviceEvents              |
  |    4    | DeviceFileCertificateInfo |
  |    5    | DeviceFileEvents          |
  |    6    | DeviceImageLoadEvents     |
  |    7    | DeviceInfo                |
  |    8    | DeviceLogonEvents         |
  |    9    | DeviceNetworkEvents       |
  |   10    | DeviceNetworkInfo         |
  |   11    | DeviceProcessEvents       |
  |   12    | DeviceRegistryEvents      |
  |   13    | EmailAttachmentInfo       |
  |   14    | EmailEvents               |
  |   15    | EmailPostDeliveryEvents   |
  |   16    | EmailUrlInfo              |
  |   17    | IdentityLogonEvents       |
  |   18    | IdentityQueryEvents       |
  |   19    | IdentityDirectoryEvents   |
  |   20    | CloudAppEvents            |
  |   21    | UrlClickEvent             |

## Setup

### To collect data from Microsoft Azure Event Hub, follow the below steps:
1. [Configure Microsoft 365 Defender to stream Advanced Hunting events to your Azure Event Hub](https://learn.microsoft.com/en-us/microsoft-365/security/defender/streaming-api-event-hub?view=o365-worldwide).

### To collect data from Microsoft Graph Security v1.0 REST API, follow the below steps:

1. [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
2. Permission required for accessing Incident API would be **SecurityIncident.Read.All**. See more details [here](https://learn.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0)
3. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for alert and incident data collection.

### To collect data from Microsoft 365 Defender REST API, follow the below steps:

1. [Register a new Azure Application](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app).
2. Permission required for accessing Log API would be **Incident.Read.All**.
3. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for log data collection.

## Logs reference

### event

This is the `event` dataset.

#### Example

{{fields "event"}}

### incident

This is the `incident` dataset.

#### Example

{{event "incident"}}

{{fields "incident"}}

### log

This is the `log` dataset.

#### Example

{{event "log"}}

{{fields "log"}}
