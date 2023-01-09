# M365 Defender integration

## Overview

The [Microsoft 365 Defender](https://learn.microsoft.com/en-us/microsoft-365/security/defender) integration allows you to monitor Incident Logs. Microsoft 365 Defender is a unified pre and post-breach enterprise defense suite that natively coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated protection against sophisticated attacks.

Use the Microsoft 365 Defender integration to collect and parse data from the Microsoft Graph Security v1.0 REST API and Microsoft 365 Defender API. Then visualise that data in Kibana.

For example, you could use the data from this integration to consolidate and correlate security alerts from multiple sources. Also, by looking into the alert and incident, a user can take an appropriate action in the Microsoft 365 Defender Portal.

## Data streams

The Microsoft 365 Defender integration collects logs for two types of events: Incident and Log.

**Incident** in Microsoft 365 Defender is a collection of correlated alert instances and associated metadata that reflects the story of an attack in a tenant. It uses the Microsoft Graph Security v1.0 REST API to collect data. See Example Schema [here](https://learn.microsoft.com/en-us/graph/api/resources/security-incident?view=graph-rest-1.0#properties).

**Log (Deprecated)** incidents API allows you to sort through incidents to create an informed cybersecurity response. It exposes a collection of incidents that were flagged in your network, within the time range you specified in your environmental retention policy. The most recent incidents are displayed at the top of the list. Each incident contains an array of related alerts and their related entities. It uses the Microsoft 365 Defender API to collect data. See Example Schema [here](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-list-incidents?view=o365-worldwide#schema-mapping).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has used **Microsoft Graph Security v1.0 REST API** and **Microsoft 365 Defender API**.

## Setup

### To collect data from Microsoft Graph Security v1.0 REST API, follow the below steps:

1. [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-1.0).
2. Permission required for accessing Incident API would be **SecurityIncident.Read.All**. See more details [here](https://learn.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0)
3. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for alert and incident data collection.

### To collect data from Microsoft 365 Defender REST API, follow the below steps:

1. [Register a new Azure Application](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app).
2. Permission required for accessing Log API would be **Incident.Read.All**.
3. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for log data collection.

## Logs reference

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
