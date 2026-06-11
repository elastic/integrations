# Sophos Central Integration

The [Sophos Central](https://www.sophos.com/en-us/products/sophos-central) integration allows you to monitor Alerts and Events logs. Sophos Central is a cloud-native application with high availability. It is a cybersecurity management platform hosted on public cloud platforms. Each Sophos Central account is hosted in a named region. Sophos Central uses well-known, widely used, and industry-standard software libraries to mitigate common vulnerabilities.

Use the Sophos Central integration to collect logs across Sophos Central managed by your Sophos account.
Visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data streams

The Sophos Central integration collects logs for two types of events: alerts and events.

**Alerts**: See Example Schema [here](https://developer.sophos.com/docs/siem-v1/1/routes/alerts/get) for more information.

**Events**: See Example Schema [here](https://developer.sophos.com/docs/siem-v1/1/routes/events/get) for more information.

## Compatibility

The Sophos Central Application does not feature version numbers. This integration has been configured and tested against **Sophos Central SIEM Integration API version v1**.

## Requirements

You need Elasticsearch for storing and searching your data, and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Elastic Integration for Sophos Central Settings

Follow this [link](https://developer.sophos.com/getting-started-tenant) to guide you through the process of generating authentication credentials for Sophos Central.

The Elastic Integration for Sophos Central requires the following Authentication Settings in order to connect to the Target service:
  - Client ID
  - Client Secret
  - Grant Type
  - Scope
  - Tenant ID
  - Token URL (without the URL path)

**NOTE**: Sophos central supports logs only upto last 24 hrs.

## Logs reference

### Alerts

This is the `alerts` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}

### Events

This is the `events` dataset.

#### Example

{{event "event"}}

{{fields "event"}}