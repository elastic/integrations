# Doppel Integration for Elastic

## Overview
The Doppel integration for Elastic enables the automated collection of security alerts directly from the Doppel API. By ingesting these alerts into the Elastic Common Schema (ECS), security teams can centralize their threat monitoring, perform cross-source correlation, and visualize Doppel data within Kibana dashboards.

### Compatibility
This integration is compatible with the Doppel API v1 and Elastic Stack version 8.12.0 or higher.

### How it works
This integration uses the `httpjson` input to periodically poll the Doppel `/v1/alerts` endpoint. It uses a cursor-based polling mechanism (stateful) to ensure that only new or updated alerts are ingested, minimizing API overhead and preventing data gaps.

## What data does this integration collect?
The Doppel integration collects security alerts, including:
* **Alert Metadata:** IDs, creation timestamps, and last activity timestamps.
* **Threat Indicators:** Targeted entities, domains, and associated IP addresses.
* **Contextual Data:** Severity levels, brand information, and internal notes.

All data is mapped to the [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) to ensure compatibility with Elastic Security apps.

### Supported use cases
* **Threat Detection:** Monitor for new brand-related threats detected by Doppel.
* **Incident Response:** Pivot from an Elastic Security alert directly to the Doppel dashboard using the provided reference links.
* **Historical Analysis:** Trend Doppel alert severity and volume over time to identify persistent threat patterns.

## What do I need to use this integration?
To use this integration, you will need:
* A valid Doppel **API Key**.
* An optional **Organization Code** (if required by your Doppel instance).

## How do I deploy this integration?

### Agent-based deployment
Elastic Agent must be installed on a host with outbound internet access to reach the Doppel API. For more details, refer to the [Elastic Agent installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The agent will act as a centralized poller, fetching data from the API and shipping it to your Elastic cluster.

### Agentless deployment
This integration supports **Agentless (BETA)** deployment in Elastic Cloud environments. When using Agentless mode, Elastic manages the polling infrastructure for you, eliminating the need to install or maintain a local Elastic Agent.

## Onboard / configure
1. Navigate to **Management > Integrations** in Kibana.
2. Search for **Doppel** and click **Add Doppel**.
3. Enter your **API Key** and configure the **Polling Interval**.
4. Choose your deployment mode (Agent-based or Agentless).
5. Save the integration to begin ingesting data.

## Reference

### Alerts
The `alerts` data stream provides security events from the Doppel API.

#### Alerts fields
{{ fields "alerts" }}

#### Alerts sample event
{{ event "alerts" }}

### Inputs used
{{ inputDocs }}

### API usage
This integration interacts with the following Doppel API endpoints:
* `GET /v1/alerts`: Used to fetch the list of alerts based on activity timestamps.