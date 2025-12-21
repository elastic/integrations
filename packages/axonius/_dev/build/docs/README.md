# Axonius Integration for Elastic

## Overview

[Axonius](https://www.axonius.com/) is a cybersecurity asset management platform that automatically collects data from hundreds of IT and security tools through adapters, merges that information, and builds a unified inventory of all assets including devices, users, SaaS apps, cloud instances, and more. By correlating data from multiple systems, Axonius helps organizations identify visibility gaps, missing security controls, risky configurations, and compliance issues. It lets you create powerful queries to answer any security or IT question and automate actions such as sending alerts, creating tickets, or enforcing policies.

This integration for Elastic allows you to collect assets and security events data using the Axonius API, then visualize the data in Kibana.

### Compatibility
The Axonius integration is compatible with product version **7.0**.

### How it works
This integration periodically queries the Axonius API to retrieve logs.

## What data does this integration collect?
This integration collects log messages of the following type:

- `Network`: Collect details of all identity assets including:
    - networks (endpoint: `/api/v2/networks`)
    - load_balancers (endpoint: `/api/v2/load_balancers`)
    - network_services (endpoint: `/api/v2/network_services`)
    - network_devices (endpoint: `/api/v2/network_devices`)
    - firewalls (endpoint: `/api/v2/firewalls`)
    - nat_rules (endpoint: `/api/v2/nat_rules`)
    - network_routes (endpoint: `/api/v2/network_routes`)

### Supported use cases

Integrating the Axonius Network Datastream with Elastic SIEM provides centralized visibility into network assets, traffic exposure, and connectivity across the environment. Kibana dashboards surface key insights into network asset status, device states, and routing behavior, helping analysts quickly understand overall network posture and potential exposure points.

The dashboards present clear breakdowns of assets by protocol, type, category, and operating system, while metrics highlight publicly exposed and unsafe network devices. Tables provide actionable context around top sources, destinations, subnetworks, routes, locations, and vendors, supporting deeper analysis of network dependencies and communication paths.

These insights help security teams identify network exposure hotspots, detect misconfigurations or risky assets, and streamline network-focused investigations across the organization.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Axonius

To collect data through the Axonius APIs, you need to provide the **URL**, **API Key** and **API Secret**. Authentication is handled using the **API Key** and **API Secret**, which serves as the required credential.

#### Retrieve URL, API Token and API Secret:

1. Log in to the **Axonius** instance.
2. Your instance URL is your Base **URL**.
3. Navigate to **User Settings > API Key**.
4. Generate an **API Key**.
5. Copy both values including **API Key and Secret Key** and store them securely for use in the Integration configuration.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html)

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Axonius**.
3. Select the **Axonius** integration from the search results.
4. Select **Add Axonius** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs from Axonius API**, you'll need to:

        - Configure **URL**, **API Key** and **API Secret**.
        - Adjust the integration configuration parameters if required, including the Interval, HTTP Client Timeout etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Axonius**, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **axonius**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Network

The `network` data stream provides network events from axonius.

#### network fields

{{ fields "network" }}

{{ event "network" }}

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}

### API usage

These APIs are used with this integration:

* Network
    * networks (endpoint: `/api/v2/networks`)
    * load_balancers (endpoint: `/api/v2/load_balancers`)
    * network_services (endpoint: `/api/v2/network_services`)
    * network_devices (endpoint: `/api/v2/network_devices`)
    * firewalls (endpoint: `/api/v2/firewalls`)
    * nat_rules (endpoint: `/api/v2/nat_rules`)
    * network_routes (endpoint: `/api/v2/network_routes`)

#### ILM Policy

To facilitate network data, source data stream-backed indices `.ds-logs-axonius.network-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-axonius.network-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
