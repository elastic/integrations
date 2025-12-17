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

- `Adapter`: Collect details of all adapters (endpoint: `/api/v2/adapters`).

- `User`: Collect details of all users (endpoint: `/api/v2/users`).

- `Gateway`: Collect details of all Gateway (endpoint: `/api/v2/gateway`).

- `Exposure`: Collect details of all exposure assets including:
    - vulnerability_instances (endpoint: `/api/v2/vulnerability_instances`)
    - vulnerabilities (endpoint: `/api/v2/vulnerabilities`)
    - vulnerabilities_repository (endpoint: `/api/v2/vulnerabilities_repository`)

- `Alert and Incidents`: Collect details of all alert findings and incident assets including:
    - alert_findings (endpoint: `/api/v2/alert_findings`)
    - incidents (endpoint: `/api/v2/incidents`)

### Supported use cases

Integrating the Axonius Adapter, User, Gateway, Exposure, and Alert/Incident data streams with Elastic SIEM provides centralized, end-to-end visibility across data ingestion, identity posture, network configuration, vulnerability exposure, and active security events. Together, these data streams help analysts understand how data enters the platform, how it maps to users and access, how gateways operate within the network, where risks exist, and how alerts evolve into incidents.

The dashboards surface insights into integration health, connection behavior, user roles, routing context, vulnerability severity, and alert and incident trends, making it easier to detect misconfigurations, high-risk exposures, and suspicious activity. By correlating operational, identity, exposure, and incident data in one place, security teams can reduce blind spots, prioritize remediation, and streamline investigations with complete, actionable context across the environment.

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
5. If you do not see the API Key tab in your user settings, follow these steps:
    1.  Go to **System Settings** > **User and Role Management** > **Service Accounts**.
    2. Create a Service Account, and then generate an **API Key**.
6. Copy both values including **API Key and Secret Key** and store them securely for use in the Integration configuration.

**Note:**
To generate or reset an API key, your role must be **Admin**, and you must have **API Access** permissions, which include **API Access Enabled** and **Reset API Key**.

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
3. In the search bar, type **Axonius**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Adapter

The `adapter` data stream provides adapter logs from axonius.

#### adapter fields

{{ fields "adapter" }}

{{ event "adapter" }}

### User

The `user` data stream provides user events from axonius.

#### user fields

{{ fields "user" }}

{{ event "user" }}

### Gateway

The `gateway` data stream provides gateway events from axonius.

#### gateway fields

{{ fields "gateway" }}

{{ event "gateway" }}

### Exposure

The `exposure` data stream provides exposure logs from axonius.

#### exposure fields

{{ fields "exposure" }}

{{event "exposure"}}

### Alert and Incident

The `alert_and_incident` data stream provides alert findings and incident asset logs from axonius.

#### alert_and_incident fields

{{ fields "alert_and_incident" }}

{{event "alert_and_incident"}}

### Inputs used

{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}

### API usage

These APIs are used with this integration:

* Adapter (endpoint: `/api/v2/adapters`)
* User (endpoint: `/api/v2/users`)
* Gateway (endpoint: `/api/v2/gateway`)
* Exposure:
    * vulnerability_instances (endpoint: `/api/v2/vulnerability_instances`)
    * vulnerabilities (endpoint: `/api/v2/vulnerabilities`)
    * vulnerabilities_repository (endpoint: `/api/v2/vulnerabilities_repository`)
* Alert Findings and Incidents:
    * alert_findings (endpoint: `/api/v2/alert_findings`)
    * incidents (endpoint: `/api/v2/incidents`)

### ILM Policy

To facilitate adapter, user, gateway and assets data including exposures, alert findings and incidents, source data stream-backed indices `.ds-logs-axonius.adapter-*`, `.ds-logs-axonius.user-*`, `.ds-logs-axonius.gateway-*`, `.ds-logs-axonius.exposure-*` and `.ds-logs-axonius.alert_and_incident-*` respectively are allowed to contain duplicates from each polling interval. ILM policies `logs-axonius.adapter-default_policy`, `logs-axonius.user-default_policy`, `logs-axonius.gateway-default_policy`, `logs-axonius.exposure-default_policy` and `logs-axonius.alert_and_incident-default_policy` are added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
