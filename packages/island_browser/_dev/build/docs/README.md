# Island Browser Integration for Elastic

## Overview

[Island](https://www.island.io/) reimagines what the browser can be. By taking in the needs of the enterprise, Island delivers a dramatic positive impact on every layer of cybersecurity and all other functions of IT, while improving the end-user experience and productivity. Leveraging the open-source Chromium project that all major browsers are based on, Island provides fine-grain policy control over every facet of a user’s interaction with a web application giving the enterprise limitless visibility, control, and compliance with their most critical applications. As a result, Island can serve as the platform for the future of productive and secured work.

The Island Browser integration for Elastic allows you to collect logs using [Island Browser API](https://documentation.island.io/apidocs), then visualise the data in Kibana.

### Compatibility

The Island Browser integration is compatible with `v1` version of Island Browser API.

### How it works

This integration periodically queries the Island Browser API to retrieve details for users, devices and compromised credentials.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Compromised Credential`: Collects a list of all compromised credentials from the Island Browser via [Compromised Credential API endpoint](https://documentation.island.io/apidocs/get-a-list-of-all-compromised-credentials).
- `Device`: Collects a list of all devices from the Island Browser via [Device API endpoint](https://documentation.island.io/apidocs/get-a-list-of-all-devices-1).
- `User`: Collects all the users from the Island Browser via [User API endpoint](https://documentation.island.io/apidocs/get-all-browser-users-that-match-the-specified-simple-filter).

### Supported use cases

Integrating Island Browser User, Device, and Compromised Credential data streams with Elastic SIEM provides a holistic view of identity posture, endpoint activity, and credential exposure.

Dashboards monitor user metrics such as total and active accounts, login trends, and group distributions, alongside device insights including activity status, archived or jailbroken states, OS platform coverage, policy updates, browser version compliance, and risk indicators. Compromised credential dashboards enrich this context by surfacing unresolved exposures over time, breach sources, impacted domains, and top affected users. Saved searches and tables provide essential investigation details such as verified emails, IDs, IPs, MAC addresses, and user associations enabling analysts to detect anomalies, prioritize unresolved risks, investigate efficiently, and strengthen security oversight across identities, endpoints, and credential hygiene.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Island Browser

To collect data through the Island Browser APIs, `Admin` role must be required and admin must have permission to generate and manage API keys (i.e. full admin, system admin). Authentication is handled using a `API Key`, which serve as the required credentials.

#### Generate an `API Key`:

1. Log in to Island Browser Management Console.
2. From the **Island Management Console**, navigate to **Modules > Platform Settings > System Settings > Integrations > API**.
3. Click **+ Create**. The **Create API Key** drawer is displayed to assist in the key creation.
4. Enter a **Name**.
5. Select the **Role** that applies to this API key (i.e. Full Admin, or Read Only).
6. Click **Generate API Key**.
7. Copy the **API Key** to your clipboard to be used when using the [API Explorer](https://documentation.island.io/v1-api/apidocs/introduction-to-the-api-explorer).
8. Click **Save**.

For more details, check [Documentation](https://documentation.island.io/apidocs/generate-and-manage-api-keys).

>**Note**: If an API key already exists and you need to create a new one, you must first deactivate and delete the existing key by selecting **Deactivate and Delete API Key**.


## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Island Browser**.
3. Select the **Island Browser** integration from the search results.
4. Select **Add Island Browser** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs from Island Browser API**, you'll need to:

        - Configure **URL** and **API Key**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the Interval, Batch Size etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **island_browser**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **island_browser**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### User

{{fields "user"}}

#### Device

{{fields "device"}}

#### Compromised Credential

{{fields "compromised_credential"}}

### Example event

#### User

{{event "user"}}

#### Device

{{event "device"}}

#### Compromised Credential

{{event "compromised_credential"}}

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following APIs:

- `User`: [Island Browser API](https://documentation.island.io/apidocs/get-all-browser-users-that-match-the-specified-simple-filter).
- `Device`: [Island Browser API](https://documentation.island.io/apidocs/get-a-list-of-all-devices-1).
- `Compromised Credential`: [Island Browser API](https://documentation.island.io/apidocs/get-a-list-of-all-compromised-credentials).

#### ILM Policy

To facilitate user and device data, source data stream-backed indices `.ds-logs-island_browser.user-*` and `.ds-logs-island_browser.device-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-island_browser.user-default_policy` and `logs-island_browser.device-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
