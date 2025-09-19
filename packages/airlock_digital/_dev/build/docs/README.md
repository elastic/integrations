# Airlock Digital Integration for Elastic

## Overview

[Airlock Digital](https://www.airlockdigital.com/) delivers an easy-to-manage and scalable application control solution to protect endpoints with confidence. Built by cybersecurity professionals and trusted by organizations worldwide, Airlock Digital enforces a Deny by Default security posture to block all untrusted code, including unknown applications, unwanted scripts, malware, and ransomware.

The Airlock Digital integration for Elastic allows you to collect logs from, [Airlock Digital REST API](https://api.airlockdigital.com/), then visualise the data in Kibana.

### Compatibility

The Airlock Digital integration is compatible with version `v6.1.x` of Airlock Digital and `v1` of the REST API.

### How it works

This integration periodically queries the Airlock Digital REST API to retrieve Execution Histories.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Execution Histories`: Collects executions history logs via [Airlock Digital REST API](https://api.airlockdigital.com/#3634a82d-eb6b-44b7-b662-dddc37d4d9d6).

### Supported use cases
Integrating Airlock Digital’s execution history logs into Elastic SIEM gives SOC teams deep visibility into endpoint activity, allowing seamless tracking of blocked or untrusted executions, policy violations, and execution patterns to accelerate investigations, strengthen compliance, and enhance endpoint security.

## What do I need to use this integration?

### From Airlock Digital

#### To collect data from the REST API:

1. In order to make the API calls, the User Group to which a user belongs should contain required permissions. You can follow the below steps for that:
2. Go to the **Settings** and navigate to **Users** tab.
3. Under **User Group Management** for the respective user group provide **logging/exechistories** roles in the REST API Roles section and click on save.

#### Generate Client API key for Authentication:

1. Log in to your Airlock console.
2. On the right side of the navigation bar, click on the dropdown with the user’s name and navigate to **My profile** section.
3. Click on the **Generate API Key** button.
4. Copy the displayed API key — it will be required later for configuration.

For more details, check [Documentation](https://api.airlockdigital.com/).

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Airlock Digital**.
3. Select the **Airlock Digital** integration from the search results.
4. Select **Add Airlock Digital** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect Airlock Digital logs via API**, you'll need to:

        - Configure **URL** and **API Key**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the Interval, Preserve original event etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Airlock Digital**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Execution Histories

{{fields "execution_histories"}}

### Example event

#### Execution Histories

{{event "execution_histories"}}

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

These integration datasets use the following API:

- `Execution Histories`: [Airlock Digital REST API](https://api.airlockdigital.com/#3634a82d-eb6b-44b7-b662-dddc37d4d9d6). Supported execution types are:
    - Trusted Execution
    - Blocked Execution
    - Untrusted Execution [Audit]
    - Untrusted Execution [OTP]
    - Trusted Path Execution
    - Trusted Publisher Execution
    - Blocklist Execution
    - Blocklist Execution [Audit]
    - Trusted Process Execution
    - Constrained Execution
    - Trusted Metadata Execution
    - Trusted Browser Execution
    - Blocked Browser Execution
    - Untrusted Browser Execution [Audit]
    - Untrusted Browser Execution [OTP]
    - Blocklist Browser Execution [Audit]
    - Blocklist Browser Execution
    - Trusted Installer Execution
    - Trusted Browser Metadata Execution
