# SentinelOne Integration for Elastic

## Overview

The [SentinelOne](https://www.sentinelone.com/) integration collects and parses data from SentinelOne REST APIs. This integration also offers the capability to perform response actions on SentinelOne hosts directly through the Elastic Security interface (introduced with v8.12.0). Additional configuration is required; for detailed guidance, refer to [documentation](https://www.elastic.co/guide/en/security/current/response-actions-config.html).

### Compatibility

This module has been tested against `SentinelOne Management Console API version 2.1`.

### How it works

This integration periodically queries the SentinelOne REST API to retrieve Activity, Agent, Alert, Application, Application Risk, Group, Threat and Threat Event logs.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Activity`: Captures general actions or events occurring within the SentinelOne environment, such as policy updates or administrative operations.
- `Agent`: Provides details about endpoint agents, including their status, configuration, and activity on protected devices.
- `Alert`: Represents security notifications triggered by detected suspicious or malicious activity requiring attention.
- `Application`: Logs information about installed or executed applications identified on endpoints.
- `Application Risk`: Assesses and records the risk level or reputation of discovered applications based on behavior and source.
- `Group`: Contains configuration and status information for endpoint groups within a site or tenant.
- `Threat`: Logs confirmed malicious detections, such as malware, exploits, or ransomware identified by SentinelOne.
- `Threat Event`: Provides detailed event-level information related to a specific threat, including process, file, and network indicators.

### Supported use cases
Integrating SentinelOne Activity, Agent, Alert, Application, Application Risk, Group, Threat, and Threat Event logs with Elastic SIEM provides centralized visibility across endpoint operations and security events. Dashboards deliver insights into agent status, detections, application behavior, and threat lifecycle, helping SOC teams quickly identify malicious activity, enforce policy compliance, and accelerate investigation and response efforts.

## What do I need to use this integration?

### From SentinelOne

To collect data from SentinelOne APIs, you must have an API token. To create an API token, follow these steps:

  1. Log in to the **SentinelOne Management Console** as an **Admin**.
  ![SentinelOne dashboards](../img/sentinel-one-dashboard.png)
  2. Navigate to **Logged User Account** from top right panel in the navigation bar.
  3. Click **My User**.
  4. In the API token section, navigate to **Actions** > **API Token Operators** > **Generate API Token**.  
  ![SentinelOne generate API token ](../img/sentinel-one-api-token-generate.png)
  5. Enter the MFA code, if enabled.
  ![SentinelOne generate MFA Code ](../img/sentinel-one-mfa-code.png)
  6. You will see the API token on the screen.

**Permissions Required for the Role Attached to the User**

| **Data Stream**   | **Permission**                  |
|-------------------|---------------------------------|
| Activity          | Activity -> view                |
| Agent             | Endpoints -> view               |
| Alert             | STAR Rule Alerts -> view        |
| Application       | Applications -> view            |
| Application Risk  | Applications -> viewRisks       |
| Group             | Groups -> view                  |
| Threat            | Threats -> view                 |
| Threat Event      | Threats -> view                 |

## Note

The **alert** data stream depends on STAR Custom Rules. STAR Custom Rules are supported in Cloud environments, but are not supported in on-premises environments. Because of this, the **alert** data stream is not supported in on-premises environments.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Troubleshooting

- The API token generated by the user is time-limited. The user must reconfigure a new API token before it expires.
  - For console users, the default expiration time limit is 30 days.
  - For service users, the expiration time limit is the same as the duration specified while generating the API token.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **SentinelOne**.
3. Select the **SentinelOne** integration from the search results.
4. Select **Add SentinelOne** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect SentinelOne logs via API**, you'll need to:

        - Configure **URL** and **API Token**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the Interval, Preserve original event etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **SentinelOne**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Logs reference

### activity

This is the `activity` dataset.

{{event "activity"}}

{{fields "activity"}}

### agent

This is the `agent` dataset.

{{event "agent"}}

{{fields "agent"}}

### alert

This is the `alert` dataset.

{{event "alert"}}

{{fields "alert"}}

### application

This is the `application` dataset.

{{event "application"}}

{{fields "application"}}

### application risk

This is the `application risk` dataset.

{{event "application_risk"}}

{{fields "application_risk"}}

### group

This is the `group` dataset.

{{event "group"}}

{{fields "group"}}

### threat

This is the `threat` dataset.

{{event "threat"}}

{{fields "threat"}}

### threat event

This is the `threat event` dataset.

{{event "threat_event"}}

{{fields "threat_event"}}
