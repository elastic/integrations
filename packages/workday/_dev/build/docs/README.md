# Workday

## Overview

[Workday](https://www.workday.com/en-in/homepage.html) is a cloud-based ERP system that manages business processes and allows organizations to use an integrated application. Workday is a coherent cloud ERP system for financial analysis, analytical solutions, HCM suites, and better business processes.

The Workday integration for Elastic collects `Activity Logs` via **API** and visualizes them in Kibana.

### Compatibility

The Workday integration is compatible with API version **v1**.

### How it works

This integration periodically queries the Workday API to retrieve logs.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Activity`: Collects [Activity Logs](https://community.workday.com/sites/default/files/file-hosting/restapi/#privacy/v1/get-/activityLogging) logs via Workday API (endpoint: `/activityLogging`).

### Supported use cases

Integrating Workday with Elastic gives security and IT teams centralized visibility into **Workday activity logging**, so you can monitor configuration and usage changes, support audits, and investigate suspicious behavior from Kibana.

The **Activity** dashboard summarizes key patterns such as **activity volume over time** and **top actors**, helping you spot unusual spikes and focus on the users and operations that matter.

Built-in filters make it easier to narrow events by attributes such as **task**, **system account**, and **IP address**, which supports faster triage and a more consistent investigation workflow across your Workday telemetry.

## What do I need to use this integration?

### From Workday

#### Collect Workday API credentials

##### Enable User Activity Logging

1. Sign in to your Workday tenant as a Security Administrator.
2. In the Workday search bar, search for and open the Edit Tenant Setup - System task.
3. In the Security section, select the Enable User Activity Logging checkbox.
4. Click OK to save the changes.

**Note:** Once enabled, Workday records all user activity in a secure tenant database. Activity logging must be enabled before any logs are available for export.

#### Create Integration System User (ISU)

1. In the Workday search bar, search for Create Integration System User.
2. Enter a User Name (for example, ISU_SIEM_Export) and a strong Password.
3. Clear the Require New Password at Next Sign In checkbox.
4. Click OK.
5. Search for Create Security Group and create an Integration System Security Group (Unconstrained).
6. Add the ISU (ISU_SIEM_Export) to this security group.
7. Search for View Domain and locate the User Activity Logging domain. Grant Get access to the ISU security group for this domain.
8. Search for Activate Pending Security Policy Changes and activate the changes.

#### Register API client for OAuth

1. In the Workday search bar, search for Register API Client for Integrations.
2. Enter a Client Name (for example, SIEM_OAuth_Client).
3. Select the Non-Expiring Refresh Tokens option.
4. Add the scope: System (or the scope required for User Activity Logging API).
5. Click OK.
6. Copy and save the following details in a secure location:
   - Client ID: The API client identifier.
   - Client Secret: The API client secret.
7. Search for Manage Refresh Tokens for Integrations.
8. Select the ISU account (ISU_SIEM_Export).
9. Generate a new refresh token for the API client.
10. Copy and save the Refresh Token.

#### Determine tenant URL

The API endpoint is based on your Workday tenant. The format is:

Component   | Value

Token endpoint | https://HOST/ccx/oauth2/TENANT/token

Activity Logging API |	https://HOST/ccx/api/privacy/v1/TENANT/activityLogging

**Note:** Replace HOST with your Workday hostname and TENANT with your tenant name.

**Note:** For additional Workday API security context, see [Generating API Keys for the Workday API](https://workday.my.site.com/customercenter/article?no=000013105&redirect=false).

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Configure the integration

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Workday**.
3. Select the **Workday** integration from the search results.
4. Select **Add Workday** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect Workday logs via API**, you'll need to:

        - Configure **Hostname**.
        - Configure **Tenant**.
        - Configure **Client ID**.
        - Configure **Client Secret**.
        - Configure **Refresh Token**.
        - Adjust the integration configuration parameters if required, including the **Interval**, **Initial Interval**, **Preserve original event** etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Workday**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Activity

{{fields "activity"}}

### Example event

#### Activity

{{event "activity"}}

### Inputs used

These input is used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following Workday API:

**Activity**: [Workday Activity API documentation](https://community.workday.com/sites/default/files/file-hosting/restapi/#privacy/v1/get-/activityLogging).
