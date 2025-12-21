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

- `Application`: Collect details of all application assets including:
    - software (endpoint: `/api/v2/software`)
    - saas_applications (endpoint: `/api/v2/saas_applications`)
    - application_settings (endpoint: `/api/v2/application_settings`)
    - licenses (endpoint: `/api/v2/licenses`)
    - expenses (endpoint: `/api/v2/expenses`)
    - admin_managed_extensions (endpoint: `/api/v2/admin_managed_extensions`)
    - user_initiated_extensions (endpoint: `/api/v2/user_initiated_extensions`)
    - application_addons (endpoint: `/api/v2/application_addons`)
    - admin_managed_extension_instances (endpoint: `/api/v2/admin_managed_extension_instances`)
    - user_initiated_extension_instances (endpoint: `/api/v2/user_initiated_extension_instances`)
    - application_addon_instances (endpoint: `/api/v2/application_addon_instances`)
    - application_keys (endpoint: `/api/v2/application_keys`)
    - audit_activities (endpoint: `/api/v2/audit_activities`)
    - business_applications (endpoint: `/api/v2/business_applications`)
    - urls (endpoint: `/api/v2/urls`)
    - application_services (endpoint: `/api/v2/application_services`)
    - application_resources (endpoint: `/api/v2/application_resources`)
    - secrets (endpoint: `/api/v2/secrets`)

### Supported use cases

Integrating the Axonius Application Datastream with Elastic SIEM provides clear visibility into application related activity and usage across the environment. This datastream helps analysts understand how business applications and installed software are being used, where activity is occurring, and which applications are most active or impactful.

It offers consolidated views of business applications, installed software, sources, users, and domains, enabling teams to quickly validate application activity, assess risk especially for SaaS applications and understand how events are distributed across asset types and actions. Time based trends and activity status insights help identify spikes, dormant applications, or unusual behavior patterns.

These insights enable organizations to monitor application usage, detect risky or unauthorized application activity, maintain accurate application inventories, and support investigations where application related context is critical.

## What do I need to use this integration?

### From Axonius

To collect data through the Axonius APIs, you need to provide the **URL**, **API Key** and **API Secret**. Authentication is handled using the **API Key** and **API Secret**, which serves as the required credential.

#### Retrieve URL, API Token and API Secret:

1. Log in to the **Axonius** instance.
2. Your instance URL is your Base **URL**.
3. Navigate to **User Settings > API Key**.
4. Generate an **API Key**.
5. If you don’t see the API Key tab in your user settings, follow these steps:
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


### Inputs used

These inputs can be used with this integration:
<details>
<summary>cel</summary>

## Setup

For more details about the CEL input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html).

Before configuring the CEL input, make sure you have:
- Network connectivity to the target API endpoint
- Valid authentication credentials (API keys, tokens, or certificates as required)
- Appropriate permissions to read from the target data source

### Collecting logs from CEL

To configure the CEL input, you must specify the `request.url` value pointing to the API endpoint. The interval parameter controls how frequently requests are made and is the primary way to balance data freshness with API rate limits and costs. Authentication is often configured through the `request.headers` section using the appropriate method for the service.

NOTE: To access the API service, make sure you have the necessary API credentials and that the Filebeat instance can reach the endpoint URL. Some services may require IP whitelisting or VPN access.

To collect logs via API endpoint, configure the following parameters:

- API Endpoint URL
- API credentials (tokens, keys, or username/password)
- Request interval (how often to fetch data)
</details>


### API usage

These APIs are used with this integration:

* Application:
    * software (endpoint: `/api/v2/software`)
    * saas_applications (endpoint: `/api/v2/saas_applications`)
    * application_settings (endpoint: `/api/v2/application_settings`)
    * licenses (endpoint: `/api/v2/licenses`)
    * expenses (endpoint: `/api/v2/expenses`)
    * admin_managed_extensions (endpoint: `/api/v2/admin_managed_extensions`)
    * user_initiated_extensions (endpoint: `/api/v2/user_initiated_extensions`)
    * application_addons (endpoint: `/api/v2/application_addons`)
    * admin_managed_extension_instances (endpoint: `/api/v2/admin_managed_extension_instances`)
    * user_initiated_extension_instances (endpoint: `/api/v2/user_initiated_extension_instances`)
    * application_addon_instances (endpoint: `/api/v2/application_addon_instances`)
    * application_keys (endpoint: `/api/v2/application_keys`)
    * audit_activities (endpoint: `/api/v2/audit_activities`)
    * business_applications (endpoint: `/api/v2/business_applications`)
    * urls (endpoint: `/api/v2/urls`)
    * application_services (endpoint: `/api/v2/application_services`)
    * application_resources (endpoint: `/api/v2/application_resources`)
    * secrets (endpoint: `/api/v2/secrets`)

#### ILM Policy

To facilitate application data, source data stream-backed indices `.ds-logs-axonius.application-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-axonius.application-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.