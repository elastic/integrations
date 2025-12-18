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

- `Identity`: Collect details of all identity assets including:
    - users (endpoint: `/api/v2/users`)
    - groups (endpoint: `/api/v2/groups`)
    - security_roles (endpoint: `/api/v2/security_roles`)
    - organizational_units (endpoint: `/api/v2/organizational_units`)
    - accounts (endpoint: `/api/v2/accounts`)
    - certificates (endpoint: `/api/v2/certificates`)
    - permissions (endpoint: `/api/v2/permissions`)
    - latest_rules (endpoint: `/api/v2/latest_rules`)
    - profiles (endpoint: `/api/v2/profiles`)
    - job_titles (endpoint: `/api/v2/job_titles`)
    - access_review_campaign_instances (endpoint: `/api/v2/access_review_campaign_instances`)
    - access_review_approval_items (endpoint: `/api/v2/access_review_approval_items`)

### Supported use cases

Integrating the Axonius Identity Datastream with Elastic SIEM provides a unified view of users, groups, roles, organizational units, accounts, permissions, certificates, profiles, and access-review activity. Metrics and breakdowns help teams quickly assess identity posture by highlighting active, inactive, suspended, and external users, as well as patterns across user types and departments.

Tables showing top email addresses and cloud providers add context into frequently used identities and their sources. These insights help security and IAM teams detect identity anomalies, validate account hygiene, and maintain strong visibility into access across the organization.

## What do I need to use this integration?

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

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Identity

The `identity` data stream provides identity asset logs from axonius.

#### identity fields

{{ fields "identity" }}

{{event "identity"}}

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}

### API usage

These APIs are used with this integration:

* Identity:
    * users (endpoint: `/api/v2/users`)
    * groups (endpoint: `/api/v2/groups`)
    * security_roles (endpoint: `/api/v2/security_roles`)
    * organizational_units (endpoint: `/api/v2/organizational_units`)
    * accounts (endpoint: `/api/v2/accounts`)
    * certificates (endpoint: `/api/v2/certificates`)
    * permissions (endpoint: `/api/v2/permissions`)
    * latest_rules (endpoint: `/api/v2/latest_rules`)
    * profiles (endpoint: `/api/v2/profiles`)
    * job_titles (endpoint: `/api/v2/job_titles`)
    * access_review_campaign_instances (endpoint: `/api/v2/access_review_campaign_instances`)
    * access_review_approval_items (endpoint: `/api/v2/access_review_approval_items`)
