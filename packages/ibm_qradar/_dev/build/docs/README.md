# IBM QRadar Integration for Elastic

## Overview

[IBM QRadar](https://www.ibm.com/docs/en/qsip/7.5) is a Security Intelligence Platform that provides a unified architecture for integrating security information and event management (SIEM), log management, anomaly detection, incident forensics, and configuration and vulnerability management.

The IBM QRadar integration for Elastic allows you to collect logs using [IBM QRadar API](https://ibmsecuritydocs.github.io/qradar_api_20.0), then visualise the data in Kibana.

### Compatibility

The IBM QRadar integration is compatible with QRadar API version **20.0**.

### How it works

This integration periodically queries the QRadar API to retrieve logs.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Offense`: collect offense records from the [Offenses](https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--siem-offenses-GET.html) and [Rules](https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--analytics-rules-GET.html) endpoints, with rule data enriched into the offenses to provide additional context.

### Supported use cases
Integrating IBM QRadar with Elastic SIEM provides deep visibility into security offenses and their underlying context. Kibana dashboards track active and protected offenses, with metrics. Bar and pie charts highlight offense severity and status distribution, helping analysts quickly prioritize investigations.

Tables showcase the top contributing elements including rule types, assignees, log source types, log source names, and offense sources. A saved search of essential offense attributes IDs, severity, descriptions, categories, status, rules, assignees, activation and protection details ensures investigations are enriched with the necessary context.

These insights empower analysts to monitor offense activity, identify high-risk areas, and accelerate threat detection and response workflows.


## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From IBM QRadar

To collect data through the IBM QRadar APIs, you need to create an **Authorized Service Token** with sufficient permissions. Authentication is handled using an **Authorized Service Token**, which serves as the required credential.

#### Generate an Authorized Service Token:

1. Log in to the **QRadar Console** with an admin account.
2. Go to the **Admin** tab, and in the **User Management** section, click **Authorized Services**.
3. In the Authorized Services window, click **Add Authorized Service**.
4. Fill in the following fields:
   - **Service Name**: Provide a descriptive name for this service.
   - **User Role**: Select the appropriate user role.
   - **Security Profile**: Assign the security profile to define which networks and log sources this service can access.
   - **Expiry Date**: Choose a date for the token to expire, or select **No Expiry** if indefinite use is required.
5. Click **Create Service**.
6. Select the row for the service you created, then copy the **token string** from the **Selected Token** field.
7. Close the Authorized Services window.
8. On the **Admin** tab, click **Deploy Changes** to apply the configuration.

For more details, see [IBM Documentation](https://www.ibm.com/docs/en/qsip/7.5?topic=services-creating-authorized-service).

## How do I deploy this integration?

This integration supports both Elastic Managed and Agent-based installations.

### Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **IBM QRadar**.
3. Select the **IBM QRadar** integration from the search results.
4. Select **Add IBM QRadar** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs from QRadar API**, you'll need to:

        - Configure **URL** and **Authorized Service Token**.
        - Adjust the integration configuration parameters if required, including the Interval, Batch Size etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **IBM QRadar**, and verify the dashboard information is populated.

#### Transform healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **ibm_qradar**.
4. Transform from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Offense

{{fields "offense"}}

### Example event

#### Offense

{{event "offense"}}

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following API:

- `Offense`: [QRadar Offense API](https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--siem-offenses-GET.html).
- `Rule`: [QRadar Rule API](https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--analytics-rules-GET.html).
