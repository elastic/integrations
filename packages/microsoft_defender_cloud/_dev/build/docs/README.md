# Microsoft Defender for Cloud Integration for Elastic

## Overview

The [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction) integration allows you to monitor security alert events and assessments. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for analyzing the resources and services that users are protecting through Microsoft Defender.

Use the Microsoft Defender for Cloud integration to collect and parse data from Azure Event Hub, Azure REST API, and then visualize that data in Kibana.

### Compatibility

The Microsoft Defender for Cloud integration uses the Azure REST API. It uses the `2021-06-01` API version for retrieving assessments and the `2019-01-01-preview` API version for retrieving sub-assessments.

### How it works

For the **assessment** data stream, the `/assessments` endpoint retrieves all available assessments for the provided scope, which can be a Subscription ID or a Management Group Name. For each assessment, if sub-assessments are available, we will make another call to collect them. We will aggregate the results from both calls and publish them.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Event`: allows users to preserve a record of security events that occurred on the subscription, which includes real-time events that affect the security of the user's environment. For further information connected to security alerts and type, Refer to the page [here](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference).
- `Assessment`: collect security assessments on all your scanned resources inside a scope via [Assessments endpoint](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/assessments/list?view=rest-defenderforcloud-composite-latest&tabs=HTTP) & [Sub Assessments endpoint](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/sub-assessments/list?view=rest-defenderforcloud-composite-latest&tabs=HTTP).

### Supported use cases
Integrating Microsoft Defender for Cloud with Elastic SIEM provides advanced threat protection and security assessments for your cloud services. It monitors security events in real-time, offers actionable recommendations to improve your security posture, and helps ensure compliance with industry standards. Leveraging Defender for Cloud integration allows organizations to enhance their cloud security and mitigate potential risks.

## What do I need to use this integration?

### From Elastic

Version 3.0.0 of the Microsoft Defender for Cloud integration adds [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Microsoft Defender for Cloud

Configure the Microsoft Defender for Cloud on Azure subscription. For more detail, refer to the link [here](https://learn.microsoft.com/en-us/azure/defender-for-cloud/get-started).

#### 1. Collecting Data from Microsoft Azure Event Hub

- [Configure continuous export to stream security events to your Azure Event Hub](https://learn.microsoft.com/en-us/azure/defender-for-cloud/continuous-export).

#### 2. Collecting Data from Microsoft Defender for Endpoint API
To allow the integration to ingest data from the Microsoft Defender API, you need to create a new application on your Azure domain. The procedure to create an application is found on the [Create a new Azure Application](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-create-app-webapp) documentation page.

- [Register a new Azure Application](https://learn.microsoft.com/en-us/rest/api/azure/?view=rest-defenderforcloud-composite-latest#register-your-client-application-with-microsoft-entra-id).
- Assign the required permission: **user_impersonation** in Azure Service Management.
- Once the application is registered, note the following values for use during configuration:
  - Client ID
  - Client Secret
  - Tenant ID

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Microsoft Defender for Cloud**.
3. Select the **Microsoft Defender for Cloud** integration from the search results.
4. Select **Add Microsoft Defender for Cloud** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect Microsoft Defender Cloud logs via API**, you'll need to:

        - Configure **Client ID**, **Client Secret** and **Tenant ID**. Configure either **Subscription ID** or **Management Group Name** as the scope.
        - Adjust the integration configuration parameters if required, including the **Interval**, to enable data collection.
    * To **Collect logs from Azure Event Hub**, you'll need to:

        - Configure **Azure Event Hub**, **Connection String**, **Storage Account**, and **storage_account_key**.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **microsoft_defender_cloud**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **microsoft_defender_cloud**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Event

{{fields "event"}}

#### Assessment

{{fields "assessment"}}

### Example event

#### Assessment

{{event "assessment"}}

### Inputs used

These inputs are used in this integration:

- [azure-eventhub](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-azure-eventhub)
- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following APIs:

- `Assessments`: [Azure REST API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/assessments/list?view=rest-defenderforcloud-composite-latest&tabs=HTTP).
- `Sub Assessments`: [Azure REST API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/sub-assessments/list?view=rest-defenderforcloud-composite-latest&tabs=HTTP).

#### ILM Policy

To facilitate assessment data, source data stream-backed indices `.ds-logs-microsoft_defender_cloud.assessment-*` is allowed to contain duplicates from each polling interval. ILM policy `logs-microsoft_defender_cloud.assessment-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
