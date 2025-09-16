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

- `Event`: allows users to preserve a record of security events that occurred on the subscription, which includes real-time events that affect the security of the user's environment. For further information connected to security alerts and type, refer to the [security alerts reference guide](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference).
- `Assessment`: collect security assessments on all your scanned resources inside a scope from the [Assessments](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/assessments/list?view=rest-defenderforcloud-composite-latest&tabs=HTTP) and [Sub Assessments](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/sub-assessments/list?view=rest-defenderforcloud-composite-latest&tabs=HTTP) endpoints.

### Supported use cases
Integrating Microsoft Defender for Cloud with Elastic SIEM provides advanced threat protection and security assessments for your cloud services. It monitors security events in real time, offers actionable recommendations to improve your security posture, and helps ensure compliance with industry standards. Leveraging Defender for Cloud integration allows organizations to enhance their cloud security and mitigate potential risks.

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
- Assign the built-in **Reader** role to the new application for the required scope, which will be used in the API to retrieve the assessments. For more details, check out the [role assignment using the Azure portal](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal) documentation.
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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| microsoft_defender_cloud.event.agent_id |  | keyword |
| microsoft_defender_cloud.event.alert_type | Unique identifier for the detection logic (all alert instances from the same detection logic will have the same alertType). | keyword |
| microsoft_defender_cloud.event.assessment_event_data_enrichment.action |  | keyword |
| microsoft_defender_cloud.event.assessment_event_data_enrichment.api_version |  | keyword |
| microsoft_defender_cloud.event.assessment_event_data_enrichment.is_snapshot |  | boolean |
| microsoft_defender_cloud.event.azure_resource_id |  | keyword |
| microsoft_defender_cloud.event.compromised_entity | The display name of the resource most related to this alert. | keyword |
| microsoft_defender_cloud.event.confidence.level |  | keyword |
| microsoft_defender_cloud.event.confidence.reasons |  | keyword |
| microsoft_defender_cloud.event.confidence.score |  | keyword |
| microsoft_defender_cloud.event.correlation_key | Key for corelating related alerts. Alerts with the same correlation key considered to be related. | keyword |
| microsoft_defender_cloud.event.description | Description of the suspicious activity that was detected. | keyword |
| microsoft_defender_cloud.event.display_name | The display name of the alert. | keyword |
| microsoft_defender_cloud.event.end_time_utc | The UTC time of the last event or activity included in the alert in ISO8601 format. | date |
| microsoft_defender_cloud.event.entities.aad_tenant_id |  | keyword |
| microsoft_defender_cloud.event.entities.aad_user_id |  | keyword |
| microsoft_defender_cloud.event.entities.account.ref |  | keyword |
| microsoft_defender_cloud.event.entities.address |  | ip |
| microsoft_defender_cloud.event.entities.algorithm |  | keyword |
| microsoft_defender_cloud.event.entities.amazon_resource_id |  | keyword |
| microsoft_defender_cloud.event.entities.asset |  | boolean |
| microsoft_defender_cloud.event.entities.azure_id |  | keyword |
| microsoft_defender_cloud.event.entities.blob_container.ref |  | keyword |
| microsoft_defender_cloud.event.entities.category |  | keyword |
| microsoft_defender_cloud.event.entities.cloud_resource.ref |  | keyword |
| microsoft_defender_cloud.event.entities.cluster.ref |  | keyword |
| microsoft_defender_cloud.event.entities.command_line |  | keyword |
| microsoft_defender_cloud.event.entities.container_id |  | keyword |
| microsoft_defender_cloud.event.entities.creation_time_utc |  | date |
| microsoft_defender_cloud.event.entities.directory |  | keyword |
| microsoft_defender_cloud.event.entities.dns_domain |  | keyword |
| microsoft_defender_cloud.event.entities.domain_name |  | keyword |
| microsoft_defender_cloud.event.entities.elevation_token |  | keyword |
| microsoft_defender_cloud.event.entities.end_time_utc |  | date |
| microsoft_defender_cloud.event.entities.etag |  | keyword |
| microsoft_defender_cloud.event.entities.file_hashes.algorithm |  | keyword |
| microsoft_defender_cloud.event.entities.file_hashes.asset |  | boolean |
| microsoft_defender_cloud.event.entities.file_hashes.id |  | keyword |
| microsoft_defender_cloud.event.entities.file_hashes.ref |  | keyword |
| microsoft_defender_cloud.event.entities.file_hashes.type |  | keyword |
| microsoft_defender_cloud.event.entities.file_hashes.value |  | keyword |
| microsoft_defender_cloud.event.entities.files.ref |  | keyword |
| microsoft_defender_cloud.event.entities.host.ref |  | keyword |
| microsoft_defender_cloud.event.entities.host_ip_address.ref |  | keyword |
| microsoft_defender_cloud.event.entities.host_name |  | keyword |
| microsoft_defender_cloud.event.entities.id |  | keyword |
| microsoft_defender_cloud.event.entities.image.ref |  | keyword |
| microsoft_defender_cloud.event.entities.image_file.ref |  | keyword |
| microsoft_defender_cloud.event.entities.image_id |  | keyword |
| microsoft_defender_cloud.event.entities.ip_addresses.address |  | ip |
| microsoft_defender_cloud.event.entities.ip_addresses.asset |  | boolean |
| microsoft_defender_cloud.event.entities.ip_addresses.id |  | keyword |
| microsoft_defender_cloud.event.entities.ip_addresses.location.asn |  | long |
| microsoft_defender_cloud.event.entities.ip_addresses.location.city |  | keyword |
| microsoft_defender_cloud.event.entities.ip_addresses.location.country_code |  | keyword |
| microsoft_defender_cloud.event.entities.ip_addresses.location.country_name |  | keyword |
| microsoft_defender_cloud.event.entities.ip_addresses.location.latitude |  | double |
| microsoft_defender_cloud.event.entities.ip_addresses.location.longitude |  | double |
| microsoft_defender_cloud.event.entities.ip_addresses.location.state |  | keyword |
| microsoft_defender_cloud.event.entities.ip_addresses.type |  | keyword |
| microsoft_defender_cloud.event.entities.is_domain_joined |  | boolean |
| microsoft_defender_cloud.event.entities.is_valid |  | boolean |
| microsoft_defender_cloud.event.entities.location.asn |  | long |
| microsoft_defender_cloud.event.entities.location.carrier |  | keyword |
| microsoft_defender_cloud.event.entities.location.city |  | keyword |
| microsoft_defender_cloud.event.entities.location.cloud_provider |  | keyword |
| microsoft_defender_cloud.event.entities.location.country_code |  | keyword |
| microsoft_defender_cloud.event.entities.location.country_name |  | keyword |
| microsoft_defender_cloud.event.entities.location.latitude |  | double |
| microsoft_defender_cloud.event.entities.location.longitude |  | double |
| microsoft_defender_cloud.event.entities.location.organization |  | keyword |
| microsoft_defender_cloud.event.entities.location.organization_type |  | keyword |
| microsoft_defender_cloud.event.entities.location.state |  | keyword |
| microsoft_defender_cloud.event.entities.location.system_service |  | keyword |
| microsoft_defender_cloud.event.entities.location_type |  | keyword |
| microsoft_defender_cloud.event.entities.location_value |  | keyword |
| microsoft_defender_cloud.event.entities.logon_id |  | keyword |
| microsoft_defender_cloud.event.entities.name |  | keyword |
| microsoft_defender_cloud.event.entities.namespace.ref |  | keyword |
| microsoft_defender_cloud.event.entities.net_bios_name |  | keyword |
| microsoft_defender_cloud.event.entities.nt_domain |  | keyword |
| microsoft_defender_cloud.event.entities.object_guid |  | keyword |
| microsoft_defender_cloud.event.entities.oms_agent_id |  | keyword |
| microsoft_defender_cloud.event.entities.os_family |  | keyword |
| microsoft_defender_cloud.event.entities.os_version |  | keyword |
| microsoft_defender_cloud.event.entities.parent_process.ref |  | keyword |
| microsoft_defender_cloud.event.entities.pod.ref |  | keyword |
| microsoft_defender_cloud.event.entities.process_id |  | keyword |
| microsoft_defender_cloud.event.entities.project_id |  | keyword |
| microsoft_defender_cloud.event.entities.protocol |  | keyword |
| microsoft_defender_cloud.event.entities.ref |  | keyword |
| microsoft_defender_cloud.event.entities.related_azure_resource_ids |  | keyword |
| microsoft_defender_cloud.event.entities.resource_id |  | keyword |
| microsoft_defender_cloud.event.entities.resource_name |  | keyword |
| microsoft_defender_cloud.event.entities.resource_type |  | keyword |
| microsoft_defender_cloud.event.entities.session_id |  | keyword |
| microsoft_defender_cloud.event.entities.sid |  | keyword |
| microsoft_defender_cloud.event.entities.source_address.ref |  | keyword |
| microsoft_defender_cloud.event.entities.start_time_utc |  | date |
| microsoft_defender_cloud.event.entities.storage_resource.ref |  | keyword |
| microsoft_defender_cloud.event.entities.threat_intelligence.confidence |  | double |
| microsoft_defender_cloud.event.entities.threat_intelligence.description |  | keyword |
| microsoft_defender_cloud.event.entities.threat_intelligence.name |  | keyword |
| microsoft_defender_cloud.event.entities.threat_intelligence.provider_name |  | keyword |
| microsoft_defender_cloud.event.entities.threat_intelligence.report_link |  | keyword |
| microsoft_defender_cloud.event.entities.threat_intelligence.type |  | keyword |
| microsoft_defender_cloud.event.entities.type |  | keyword |
| microsoft_defender_cloud.event.entities.upn_suffix |  | keyword |
| microsoft_defender_cloud.event.entities.url |  | keyword |
| microsoft_defender_cloud.event.entities.value |  | keyword |
| microsoft_defender_cloud.event.event_type |  | keyword |
| microsoft_defender_cloud.event.extended_links.category | Links related to the alert | keyword |
| microsoft_defender_cloud.event.extended_links.href |  | keyword |
| microsoft_defender_cloud.event.extended_links.label |  | keyword |
| microsoft_defender_cloud.event.extended_links.type |  | keyword |
| microsoft_defender_cloud.event.extended_properties | Custom properties for the alert. | flattened |
| microsoft_defender_cloud.event.id | Resource Id. | keyword |
| microsoft_defender_cloud.event.intent | The kill chain related intent behind the alert. For list of supported values, and explanations of Azure Security Center's supported kill chain intents. | keyword |
| microsoft_defender_cloud.event.is_incident | This field determines whether the alert is an incident (a compound grouping of several alerts) or a single alert. | boolean |
| microsoft_defender_cloud.event.kind |  | keyword |
| microsoft_defender_cloud.event.location |  | keyword |
| microsoft_defender_cloud.event.name | Resource name. | keyword |
| microsoft_defender_cloud.event.processing_end_time | The UTC processing end time of the alert in ISO8601 format. | date |
| microsoft_defender_cloud.event.product.name | The name of the product which published this alert (Microsoft Sentinel, Microsoft Defender for Identity, Microsoft Defender for Endpoint, Microsoft Defender for Office, Microsoft Defender for Cloud Apps, and so on). | keyword |
| microsoft_defender_cloud.event.properties.additional_data |  | flattened |
| microsoft_defender_cloud.event.properties.assessment.definitions |  | keyword |
| microsoft_defender_cloud.event.properties.assessment.details_link |  | keyword |
| microsoft_defender_cloud.event.properties.assessment.type |  | keyword |
| microsoft_defender_cloud.event.properties.category |  | keyword |
| microsoft_defender_cloud.event.properties.definition.display_name |  | keyword |
| microsoft_defender_cloud.event.properties.definition.id |  | keyword |
| microsoft_defender_cloud.event.properties.definition.max_score |  | long |
| microsoft_defender_cloud.event.properties.definition.name |  | keyword |
| microsoft_defender_cloud.event.properties.definition.source_type |  | keyword |
| microsoft_defender_cloud.event.properties.definition.type |  | keyword |
| microsoft_defender_cloud.event.properties.description |  | keyword |
| microsoft_defender_cloud.event.properties.display_name |  | keyword |
| microsoft_defender_cloud.event.properties.environment |  | keyword |
| microsoft_defender_cloud.event.properties.failed_resources |  | long |
| microsoft_defender_cloud.event.properties.healthy_resource_count |  | long |
| microsoft_defender_cloud.event.properties.id |  | keyword |
| microsoft_defender_cloud.event.properties.impact |  | keyword |
| microsoft_defender_cloud.event.properties.links.azure_portal |  | keyword |
| microsoft_defender_cloud.event.properties.metadata.assessment_type |  | keyword |
| microsoft_defender_cloud.event.properties.metadata.categories |  | keyword |
| microsoft_defender_cloud.event.properties.metadata.description |  | keyword |
| microsoft_defender_cloud.event.properties.metadata.display_name |  | keyword |
| microsoft_defender_cloud.event.properties.metadata.implementation_effort |  | keyword |
| microsoft_defender_cloud.event.properties.metadata.policy_definition_id |  | keyword |
| microsoft_defender_cloud.event.properties.metadata.preview |  | boolean |
| microsoft_defender_cloud.event.properties.metadata.remediation_description |  | keyword |
| microsoft_defender_cloud.event.properties.metadata.severity |  | keyword |
| microsoft_defender_cloud.event.properties.metadata.threats |  | keyword |
| microsoft_defender_cloud.event.properties.metadata.user_impact |  | keyword |
| microsoft_defender_cloud.event.properties.not_applicable_resource_count |  | long |
| microsoft_defender_cloud.event.properties.passed_resources |  | long |
| microsoft_defender_cloud.event.properties.remediation |  | keyword |
| microsoft_defender_cloud.event.properties.resource_details.id |  | keyword |
| microsoft_defender_cloud.event.properties.resource_details.machine_name |  | keyword |
| microsoft_defender_cloud.event.properties.resource_details.source |  | keyword |
| microsoft_defender_cloud.event.properties.resource_details.source_computer_id |  | keyword |
| microsoft_defender_cloud.event.properties.resource_details.type |  | keyword |
| microsoft_defender_cloud.event.properties.resource_details.vm_uuid |  | keyword |
| microsoft_defender_cloud.event.properties.resource_details.workspace_id |  | keyword |
| microsoft_defender_cloud.event.properties.score.current |  | double |
| microsoft_defender_cloud.event.properties.score.max |  | long |
| microsoft_defender_cloud.event.properties.score.percentage |  | double |
| microsoft_defender_cloud.event.properties.skipped_resources |  | long |
| microsoft_defender_cloud.event.properties.state |  | keyword |
| microsoft_defender_cloud.event.properties.status.cause |  | keyword |
| microsoft_defender_cloud.event.properties.status.code |  | keyword |
| microsoft_defender_cloud.event.properties.status.description |  | keyword |
| microsoft_defender_cloud.event.properties.status.first_evaluation_date |  | date |
| microsoft_defender_cloud.event.properties.status.severity |  | keyword |
| microsoft_defender_cloud.event.properties.status.status_change_date |  | date |
| microsoft_defender_cloud.event.properties.status.type |  | keyword |
| microsoft_defender_cloud.event.properties.time_generated |  | date |
| microsoft_defender_cloud.event.properties.type |  | keyword |
| microsoft_defender_cloud.event.properties.unhealthy_resource_count |  | long |
| microsoft_defender_cloud.event.properties.weight |  | long |
| microsoft_defender_cloud.event.provider_alert_status |  | keyword |
| microsoft_defender_cloud.event.remediation_steps | Manual action items to take to remediate the alert. | keyword |
| microsoft_defender_cloud.event.resource_identifiers.aad_tenant_id |  | keyword |
| microsoft_defender_cloud.event.resource_identifiers.agent_id | (optional) The LogAnalytics agent id reporting the event that this alert is based on. | keyword |
| microsoft_defender_cloud.event.resource_identifiers.azure_id | ARM resource identifier for the cloud resource being alerted on | keyword |
| microsoft_defender_cloud.event.resource_identifiers.azure_tenant_id |  | keyword |
| microsoft_defender_cloud.event.resource_identifiers.id | The resource identifiers that can be used to direct the alert to the right product exposure group (tenant, workspace, subscription etc.). There can be multiple identifiers of different type per alert. | keyword |
| microsoft_defender_cloud.event.resource_identifiers.type | There can be multiple identifiers of different type per alert, this field specify the identifier type. | keyword |
| microsoft_defender_cloud.event.resource_identifiers.workspace_id | The LogAnalytics workspace id that stores this alert. | keyword |
| microsoft_defender_cloud.event.resource_identifiers.workspace_resource_group | The azure resource group for the LogAnalytics workspace storing this alert | keyword |
| microsoft_defender_cloud.event.resource_identifiers.workspace_subscription_id | The azure subscription id for the LogAnalytics workspace storing this alert. | keyword |
| microsoft_defender_cloud.event.security_event_data_enrichment.action |  | keyword |
| microsoft_defender_cloud.event.security_event_data_enrichment.api_version |  | keyword |
| microsoft_defender_cloud.event.security_event_data_enrichment.interval |  | keyword |
| microsoft_defender_cloud.event.security_event_data_enrichment.is_snapshot |  | boolean |
| microsoft_defender_cloud.event.security_event_data_enrichment.type |  | keyword |
| microsoft_defender_cloud.event.severity | The risk level of the threat that was detected. | keyword |
| microsoft_defender_cloud.event.start_time_utc | The UTC time of the first event or activity included in the alert in ISO8601 format. | date |
| microsoft_defender_cloud.event.status | The life cycle status of the alert. | keyword |
| microsoft_defender_cloud.event.sub_assessment_event.data_enrichment.action |  | keyword |
| microsoft_defender_cloud.event.sub_assessment_event.data_enrichment.api_version |  | keyword |
| microsoft_defender_cloud.event.sub_assessment_event.data_enrichment.is_snapshot |  | boolean |
| microsoft_defender_cloud.event.sub_assessment_event.data_enrichment.type |  | keyword |
| microsoft_defender_cloud.event.system.alert_id | Unique identifier for the alert. | keyword |
| microsoft_defender_cloud.event.tags |  | keyword |
| microsoft_defender_cloud.event.tenant_id |  | keyword |
| microsoft_defender_cloud.event.time_generated | The UTC time the alert was generated in ISO8601 format. | date |
| microsoft_defender_cloud.event.type | Resource type. | keyword |
| microsoft_defender_cloud.event.uri | A direct link to the alert page in Azure Portal. | keyword |
| microsoft_defender_cloud.event.vendor_name | The name of the vendor that raises the alert. | keyword |
| microsoft_defender_cloud.event.workspace.id |  | keyword |
| microsoft_defender_cloud.event.workspace.resource_group |  | keyword |
| microsoft_defender_cloud.event.workspace.subscription_id |  | keyword |


#### Assessment

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| microsoft_defender_cloud.assessment.additional_data.can_onboard_to_byol |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.controller_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.controller_type |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.cves.base_score |  | float |
| microsoft_defender_cloud.assessment.additional_data.cves.cve |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.cves.severity |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.cves_count |  | long |
| microsoft_defender_cloud.assessment.additional_data.digest |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.edrs_found |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.highest_severity |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.identity_designate_less_than_xowners_object_id_list |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.image_uri |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.inventory_source |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.k8s_cluster_id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.k8s_cluster_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.max_cvss30_score |  | float |
| microsoft_defender_cloud.assessment.additional_data.namespace |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.nsg_open_ports |  | long |
| microsoft_defender_cloud.assessment.additional_data.os_distribution |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.os_type |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.pod_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.repo |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.resource_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.resource_provider |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.resource_type |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.resource_url |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.role_and_scope |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.affected_nodes |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.aggregate_server_resource_metadata.managed_aggregate_resource_id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.aggregate_server_resource_metadata.managed_pool_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.artifact_details.artifact_type |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.artifact_details.digest |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.artifact_details.registry_host |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.artifact_details.repository_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.assessed_resource_type |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cluster_details.cluster_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cluster_details.cluster_resource_id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.cvss_score |  | float |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.cvss_vector_string |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.cvss_version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.description |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.exploit_types |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.exploitability_level |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.has_public_exploit |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.is_exploit_in_kit |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.is_exploit_verified |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.is_zero_day |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.last_modified_date |  | date |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.published_date |  | date |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.severity |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve.title |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_edges_details.cve_id_as_source_node_id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.cvss_score |  | float |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.cvss_vector_string |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.cvss_version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.description |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.exploit_types |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.exploitability_level |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.has_public_exploit |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.is_exploit_in_kit |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.is_exploit_verified |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.is_zero_day |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.last_modified_date |  | date |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.published_date |  | date |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.severity |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cve_list.title |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.cvss_v30_score |  | float |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.data.resources |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.data.signature_update_date |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.fixed_cluster_version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.fixed_node_pool_version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.installed_cluster_version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.installed_node_pool_version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_context.workloads.kind |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_context.workloads.name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_context.workloads.namespace |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_context.workloads.owned_resources.containers.name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_context.workloads.owned_resources.kind |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_context.workloads.owned_resources.name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_details.cloud |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_details.cluster_kind |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_details.cluster_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_details.cluster_resource_id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_details.container_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_details.controller_kind |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_details.controller_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_details.namespace |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.kubernetes_details.pod_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.metadata.inventory_source |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.metadata.scanner |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.recommended_program |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.recommended_vendor |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.recommended_version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.resource_id_as_target_node_id.azure_resource_id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.resource_id_as_target_node_id.target_resource_id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.resource_id_as_target_node_id.target_resource_type |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.security_gating.evaluated_resource_kind |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.security_gating.evaluated_resource_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.security_gating.request_id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.category |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.evidence |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.fix_reference.description |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.fix_reference.id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.fix_reference.release_date |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.fix_reference.url |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.fix_status |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.fixed_version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.language |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.os_details.os_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.os_details.os_platform |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.os_details.os_version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.package_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.patchable |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.vendor |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_details.version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_vendor |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.software_version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.source |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.edition |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.language |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.other |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.part |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.product |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.software_edition |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.target_hardware |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.target_software |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.update |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.uri |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.vendor |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cpe.version |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cve_id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cvss_v2.base |  | float |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cvss_v2.cvss_vector_string |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cvss_v3.base |  | float |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cvss_v3.cvss_vector_string |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cvss_v4.base |  | float |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.cvss_v4.cvss_vector_string |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.exploitability_assessment.is_in_exploit_kit |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.exploitability_assessment.is_publicly_disclosed |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.exploitability_assessment.is_verified |  | boolean |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.last_modified_date |  | date |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.published_date |  | date |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.references.link |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.references.title |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.severity |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.additional_data.vulnerability_details.weaknesses.cwe.id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.category |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.description |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.display_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.event_id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.impact |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.remediation |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.resource_details.id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.resource_details.native_resource_id |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.resource_details.resource_name |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.resource_details.resource_provider |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.resource_details.resource_type |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.resource_details.source |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.status.cause |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.status.code |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.status.description |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.status.severity |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.time_generated |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessment.type |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.sub_assessments_link |  | keyword |
| microsoft_defender_cloud.assessment.additional_data.tags |  | keyword |
| microsoft_defender_cloud.assessment.class |  | keyword |
| microsoft_defender_cloud.assessment.display_name |  | keyword |
| microsoft_defender_cloud.assessment.id |  | keyword |
| microsoft_defender_cloud.assessment.name |  | keyword |
| microsoft_defender_cloud.assessment.resource_details.id |  | keyword |
| microsoft_defender_cloud.assessment.resource_details.native_resource_id |  | keyword |
| microsoft_defender_cloud.assessment.resource_details.resource_id |  | keyword |
| microsoft_defender_cloud.assessment.resource_details.resource_name |  | keyword |
| microsoft_defender_cloud.assessment.resource_details.resource_provider |  | keyword |
| microsoft_defender_cloud.assessment.resource_details.resource_type |  | keyword |
| microsoft_defender_cloud.assessment.resource_details.source |  | keyword |
| microsoft_defender_cloud.assessment.status.cause |  | keyword |
| microsoft_defender_cloud.assessment.status.code |  | keyword |
| microsoft_defender_cloud.assessment.status.description |  | keyword |
| microsoft_defender_cloud.assessment.status.first_evaluation_date |  | date |
| microsoft_defender_cloud.assessment.status.status_change_date |  | date |
| microsoft_defender_cloud.assessment.type |  | keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| package.fixed_version | In which version of the package the vulnerability was fixed. | keyword |
| resource.id | The ID of the resource. | keyword |
| resource.name | The name of the resource. | keyword |
| resource.sub_type | The subtype of the resource. | keyword |
| resource.type | The type of the resource. | keyword |
| result.evaluation | The result of the evaluation. | keyword |
| rule.impact | The impact of misconfigured rule. | keyword |
| rule.remediation | The remediation actions for the rule. | keyword |
| vulnerability.cve | The CVE id of the vulnerability. | keyword |
| vulnerability.published_date | When the vulnerability was published. | date |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | constant_keyword |
| vulnerability.title | The human readable title of the vulnerability. | keyword |


### Example event

#### Assessment

An example event for `assessment` looks as following:

```json
{
    "@timestamp": "2025-09-16T10:37:54.277Z",
    "agent": {
        "ephemeral_id": "6082d85b-0f3b-41f4-bd3a-ff3fa234f725",
        "id": "0fed4907-47d7-4a56-8083-2002e77c36ab",
        "name": "elastic-agent-83525",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "cloud": {
        "account": {
            "id": "5abcdef6-1234-5678-8912-e1234abcdef1"
        },
        "instance": {
            "id": "/subscriptions/5abcdef6-1234-5678-8912-e1234abcdef1/resourceGroups/DEFENDER_CLOUD_GROUP/providers/Microsoft.Compute/virtualMachines/vm-for-defender-cloud-test",
            "name": "vm-for-defender-cloud-test"
        },
        "provider": "azure",
        "service": {
            "name": "Microsoft.Compute"
        }
    },
    "data_stream": {
        "dataset": "microsoft_defender_cloud.assessment",
        "namespace": "20516",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "0fed4907-47d7-4a56-8083-2002e77c36ab",
        "snapshot": true,
        "version": "8.19.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "microsoft_defender_cloud.assessment",
        "id": "/subscriptions/5abcdef6-1234-5678-8912-e1234abcdef1/resourceGroups/DEFENDER_CLOUD_GROUP/providers/Microsoft.Compute/virtualMachines/vm-for-defender-cloud-test/providers/Microsoft.Security/assessments/fabcdef2-5678-1234-8382-21234567890d",
        "ingested": "2025-09-16T10:37:57Z",
        "kind": "state",
        "original": "{\"id\":\"/subscriptions/5abcdef6-1234-5678-8912-e1234abcdef1/resourceGroups/DEFENDER_CLOUD_GROUP/providers/Microsoft.Compute/virtualMachines/vm-for-defender-cloud-test/providers/Microsoft.Security/assessments/fabcdef2-5678-1234-8382-21234567890d\",\"name\":\"fabcdef2-5678-1234-8382-21234567890d\",\"properties\":{\"additionalData\":{\"Can onboard to BYOL\":\"true\"},\"displayName\":\"Machines should have a vulnerability assessment solution\",\"resourceDetails\":{\"Id\":\"/subscriptions/5abcdef6-1234-5678-8912-e1234abcdef1/resourceGroups/DEFENDER_CLOUD_GROUP/providers/Microsoft.Compute/virtualMachines/vm-for-defender-cloud-test\",\"NativeResourceId\":\"/subscriptions/5abcdef6-1234-5678-8912-e1234abcdef1/resourceGroups/DEFENDER_CLOUD_GROUP/providers/Microsoft.Compute/virtualMachines/vm-for-defender-cloud-test\",\"ResourceName\":\"vm-for-defender-cloud-test\",\"ResourceProvider\":\"Microsoft.Compute\",\"ResourceType\":\"virtualMachines\",\"Source\":\"Azure\"},\"status\":{\"cause\":\"mdeTvm\",\"code\":\"Healthy\",\"description\":\"The machine is onboarded to Microsoft defender vulnerability management\"}},\"type\":\"Microsoft.Security/assessments\"}",
        "outcome": "success",
        "reason": "The machine is onboarded to Microsoft defender vulnerability management",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "vm-for-defender-cloud-test"
    },
    "input": {
        "type": "cel"
    },
    "message": "Machines should have a vulnerability assessment solution",
    "microsoft_defender_cloud": {
        "assessment": {
            "additional_data": {
                "can_onboard_to_byol": true
            },
            "class": "misconfiguration",
            "display_name": "Machines should have a vulnerability assessment solution",
            "id": "/subscriptions/5abcdef6-1234-5678-8912-e1234abcdef1/resourceGroups/DEFENDER_CLOUD_GROUP/providers/Microsoft.Compute/virtualMachines/vm-for-defender-cloud-test/providers/Microsoft.Security/assessments/fabcdef2-5678-1234-8382-21234567890d",
            "name": "fabcdef2-5678-1234-8382-21234567890d",
            "resource_details": {
                "id": "/subscriptions/5abcdef6-1234-5678-8912-e1234abcdef1/resourceGroups/DEFENDER_CLOUD_GROUP/providers/Microsoft.Compute/virtualMachines/vm-for-defender-cloud-test",
                "native_resource_id": "/subscriptions/5abcdef6-1234-5678-8912-e1234abcdef1/resourceGroups/DEFENDER_CLOUD_GROUP/providers/Microsoft.Compute/virtualMachines/vm-for-defender-cloud-test",
                "resource_name": "vm-for-defender-cloud-test",
                "resource_provider": "Microsoft.Compute",
                "resource_type": "virtualMachines",
                "source": "Azure"
            },
            "status": {
                "cause": "mdeTvm",
                "code": "Healthy",
                "description": "The machine is onboarded to Microsoft defender vulnerability management"
            },
            "type": "Microsoft.Security/assessments"
        }
    },
    "observer": {
        "vendor": "Microsoft Defender for Cloud"
    },
    "related": {
        "hosts": [
            "vm-for-defender-cloud-test"
        ]
    },
    "resource": {
        "id": "/subscriptions/5abcdef6-1234-5678-8912-e1234abcdef1/resourceGroups/DEFENDER_CLOUD_GROUP/providers/Microsoft.Compute/virtualMachines/vm-for-defender-cloud-test",
        "name": "vm-for-defender-cloud-test",
        "sub_type": "virtualMachines",
        "type": "Microsoft.Compute"
    },
    "result": {
        "evaluation": "passed"
    },
    "rule": {
        "name": "Machines should have a vulnerability assessment solution",
        "uuid": "GWgODMK4x9cVQi6d4ipRByaXvpE="
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "microsoft_defender_cloud-assessment"
    ]
}
```

### Inputs used

These inputs are used in this integration:

- [azure-eventhub](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-azure-eventhub)
- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following APIs:

- `Assessments`: [Azure REST API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/assessments/list?view=rest-defenderforcloud-composite-latest&tabs=HTTP).
- `Sub Assessments`: [Azure REST API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/sub-assessments/list?view=rest-defenderforcloud-composite-latest&tabs=HTTP).

#### ILM Policy

To facilitate assessment data, source data stream-backed indices `.ds-logs-microsoft_defender_cloud.assessment-*` is allowed to contain duplicates from each polling interval. ILM policy `logs-microsoft_defender_cloud.assessment-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `7 days` from ingested date.
