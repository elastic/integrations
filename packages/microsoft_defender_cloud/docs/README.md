# Microsoft Defender for Cloud

The [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction) integration allows you to monitor security alert events. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for analyzing the resources and services that users are protecting through Microsoft Defender.

Use the Microsoft Defender for Cloud integration to collect and parse data from **Azure Event Hub** and then visualize that data in Kibana.

## Data streams

The Microsoft Defender for Cloud integration collects one type of data: event.

**Event** allows users to preserve a record of security events that occurred on the subscription, which includes real-time events that affect the security of the user's environment. For further information connected to security alerts and type, Refer to the page [here](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference).

## Prerequisites

To get started with Defender for Cloud, user must have a subscription to Microsoft Azure.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the **Azure Event Hub** and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.3.0**.

## Setup

### To collect data from Microsoft Azure Event Hub, follow the below steps:

- Configure the Microsoft Defender for Cloud on Azure subscription. For more detail, refer to the link [here](https://learn.microsoft.com/en-us/azure/defender-for-cloud/get-started).

### Enabling the integration in Elastic:

1. In Kibana, go to Management > Integrations.
2. In the "Search for integrations" search bar, type Microsoft Defender for Cloud.
3. Click on the "Microsoft Defender for Cloud" integration from the search results.
4. Click on the Add Microsoft Defender for Cloud Integration button to add the integration.
5. While adding the integration, if you want to collect logs via **Azure Event Hub**, then you have to put the following details:
   - eventhub
   - consumer_group
   - connection_string
   - storage_account
   - storage_account_key
   - storage_account_container (optional)
   - resource_manager_endpoint (optional)

## Logs reference

### Event

This is the `Event` dataset.

#### Example

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

