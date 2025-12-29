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

- `Compute`: Collect details of all compute assets including:
    - devices (endpoint: `/api/v2/devices`)
    - compute_services (endpoint: `/api/v2/compute_services`)
    - databases (endpoint: `/api/v2/databases`)
    - containers (endpoint: `/api/v2/containers`)
    - serverless_functions (endpoint: `/api/v2/serverless_functions`)
    - compute_images (endpoint: `/api/v2/compute_images`)
    - configurations (endpoint: `/api/v2/configurations`)

### Supported use cases

Integrating the Axonius Compute Datastream with Elastic SIEM provides a consolidated view of compute activity across the environment. Event trends help teams quickly spot abnormalities, while breakdowns by device type, OS, and status show which systems are driving activity and where issues may be emerging.

Tables highlight the most active data centers, users, hosts, vendors, manufacturers, software, and vulnerabilities, giving analysts clear insights into high-impact assets and potential risk areas. These views enable teams to detect anomalies, prioritize investigations, and maintain strong visibility into the health and behavior of compute resources across the organization.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Axonius

To collect data through the Axonius APIs, you need to provide the **URL**, **API Key** and **API Secret**. Authentication is handled using the **API Key** and **API Secret**, which serves as the required credential.

#### Retrieve URL, API Token and API Secret:

1. Log in to the **Axonius** instance.
2. Your instance URL is your Base **URL**.
3. Navigate to **User Settings > API Key**.
4. Generate an **API Key**.
5. If you do not see the API Key tab in your user settings, follow these steps:
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

### Compute

The `compute` data stream provides compute asset logs from axonius.

#### compute fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| axonius.compute.adapter_list_length |  | long |
| axonius.compute.adapters |  | keyword |
| axonius.compute.asset_type |  | keyword |
| axonius.compute.event.accurate_for_datetime |  | date |
| axonius.compute.event.action_if_exists |  | keyword |
| axonius.compute.event.adapter_categories |  | keyword |
| axonius.compute.event.associated_adapter_plugin_name |  | keyword |
| axonius.compute.event.association_type |  | keyword |
| axonius.compute.event.client_used |  | keyword |
| axonius.compute.event.data.accurate_for_datetime |  | date |
| axonius.compute.event.data.adapter_properties |  | keyword |
| axonius.compute.event.data.agent_versions.adapter_name |  | keyword |
| axonius.compute.event.data.agent_versions.agent_version |  | keyword |
| axonius.compute.event.data.agent_versions.agent_version_raw |  | keyword |
| axonius.compute.event.data.all_associated_email_addresses |  | keyword |
| axonius.compute.event.data.anti_malware_agent_status |  | keyword |
| axonius.compute.event.data.anti_malware_agent_status_message |  | keyword |
| axonius.compute.event.data.anti_malware_state |  | keyword |
| axonius.compute.event.data.appliance_sites |  | keyword |
| axonius.compute.event.data.application_and_account_name |  | keyword |
| axonius.compute.event.data.architecture |  | keyword |
| axonius.compute.event.data.arp_interface |  | keyword |
| axonius.compute.event.data.arp_port |  | keyword |
| axonius.compute.event.data.arp_status |  | keyword |
| axonius.compute.event.data.arp_ttl |  | long |
| axonius.compute.event.data.assessed_for_policies |  | boolean |
| axonius.compute.event.data.assessed_for_vulnerabilities |  | boolean |
| axonius.compute.event.data.asset_entity_info |  | keyword |
| axonius.compute.event.data.asset_install_status |  | keyword |
| axonius.compute.event.data.asset_tag |  | keyword |
| axonius.compute.event.data.asset_type |  | keyword |
| axonius.compute.event.data.asset_user_name |  | keyword |
| axonius.compute.event.data.associated_device_users.internal_axon_id |  | keyword |
| axonius.compute.event.data.associated_device_users.is_latest_used_user |  | boolean |
| axonius.compute.event.data.associated_device_users.last_used_departments |  | keyword |
| axonius.compute.event.data.associated_device_users.last_used_email |  | keyword |
| axonius.compute.event.data.associated_device_users.last_used_email_domain |  | keyword |
| axonius.compute.event.data.associated_device_users.last_used_user_manager |  | keyword |
| axonius.compute.event.data.associated_saas_applications.internal_axon_id |  | keyword |
| axonius.compute.event.data.associated_saas_applications.name |  | keyword |
| axonius.compute.event.data.aws_organization.arn |  | keyword |
| axonius.compute.event.data.aws_organization.available_policy_types.status |  | keyword |
| axonius.compute.event.data.aws_organization.available_policy_types.type |  | keyword |
| axonius.compute.event.data.aws_organization.feature_set |  | keyword |
| axonius.compute.event.data.aws_organization.id |  | keyword |
| axonius.compute.event.data.aws_organization.master_account_arn |  | keyword |
| axonius.compute.event.data.aws_organization.master_account_email |  | keyword |
| axonius.compute.event.data.aws_organization.master_account_id |  | keyword |
| axonius.compute.event.data.aws_region |  | keyword |
| axonius.compute.event.data.axon_id |  | keyword |
| axonius.compute.event.data.axonius_instance_name |  | keyword |
| axonius.compute.event.data.browsers.channel |  | keyword |
| axonius.compute.event.data.browsers.version |  | keyword |
| axonius.compute.event.data.capture_device |  | keyword |
| axonius.compute.event.data.category |  | keyword |
| axonius.compute.event.data.certificate_expiry_date |  | date |
| axonius.compute.event.data.chrome_device_type |  | keyword |
| axonius.compute.event.data.cisa_vulnerabilities.action |  | keyword |
| axonius.compute.event.data.cisa_vulnerabilities.added |  | date |
| axonius.compute.event.data.cisa_vulnerabilities.cve_id |  | keyword |
| axonius.compute.event.data.cisa_vulnerabilities.desc |  | keyword |
| axonius.compute.event.data.cisa_vulnerabilities.due_date |  | date |
| axonius.compute.event.data.cisa_vulnerabilities.notes |  | keyword |
| axonius.compute.event.data.cisa_vulnerabilities.product |  | keyword |
| axonius.compute.event.data.cisa_vulnerabilities.used_in_ransomware |  | boolean |
| axonius.compute.event.data.cisa_vulnerabilities.vendor |  | keyword |
| axonius.compute.event.data.cisa_vulnerabilities.vulnerability_name |  | keyword |
| axonius.compute.event.data.class_name |  | keyword |
| axonius.compute.event.data.class_title |  | keyword |
| axonius.compute.event.data.class_type |  | keyword |
| axonius.compute.event.data.cloud_provider_account_id |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.app_owner |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.assignment_group |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.business_criticality |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.install_status |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.managed_by |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.name |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.number |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.u_architect |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.u_availability_criticality |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.u_confidentiality_criticality |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.u_crown_jewel |  | boolean |
| axonius.compute.event.data.cmdb_business_applications.u_integrity_criticality |  | keyword |
| axonius.compute.event.data.cmdb_business_applications.u_privacy_criticality |  | keyword |
| axonius.compute.event.data.color |  | keyword |
| axonius.compute.event.data.common_users |  | keyword |
| axonius.compute.event.data.company |  | keyword |
| axonius.compute.event.data.confidence_level |  | long |
| axonius.compute.event.data.connected_assets |  | keyword |
| axonius.compute.event.data.connected_devices |  | keyword |
| axonius.compute.event.data.cp_type |  | keyword |
| axonius.compute.event.data.cpus.cores |  | long |
| axonius.compute.event.data.cpus.ghz |  | double |
| axonius.compute.event.data.cpus.manufacturer |  | keyword |
| axonius.compute.event.data.cpus.name |  | keyword |
| axonius.compute.event.data.create_time |  | date |
| axonius.compute.event.data.creation_date |  | date |
| axonius.compute.event.data.criticality |  | keyword |
| axonius.compute.event.data.custom_risk_owner |  | keyword |
| axonius.compute.event.data.data_center |  | keyword |
| axonius.compute.event.data.description |  | keyword |
| axonius.compute.event.data.device_manufacturer |  | keyword |
| axonius.compute.event.data.device_serial |  | keyword |
| axonius.compute.event.data.device_type |  | keyword |
| axonius.compute.event.data.disk_encryption_configuration |  | keyword |
| axonius.compute.event.data.domain |  | keyword |
| axonius.compute.event.data.ebs_volumes.create_time |  | date |
| axonius.compute.event.data.ebs_volumes.encrypted |  | boolean |
| axonius.compute.event.data.ebs_volumes.iops |  | long |
| axonius.compute.event.data.ebs_volumes.name |  | keyword |
| axonius.compute.event.data.ebs_volumes.size |  | double |
| axonius.compute.event.data.ebs_volumes.snapshot_id |  | keyword |
| axonius.compute.event.data.ebs_volumes.volume_type |  | keyword |
| axonius.compute.event.data.encrypted |  | boolean |
| axonius.compute.event.data.entity_id |  | keyword |
| axonius.compute.event.data.entry_point |  | keyword |
| axonius.compute.event.data.environment |  | keyword |
| axonius.compute.event.data.epo_host |  | keyword |
| axonius.compute.event.data.epo_id |  | keyword |
| axonius.compute.event.data.epo_products |  | keyword |
| axonius.compute.event.data.excluded_software_cves |  | keyword |
| axonius.compute.event.data.external_cloud_account_id |  | keyword |
| axonius.compute.event.data.external_ip |  | ip |
| axonius.compute.event.data.external_nat_ip |  | ip |
| axonius.compute.event.data.fetch_proto |  | keyword |
| axonius.compute.event.data.fetch_time |  | date |
| axonius.compute.event.data.fields_to_unset |  | keyword |
| axonius.compute.event.data.fingerprint |  | keyword |
| axonius.compute.event.data.firewall_enabled |  | boolean |
| axonius.compute.event.data.firewall_rules.direction |  | keyword |
| axonius.compute.event.data.firewall_rules.from_port |  | long |
| axonius.compute.event.data.firewall_rules.name |  | keyword |
| axonius.compute.event.data.firewall_rules.protocol |  | keyword |
| axonius.compute.event.data.firewall_rules.source |  | keyword |
| axonius.compute.event.data.firewall_rules.target_ip |  | ip |
| axonius.compute.event.data.firewall_rules.target_subnet_count |  | long |
| axonius.compute.event.data.firewall_rules.target_subnet_mask |  | long |
| axonius.compute.event.data.firewall_rules.to_port |  | long |
| axonius.compute.event.data.firewall_rules.type |  | keyword |
| axonius.compute.event.data.first_fetch_time |  | date |
| axonius.compute.event.data.first_seen |  | date |
| axonius.compute.event.data.fqdn |  | keyword |
| axonius.compute.event.data.free_physical_memory |  | double |
| axonius.compute.event.data.from_last_fetch |  | boolean |
| axonius.compute.event.data.general.extension_name |  | keyword |
| axonius.compute.event.data.general.extension_value |  | keyword |
| axonius.compute.event.data.generic_encryption.status |  | boolean |
| axonius.compute.event.data.ghost |  | boolean |
| axonius.compute.event.data.guest_dns_name |  | keyword |
| axonius.compute.event.data.guest_family |  | keyword |
| axonius.compute.event.data.guest_name |  | keyword |
| axonius.compute.event.data.guest_state |  | keyword |
| axonius.compute.event.data.hard_drives.free_size |  | double |
| axonius.compute.event.data.hard_drives.is_encrypted |  | boolean |
| axonius.compute.event.data.hard_drives.total_size |  | double |
| axonius.compute.event.data.hardware_status |  | keyword |
| axonius.compute.event.data.hostname |  | keyword |
| axonius.compute.event.data.hosts.last_vm_scan_date |  | date |
| axonius.compute.event.data.hosts.last_vm_scan_duration |  | double |
| axonius.compute.event.data.hosts.last_vulm_scan_datetime |  | date |
| axonius.compute.event.data.id |  | keyword |
| axonius.compute.event.data.id_raw |  | keyword |
| axonius.compute.event.data.in_groups |  | keyword |
| axonius.compute.event.data.install_status |  | keyword |
| axonius.compute.event.data.installed_software.generated_cpe |  | keyword |
| axonius.compute.event.data.installed_software.name |  | keyword |
| axonius.compute.event.data.installed_software.name_version |  | keyword |
| axonius.compute.event.data.installed_software.sw_uid |  | keyword |
| axonius.compute.event.data.installed_software.vendor |  | keyword |
| axonius.compute.event.data.installed_software.vendor_publisher |  | boolean |
| axonius.compute.event.data.installed_software.version |  | keyword |
| axonius.compute.event.data.installed_software.version_raw |  | keyword |
| axonius.compute.event.data.ip_address_guid |  | keyword |
| axonius.compute.event.data.is_authenticated_scan |  | boolean |
| axonius.compute.event.data.is_fetched_from_adapter |  | boolean |
| axonius.compute.event.data.is_fragile |  | boolean |
| axonius.compute.event.data.is_latest_last_seen |  | boolean |
| axonius.compute.event.data.is_managed |  | boolean |
| axonius.compute.event.data.is_network_infra_device |  | boolean |
| axonius.compute.event.data.is_purchased |  | boolean |
| axonius.compute.event.data.jamf_groups |  | keyword |
| axonius.compute.event.data.jamf_groups_detailed.group_id |  | keyword |
| axonius.compute.event.data.jamf_groups_detailed.group_name |  | keyword |
| axonius.compute.event.data.jamf_groups_detailed.smart_group |  | boolean |
| axonius.compute.event.data.jamf_id |  | keyword |
| axonius.compute.event.data.jamf_location.building |  | keyword |
| axonius.compute.event.data.jamf_location.email_address |  | keyword |
| axonius.compute.event.data.jamf_location.phone_number |  | keyword |
| axonius.compute.event.data.jamf_location.position |  | keyword |
| axonius.compute.event.data.jamf_location.real_name |  | keyword |
| axonius.compute.event.data.jamf_location.room |  | keyword |
| axonius.compute.event.data.jamf_location.username |  | keyword |
| axonius.compute.event.data.jamf_version |  | keyword |
| axonius.compute.event.data.keep_hostname_empty |  | boolean |
| axonius.compute.event.data.last_agent_import |  | date |
| axonius.compute.event.data.last_auth_run |  | date |
| axonius.compute.event.data.last_contact_time |  | date |
| axonius.compute.event.data.last_enrolled_date_utc |  | date |
| axonius.compute.event.data.last_fetch_connection_id |  | keyword |
| axonius.compute.event.data.last_fetch_connection_label |  | keyword |
| axonius.compute.event.data.last_scan |  | date |
| axonius.compute.event.data.last_seen |  | date |
| axonius.compute.event.data.last_seen_agents |  | date |
| axonius.compute.event.data.last_unauth_run |  | date |
| axonius.compute.event.data.last_used_users |  | keyword |
| axonius.compute.event.data.last_used_users_departments_association |  | keyword |
| axonius.compute.event.data.last_used_users_email_domain_association |  | keyword |
| axonius.compute.event.data.last_used_users_internal_axon_id_association |  | keyword |
| axonius.compute.event.data.last_used_users_mail_association |  | keyword |
| axonius.compute.event.data.last_used_users_user_manager_association |  | keyword |
| axonius.compute.event.data.last_used_users_user_manager_mail_association |  | keyword |
| axonius.compute.event.data.last_used_users_user_status_association |  | keyword |
| axonius.compute.event.data.last_used_users_user_title_association |  | keyword |
| axonius.compute.event.data.last_vuln_scan |  | date |
| axonius.compute.event.data.latest_used_user |  | keyword |
| axonius.compute.event.data.latest_used_user_department |  | keyword |
| axonius.compute.event.data.latest_used_user_email_domain |  | keyword |
| axonius.compute.event.data.latest_used_user_mail |  | keyword |
| axonius.compute.event.data.latest_used_user_user_manager |  | keyword |
| axonius.compute.event.data.latest_used_user_user_status |  | keyword |
| axonius.compute.event.data.latest_used_user_user_title |  | keyword |
| axonius.compute.event.data.linked_tickets.category |  | keyword |
| axonius.compute.event.data.linked_tickets.created |  | date |
| axonius.compute.event.data.linked_tickets.description |  | keyword |
| axonius.compute.event.data.linked_tickets.display_id |  | keyword |
| axonius.compute.event.data.linked_tickets.priority |  | keyword |
| axonius.compute.event.data.linked_tickets.reporter |  | keyword |
| axonius.compute.event.data.linked_tickets.status |  | keyword |
| axonius.compute.event.data.linked_tickets.summary |  | keyword |
| axonius.compute.event.data.linked_tickets.updated |  | date |
| axonius.compute.event.data.lock |  | keyword |
| axonius.compute.event.data.meeting_id |  | keyword |
| axonius.compute.event.data.memory_size |  | double |
| axonius.compute.event.data.microphone |  | keyword |
| axonius.compute.event.data.name |  | keyword |
| axonius.compute.event.data.nat_policy_ips.address |  | ip |
| axonius.compute.event.data.nat_policy_ips.direction |  | keyword |
| axonius.compute.event.data.nat_policy_ips.matched_on |  | keyword |
| axonius.compute.event.data.nat_policy_ips.policy_name |  | keyword |
| axonius.compute.event.data.nat_policy_ips.rule_num |  | long |
| axonius.compute.event.data.nat_policy_ips.uid |  | keyword |
| axonius.compute.event.data.network |  | keyword |
| axonius.compute.event.data.network_interfaces.ips |  | keyword |
| axonius.compute.event.data.network_interfaces.ips_raw |  | long |
| axonius.compute.event.data.network_interfaces.ips_v4 |  | keyword |
| axonius.compute.event.data.network_interfaces.ips_v4_raw |  | long |
| axonius.compute.event.data.network_interfaces.mac |  | keyword |
| axonius.compute.event.data.network_interfaces.manufacturer |  | keyword |
| axonius.compute.event.data.network_interfaces.subnets |  | keyword |
| axonius.compute.event.data.network_status |  | keyword |
| axonius.compute.event.data.network_type |  | keyword |
| axonius.compute.event.data.nexpose_id |  | keyword |
| axonius.compute.event.data.nexpose_type |  | keyword |
| axonius.compute.event.data.node_id |  | keyword |
| axonius.compute.event.data.node_name |  | keyword |
| axonius.compute.event.data.normalization_reasons.calculated_time |  | date |
| axonius.compute.event.data.normalization_reasons.key |  | keyword |
| axonius.compute.event.data.normalization_reasons.original |  | keyword |
| axonius.compute.event.data.normalization_reasons.reason |  | keyword |
| axonius.compute.event.data.not_fetched_count |  | long |
| axonius.compute.event.data.open_ports.port_id |  | keyword |
| axonius.compute.event.data.open_ports.protocol |  | keyword |
| axonius.compute.event.data.operational_status |  | keyword |
| axonius.compute.event.data.organizational_unit |  | keyword |
| axonius.compute.event.data.os.codename |  | keyword |
| axonius.compute.event.data.os.distribution |  | keyword |
| axonius.compute.event.data.os.distribution_name |  | keyword |
| axonius.compute.event.data.os.end_of_life |  | date |
| axonius.compute.event.data.os.end_of_support |  | date |
| axonius.compute.event.data.os.is_end_of_life |  | boolean |
| axonius.compute.event.data.os.is_end_of_support |  | boolean |
| axonius.compute.event.data.os.is_latest_os_version |  | boolean |
| axonius.compute.event.data.os.is_windows_server |  | boolean |
| axonius.compute.event.data.os.latest_os_version |  | keyword |
| axonius.compute.event.data.os.major |  | long |
| axonius.compute.event.data.os.minor |  | long |
| axonius.compute.event.data.os.os_cpe |  | keyword |
| axonius.compute.event.data.os.os_dotted |  | keyword |
| axonius.compute.event.data.os.os_dotted_raw |  | keyword |
| axonius.compute.event.data.os.os_str |  | keyword |
| axonius.compute.event.data.os.type |  | keyword |
| axonius.compute.event.data.os.type_distribution |  | keyword |
| axonius.compute.event.data.os_ext_attributes.attr_name |  | keyword |
| axonius.compute.event.data.os_ext_attributes.data_type |  | keyword |
| axonius.compute.event.data.os_ext_attributes.definition_id |  | keyword |
| axonius.compute.event.data.os_ext_attributes.ext_description |  | keyword |
| axonius.compute.event.data.os_ext_attributes.input_type |  | keyword |
| axonius.compute.event.data.os_ext_attributes.is_enabled |  | boolean |
| axonius.compute.event.data.os_ext_attributes.is_multivalue |  | boolean |
| axonius.compute.event.data.os_ext_attributes.values |  | keyword |
| axonius.compute.event.data.owner |  | keyword |
| axonius.compute.event.data.paloalto_device_type |  | keyword |
| axonius.compute.event.data.part_of_domain |  | boolean |
| axonius.compute.event.data.physical_location |  | keyword |
| axonius.compute.event.data.physical_memory_percentage |  | double |
| axonius.compute.event.data.plugin_and_severities.cve |  | keyword |
| axonius.compute.event.data.plugin_and_severities.has_been_mitigated |  | boolean |
| axonius.compute.event.data.plugin_and_severities.mitigated |  | boolean |
| axonius.compute.event.data.plugin_and_severities.plugin |  | keyword |
| axonius.compute.event.data.policy_id |  | keyword |
| axonius.compute.event.data.policy_name |  | keyword |
| axonius.compute.event.data.power_state |  | keyword |
| axonius.compute.event.data.pretty_id |  | keyword |
| axonius.compute.event.data.protocols |  | keyword |
| axonius.compute.event.data.qualys_agent_vulns.first_found |  | date |
| axonius.compute.event.data.qualys_agent_vulns.last_found |  | date |
| axonius.compute.event.data.qualys_agent_vulns.qid |  | keyword |
| axonius.compute.event.data.qualys_agent_vulns.qualys_cve_id |  | keyword |
| axonius.compute.event.data.qualys_agent_vulns.qualys_solution |  | keyword |
| axonius.compute.event.data.qualys_agent_vulns.severity |  | long |
| axonius.compute.event.data.qualys_agent_vulns.vuln_id |  | keyword |
| axonius.compute.event.data.ranger_version |  | keyword |
| axonius.compute.event.data.raw_hostname |  | keyword |
| axonius.compute.event.data.read_only |  | boolean |
| axonius.compute.event.data.recording |  | boolean |
| axonius.compute.event.data.relatable_ids |  | keyword |
| axonius.compute.event.data.relative_path |  | keyword |
| axonius.compute.event.data.report_date |  | date |
| axonius.compute.event.data.resource_group |  | keyword |
| axonius.compute.event.data.risk_level |  | keyword |
| axonius.compute.event.data.roles |  | keyword |
| axonius.compute.event.data.scan_results |  | keyword |
| axonius.compute.event.data.scan_results_objs.id |  | keyword |
| axonius.compute.event.data.scan_results_objs.name |  | keyword |
| axonius.compute.event.data.scan_results_objs.status |  | keyword |
| axonius.compute.event.data.scanner |  | boolean |
| axonius.compute.event.data.security_updates_last_changed |  | date |
| axonius.compute.event.data.security_updates_status |  | keyword |
| axonius.compute.event.data.services.display_name |  | keyword |
| axonius.compute.event.data.services.hash_id |  | keyword |
| axonius.compute.event.data.services.state |  | keyword |
| axonius.compute.event.data.severity_critical |  | long |
| axonius.compute.event.data.severity_high |  | long |
| axonius.compute.event.data.severity_info |  | long |
| axonius.compute.event.data.severity_low |  | long |
| axonius.compute.event.data.severity_medium |  | long |
| axonius.compute.event.data.share_application |  | boolean |
| axonius.compute.event.data.share_desktop |  | boolean |
| axonius.compute.event.data.share_whiteboard |  | boolean |
| axonius.compute.event.data.sip_status |  | boolean |
| axonius.compute.event.data.site_name |  | keyword |
| axonius.compute.event.data.size |  | double |
| axonius.compute.event.data.software_cves.axonius_risk_score |  | double |
| axonius.compute.event.data.software_cves.axonius_status |  | keyword |
| axonius.compute.event.data.software_cves.axonius_status_last_update |  | date |
| axonius.compute.event.data.software_cves.custom_software_cves_business_unit |  | keyword |
| axonius.compute.event.data.software_cves.custom_software_cves_exception_justification |  | keyword |
| axonius.compute.event.data.software_cves.custom_software_cves_exception_status |  | keyword |
| axonius.compute.event.data.software_cves.cve_from_sw_analysis |  | boolean |
| axonius.compute.event.data.software_cves.cve_id |  | keyword |
| axonius.compute.event.data.software_cves.cve_list |  | keyword |
| axonius.compute.event.data.software_cves.cve_severity |  | keyword |
| axonius.compute.event.data.software_cves.cve_synopsis |  | keyword |
| axonius.compute.event.data.software_cves.cvss |  | float |
| axonius.compute.event.data.software_cves.cvss2_score |  | float |
| axonius.compute.event.data.software_cves.cvss2_score_num |  | float |
| axonius.compute.event.data.software_cves.cvss3_score |  | float |
| axonius.compute.event.data.software_cves.cvss3_score_num |  | float |
| axonius.compute.event.data.software_cves.cvss4_score |  | float |
| axonius.compute.event.data.software_cves.cvss4_score_num |  | float |
| axonius.compute.event.data.software_cves.cvss_str |  | keyword |
| axonius.compute.event.data.software_cves.cvss_vector |  | keyword |
| axonius.compute.event.data.software_cves.cvss_version |  | keyword |
| axonius.compute.event.data.software_cves.cwe_id |  | keyword |
| axonius.compute.event.data.software_cves.epss.creation_date |  | date |
| axonius.compute.event.data.software_cves.epss.cve_id |  | keyword |
| axonius.compute.event.data.software_cves.epss.percentile |  | double |
| axonius.compute.event.data.software_cves.epss.score |  | double |
| axonius.compute.event.data.software_cves.exploitability_score |  | float |
| axonius.compute.event.data.software_cves.first_fetch_time |  | date |
| axonius.compute.event.data.software_cves.hash_id |  | keyword |
| axonius.compute.event.data.software_cves.impact_score |  | float |
| axonius.compute.event.data.software_cves.last_fetch_time |  | date |
| axonius.compute.event.data.software_cves.last_modified_date |  | date |
| axonius.compute.event.data.software_cves.mitigated |  | boolean |
| axonius.compute.event.data.software_cves.msrc.creation_date |  | date |
| axonius.compute.event.data.software_cves.msrc.cve_id |  | keyword |
| axonius.compute.event.data.software_cves.msrc.title |  | keyword |
| axonius.compute.event.data.software_cves.nvd_publish_age |  | long |
| axonius.compute.event.data.software_cves.publish_date |  | date |
| axonius.compute.event.data.software_cves.software_name |  | keyword |
| axonius.compute.event.data.software_cves.software_type |  | keyword |
| axonius.compute.event.data.software_cves.software_vendor |  | keyword |
| axonius.compute.event.data.software_cves.software_version |  | keyword |
| axonius.compute.event.data.software_cves.solution_hash_id |  | keyword |
| axonius.compute.event.data.software_cves.status |  | keyword |
| axonius.compute.event.data.software_cves.version_raw |  | keyword |
| axonius.compute.event.data.source_application |  | keyword |
| axonius.compute.event.data.speaker |  | keyword |
| axonius.compute.event.data.special_hint |  | long |
| axonius.compute.event.data.special_hint_underscore |  | keyword |
| axonius.compute.event.data.state |  | keyword |
| axonius.compute.event.data.status |  | keyword |
| axonius.compute.event.data.subnet_tag |  | keyword |
| axonius.compute.event.data.subscription_id |  | keyword |
| axonius.compute.event.data.subscription_name |  | keyword |
| axonius.compute.event.data.swap_free |  | float |
| axonius.compute.event.data.swap_total |  | long |
| axonius.compute.event.data.sys_id |  | keyword |
| axonius.compute.event.data.table_type |  | keyword |
| axonius.compute.event.data.tags.tag_key |  | keyword |
| axonius.compute.event.data.tags.tag_source |  | keyword |
| axonius.compute.event.data.tags.tag_value |  | keyword |
| axonius.compute.event.data.tenant_number |  | keyword |
| axonius.compute.event.data.threat_level |  | keyword |
| axonius.compute.event.data.threats |  | keyword |
| axonius.compute.event.data.total |  | long |
| axonius.compute.event.data.total_number_of_cores |  | long |
| axonius.compute.event.data.total_physical_memory |  | double |
| axonius.compute.event.data.type |  | keyword |
| axonius.compute.event.data.u_business_owner |  | keyword |
| axonius.compute.event.data.u_business_unit |  | keyword |
| axonius.compute.event.data.uniq_sites_count |  | long |
| axonius.compute.event.data.uri |  | keyword |
| axonius.compute.event.data.uuid |  | keyword |
| axonius.compute.event.data.vendor |  | keyword |
| axonius.compute.event.data.virtual_host |  | boolean |
| axonius.compute.event.data.virtual_zone |  | keyword |
| axonius.compute.event.data.vpn_domain |  | keyword |
| axonius.compute.event.data.vpn_is_local |  | boolean |
| axonius.compute.event.data.vpn_lifetime |  | long |
| axonius.compute.event.data.vpn_public_ip |  | ip |
| axonius.compute.event.data.vpn_tunnel_type |  | keyword |
| axonius.compute.event.data.vpn_type |  | keyword |
| axonius.compute.event.data.z_sys_class_name |  | keyword |
| axonius.compute.event.data.z_table_hierarchy.name |  | keyword |
| axonius.compute.event.data.zoom_ip |  | ip |
| axonius.compute.event.enrichment_type |  | keyword |
| axonius.compute.event.entity |  | keyword |
| axonius.compute.event.initial_plugin_unique_name |  | keyword |
| axonius.compute.event.plugin_name |  | keyword |
| axonius.compute.event.plugin_type |  | keyword |
| axonius.compute.event.plugin_unique_name |  | keyword |
| axonius.compute.event.quick_id |  | keyword |
| axonius.compute.event.type |  | keyword |
| axonius.compute.internal_axon_id |  | keyword |
| axonius.compute.labels |  | keyword |
| axonius.compute.transform_unique_id |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Indicates whether a compute event is in the raw source data stream, or in the latest destination index. | constant_keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


An example event for `compute` looks as following:

```json
{
    "@timestamp": "2025-12-05T00:02:00.000Z",
    "agent": {
        "ephemeral_id": "7f57e733-1df8-49a8-812e-ce9ea3f54ce5",
        "id": "32cc86c3-bf76-4cc1-a389-5aaf51ace57c",
        "name": "elastic-agent-42371",
        "type": "filebeat",
        "version": "9.1.3"
    },
    "axonius": {
        "compute": {
            "adapter_list_length": 1,
            "adapters": "azure_adapter",
            "asset_type": "containers",
            "event": {
                "accurate_for_datetime": "2025-12-05T00:02:00.000Z",
                "adapter_categories": "Cloud Infra",
                "client_used": "67fd09ca731ccb5730923106",
                "data": {
                    "accurate_for_datetime": "2025-12-05T00:02:00.000Z",
                    "application_and_account_name": "azure/azure-demo",
                    "asset_entity_info": "AzureEntityType.KubernetesCluster",
                    "asset_type": "Kubernetes Container",
                    "connected_assets": "subscription_id::969f0354-b771-4580-8a84-0634c45bbd5b",
                    "fetch_time": "2025-12-05T00:01:58.000Z",
                    "first_fetch_time": "2025-04-14T13:26:37.000Z",
                    "from_last_fetch": true,
                    "id": "a52f35b7d37e0ab76b58",
                    "id_raw": "0a4c0d54-e95a-469c-84c8-39cd53181def",
                    "is_fetched_from_adapter": true,
                    "last_fetch_connection_id": "67fd09ca731ccb5730923106",
                    "last_fetch_connection_label": "azure-demo",
                    "name": "aks-casualty-rnd-central",
                    "not_fetched_count": 0,
                    "source_application": "Azure",
                    "subscription_id": "f7f03c3d-a8aa-443d-94ea-f0948fdda5fe",
                    "subscription_name": "Azure Public Cloud",
                    "tags": {
                        "tag_key": [
                            "AUDIT SCOPE",
                            "Application",
                            "Assigned VP"
                        ],
                        "tag_value": [
                            "Yes",
                            "Shared",
                            "Chris Swarey"
                        ]
                    },
                    "tenant_number": "4",
                    "type": "Containers"
                },
                "initial_plugin_unique_name": "azure_adapter_0",
                "plugin_name": "azure_adapter",
                "plugin_type": "Adapter",
                "plugin_unique_name": "azure_adapter_0",
                "quick_id": "azure_adapter_0!a52f35b7d37e0ab76b58",
                "type": "entitydata"
            },
            "internal_axon_id": "6abd6f55a9bc045510739cb2eb23be21",
            "transform_unique_id": "1qDt9m3qt7HtGa9rDHmFXO6zQ4A="
        }
    },
    "data_stream": {
        "dataset": "axonius.compute",
        "namespace": "87756",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "32cc86c3-bf76-4cc1-a389-5aaf51ace57c",
        "snapshot": false,
        "version": "9.1.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host",
            "vulnerability"
        ],
        "dataset": "axonius.compute",
        "ingested": "2025-12-21T08:31:04Z",
        "kind": "event",
        "module": "axonius",
        "original": "{\"adapter_list_length\":1,\"adapters\":[\"azure_adapter\"],\"asset_type\":\"containers\",\"event\":{\"accurate_for_datetime\":\"Fri, 05 Dec 2025 00:02:00 GMT\",\"adapter_categories\":[\"Cloud Infra\"],\"client_used\":\"67fd09ca731ccb5730923106\",\"data\":{\"accurate_for_datetime\":\"Fri, 05 Dec 2025 00:02:00 GMT\",\"application_and_account_name\":\"azure/azure-demo\",\"asset_entity_info\":\"AzureEntityType.KubernetesCluster\",\"asset_type\":\"Kubernetes Container\",\"connected_assets\":[\"subscription_id::969f0354-b771-4580-8a84-0634c45bbd5b\"],\"fetch_time\":\"Fri, 05 Dec 2025 00:01:58 GMT\",\"first_fetch_time\":\"Mon, 14 Apr 2025 13:26:37 GMT\",\"from_last_fetch\":true,\"id\":\"a52f35b7d37e0ab76b58\",\"id_raw\":\"0a4c0d54-e95a-469c-84c8-39cd53181def\",\"is_fetched_from_adapter\":true,\"last_fetch_connection_id\":\"67fd09ca731ccb5730923106\",\"last_fetch_connection_label\":\"azure-demo\",\"name\":\"aks-casualty-rnd-central\",\"not_fetched_count\":0,\"relatable_ids\":[],\"software_cves\":[],\"source_application\":\"Azure\",\"subscription_id\":\"f7f03c3d-a8aa-443d-94ea-f0948fdda5fe\",\"subscription_name\":\"Azure Public Cloud\",\"tags\":[{\"tag_key\":\"AUDIT SCOPE\",\"tag_value\":\"Yes\"},{\"tag_key\":\"Application\",\"tag_value\":\"Shared\"},{\"tag_key\":\"Assigned VP\",\"tag_value\":\"Chris Swarey\"}],\"tenant_number\":[\"4\"],\"type\":\"Containers\"},\"initial_plugin_unique_name\":\"azure_adapter_0\",\"plugin_name\":\"azure_adapter\",\"plugin_type\":\"Adapter\",\"plugin_unique_name\":\"azure_adapter_0\",\"quick_id\":\"azure_adapter_0!a52f35b7d37e0ab76b58\",\"type\":\"entitydata\"},\"internal_axon_id\":\"6abd6f55a9bc045510739cb2eb23be21\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_transform_source": "true"
    },
    "observer": {
        "vendor": "Axonius"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "axonius-compute"
    ]
}
```

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

* Compute:
    * devices (endpoint: `/api/v2/devices`)
    * compute_services (endpoint: `/api/v2/compute_services`)
    * databases (endpoint: `/api/v2/databases`)
    * containers (endpoint: `/api/v2/containers`)
    * serverless_functions (endpoint: `/api/v2/serverless_functions`)
    * compute_images (endpoint: `/api/v2/compute_images`)
    * configurations (endpoint: `/api/v2/configurations`)

#### ILM Policy

To facilitate compute data, source data stream-backed indices `.ds-logs-axonius.compute-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-axonius.compute-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
