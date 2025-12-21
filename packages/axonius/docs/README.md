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

- `Network`: Collect details of all identity assets including:
    - networks (endpoint: `/api/v2/networks`)
    - load_balancers (endpoint: `/api/v2/load_balancers`)
    - network_services (endpoint: `/api/v2/network_services`)
    - network_devices (endpoint: `/api/v2/network_devices`)
    - firewalls (endpoint: `/api/v2/firewalls`)
    - nat_rules (endpoint: `/api/v2/nat_rules`)
    - network_routes (endpoint: `/api/v2/network_routes`)

### Supported use cases

Integrating the Axonius Network Datastream with Elastic SIEM provides centralized visibility into network assets, traffic exposure, and connectivity across the environment. Kibana dashboards surface key insights into network asset status, device states, and routing behavior, helping analysts quickly understand overall network posture and potential exposure points.

The dashboards present clear breakdowns of assets by protocol, type, category, and operating system, while metrics highlight publicly exposed and unsafe network devices. Tables provide actionable context around top sources, destinations, subnetworks, routes, locations, and vendors, supporting deeper analysis of network dependencies and communication paths.

These insights help security teams identify network exposure hotspots, detect misconfigurations or risky assets, and streamline network-focused investigations across the organization.

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

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **axonius**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Network

The `network` data stream provides network events from axonius.

#### network fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| axonius.network.adapter_list_length |  | long |
| axonius.network.adapters |  | keyword |
| axonius.network.asset_type |  | keyword |
| axonius.network.event.accurate_for_datetime |  | date |
| axonius.network.event.action_if_exists |  | keyword |
| axonius.network.event.adapter_categories |  | keyword |
| axonius.network.event.associated_adapter_plugin_name |  | keyword |
| axonius.network.event.association_type |  | keyword |
| axonius.network.event.client_used |  | keyword |
| axonius.network.event.data._keep_hostname_empty |  | boolean |
| axonius.network.event.data.access |  | keyword |
| axonius.network.event.data.accurate_for_datetime |  | date |
| axonius.network.event.data.action |  | keyword |
| axonius.network.event.data.adapter_properties |  | keyword |
| axonius.network.event.data.agent_version |  | keyword |
| axonius.network.event.data.agent_versions.adapter_name |  | keyword |
| axonius.network.event.data.agent_versions.agent_version |  | keyword |
| axonius.network.event.data.agent_versions.agent_version_raw |  | keyword |
| axonius.network.event.data.all_associated_email_addresses |  | keyword |
| axonius.network.event.data.allow_nat |  | boolean |
| axonius.network.event.data.anti_malware_agent_status |  | keyword |
| axonius.network.event.data.anti_malware_agent_status_message |  | keyword |
| axonius.network.event.data.anti_malware_state |  | keyword |
| axonius.network.event.data.application_and_account_name |  | keyword |
| axonius.network.event.data.applications |  | keyword |
| axonius.network.event.data.arp_interface |  | keyword |
| axonius.network.event.data.arp_port |  | keyword |
| axonius.network.event.data.arp_status |  | keyword |
| axonius.network.event.data.arp_ttl |  | long |
| axonius.network.event.data.assessed_for_policies |  | boolean |
| axonius.network.event.data.assessed_for_vulnerabilities |  | boolean |
| axonius.network.event.data.asset_entity_info |  | keyword |
| axonius.network.event.data.asset_install_status |  | keyword |
| axonius.network.event.data.asset_tag |  | keyword |
| axonius.network.event.data.asset_type |  | keyword |
| axonius.network.event.data.asset_user_name |  | keyword |
| axonius.network.event.data.associated_device_users.internal_axon_id |  | keyword |
| axonius.network.event.data.associated_device_users.is_latest_used_user |  | boolean |
| axonius.network.event.data.associated_device_users.last_used_departments |  | keyword |
| axonius.network.event.data.associated_device_users.last_used_email |  | keyword |
| axonius.network.event.data.associated_device_users.last_used_email_domain |  | keyword |
| axonius.network.event.data.associated_device_users.last_used_user_manager |  | keyword |
| axonius.network.event.data.associated_saas_applications.internal_axon_id |  | keyword |
| axonius.network.event.data.associated_saas_applications.name |  | keyword |
| axonius.network.event.data.axon_id |  | keyword |
| axonius.network.event.data.axonius_instance_name |  | keyword |
| axonius.network.event.data.balanced_integer_ips |  | long |
| axonius.network.event.data.balanced_ips |  | ip |
| axonius.network.event.data.browsers.channel |  | keyword |
| axonius.network.event.data.browsers.version |  | keyword |
| axonius.network.event.data.category |  | keyword |
| axonius.network.event.data.certificate_expiry_date |  | date |
| axonius.network.event.data.chrome_device_type |  | keyword |
| axonius.network.event.data.cidr_blocks |  | keyword |
| axonius.network.event.data.cisa_vulnerabilities.action |  | keyword |
| axonius.network.event.data.cisa_vulnerabilities.added |  | date |
| axonius.network.event.data.cisa_vulnerabilities.cve_id |  | keyword |
| axonius.network.event.data.cisa_vulnerabilities.desc |  | keyword |
| axonius.network.event.data.cisa_vulnerabilities.due_date |  | date |
| axonius.network.event.data.cisa_vulnerabilities.notes |  | keyword |
| axonius.network.event.data.cisa_vulnerabilities.product |  | keyword |
| axonius.network.event.data.cisa_vulnerabilities.used_in_ransomware |  | boolean |
| axonius.network.event.data.cisa_vulnerabilities.vendor |  | keyword |
| axonius.network.event.data.cisa_vulnerabilities.vulnerability_name |  | keyword |
| axonius.network.event.data.class_name |  | keyword |
| axonius.network.event.data.class_title |  | keyword |
| axonius.network.event.data.class_type |  | keyword |
| axonius.network.event.data.cloud_provider_account_id |  | keyword |
| axonius.network.event.data.cmdb_business_applications.app_owner |  | keyword |
| axonius.network.event.data.cmdb_business_applications.assignment_group |  | keyword |
| axonius.network.event.data.cmdb_business_applications.business_criticality |  | keyword |
| axonius.network.event.data.cmdb_business_applications.install_status |  | keyword |
| axonius.network.event.data.cmdb_business_applications.managed_by |  | keyword |
| axonius.network.event.data.cmdb_business_applications.name |  | keyword |
| axonius.network.event.data.cmdb_business_applications.number |  | keyword |
| axonius.network.event.data.cmdb_business_applications.u_architect |  | keyword |
| axonius.network.event.data.cmdb_business_applications.u_availability_criticality |  | keyword |
| axonius.network.event.data.cmdb_business_applications.u_confidentiality_criticality |  | keyword |
| axonius.network.event.data.cmdb_business_applications.u_crown_jewel |  | boolean |
| axonius.network.event.data.cmdb_business_applications.u_integrity_criticality |  | keyword |
| axonius.network.event.data.cmdb_business_applications.u_privacy_criticality |  | keyword |
| axonius.network.event.data.color |  | keyword |
| axonius.network.event.data.common_users |  | keyword |
| axonius.network.event.data.company |  | keyword |
| axonius.network.event.data.confidence_level |  | long |
| axonius.network.event.data.connected_assets |  | keyword |
| axonius.network.event.data.connected_devices |  | keyword |
| axonius.network.event.data.cp_type |  | keyword |
| axonius.network.event.data.cpus.cores |  | long |
| axonius.network.event.data.cpus.ghz |  | double |
| axonius.network.event.data.cpus.manufacturer |  | keyword |
| axonius.network.event.data.cpus.name |  | keyword |
| axonius.network.event.data.creation_time_stamp |  | date |
| axonius.network.event.data.criticality |  | keyword |
| axonius.network.event.data.custom_risk_owner |  | keyword |
| axonius.network.event.data.data_center |  | keyword |
| axonius.network.event.data.destination |  | keyword |
| axonius.network.event.data.destination_addresses |  | keyword |
| axonius.network.event.data.destination_ips |  | ip |
| axonius.network.event.data.destination_port |  | long |
| axonius.network.event.data.destination_zone |  | keyword |
| axonius.network.event.data.device_group |  | keyword |
| axonius.network.event.data.device_manufacturer |  | keyword |
| axonius.network.event.data.device_serial |  | keyword |
| axonius.network.event.data.device_state |  | keyword |
| axonius.network.event.data.device_type |  | keyword |
| axonius.network.event.data.devices_axon_ids |  | keyword |
| axonius.network.event.data.direction |  | keyword |
| axonius.network.event.data.disk_encryption_configuration |  | keyword |
| axonius.network.event.data.domain |  | keyword |
| axonius.network.event.data.entity_id |  | keyword |
| axonius.network.event.data.environment |  | keyword |
| axonius.network.event.data.epo_host |  | keyword |
| axonius.network.event.data.epo_id |  | keyword |
| axonius.network.event.data.epo_products |  | keyword |
| axonius.network.event.data.excluded_software_cves |  | keyword |
| axonius.network.event.data.external_cloud_account_id |  | keyword |
| axonius.network.event.data.external_ip |  | ip |
| axonius.network.event.data.external_nat_ip |  | ip |
| axonius.network.event.data.fetch_proto |  | keyword |
| axonius.network.event.data.fetch_time |  | date |
| axonius.network.event.data.fields_to_unset |  | keyword |
| axonius.network.event.data.fingerprint |  | keyword |
| axonius.network.event.data.firewall_enabled |  | boolean |
| axonius.network.event.data.firewall_rules |  | keyword |
| axonius.network.event.data.first_fetch_time |  | date |
| axonius.network.event.data.first_seen |  | date |
| axonius.network.event.data.fqdn |  | keyword |
| axonius.network.event.data.free_physical_memory |  | double |
| axonius.network.event.data.from_last_fetch |  | boolean |
| axonius.network.event.data.general.extension_name |  | keyword |
| axonius.network.event.data.general.extension_value |  | keyword |
| axonius.network.event.data.generic_encryption.status |  | boolean |
| axonius.network.event.data.ghost |  | boolean |
| axonius.network.event.data.guest_dns_name |  | keyword |
| axonius.network.event.data.guest_family |  | keyword |
| axonius.network.event.data.guest_name |  | keyword |
| axonius.network.event.data.guest_state |  | keyword |
| axonius.network.event.data.hard_drives.free_size |  | double |
| axonius.network.event.data.hard_drives.is_encrypted |  | boolean |
| axonius.network.event.data.hard_drives.total_size |  | double |
| axonius.network.event.data.hardware_status |  | keyword |
| axonius.network.event.data.hostname |  | keyword |
| axonius.network.event.data.id |  | keyword |
| axonius.network.event.data.id_raw |  | keyword |
| axonius.network.event.data.in_groups |  | keyword |
| axonius.network.event.data.inbound_rules.from_port |  | long |
| axonius.network.event.data.inbound_rules.ip_protocol |  | keyword |
| axonius.network.event.data.inbound_rules.ip_ranges |  | keyword |
| axonius.network.event.data.inbound_rules.to_port |  | long |
| axonius.network.event.data.inbound_rules.type |  | keyword |
| axonius.network.event.data.install_status |  | keyword |
| axonius.network.event.data.installed_software.generated_cpe |  | keyword |
| axonius.network.event.data.installed_software.name |  | keyword |
| axonius.network.event.data.installed_software.name_version |  | keyword |
| axonius.network.event.data.installed_software.sw_uid |  | keyword |
| axonius.network.event.data.installed_software.vendor |  | keyword |
| axonius.network.event.data.installed_software.vendor_publisher |  | keyword |
| axonius.network.event.data.installed_software.version |  | keyword |
| axonius.network.event.data.installed_software.version_raw |  | keyword |
| axonius.network.event.data.ip_address_guid |  | keyword |
| axonius.network.event.data.is_authenticated_scan |  | boolean |
| axonius.network.event.data.is_enabled |  | boolean |
| axonius.network.event.data.is_exposing_public_traffic |  | boolean |
| axonius.network.event.data.is_fetched_from_adapter |  | boolean |
| axonius.network.event.data.is_fragile |  | boolean |
| axonius.network.event.data.is_latest_last_seen |  | boolean |
| axonius.network.event.data.is_managed |  | boolean |
| axonius.network.event.data.is_network_infra_device |  | boolean |
| axonius.network.event.data.is_purchased |  | boolean |
| axonius.network.event.data.is_safe |  | boolean |
| axonius.network.event.data.jamf_groups |  | keyword |
| axonius.network.event.data.jamf_groups_detailed.group_id |  | keyword |
| axonius.network.event.data.jamf_groups_detailed.group_name |  | keyword |
| axonius.network.event.data.jamf_groups_detailed.smart_group |  | boolean |
| axonius.network.event.data.jamf_id |  | keyword |
| axonius.network.event.data.jamf_location.building |  | keyword |
| axonius.network.event.data.jamf_location.email_address |  | keyword |
| axonius.network.event.data.jamf_location.phone_number |  | keyword |
| axonius.network.event.data.jamf_location.position |  | keyword |
| axonius.network.event.data.jamf_location.real_name |  | keyword |
| axonius.network.event.data.jamf_location.room |  | long |
| axonius.network.event.data.jamf_location.username |  | keyword |
| axonius.network.event.data.jamf_version |  | keyword |
| axonius.network.event.data.last_agent_import |  | date |
| axonius.network.event.data.last_auth_run |  | date |
| axonius.network.event.data.last_contact_time |  | date |
| axonius.network.event.data.last_enrolled_date_utc |  | date |
| axonius.network.event.data.last_fetch_connection_id |  | keyword |
| axonius.network.event.data.last_fetch_connection_label |  | keyword |
| axonius.network.event.data.last_scan |  | date |
| axonius.network.event.data.last_seen |  | date |
| axonius.network.event.data.last_seen_agents |  | date |
| axonius.network.event.data.last_unauth_run |  | date |
| axonius.network.event.data.last_used_users |  | keyword |
| axonius.network.event.data.last_used_users_departments_association |  | keyword |
| axonius.network.event.data.last_used_users_email_domain_association |  | keyword |
| axonius.network.event.data.last_used_users_internal_axon_id_association |  | keyword |
| axonius.network.event.data.last_used_users_mail_association |  | keyword |
| axonius.network.event.data.last_used_users_user_manager_association |  | keyword |
| axonius.network.event.data.last_used_users_user_manager_mail_association |  | keyword |
| axonius.network.event.data.last_used_users_user_status_association |  | keyword |
| axonius.network.event.data.last_used_users_user_title_association |  | keyword |
| axonius.network.event.data.latest_used_user |  | keyword |
| axonius.network.event.data.latest_used_user_department |  | keyword |
| axonius.network.event.data.latest_used_user_email_domain |  | keyword |
| axonius.network.event.data.latest_used_user_mail |  | keyword |
| axonius.network.event.data.latest_used_user_user_manager |  | keyword |
| axonius.network.event.data.latest_used_user_user_status |  | keyword |
| axonius.network.event.data.latest_used_user_user_title |  | keyword |
| axonius.network.event.data.linked_tickets.category |  | keyword |
| axonius.network.event.data.linked_tickets.created |  | date |
| axonius.network.event.data.linked_tickets.description |  | keyword |
| axonius.network.event.data.linked_tickets.display_id |  | keyword |
| axonius.network.event.data.linked_tickets.priority |  | keyword |
| axonius.network.event.data.linked_tickets.reporter |  | keyword |
| axonius.network.event.data.linked_tickets.status |  | keyword |
| axonius.network.event.data.linked_tickets.summary |  | keyword |
| axonius.network.event.data.linked_tickets.updated |  | date |
| axonius.network.event.data.load_balancers_axon_ids |  | keyword |
| axonius.network.event.data.location |  | keyword |
| axonius.network.event.data.lock |  | keyword |
| axonius.network.event.data.meeting_id |  | keyword |
| axonius.network.event.data.method |  | keyword |
| axonius.network.event.data.microphone |  | keyword |
| axonius.network.event.data.mtu |  | long |
| axonius.network.event.data.name |  | keyword |
| axonius.network.event.data.nat_policy_ips.address |  | ip |
| axonius.network.event.data.nat_policy_ips.direction |  | keyword |
| axonius.network.event.data.nat_policy_ips.matched_on |  | keyword |
| axonius.network.event.data.nat_policy_ips.policy_name |  | keyword |
| axonius.network.event.data.nat_policy_ips.rule_num |  | long |
| axonius.network.event.data.nat_policy_ips.uid |  | keyword |
| axonius.network.event.data.nat_rules_axon_ids |  | keyword |
| axonius.network.event.data.nat_translations.from_destination_integer_ip |  | long |
| axonius.network.event.data.nat_translations.from_source_integer_ip |  | long |
| axonius.network.event.data.nat_translations.is_destination_ip_range_public |  | boolean |
| axonius.network.event.data.nat_translations.is_source_ip_range_public |  | boolean |
| axonius.network.event.data.nat_translations.to_destination_integer_ip |  | long |
| axonius.network.event.data.nat_translations.to_source_integer_ip |  | long |
| axonius.network.event.data.network |  | keyword |
| axonius.network.event.data.network_firewall_policy |  | keyword |
| axonius.network.event.data.network_interfaces.ips |  | keyword |
| axonius.network.event.data.network_interfaces.ips_raw |  | long |
| axonius.network.event.data.network_interfaces.ips_v4 |  | keyword |
| axonius.network.event.data.network_interfaces.ips_v4_raw |  | long |
| axonius.network.event.data.network_interfaces.mac |  | keyword |
| axonius.network.event.data.network_interfaces.manufacturer |  | keyword |
| axonius.network.event.data.network_interfaces.subnets |  | keyword |
| axonius.network.event.data.network_status |  | keyword |
| axonius.network.event.data.network_type |  | keyword |
| axonius.network.event.data.nexpose_id |  | keyword |
| axonius.network.event.data.nexpose_type |  | keyword |
| axonius.network.event.data.node_id |  | keyword |
| axonius.network.event.data.node_name |  | keyword |
| axonius.network.event.data.normalization_reasons.calculated_time |  | date |
| axonius.network.event.data.normalization_reasons.key |  | keyword |
| axonius.network.event.data.normalization_reasons.original |  | keyword |
| axonius.network.event.data.normalization_reasons.reason |  | keyword |
| axonius.network.event.data.not_fetched_count |  | long |
| axonius.network.event.data.open_ports.port_id |  | keyword |
| axonius.network.event.data.open_ports.protocol |  | keyword |
| axonius.network.event.data.operational_status |  | keyword |
| axonius.network.event.data.organizational_unit |  | keyword |
| axonius.network.event.data.os.codename |  | keyword |
| axonius.network.event.data.os.distribution |  | keyword |
| axonius.network.event.data.os.distribution_name |  | keyword |
| axonius.network.event.data.os.end_of_life |  | date |
| axonius.network.event.data.os.end_of_support |  | date |
| axonius.network.event.data.os.is_end_of_life |  | boolean |
| axonius.network.event.data.os.is_end_of_support |  | boolean |
| axonius.network.event.data.os.is_latest_os_version |  | boolean |
| axonius.network.event.data.os.is_windows_server |  | boolean |
| axonius.network.event.data.os.latest_os_version |  | keyword |
| axonius.network.event.data.os.major |  | long |
| axonius.network.event.data.os.minor |  | long |
| axonius.network.event.data.os.os_cpe |  | keyword |
| axonius.network.event.data.os.os_dotted |  | keyword |
| axonius.network.event.data.os.os_dotted_raw |  | long |
| axonius.network.event.data.os.os_str |  | keyword |
| axonius.network.event.data.os.type |  | keyword |
| axonius.network.event.data.os.type_distribution |  | keyword |
| axonius.network.event.data.os_ext_attributes.attr_name |  | keyword |
| axonius.network.event.data.os_ext_attributes.data_type |  | keyword |
| axonius.network.event.data.os_ext_attributes.definition_id |  | keyword |
| axonius.network.event.data.os_ext_attributes.ext_description |  | keyword |
| axonius.network.event.data.os_ext_attributes.input_type |  | keyword |
| axonius.network.event.data.os_ext_attributes.is_enabled |  | boolean |
| axonius.network.event.data.os_ext_attributes.is_multivalue |  | boolean |
| axonius.network.event.data.os_ext_attributes.values |  | keyword |
| axonius.network.event.data.owner |  | keyword |
| axonius.network.event.data.paloalto_device_type |  | keyword |
| axonius.network.event.data.part_of_domain |  | boolean |
| axonius.network.event.data.peerings.exchange_subnet_routes |  | boolean |
| axonius.network.event.data.peerings.export_custom_routes |  | boolean |
| axonius.network.event.data.peerings.import_custom_routes |  | boolean |
| axonius.network.event.data.peerings.peer_mtu |  | long |
| axonius.network.event.data.peerings.state |  | keyword |
| axonius.network.event.data.peerings.state_details |  | keyword |
| axonius.network.event.data.physical_location |  | keyword |
| axonius.network.event.data.physical_memory_percentage |  | double |
| axonius.network.event.data.plugin_and_severities.cpe |  | keyword |
| axonius.network.event.data.plugin_and_severities.cve |  | keyword |
| axonius.network.event.data.plugin_and_severities.cvss_base_score |  | float |
| axonius.network.event.data.plugin_and_severities.days_seen |  | long |
| axonius.network.event.data.plugin_and_severities.exploit_available |  | boolean |
| axonius.network.event.data.plugin_and_severities.family.id |  | keyword |
| axonius.network.event.data.plugin_and_severities.family.name |  | keyword |
| axonius.network.event.data.plugin_and_severities.first_found |  | date |
| axonius.network.event.data.plugin_and_severities.first_seen |  | date |
| axonius.network.event.data.plugin_and_severities.has_been_mitigated |  | boolean |
| axonius.network.event.data.plugin_and_severities.has_patch |  | boolean |
| axonius.network.event.data.plugin_and_severities.last_fixed |  | date |
| axonius.network.event.data.plugin_and_severities.last_found |  | date |
| axonius.network.event.data.plugin_and_severities.last_seen |  | date |
| axonius.network.event.data.plugin_and_severities.mitigated |  | boolean |
| axonius.network.event.data.plugin_and_severities.nessus_instance.credentialed_check |  | keyword |
| axonius.network.event.data.plugin_and_severities.nessus_instance.display_superseded_patches |  | boolean |
| axonius.network.event.data.plugin_and_severities.nessus_instance.experimental_tests |  | boolean |
| axonius.network.event.data.plugin_and_severities.nessus_instance.patch_management_checks |  | keyword |
| axonius.network.event.data.plugin_and_severities.nessus_instance.plugin_feed_version |  | keyword |
| axonius.network.event.data.plugin_and_severities.nessus_instance.report_verbosity |  | long |
| axonius.network.event.data.plugin_and_severities.nessus_instance.safe_check |  | boolean |
| axonius.network.event.data.plugin_and_severities.nessus_instance.scan_name |  | keyword |
| axonius.network.event.data.plugin_and_severities.nessus_instance.scan_policy_used |  | keyword |
| axonius.network.event.data.plugin_and_severities.nessus_instance.scan_type |  | keyword |
| axonius.network.event.data.plugin_and_severities.nessus_instance.scanner_edition_used |  | keyword |
| axonius.network.event.data.plugin_and_severities.nessus_instance.scanner_ip |  | ip |
| axonius.network.event.data.plugin_and_severities.nessus_instance.thorough_tests |  | boolean |
| axonius.network.event.data.plugin_and_severities.nessus_instance.version |  | keyword |
| axonius.network.event.data.plugin_and_severities.patch_publication_date |  | date |
| axonius.network.event.data.plugin_and_severities.plugin |  | keyword |
| axonius.network.event.data.plugin_and_severities.plugin_id |  | keyword |
| axonius.network.event.data.plugin_and_severities.plugin_id_number |  | keyword |
| axonius.network.event.data.plugin_and_severities.severity |  | keyword |
| axonius.network.event.data.plugin_and_severities.severity_modification_type |  | keyword |
| axonius.network.event.data.plugin_and_severities.solution |  | keyword |
| axonius.network.event.data.plugin_and_severities.state |  | keyword |
| axonius.network.event.data.plugin_and_severities.unsupported_by_vendor |  | boolean |
| axonius.network.event.data.plugin_and_severities.vpr_score |  | float |
| axonius.network.event.data.plugin_and_severities.vuln_state |  | keyword |
| axonius.network.event.data.policy_id |  | keyword |
| axonius.network.event.data.policy_name |  | keyword |
| axonius.network.event.data.pool_members_ips |  | ip |
| axonius.network.event.data.pool_name |  | keyword |
| axonius.network.event.data.power_state |  | keyword |
| axonius.network.event.data.pretty_id |  | keyword |
| axonius.network.event.data.priority |  | long |
| axonius.network.event.data.private_integer_ips |  | long |
| axonius.network.event.data.private_ips |  | ip |
| axonius.network.event.data.project_id |  | keyword |
| axonius.network.event.data.protocol |  | keyword |
| axonius.network.event.data.provisioningState |  | keyword |
| axonius.network.event.data.public_ips |  | ip |
| axonius.network.event.data.ranger_version |  | keyword |
| axonius.network.event.data.raw_hostname |  | keyword |
| axonius.network.event.data.read_only |  | boolean |
| axonius.network.event.data.recording |  | boolean |
| axonius.network.event.data.relatable_ids |  | keyword |
| axonius.network.event.data.related_network_route_ids |  | keyword |
| axonius.network.event.data.relative_path |  | keyword |
| axonius.network.event.data.report_date |  | date |
| axonius.network.event.data.resource_group |  | keyword |
| axonius.network.event.data.risk_level |  | long |
| axonius.network.event.data.risk_level_value |  | keyword |
| axonius.network.event.data.route.asset |  | keyword |
| axonius.network.event.data.route.asset_internal_axon_id |  | keyword |
| axonius.network.event.data.route.host_ipv4s |  | ip |
| axonius.network.event.data.route.is_end_point |  | boolean |
| axonius.network.event.data.route.is_entry_point |  | boolean |
| axonius.network.event.data.route.is_public_facing |  | boolean |
| axonius.network.event.data.route.name |  | keyword |
| axonius.network.event.data.route.nat.from_destination_integer_ip |  | long |
| axonius.network.event.data.route.nat.from_destination_ip_address |  | ip |
| axonius.network.event.data.route.nat.from_source_integer_ip |  | long |
| axonius.network.event.data.route.nat.from_source_ip_address |  | ip |
| axonius.network.event.data.route.nat.is_destination_ip_range_public |  | boolean |
| axonius.network.event.data.route.nat.is_source_ip_range_public |  | boolean |
| axonius.network.event.data.route.nat.to_destination_integer_ip |  | long |
| axonius.network.event.data.route.nat.to_destination_ip_address |  | ip |
| axonius.network.event.data.route.nat.to_source_integer_ip |  | long |
| axonius.network.event.data.route.nat.to_source_ip_address |  | ip |
| axonius.network.event.data.route.order |  | keyword |
| axonius.network.event.data.route.product_type |  | keyword |
| axonius.network.event.data.route.vendors |  | keyword |
| axonius.network.event.data.routing_mode |  | keyword |
| axonius.network.event.data.rule_base_type |  | keyword |
| axonius.network.event.data.rule_type |  | keyword |
| axonius.network.event.data.scan_results |  | keyword |
| axonius.network.event.data.scan_results_objs.id |  | keyword |
| axonius.network.event.data.scan_results_objs.name |  | keyword |
| axonius.network.event.data.scan_results_objs.status |  | keyword |
| axonius.network.event.data.scanner |  | boolean |
| axonius.network.event.data.security_updates_last_changed |  | date |
| axonius.network.event.data.security_updates_status |  | keyword |
| axonius.network.event.data.server_type |  | keyword |
| axonius.network.event.data.service |  | keyword |
| axonius.network.event.data.services |  | keyword |
| axonius.network.event.data.severity_critical |  | long |
| axonius.network.event.data.severity_high |  | long |
| axonius.network.event.data.severity_info |  | long |
| axonius.network.event.data.severity_low |  | long |
| axonius.network.event.data.severity_medium |  | long |
| axonius.network.event.data.share_application |  | boolean |
| axonius.network.event.data.share_desktop |  | boolean |
| axonius.network.event.data.share_whiteboard |  | boolean |
| axonius.network.event.data.sip_status |  | boolean |
| axonius.network.event.data.site_name |  | keyword |
| axonius.network.event.data.software_cves.axonius_risk_score |  | double |
| axonius.network.event.data.software_cves.axonius_status |  | keyword |
| axonius.network.event.data.software_cves.axonius_status_last_update |  | date |
| axonius.network.event.data.software_cves.custom_software_cves_business_unit |  | keyword |
| axonius.network.event.data.software_cves.cve_from_sw_analysis |  | boolean |
| axonius.network.event.data.software_cves.cve_id |  | keyword |
| axonius.network.event.data.software_cves.cve_list |  | keyword |
| axonius.network.event.data.software_cves.cve_severity |  | keyword |
| axonius.network.event.data.software_cves.cve_synopsis |  | keyword |
| axonius.network.event.data.software_cves.cvss |  | float |
| axonius.network.event.data.software_cves.cvss2_score |  | float |
| axonius.network.event.data.software_cves.cvss2_score_num |  | float |
| axonius.network.event.data.software_cves.cvss3_score |  | float |
| axonius.network.event.data.software_cves.cvss3_score_num |  | float |
| axonius.network.event.data.software_cves.cvss4_score |  | float |
| axonius.network.event.data.software_cves.cvss4_score_num |  | float |
| axonius.network.event.data.software_cves.cvss_str |  | keyword |
| axonius.network.event.data.software_cves.cvss_vector |  | keyword |
| axonius.network.event.data.software_cves.cvss_version |  | keyword |
| axonius.network.event.data.software_cves.cwe_id |  | keyword |
| axonius.network.event.data.software_cves.epss.creation_date |  | date |
| axonius.network.event.data.software_cves.epss.cve_id |  | keyword |
| axonius.network.event.data.software_cves.epss.percentile |  | double |
| axonius.network.event.data.software_cves.epss.score |  | double |
| axonius.network.event.data.software_cves.exploitability_score |  | double |
| axonius.network.event.data.software_cves.first_fetch_time |  | date |
| axonius.network.event.data.software_cves.hash_id |  | keyword |
| axonius.network.event.data.software_cves.impact_score |  | double |
| axonius.network.event.data.software_cves.last_fetch_time |  | date |
| axonius.network.event.data.software_cves.last_modified_date |  | date |
| axonius.network.event.data.software_cves.mitigated |  | boolean |
| axonius.network.event.data.software_cves.msrc.creation_date |  | keyword |
| axonius.network.event.data.software_cves.msrc.cve_id |  | keyword |
| axonius.network.event.data.software_cves.msrc.title |  | keyword |
| axonius.network.event.data.software_cves.nvd_publish_age |  | long |
| axonius.network.event.data.software_cves.publish_date |  | date |
| axonius.network.event.data.software_cves.software_name |  | keyword |
| axonius.network.event.data.software_cves.software_type |  | keyword |
| axonius.network.event.data.software_cves.software_vendor |  | keyword |
| axonius.network.event.data.software_cves.software_version |  | keyword |
| axonius.network.event.data.software_cves.solution_hash_id |  | keyword |
| axonius.network.event.data.software_cves.version_raw |  | keyword |
| axonius.network.event.data.source_addresses |  | ip |
| axonius.network.event.data.source_application |  | keyword |
| axonius.network.event.data.source_ips |  | ip |
| axonius.network.event.data.source_zone |  | keyword |
| axonius.network.event.data.speaker |  | keyword |
| axonius.network.event.data.special_hint |  | long |
| axonius.network.event.data.special_hint_underscore |  | keyword |
| axonius.network.event.data.state |  | keyword |
| axonius.network.event.data.subnet_tag |  | keyword |
| axonius.network.event.data.subnetworks.creation_timestamp |  | date |
| axonius.network.event.data.subnetworks.gateway_address |  | ip |
| axonius.network.event.data.subnetworks.id |  | keyword |
| axonius.network.event.data.subnetworks.ip_cidr_range |  | ip |
| axonius.network.event.data.subnetworks.name |  | keyword |
| axonius.network.event.data.subnetworks.private_ip_google_access |  | boolean |
| axonius.network.event.data.subscription_id |  | keyword |
| axonius.network.event.data.subscription_name |  | keyword |
| axonius.network.event.data.swap_free |  | double |
| axonius.network.event.data.swap_total |  | double |
| axonius.network.event.data.sys_id |  | keyword |
| axonius.network.event.data.table_type |  | keyword |
| axonius.network.event.data.tenant_number |  | keyword |
| axonius.network.event.data.tenant_tag |  | keyword |
| axonius.network.event.data.threat_level |  | keyword |
| axonius.network.event.data.threats |  | keyword |
| axonius.network.event.data.total |  | long |
| axonius.network.event.data.total_number_of_cores |  | long |
| axonius.network.event.data.total_physical_memory |  | double |
| axonius.network.event.data.traffic_direction |  | keyword |
| axonius.network.event.data.type |  | keyword |
| axonius.network.event.data.u_business_owner |  | keyword |
| axonius.network.event.data.u_business_unit |  | keyword |
| axonius.network.event.data.uniq_sites_count |  | long |
| axonius.network.event.data.uri |  | keyword |
| axonius.network.event.data.urls_axon_ids |  | keyword |
| axonius.network.event.data.uuid |  | keyword |
| axonius.network.event.data.vendor |  | keyword |
| axonius.network.event.data.virtual_host |  | boolean |
| axonius.network.event.data.vm_status |  | keyword |
| axonius.network.event.data.vm_type |  | keyword |
| axonius.network.event.data.vpn_domain |  | keyword |
| axonius.network.event.data.vpn_is_local |  | boolean |
| axonius.network.event.data.vpn_lifetime |  | long |
| axonius.network.event.data.vpn_public_ip |  | ip |
| axonius.network.event.data.vpn_tunnel_type |  | keyword |
| axonius.network.event.data.vpn_type |  | keyword |
| axonius.network.event.data.z_sys_class_name |  | keyword |
| axonius.network.event.data.z_table_hierarchy.name |  | keyword |
| axonius.network.event.data.zoom_ip |  | ip |
| axonius.network.event.enrichment_type |  | keyword |
| axonius.network.event.entity |  | keyword |
| axonius.network.event.hidden_for_gui |  | boolean |
| axonius.network.event.initial_plugin_unique_name |  | keyword |
| axonius.network.event.name |  | keyword |
| axonius.network.event.plugin_name |  | keyword |
| axonius.network.event.plugin_type |  | keyword |
| axonius.network.event.plugin_unique_name |  | keyword |
| axonius.network.event.quick_id |  | keyword |
| axonius.network.event.type |  | keyword |
| axonius.network.internal_axon_id |  | keyword |
| axonius.network.labels |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


An example event for `network` looks as following:

```json
{
    "@timestamp": "2025-12-16T00:02:05.000Z",
    "agent": {
        "ephemeral_id": "69231e59-4d1b-4135-a120-8470b0e1ec9f",
        "id": "f6374adb-d8cd-42be-a634-ec45f978203a",
        "name": "elastic-agent-71306",
        "type": "filebeat",
        "version": "9.1.3"
    },
    "axonius": {
        "network": {
            "adapter_list_length": 1,
            "adapters": "azure_adapter",
            "asset_type": "networks",
            "event": {
                "accurate_for_datetime": "2025-12-16T00:02:05.000Z",
                "adapter_categories": "Cloud Infra",
                "client_used": "67fd09ca731ccb5730923106",
                "data": {
                    "access": "Allow",
                    "accurate_for_datetime": "2025-12-16T00:02:05.000Z",
                    "application_and_account_name": "azure/azure-demo",
                    "connected_assets": "subscription_id::64062aef-14a6-42a4-86b1-8a25d0c7cb24",
                    "direction": "Inbound",
                    "fetch_time": "2025-12-16T00:02:04.000Z",
                    "first_fetch_time": "2025-12-14T16:49:34.000Z",
                    "from_last_fetch": true,
                    "id": "2142ce3eb735930b68a7",
                    "id_raw": "912b0b56-fb12-4fe9-8f88-214c6c6b32e5",
                    "is_fetched_from_adapter": true,
                    "last_fetch_connection_id": "67fd09ca731ccb5730923106",
                    "last_fetch_connection_label": "azure-demo",
                    "location": "New York City",
                    "name": "FTP-ENABLED-Allowedcb5E-",
                    "not_fetched_count": 0,
                    "pretty_id": "AX-1156168648572164619",
                    "priority": 1937,
                    "protocol": "UDP",
                    "provisioningState": "Succeeded",
                    "source_application": "Azure",
                    "subscription_id": "b3fa20bb-a9c1-4cb6-80a9-13bcc9d68da5",
                    "subscription_name": "Microsoft Azure Enterprise",
                    "tenant_number": "2",
                    "type": "Networks"
                },
                "initial_plugin_unique_name": "azure_adapter_0",
                "plugin_name": "azure_adapter",
                "plugin_type": "Adapter",
                "plugin_unique_name": "azure_adapter_0",
                "quick_id": "azure_adapter_0!2142ce3eb735930b68a7",
                "type": "entitydata"
            },
            "internal_axon_id": "100b89429e965a0bf70a9bae08c4b679"
        }
    },
    "data_stream": {
        "dataset": "axonius.network",
        "namespace": "37570",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "f6374adb-d8cd-42be-a634-ec45f978203a",
        "snapshot": false,
        "version": "9.1.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "axonius.network",
        "ingested": "2025-12-21T07:36:35Z",
        "kind": "event",
        "module": "axonius",
        "original": "{\"adapter_list_length\":1,\"adapters\":[\"azure_adapter\"],\"asset_type\":\"networks\",\"event\":{\"accurate_for_datetime\":\"Tue, 16 Dec 2025 00:02:05 GMT\",\"adapter_categories\":[\"Cloud Infra\"],\"client_used\":\"67fd09ca731ccb5730923106\",\"data\":{\"access\":\"Allow\",\"accurate_for_datetime\":\"Tue, 16 Dec 2025 00:02:05 GMT\",\"application_and_account_name\":\"azure/azure-demo\",\"connected_assets\":[\"subscription_id::64062aef-14a6-42a4-86b1-8a25d0c7cb24\"],\"direction\":\"Inbound\",\"fetch_time\":\"Tue, 16 Dec 2025 00:02:04 GMT\",\"first_fetch_time\":\"Sun, 14 Dec 2025 16:49:34 GMT\",\"from_last_fetch\":true,\"id\":\"2142ce3eb735930b68a7\",\"id_raw\":\"912b0b56-fb12-4fe9-8f88-214c6c6b32e5\",\"is_fetched_from_adapter\":true,\"last_fetch_connection_id\":\"67fd09ca731ccb5730923106\",\"last_fetch_connection_label\":\"azure-demo\",\"location\":\"New York City\",\"name\":\"FTP-ENABLED-Allowedcb5E-\",\"not_fetched_count\":0,\"pretty_id\":\"AX-1156168648572164619\",\"priority\":1937,\"protocol\":\"UDP\",\"provisioningState\":\"Succeeded\",\"source_application\":\"Azure\",\"subscription_id\":\"b3fa20bb-a9c1-4cb6-80a9-13bcc9d68da5\",\"subscription_name\":\"Microsoft Azure Enterprise\",\"tenant_number\":[\"2\"],\"type\":\"Networks\"},\"initial_plugin_unique_name\":\"azure_adapter_0\",\"plugin_name\":\"azure_adapter\",\"plugin_type\":\"Adapter\",\"plugin_unique_name\":\"azure_adapter_0\",\"quick_id\":\"azure_adapter_0!2142ce3eb735930b68a7\",\"type\":\"entitydata\"},\"internal_axon_id\":\"100b89429e965a0bf70a9bae08c4b679\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "geo": {
            "city_name": "New York City"
        }
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_transform_source": "true"
    },
    "network": {
        "direction": "inbound",
        "protocol": "udp"
    },
    "observer": {
        "vendor": "Axonius"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "axonius-network"
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

* Network
    * networks (endpoint: `/api/v2/networks`)
    * load_balancers (endpoint: `/api/v2/load_balancers`)
    * network_services (endpoint: `/api/v2/network_services`)
    * network_devices (endpoint: `/api/v2/network_devices`)
    * firewalls (endpoint: `/api/v2/firewalls`)
    * nat_rules (endpoint: `/api/v2/nat_rules`)
    * network_routes (endpoint: `/api/v2/network_routes`)

#### ILM Policy

To facilitate network data, source data stream-backed indices `.ds-logs-axonius.network-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-axonius.network-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
