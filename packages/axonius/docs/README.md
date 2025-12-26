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

Integrating the Axonius Identity Datastream with Elastic SIEM provides a unified view of users, groups, roles, organizational units, accounts, permissions, certificates, profiles, and access review activity. Metrics and breakdowns help teams quickly assess identity posture by highlighting active, inactive, suspended, and external users, as well as patterns across user types and departments.

Tables showing top email addresses and cloud providers add context into frequently used identities and their sources. These insights help security and IAM teams detect identity anomalies, validate account hygiene, and maintain strong visibility into access across the organization.

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
3. In the search bar, type **axonius**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Identity

The `identity` data stream provides identity asset logs from axonius.

#### identity fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| axonius.identity.adapter_list_length |  | long |
| axonius.identity.adapters |  | keyword |
| axonius.identity.asset_type |  | keyword |
| axonius.identity.event.accurate_for_datetime |  | date |
| axonius.identity.event.action_if_exists |  | keyword |
| axonius.identity.event.adapter_categories |  | keyword |
| axonius.identity.event.associated_adapter_plugin_name |  | keyword |
| axonius.identity.event.association_type |  | keyword |
| axonius.identity.event.client_used |  | keyword |
| axonius.identity.event.data.account_disabled |  | boolean |
| axonius.identity.event.data.accurate_for_datetime |  | date |
| axonius.identity.event.data.active |  | keyword |
| axonius.identity.event.data.active_users |  | long |
| axonius.identity.event.data.active_users_saved_query_id |  | keyword |
| axonius.identity.event.data.admin_non_operational_users |  | long |
| axonius.identity.event.data.admin_non_operational_users_saved_query_id |  | keyword |
| axonius.identity.event.data.admin_operational_active_users |  | long |
| axonius.identity.event.data.admin_operational_active_users_saved_query_id |  | keyword |
| axonius.identity.event.data.admin_operational_inactive_users |  | long |
| axonius.identity.event.data.admin_operational_inactive_users_saved_query_id |  | keyword |
| axonius.identity.event.data.admin_operational_users |  | long |
| axonius.identity.event.data.admin_operational_users_saved_query_id |  | keyword |
| axonius.identity.event.data.admin_roles.display_name |  | keyword |
| axonius.identity.event.data.admin_roles.id |  | keyword |
| axonius.identity.event.data.admins |  | long |
| axonius.identity.event.data.admins_saved_query_id |  | keyword |
| axonius.identity.event.data.alt_names.name |  | keyword |
| axonius.identity.event.data.alt_names.name_type |  | keyword |
| axonius.identity.event.data.application_and_account_name |  | keyword |
| axonius.identity.event.data.application_id |  | keyword |
| axonius.identity.event.data.application_name |  | keyword |
| axonius.identity.event.data.asset_entity_info |  | keyword |
| axonius.identity.event.data.asset_type |  | keyword |
| axonius.identity.event.data.associated_devices.device_associated_saas_apps_names |  | keyword |
| axonius.identity.event.data.associated_devices.device_caption |  | keyword |
| axonius.identity.event.data.associated_devices.device_id |  | keyword |
| axonius.identity.event.data.associated_devices.device_labels |  | keyword |
| axonius.identity.event.data.associated_devices.device_model |  | keyword |
| axonius.identity.event.data.associated_devices.device_os_distribution |  | keyword |
| axonius.identity.event.data.associated_devices.device_os_edition |  | keyword |
| axonius.identity.event.data.associated_devices.device_os_end_of_life |  | keyword |
| axonius.identity.event.data.associated_devices.device_os_type |  | keyword |
| axonius.identity.event.data.associated_devices.device_os_version |  | keyword |
| axonius.identity.event.data.associated_devices.device_preferred_mac_address |  | keyword |
| axonius.identity.event.data.associated_devices.device_serial |  | keyword |
| axonius.identity.event.data.associated_devices.internal_axon_id |  | keyword |
| axonius.identity.event.data.associated_employees.internal_axon_id |  | keyword |
| axonius.identity.event.data.associated_employees.username |  | keyword |
| axonius.identity.event.data.associated_groups.display_name |  | keyword |
| axonius.identity.event.data.associated_groups.remote_id |  | keyword |
| axonius.identity.event.data.associated_licenses.adapter_connection_label |  | keyword |
| axonius.identity.event.data.associated_licenses.internal_axon_id |  | keyword |
| axonius.identity.event.data.associated_licenses.license_name |  | keyword |
| axonius.identity.event.data.associated_licenses.pricing_unit |  | keyword |
| axonius.identity.event.data.associated_licenses.related_vendor_name |  | keyword |
| axonius.identity.event.data.associated_licenses.unit_price |  | keyword |
| axonius.identity.event.data.aws_arn |  | keyword |
| axonius.identity.event.data.aws_iam_identity_type |  | keyword |
| axonius.identity.event.data.azure_account_id |  | keyword |
| axonius.identity.event.data.begins_on |  | date |
| axonius.identity.event.data.bit_size |  | long |
| axonius.identity.event.data.breaches_data.added_date |  | date |
| axonius.identity.event.data.breaches_data.breach_date |  | date |
| axonius.identity.event.data.breaches_data.data_classes |  | keyword |
| axonius.identity.event.data.breaches_data.domain |  | keyword |
| axonius.identity.event.data.breaches_data.is_fabricated |  | boolean |
| axonius.identity.event.data.breaches_data.is_retired |  | boolean |
| axonius.identity.event.data.breaches_data.is_sensitive |  | boolean |
| axonius.identity.event.data.breaches_data.is_spam_list |  | boolean |
| axonius.identity.event.data.breaches_data.is_verified |  | boolean |
| axonius.identity.event.data.breaches_data.logo_path |  | keyword |
| axonius.identity.event.data.breaches_data.modified_date |  | date |
| axonius.identity.event.data.breaches_data.name |  | keyword |
| axonius.identity.event.data.breaches_data.pwn_count |  | long |
| axonius.identity.event.data.breaches_data.title |  | keyword |
| axonius.identity.event.data.class_name |  | keyword |
| axonius.identity.event.data.cloud_provider |  | keyword |
| axonius.identity.event.data.connected_assets |  | keyword |
| axonius.identity.event.data.connection_label |  | keyword |
| axonius.identity.event.data.created_date |  | date |
| axonius.identity.event.data.deleted_users |  | long |
| axonius.identity.event.data.deleted_users_saved_query_id |  | keyword |
| axonius.identity.event.data.direct_not_sso_users |  | long |
| axonius.identity.event.data.direct_not_sso_users_saved_query_id |  | keyword |
| axonius.identity.event.data.display_name |  | keyword |
| axonius.identity.event.data.distinct_associated_devices_count |  | long |
| axonius.identity.event.data.domains.name |  | keyword |
| axonius.identity.event.data.email |  | keyword |
| axonius.identity.event.data.email_activity.is_deleted |  | boolean |
| axonius.identity.event.data.email_activity.product_license |  | keyword |
| axonius.identity.event.data.email_activity.read_count |  | long |
| axonius.identity.event.data.email_activity.receive_count |  | long |
| axonius.identity.event.data.email_activity.report_date |  | date |
| axonius.identity.event.data.email_activity.report_period |  | long |
| axonius.identity.event.data.email_activity.send_count |  | long |
| axonius.identity.event.data.email_notification.alternative_host_reminder |  | boolean |
| axonius.identity.event.data.email_notification.cancel_meeting_reminder |  | boolean |
| axonius.identity.event.data.email_notification.jbh_reminder |  | boolean |
| axonius.identity.event.data.employee_id |  | keyword |
| axonius.identity.event.data.employee_number |  | keyword |
| axonius.identity.event.data.employee_type |  | keyword |
| axonius.identity.event.data.expires_on |  | date |
| axonius.identity.event.data.external_users |  | long |
| axonius.identity.event.data.external_users_saved_query_id |  | keyword |
| axonius.identity.event.data.feature.cn_meeting |  | boolean |
| axonius.identity.event.data.feature.in_meeting |  | boolean |
| axonius.identity.event.data.feature.large_meeting |  | boolean |
| axonius.identity.event.data.feature.meeting_capacity |  | long |
| axonius.identity.event.data.feature.webinar |  | boolean |
| axonius.identity.event.data.feature.zoom_phone |  | boolean |
| axonius.identity.event.data.fetch_time |  | date |
| axonius.identity.event.data.first_fetch_time |  | date |
| axonius.identity.event.data.first_name |  | keyword |
| axonius.identity.event.data.first_seen |  | date |
| axonius.identity.event.data.from_last_fetch |  | boolean |
| axonius.identity.event.data.gce_account_id |  | keyword |
| axonius.identity.event.data.groups |  | keyword |
| axonius.identity.event.data.groups.display_name |  | keyword |
| axonius.identity.event.data.groups.name |  | keyword |
| axonius.identity.event.data.groups.remote_id |  | keyword |
| axonius.identity.event.data.has_administrative_permissions |  | boolean |
| axonius.identity.event.data.hire_date |  | date |
| axonius.identity.event.data.hr_employment_status |  | keyword |
| axonius.identity.event.data.id |  | keyword |
| axonius.identity.event.data.id_raw |  | keyword |
| axonius.identity.event.data.in_meeting.allow_live_streaming |  | boolean |
| axonius.identity.event.data.in_meeting.annotation |  | boolean |
| axonius.identity.event.data.in_meeting.attendee_on_hold |  | boolean |
| axonius.identity.event.data.in_meeting.auto_saving_chat |  | boolean |
| axonius.identity.event.data.in_meeting.breakout_room |  | boolean |
| axonius.identity.event.data.in_meeting.chat |  | boolean |
| axonius.identity.event.data.in_meeting.closed_caption |  | boolean |
| axonius.identity.event.data.in_meeting.co_host |  | boolean |
| axonius.identity.event.data.in_meeting.data_center_regions |  | keyword |
| axonius.identity.event.data.in_meeting.e2e_encryption |  | boolean |
| axonius.identity.event.data.in_meeting.entry_exit_chime |  | boolean |
| axonius.identity.event.data.in_meeting.far_end_camera_control |  | boolean |
| axonius.identity.event.data.in_meeting.feedback |  | boolean |
| axonius.identity.event.data.in_meeting.group_hd |  | boolean |
| axonius.identity.event.data.in_meeting.non_verbal_feedback |  | boolean |
| axonius.identity.event.data.in_meeting.polling |  | boolean |
| axonius.identity.event.data.in_meeting.private_chat |  | boolean |
| axonius.identity.event.data.in_meeting.record_play_voice |  | boolean |
| axonius.identity.event.data.in_meeting.remote_control |  | boolean |
| axonius.identity.event.data.in_meeting.remote_support |  | boolean |
| axonius.identity.event.data.in_meeting.share_dual_camera |  | boolean |
| axonius.identity.event.data.in_meeting.show_meeting_control_toolbar |  | boolean |
| axonius.identity.event.data.in_meeting.virtual_background |  | boolean |
| axonius.identity.event.data.in_meeting.waiting_room |  | boolean |
| axonius.identity.event.data.in_meeting.workplace_by_facebook |  | boolean |
| axonius.identity.event.data.inactive_users |  | long |
| axonius.identity.event.data.inactive_users_saved_query_id |  | keyword |
| axonius.identity.event.data.internal_is_admin |  | boolean |
| axonius.identity.event.data.is_active |  | boolean |
| axonius.identity.event.data.is_admin |  | boolean |
| axonius.identity.event.data.is_built_in |  | boolean |
| axonius.identity.event.data.is_delegated_admin |  | boolean |
| axonius.identity.event.data.is_fetched_from_adapter |  | boolean |
| axonius.identity.event.data.is_from_sso_provider |  | boolean |
| axonius.identity.event.data.is_latest_last_seen |  | boolean |
| axonius.identity.event.data.is_managed_by_application |  | boolean |
| axonius.identity.event.data.is_managed_by_direct_app |  | boolean |
| axonius.identity.event.data.is_managed_by_sso |  | boolean |
| axonius.identity.event.data.is_mfa_enforced |  | boolean |
| axonius.identity.event.data.is_mfa_enrolled |  | boolean |
| axonius.identity.event.data.is_non_editable |  | boolean |
| axonius.identity.event.data.is_paid |  | boolean |
| axonius.identity.event.data.is_permission_adapter |  | boolean |
| axonius.identity.event.data.is_privileged |  | boolean |
| axonius.identity.event.data.is_saas_user |  | boolean |
| axonius.identity.event.data.is_user_active |  | boolean |
| axonius.identity.event.data.is_user_deleted |  | boolean |
| axonius.identity.event.data.is_user_external |  | boolean |
| axonius.identity.event.data.is_user_inactive |  | boolean |
| axonius.identity.event.data.is_user_suspended |  | boolean |
| axonius.identity.event.data.issuer.common_name |  | keyword |
| axonius.identity.event.data.issuer.country_name |  | keyword |
| axonius.identity.event.data.issuer.organization |  | keyword |
| axonius.identity.event.data.last_client_version |  | keyword |
| axonius.identity.event.data.last_enrichment_run |  | date |
| axonius.identity.event.data.last_fetch_connection_id |  | keyword |
| axonius.identity.event.data.last_fetch_connection_label |  | keyword |
| axonius.identity.event.data.last_login_attempt |  | date |
| axonius.identity.event.data.last_logon |  | date |
| axonius.identity.event.data.last_name |  | keyword |
| axonius.identity.event.data.last_password_change |  | date |
| axonius.identity.event.data.last_seen |  | date |
| axonius.identity.event.data.mail |  | keyword |
| axonius.identity.event.data.managed_non_operational_users |  | long |
| axonius.identity.event.data.managed_non_operational_users_saved_query_id |  | keyword |
| axonius.identity.event.data.managed_operational_users |  | long |
| axonius.identity.event.data.managed_operational_users_saved_query_id |  | keyword |
| axonius.identity.event.data.managed_users |  | long |
| axonius.identity.event.data.managed_users_by_app |  | long |
| axonius.identity.event.data.managed_users_by_app_saved_query_id |  | keyword |
| axonius.identity.event.data.managed_users_by_sso |  | long |
| axonius.identity.event.data.managed_users_by_sso_saved_query_id |  | keyword |
| axonius.identity.event.data.managed_users_saved_query_id |  | keyword |
| axonius.identity.event.data.manager_id |  | keyword |
| axonius.identity.event.data.max_added_date |  | date |
| axonius.identity.event.data.max_breach_date |  | date |
| axonius.identity.event.data.max_modified_date |  | date |
| axonius.identity.event.data.name |  | keyword |
| axonius.identity.event.data.nested_applications |  | keyword |
| axonius.identity.event.data.nested_applications.active_from_direct_adapter |  | boolean |
| axonius.identity.event.data.nested_applications.app_accounts.name |  | keyword |
| axonius.identity.event.data.nested_applications.app_display_name |  | keyword |
| axonius.identity.event.data.nested_applications.app_links |  | keyword |
| axonius.identity.event.data.nested_applications.assignment_type |  | keyword |
| axonius.identity.event.data.nested_applications.extension_type |  | keyword |
| axonius.identity.event.data.nested_applications.has_administrative_permissions |  | boolean |
| axonius.identity.event.data.nested_applications.is_deleted |  | boolean |
| axonius.identity.event.data.nested_applications.is_from_direct_adapter |  | boolean |
| axonius.identity.event.data.nested_applications.is_managed |  | boolean |
| axonius.identity.event.data.nested_applications.is_suspended |  | boolean |
| axonius.identity.event.data.nested_applications.is_unmanaged_extension |  | boolean |
| axonius.identity.event.data.nested_applications.is_user_external |  | boolean |
| axonius.identity.event.data.nested_applications.is_user_paid |  | boolean |
| axonius.identity.event.data.nested_applications.last_access |  | date |
| axonius.identity.event.data.nested_applications.last_access_count |  | long |
| axonius.identity.event.data.nested_applications.last_access_count_60_days |  | long |
| axonius.identity.event.data.nested_applications.last_access_count_90_days |  | long |
| axonius.identity.event.data.nested_applications.name |  | keyword |
| axonius.identity.event.data.nested_applications.parents.name |  | keyword |
| axonius.identity.event.data.nested_applications.parents.value |  | keyword |
| axonius.identity.event.data.nested_applications.permissions.name |  | keyword |
| axonius.identity.event.data.nested_applications.relation_direct_name |  | keyword |
| axonius.identity.event.data.nested_applications.relation_discovery_name |  | keyword |
| axonius.identity.event.data.nested_applications.relation_extension_name |  | keyword |
| axonius.identity.event.data.nested_applications.relation_sso_name |  | keyword |
| axonius.identity.event.data.nested_applications.source_application |  | keyword |
| axonius.identity.event.data.nested_applications.value |  | keyword |
| axonius.identity.event.data.nested_applications.vendor_category |  | keyword |
| axonius.identity.event.data.nested_associated_devices |  | keyword |
| axonius.identity.event.data.nested_grants_last_updated |  | date |
| axonius.identity.event.data.nested_grants_managers_last_updated |  | date |
| axonius.identity.event.data.nested_groups.assignment_type |  | keyword |
| axonius.identity.event.data.nested_groups.group_name |  | keyword |
| axonius.identity.event.data.nested_groups.name |  | keyword |
| axonius.identity.event.data.nested_groups.parents.name |  | keyword |
| axonius.identity.event.data.nested_groups.parents.parent_type |  | keyword |
| axonius.identity.event.data.nested_groups.parents.value |  | keyword |
| axonius.identity.event.data.nested_groups.value |  | keyword |
| axonius.identity.event.data.nested_managers.assignment_type |  | keyword |
| axonius.identity.event.data.nested_managers.parents.name |  | keyword |
| axonius.identity.event.data.nested_managers.parents.parent_type |  | keyword |
| axonius.identity.event.data.nested_managers.parents.value |  | keyword |
| axonius.identity.event.data.nested_managers.value |  | keyword |
| axonius.identity.event.data.nested_permissions.assignment_type |  | keyword |
| axonius.identity.event.data.nested_permissions.has_administrative_permissions |  | boolean |
| axonius.identity.event.data.nested_permissions.is_admin |  | boolean |
| axonius.identity.event.data.nested_permissions.parents.name |  | keyword |
| axonius.identity.event.data.nested_permissions.parents.parent_type |  | keyword |
| axonius.identity.event.data.nested_permissions.parents.value |  | keyword |
| axonius.identity.event.data.nested_permissions.value |  | keyword |
| axonius.identity.event.data.nested_resources |  | keyword |
| axonius.identity.event.data.nested_resources.assignment_type |  | keyword |
| axonius.identity.event.data.nested_resources.name |  | keyword |
| axonius.identity.event.data.nested_resources.parents.name |  | keyword |
| axonius.identity.event.data.nested_resources.parents.value |  | keyword |
| axonius.identity.event.data.nested_resources.value |  | keyword |
| axonius.identity.event.data.nested_roles.assignment_type |  | keyword |
| axonius.identity.event.data.nested_roles.name |  | keyword |
| axonius.identity.event.data.nested_roles.parents.name |  | keyword |
| axonius.identity.event.data.nested_roles.parents.parent_type |  | keyword |
| axonius.identity.event.data.nested_roles.parents.value |  | keyword |
| axonius.identity.event.data.nested_roles.value |  | keyword |
| axonius.identity.event.data.not_fetched_count |  | long |
| axonius.identity.event.data.operational_users_count |  | long |
| axonius.identity.event.data.oracle_cloud_cis_incompliant.rule_cis_version |  | float |
| axonius.identity.event.data.oracle_cloud_cis_incompliant.rule_section |  | float |
| axonius.identity.event.data.orphaned_users |  | long |
| axonius.identity.event.data.orphaned_users_saved_query_id |  | keyword |
| axonius.identity.event.data.paid_users |  | long |
| axonius.identity.event.data.paid_users_saved_query_id |  | keyword |
| axonius.identity.event.data.password_never_expires |  | boolean |
| axonius.identity.event.data.password_not_required |  | boolean |
| axonius.identity.event.data.permissions.name |  | keyword |
| axonius.identity.event.data.pmi |  | keyword |
| axonius.identity.event.data.pretty_id |  | keyword |
| axonius.identity.event.data.project_ids |  | keyword |
| axonius.identity.event.data.project_tags.inherited |  | keyword |
| axonius.identity.event.data.project_tags.key |  | keyword |
| axonius.identity.event.data.project_tags.namespaced_tag_key |  | keyword |
| axonius.identity.event.data.project_tags.namespaced_tag_value |  | keyword |
| axonius.identity.event.data.project_tags.value |  | keyword |
| axonius.identity.event.data.projects_roles.project_id |  | keyword |
| axonius.identity.event.data.projects_roles.role_name |  | keyword |
| axonius.identity.event.data.provider_name |  | keyword |
| axonius.identity.event.data.provider_type |  | keyword |
| axonius.identity.event.data.recording.auto_delete_cmr |  | boolean |
| axonius.identity.event.data.recording.auto_delete_cmr_days |  | boolean |
| axonius.identity.event.data.recording.auto_recording |  | boolean |
| axonius.identity.event.data.recording.cloud_recording |  | boolean |
| axonius.identity.event.data.recording.host_pause_stop_recording |  | boolean |
| axonius.identity.event.data.recording.local_recording |  | boolean |
| axonius.identity.event.data.recording.record_audio_file |  | boolean |
| axonius.identity.event.data.recording.record_gallery_view |  | boolean |
| axonius.identity.event.data.recording.record_speaker_view |  | boolean |
| axonius.identity.event.data.recording.recording_audio_transcript |  | boolean |
| axonius.identity.event.data.recording.save_chat_text |  | boolean |
| axonius.identity.event.data.recording.show_timestamp |  | boolean |
| axonius.identity.event.data.recovery_question_set |  | boolean |
| axonius.identity.event.data.relatable_ids |  | keyword |
| axonius.identity.event.data.remote_account_id |  | keyword |
| axonius.identity.event.data.remote_id |  | keyword |
| axonius.identity.event.data.roles |  | keyword |
| axonius.identity.event.data.roles.display_name |  | keyword |
| axonius.identity.event.data.roles.remote_id |  | keyword |
| axonius.identity.event.data.schedule_meeting.audio_type |  | keyword |
| axonius.identity.event.data.schedule_meeting.force_pmi_jbh_password |  | boolean |
| axonius.identity.event.data.schedule_meeting.host_video |  | boolean |
| axonius.identity.event.data.schedule_meeting.join_before_host |  | boolean |
| axonius.identity.event.data.schedule_meeting.participants_video |  | boolean |
| axonius.identity.event.data.schedule_meeting.pstn_password_protected |  | boolean |
| axonius.identity.event.data.schedule_meeting.require_password_for_instant_meetings |  | boolean |
| axonius.identity.event.data.schedule_meeting.require_password_for_pmi_meetings |  | boolean |
| axonius.identity.event.data.schedule_meeting.require_password_for_scheduled_meetings |  | boolean |
| axonius.identity.event.data.schedule_meeting.require_password_for_scheduling_new_meetings |  | boolean |
| axonius.identity.event.data.schedule_meeting.use_pmi_for_instant_meetings |  | boolean |
| axonius.identity.event.data.schedule_meeting.use_pmi_for_scheduled_meetings |  | boolean |
| axonius.identity.event.data.serial_number |  | keyword |
| axonius.identity.event.data.shirt_size |  | keyword |
| axonius.identity.event.data.sm_entity_type |  | keyword |
| axonius.identity.event.data.snow_full_name |  | keyword |
| axonius.identity.event.data.snow_location |  | keyword |
| axonius.identity.event.data.source_application |  | keyword |
| axonius.identity.event.data.status |  | keyword |
| axonius.identity.event.data.status_changed |  | date |
| axonius.identity.event.data.subject.common_name |  | keyword |
| axonius.identity.event.data.subject.country_name |  | keyword |
| axonius.identity.event.data.subject.locality |  | keyword |
| axonius.identity.event.data.subject.organization |  | keyword |
| axonius.identity.event.data.subject.state |  | keyword |
| axonius.identity.event.data.suspended_users |  | long |
| axonius.identity.event.data.suspended_users_saved_query_id |  | keyword |
| axonius.identity.event.data.telephony.show_international_numbers_link |  | boolean |
| axonius.identity.event.data.telephony.third_party_audio |  | boolean |
| axonius.identity.event.data.tenant_number |  | keyword |
| axonius.identity.event.data.timezone |  | keyword |
| axonius.identity.event.data.total_users_count |  | long |
| axonius.identity.event.data.tsp.call_out |  | boolean |
| axonius.identity.event.data.tsp.show_international_numbers_link |  | boolean |
| axonius.identity.event.data.type |  | keyword |
| axonius.identity.event.data.u_department |  | keyword |
| axonius.identity.event.data.u_vip |  | boolean |
| axonius.identity.event.data.unlinked_users |  | long |
| axonius.identity.event.data.unlinked_users_saved_query_id |  | keyword |
| axonius.identity.event.data.updated_on |  | date |
| axonius.identity.event.data.user_apps.active_from_direct_adapter |  | boolean |
| axonius.identity.event.data.user_apps.app_accounts.name |  | keyword |
| axonius.identity.event.data.user_apps.app_display_name |  | keyword |
| axonius.identity.event.data.user_apps.app_id |  | keyword |
| axonius.identity.event.data.user_apps.app_links |  | keyword |
| axonius.identity.event.data.user_apps.app_name |  | keyword |
| axonius.identity.event.data.user_apps.extension_type |  | keyword |
| axonius.identity.event.data.user_apps.is_from_direct_adapter |  | boolean |
| axonius.identity.event.data.user_apps.is_managed |  | boolean |
| axonius.identity.event.data.user_apps.is_saas_application |  | boolean |
| axonius.identity.event.data.user_apps.is_unmanaged_extension |  | boolean |
| axonius.identity.event.data.user_apps.is_user_deleted |  | boolean |
| axonius.identity.event.data.user_apps.is_user_external |  | boolean |
| axonius.identity.event.data.user_apps.is_user_paid |  | boolean |
| axonius.identity.event.data.user_apps.is_user_suspended |  | boolean |
| axonius.identity.event.data.user_apps.last_access |  | date |
| axonius.identity.event.data.user_apps.permissions.name |  | keyword |
| axonius.identity.event.data.user_apps.relation_direct_name |  | keyword |
| axonius.identity.event.data.user_apps.relation_discovery_name |  | keyword |
| axonius.identity.event.data.user_apps.relation_extension_name |  | keyword |
| axonius.identity.event.data.user_apps.relation_sso_name |  | keyword |
| axonius.identity.event.data.user_apps.source_application |  | keyword |
| axonius.identity.event.data.user_apps.vendor_category |  | keyword |
| axonius.identity.event.data.user_count_link.bracketWeight |  | double |
| axonius.identity.event.data.user_count_link.compOp |  | keyword |
| axonius.identity.event.data.user_count_link.field |  | keyword |
| axonius.identity.event.data.user_count_link.leftBracket |  | double |
| axonius.identity.event.data.user_count_link.logicOp |  | keyword |
| axonius.identity.event.data.user_count_link.not |  | boolean |
| axonius.identity.event.data.user_count_link.rightBracket |  | double |
| axonius.identity.event.data.user_count_link.value |  | keyword |
| axonius.identity.event.data.user_country |  | keyword |
| axonius.identity.event.data.user_created |  | date |
| axonius.identity.event.data.user_department |  | keyword |
| axonius.identity.event.data.user_factors.created |  | date |
| axonius.identity.event.data.user_factors.factor_status |  | keyword |
| axonius.identity.event.data.user_factors.factor_type |  | keyword |
| axonius.identity.event.data.user_factors.is_enabled |  | boolean |
| axonius.identity.event.data.user_factors.last_updated |  | date |
| axonius.identity.event.data.user_factors.name |  | keyword |
| axonius.identity.event.data.user_factors.provider |  | keyword |
| axonius.identity.event.data.user_factors.strength |  | keyword |
| axonius.identity.event.data.user_factors.vendor_name |  | keyword |
| axonius.identity.event.data.user_full_name |  | keyword |
| axonius.identity.event.data.user_is_password_enabled |  | boolean |
| axonius.identity.event.data.user_manager |  | keyword |
| axonius.identity.event.data.user_manager_mail |  | keyword |
| axonius.identity.event.data.user_pass_last_used |  | keyword |
| axonius.identity.event.data.user_path |  | keyword |
| axonius.identity.event.data.user_permissions.is_admin |  | boolean |
| axonius.identity.event.data.user_permissions.name |  | keyword |
| axonius.identity.event.data.user_related_resources.id |  | keyword |
| axonius.identity.event.data.user_related_resources.name |  | keyword |
| axonius.identity.event.data.user_related_resources.type |  | keyword |
| axonius.identity.event.data.user_remote_id |  | keyword |
| axonius.identity.event.data.user_sid |  | keyword |
| axonius.identity.event.data.user_status |  | keyword |
| axonius.identity.event.data.user_telephone_number |  | keyword |
| axonius.identity.event.data.user_title |  | keyword |
| axonius.identity.event.data.user_type |  | keyword |
| axonius.identity.event.data.username |  | keyword |
| axonius.identity.event.data.verified |  | boolean |
| axonius.identity.event.data.version |  | keyword |
| axonius.identity.event.entity |  | keyword |
| axonius.identity.event.hidden_for_gui |  | boolean |
| axonius.identity.event.initial_plugin_unique_name |  | keyword |
| axonius.identity.event.name |  | keyword |
| axonius.identity.event.plugin_name |  | keyword |
| axonius.identity.event.plugin_type |  | keyword |
| axonius.identity.event.plugin_unique_name |  | keyword |
| axonius.identity.event.quick_id |  | keyword |
| axonius.identity.event.type |  | keyword |
| axonius.identity.internal_axon_id |  | keyword |
| axonius.identity.transform_unique_id |  | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| observer.vendor | Vendor name of the observer. | constant_keyword |


An example event for `identity` looks as following:

```json
{
    "@timestamp": "2025-12-09T12:02:11.000Z",
    "agent": {
        "ephemeral_id": "ba91a9bf-40c9-4bab-8184-9be7d6c2ad8f",
        "id": "f7715edc-eff0-4526-b250-1a56517c01e0",
        "name": "elastic-agent-41335",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "axonius": {
        "identity": {
            "adapter_list_length": 12,
            "adapters": [
                "aws_adapter",
                "zoom_adapter"
            ],
            "asset_type": "users",
            "event": {
                "accurate_for_datetime": "2025-12-09T12:02:11.000Z",
                "adapter_categories": [
                    "Directory",
                    "IAM",
                    "SaaS Management"
                ],
                "client_used": "67fd09bbfe1c8e812a176bb5",
                "data": {
                    "account_disabled": true,
                    "accurate_for_datetime": "2025-12-09T12:02:11.000Z",
                    "application_and_account_name": "microsoft/azure_ad-demo",
                    "associated_groups": [
                        {
                            "display_name": "developers-group",
                            "remote_id": "a3e70162"
                        }
                    ],
                    "azure_account_id": "c8103abe-eda9-472b-894a-6260bb2ba8cc",
                    "cloud_provider": "Azure",
                    "email_activity": {
                        "is_deleted": false,
                        "product_license": "MICROSOFT FABRIC (FREE)+MICROSOFT TEAMS PHONE STANDARD+MICROSOFT DEFENDER FOR OFFICE365 (PLAN 2)+MICROSOFT 365 AUDIO CONFERENCING+ENTERPRISE MOBILITY + SECURITY E3+OFFICE365 E3+MICROSOFT 365 E3 EXTRA FEATURES",
                        "read_count": 2321,
                        "receive_count": 6965,
                        "report_date": "2025-01-10T20:34:43.000Z",
                        "report_period": 90,
                        "send_count": 3030
                    },
                    "fetch_time": "2025-12-09T12:02:03.000Z",
                    "first_fetch_time": "2025-04-14T13:27:00.000Z",
                    "from_last_fetch": true,
                    "has_administrative_permissions": true,
                    "id": "c8103abe-eda9-472b-894a-6260bb2ba8cc",
                    "internal_is_admin": false,
                    "is_admin": false,
                    "is_fetched_from_adapter": true,
                    "is_latest_last_seen": true,
                    "is_managed_by_application": true,
                    "is_permission_adapter": true,
                    "is_saas_user": true,
                    "is_user_external": false,
                    "last_fetch_connection_id": "67fd09bbfe1c8e812a176bb5",
                    "last_fetch_connection_label": "azure_ad-demo",
                    "last_logon": "2025-11-30T18:50:39.000Z",
                    "last_seen": "2025-11-10T22:18:25.000Z",
                    "mail": "helen.jordan@demo.local",
                    "nested_applications": [
                        {
                            "app_display_name": "Calendly",
                            "assignment_type": "Direct",
                            "extension_type": "User Consent",
                            "is_managed": false,
                            "is_unmanaged_extension": true,
                            "name": "Calendly",
                            "permissions": [
                                {
                                    "name": "openid"
                                }
                            ],
                            "relation_extension_name": "Calendly",
                            "source_application": "Microsoft",
                            "value": "2E2a2e7c9f758BDcC0E2",
                            "vendor_category": "Productivity"
                        }
                    ],
                    "nested_grants_last_updated": "2025-12-09T12:10:06.000Z",
                    "nested_grants_managers_last_updated": "2025-12-09T12:10:10.000Z",
                    "nested_groups": [
                        {
                            "assignment_type": "Direct",
                            "name": "Office365 Users",
                            "value": "d8e66837"
                        }
                    ],
                    "not_fetched_count": 0,
                    "sm_entity_type": "saas_user",
                    "source_application": "Microsoft",
                    "tenant_number": [
                        "2"
                    ],
                    "user_created": "2024-06-28T08:49:28.000Z",
                    "user_permissions": [
                        {
                            "is_admin": false,
                            "name": "OnlineMeetings.ReadWrite"
                        }
                    ],
                    "user_remote_id": "63d52bb0-7ce0-4467-9004-2b19c06b86ae",
                    "user_type": "Member",
                    "username": "helen.jordan@demo.local"
                },
                "initial_plugin_unique_name": "azure_ad_adapter_0",
                "plugin_name": "azure_ad_adapter",
                "plugin_type": "Adapter",
                "plugin_unique_name": "azure_ad_adapter_0",
                "quick_id": "azure_ad_adapter_0!c8103abe-eda9-472b-894a-6260bb2ba8cc",
                "type": "entitydata"
            },
            "internal_axon_id": "bc11b2989fc0f69708b6865d172a49fe",
            "transform_unique_id": "N8G3qDAOmSElCdviQ3d6FpD76pE="
        }
    },
    "cloud": {
        "account": {
            "id": "c8103abe-eda9-472b-894a-6260bb2ba8cc"
        },
        "provider": "Azure"
    },
    "data_stream": {
        "dataset": "axonius.identity",
        "namespace": "56452",
        "type": "logs"
    },
    "ecs": {
        "version": "9.2.0"
    },
    "elastic_agent": {
        "id": "f7715edc-eff0-4526-b250-1a56517c01e0",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2024-06-28T08:49:28.000Z",
        "dataset": "axonius.identity",
        "ingested": "2025-12-26T10:17:19Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "developers-group",
            "helen.jordan@demo.local"
        ]
    },
    "tags": [
        "preserve_duplicate_custom_fields",
        "forwarded",
        "axonius-identity"
    ],
    "user": {
        "domain": "demo.local",
        "email": "helen.jordan@demo.local",
        "name": "helen.jordan@demo.local"
    }
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

#### ILM Policy

To facilitate identity data, source data stream-backed indices `.ds-logs-axonius.identity-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-axonius.identity-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
