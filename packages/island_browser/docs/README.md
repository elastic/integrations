# Island Browser Integration for Elastic

## Overview

[Island](https://www.island.io/) reimagines what the browser can be. By taking in the needs of the enterprise, Island delivers a dramatic positive impact on every layer of cybersecurity and all other functions of IT, while improving the end-user experience and productivity. Leveraging the open-source Chromium project that all major browsers are based on, Island provides fine-grain policy control over every facet of a user’s interaction with a web application giving the enterprise limitless visibility, control, and compliance with their most critical applications. As a result, Island can serve as the platform for the future of productive and secured work.

The Island Browser integration for Elastic allows you to collect logs using [Island Browser API](https://documentation.island.io/apidocs), then visualise the data in Kibana.

### Compatibility

The Island Browser integration is compatible with `v1` version of Island Browser API.

### How it works

This integration periodically queries the Island Browser API to retrieve details for devices, users and compromised credentials, and to log audit events.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Audit`: Collects all timeline audits from the Island Browser via [Audit API endpoint](https://documentation.island.io/apidocs/get-all-timeline-audits-that-match-the-specified-simple-filter).
- `Compromised Credential`: Collects a list of all compromised credentials from the Island Browser via [Compromised Credential API endpoint](https://documentation.island.io/apidocs/get-a-list-of-all-compromised-credentials).
- `Device`: Collects a list of all devices from the Island Browser via [Device API endpoint](https://documentation.island.io/apidocs/get-a-list-of-all-devices-1).
- `User`: Collects all the users from the Island Browser via [User API endpoint](https://documentation.island.io/apidocs/get-all-browser-users-that-match-the-specified-simple-filter).

### Supported use cases

Integrating Island Browser User, Device, Audit, and Compromised Credential endpoint data with Elastic SIEM provides unified visibility into identity activity, device posture, account exposure, and security events across the environment. This integration enables analysts to correlate user behavior, device health, and credential risks within a single view, strengthening both detection and response capabilities.

Dashboards track total and active users, login trends, and group distributions, alongside device insights such as active, archived, and jailbroken states, OS platform distribution, policy updates, browser update status, Windows license status, and MDM provider compliance. Compromised Credential visualizations highlight account risks with timelines of exposed records, unresolved credential counts, breach source breakdowns, and distributions by status. Additional charts surface top impacted domains and most affected users, enabling security teams to quickly assess exposure, prioritize remediation, and mitigate identity-based threats.

Audit dashboards further enhance oversight by showing event activity over time, verdicts and reasons, top rules, users, source IPs, event types, geographic distributions, and compatibility modes. Saved searches and tables consolidate essential attributes—including verified emails, device and host IDs, IPs, MACs, users, and organizations—adding valuable investigative context. Together, these insights allow organizations to monitor user behavior, track device health, detect compromised accounts, analyze audit activity, and strengthen compliance, identity management, and endpoint security oversight.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Island Browser

To collect data through the Island Browser APIs, `Admin` role must be required and admin must have permission to generate and manage API keys (i.e. full admin, system admin). Authentication is handled using a `API Key`, which serve as the required credentials.

#### Generate an `API Key`:

1. Log in to Island Browser Management Console.
2. From the **Island Management Console**, navigate to **Modules > Platform Settings > System Settings > Integrations > API**.
3. Click **+ Create**. The **Create API Key** drawer is displayed to assist in the key creation.
4. Enter a **Name**.
5. Select the **Role** that applies to this API key (i.e. Full Admin, or Read Only).
6. Click **Generate API Key**.
7. Copy the **API Key** to your clipboard to be used when using the [API Explorer](https://documentation.island.io/v1-api/apidocs/introduction-to-the-api-explorer).
8. Click **Save**.

For more details, check [Documentation](https://documentation.island.io/apidocs/generate-and-manage-api-keys).

>**Note**: If an API key already exists and you need to create a new one, you must first deactivate and delete the existing key by selecting **Deactivate and Delete API Key**.


## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Island Browser**.
3. Select the **Island Browser** integration from the search results.
4. Select **Add Island Browser** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs from Island Browser API**, you'll need to:

        - Configure **URL** and **API Key**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the Interval, Batch Size etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **island_browser**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **island_browser**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### User

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| island_browser.user.allowed_tenants_ids |  | keyword |
| island_browser.user.claims |  | flattened |
| island_browser.user.connection_name |  | keyword |
| island_browser.user.created_date |  | date |
| island_browser.user.email |  | keyword |
| island_browser.user.email_verified |  | boolean |
| island_browser.user.expiration_date |  | date |
| island_browser.user.first_name |  | keyword |
| island_browser.user.groups |  | keyword |
| island_browser.user.id |  | keyword |
| island_browser.user.invitation_date |  | date |
| island_browser.user.last_login |  | date |
| island_browser.user.last_name |  | keyword |
| island_browser.user.last_seen |  | date |
| island_browser.user.scim_id |  | keyword |
| island_browser.user.tenant_id |  | keyword |
| island_browser.user.updated_date |  | date |
| island_browser.user.user_id |  | keyword |
| island_browser.user.user_source |  | keyword |
| island_browser.user.user_status |  | keyword |
| island_browser.user.user_type |  | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |


#### Device

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| island_browser.device.anti_malware_products |  | keyword |
| island_browser.device.architecture |  | keyword |
| island_browser.device.auth_method |  | keyword |
| island_browser.device.azure_tenant_id |  | keyword |
| island_browser.device.browser_name |  | keyword |
| island_browser.device.browser_update_status |  | keyword |
| island_browser.device.browser_version |  | keyword |
| island_browser.device.chassis_type |  | keyword |
| island_browser.device.chromium_version |  | keyword |
| island_browser.device.country |  | keyword |
| island_browser.device.country_code |  | keyword |
| island_browser.device.cpu_model |  | keyword |
| island_browser.device.created_date |  | date |
| island_browser.device.crowdstrike_agent_id |  | keyword |
| island_browser.device.crowdstrike_cid |  | keyword |
| island_browser.device.crowdstrike_zta_score |  | long |
| island_browser.device.device_type |  | keyword |
| island_browser.device.disk_encrypted |  | boolean |
| island_browser.device.email |  | keyword |
| island_browser.device.extension_utility_version |  | keyword |
| island_browser.device.extension_version |  | keyword |
| island_browser.device.external_ip_address |  | ip |
| island_browser.device.gatekeeper_version |  | keyword |
| island_browser.device.id |  | keyword |
| island_browser.device.installed_extensions |  | keyword |
| island_browser.device.internal_ip |  | keyword |
| island_browser.device.internal_ip_address |  | ip |
| island_browser.device.is_archived |  | boolean |
| island_browser.device.is_container |  | boolean |
| island_browser.device.is_default_browser |  | boolean |
| island_browser.device.is_device_attested |  | boolean |
| island_browser.device.is_gatekeeper_enabled |  | boolean |
| island_browser.device.is_jailbroken |  | boolean |
| island_browser.device.is_system_level_install |  | boolean |
| island_browser.device.is_virtual_machine |  | boolean |
| island_browser.device.island_mdm_custom_key |  | keyword |
| island_browser.device.island_platform |  | keyword |
| island_browser.device.last_seen |  | date |
| island_browser.device.latest_security_update_id |  | keyword |
| island_browser.device.mac_addresses |  | keyword |
| island_browser.device.machine_id |  | keyword |
| island_browser.device.machine_model |  | keyword |
| island_browser.device.machine_name |  | keyword |
| island_browser.device.manufacturer |  | keyword |
| island_browser.device.mdm_compliant |  | boolean |
| island_browser.device.mdm_enrolled |  | boolean |
| island_browser.device.mdm_provider |  | keyword |
| island_browser.device.mdm_tenant_name |  | keyword |
| island_browser.device.mdm_topic |  | keyword |
| island_browser.device.mobile_enrollment_type |  | keyword |
| island_browser.device.os_code_name |  | keyword |
| island_browser.device.os_domain |  | keyword |
| island_browser.device.os_firewall_enabled |  | boolean |
| island_browser.device.os_platform |  | keyword |
| island_browser.device.os_screen_lock_enabled |  | boolean |
| island_browser.device.os_user_name |  | keyword |
| island_browser.device.os_version |  | keyword |
| island_browser.device.policy_update_time |  | date |
| island_browser.device.ram_size |  | long |
| island_browser.device.secure_boot |  | boolean |
| island_browser.device.serial_number |  | keyword |
| island_browser.device.spm_protected |  | boolean |
| island_browser.device.status |  | keyword |
| island_browser.device.storage_capacity |  | long |
| island_browser.device.sync_enabled |  | boolean |
| island_browser.device.system_integrity_protection |  | boolean |
| island_browser.device.tenant_id |  | keyword |
| island_browser.device.updated_date |  | date |
| island_browser.device.updater_version |  | keyword |
| island_browser.device.user_id |  | keyword |
| island_browser.device.user_name |  | keyword |
| island_browser.device.windows_activation_id |  | keyword |
| island_browser.device.windows_license_status |  | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |


#### Audit

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| island_browser.audit.client_event_id |  | keyword |
| island_browser.audit.compatibility_mode |  | keyword |
| island_browser.audit.country |  | keyword |
| island_browser.audit.country_code |  | keyword |
| island_browser.audit.created_date |  | date |
| island_browser.audit.details |  | flattened |
| island_browser.audit.device_id |  | keyword |
| island_browser.audit.device_posture_matching_details |  | keyword |
| island_browser.audit.domain_or_tenant |  | keyword |
| island_browser.audit.email |  | keyword |
| island_browser.audit.frame_id |  | keyword |
| island_browser.audit.frame_url |  | keyword |
| island_browser.audit.id |  | keyword |
| island_browser.audit.incognito |  | boolean |
| island_browser.audit.is_island_private_access |  | boolean |
| island_browser.audit.keystrokes |  | keyword |
| island_browser.audit.machine_id |  | keyword |
| island_browser.audit.machine_name |  | keyword |
| island_browser.audit.matched_device_posture |  | keyword |
| island_browser.audit.matched_user_group |  | keyword |
| island_browser.audit.origin |  | keyword |
| island_browser.audit.os_platform |  | keyword |
| island_browser.audit.os_user_name |  | keyword |
| island_browser.audit.processed_date |  | date |
| island_browser.audit.public_ip |  | ip |
| island_browser.audit.region |  | keyword |
| island_browser.audit.rule_id |  | keyword |
| island_browser.audit.rule_name |  | keyword |
| island_browser.audit.saas_application_category |  | keyword |
| island_browser.audit.saas_application_id |  | keyword |
| island_browser.audit.saas_application_name |  | keyword |
| island_browser.audit.screenshot_file_name |  | keyword |
| island_browser.audit.short_top_level_url |  | keyword |
| island_browser.audit.source_ip |  | ip |
| island_browser.audit.submitted_url |  | keyword |
| island_browser.audit.tab_id |  | keyword |
| island_browser.audit.tenant_id |  | keyword |
| island_browser.audit.timestamp |  | date |
| island_browser.audit.top_level_url |  | keyword |
| island_browser.audit.type |  | keyword |
| island_browser.audit.updated_date |  | date |
| island_browser.audit.url_web_categories |  | keyword |
| island_browser.audit.url_web_reputation |  | long |
| island_browser.audit.user_id |  | keyword |
| island_browser.audit.user_name |  | keyword |
| island_browser.audit.verdict |  | keyword |
| island_browser.audit.verdict_reason |  | keyword |
| island_browser.audit.website_top_level_url |  | keyword |
| island_browser.audit.window_id |  | keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |


#### Compromised Credential

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| island_browser.compromised_credential.breach_source |  | keyword |
| island_browser.compromised_credential.compromised_date |  | date |
| island_browser.compromised_credential.created_date |  | date |
| island_browser.compromised_credential.email |  | keyword |
| island_browser.compromised_credential.id |  | keyword |
| island_browser.compromised_credential.impacted_domain |  | keyword |
| island_browser.compromised_credential.status |  | keyword |
| island_browser.compromised_credential.tenant_id |  | keyword |
| island_browser.compromised_credential.updated_date |  | date |
| island_browser.compromised_credential.username |  | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |


### Example event

#### User

An example event for `user` looks as following:

```json
{
    "@timestamp": "2025-09-10T08:13:15.704Z",
    "agent": {
        "ephemeral_id": "a5e6d1ff-3024-4cd8-9dda-7550c7058387",
        "id": "2aac32f5-2967-4646-9ad6-57e343544d85",
        "name": "elastic-agent-15932",
        "type": "filebeat",
        "version": "8.18.5"
    },
    "data_stream": {
        "dataset": "island_browser.user",
        "namespace": "13484",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "2aac32f5-2967-4646-9ad6-57e343544d85",
        "snapshot": false,
        "version": "8.18.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2025-08-15T10:30:00.000Z",
        "dataset": "island_browser.user",
        "id": "f3d9a7c8-42b1-4f19-9b51-8a3c56e6d912",
        "ingested": "2025-09-10T08:13:18Z",
        "kind": "event",
        "original": "{\"allowedTenantsIds\":[\"acme-tenant-001\",\"partner-tenant-002\"],\"claims\":{},\"connectionName\":\"AzureAD\",\"createdDate\":\"2025-08-15T10:30:00Z\",\"email\":\"john.doe@example.com\",\"emailVerified\":true,\"expirationDate\":null,\"firstName\":\"John\",\"groups\":[\"Admins\",\"Security\"],\"id\":\"f3d9a7c8-42b1-4f19-9b51-8a3c56e6d912\",\"invitationDate\":\"2025-08-10T09:00:00Z\",\"lastLogin\":\"2025-08-18T14:40:10Z\",\"lastName\":\"Doe\",\"lastSeen\":\"2025-08-18T14:41:55Z\",\"scimId\":null,\"tenantId\":\"acme-tenant-001\",\"updatedDate\":\"2025-08-18T14:45:00Z\",\"userId\":\"user-12345\",\"userSource\":\"Email\",\"userStatus\":\"Active\",\"userType\":\"Management\"}",
        "type": [
            "user"
        ]
    },
    "input": {
        "type": "cel"
    },
    "island_browser": {
        "user": {
            "allowed_tenants_ids": [
                "acme-tenant-001",
                "partner-tenant-002"
            ],
            "connection_name": "AzureAD",
            "created_date": "2025-08-15T10:30:00.000Z",
            "email": "john.doe@example.com",
            "email_verified": true,
            "first_name": "John",
            "groups": [
                "Admins",
                "Security"
            ],
            "id": "f3d9a7c8-42b1-4f19-9b51-8a3c56e6d912",
            "invitation_date": "2025-08-10T09:00:00.000Z",
            "last_login": "2025-08-18T14:40:10.000Z",
            "last_name": "Doe",
            "last_seen": "2025-08-18T14:41:55.000Z",
            "tenant_id": "acme-tenant-001",
            "updated_date": "2025-08-18T14:45:00.000Z",
            "user_id": "user-12345",
            "user_source": "Email",
            "user_status": "Active",
            "user_type": "Management"
        }
    },
    "organization": {
        "id": "acme-tenant-001"
    },
    "related": {
        "user": [
            "john.doe@example.com",
            "John",
            "user-12345"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "island_browser-user"
    ],
    "user": {
        "domain": "example.com",
        "email": "john.doe@example.com",
        "full_name": "John Doe",
        "group": {
            "name": [
                "Admins",
                "Security"
            ]
        },
        "id": "user-12345",
        "name": "John"
    }
}
```

#### Device

An example event for `device` looks as following:

```json
{
    "@timestamp": "2025-09-10T08:12:25.812Z",
    "agent": {
        "ephemeral_id": "be045035-c72f-4da7-a7b6-dcd3b43a2dd1",
        "id": "51e6bec8-8fea-454f-9ff8-82dd3fb69a8d",
        "name": "elastic-agent-71934",
        "type": "filebeat",
        "version": "8.18.5"
    },
    "data_stream": {
        "dataset": "island_browser.device",
        "namespace": "33808",
        "type": "logs"
    },
    "device": {
        "manufacturer": "VMware, Inc.",
        "model": {
            "name": "VMware Virtual Platform"
        }
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "51e6bec8-8fea-454f-9ff8-82dd3fb69a8d",
        "snapshot": false,
        "version": "8.18.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "created": "2025-08-21T08:38:14.478Z",
        "dataset": "island_browser.device",
        "id": "7748cf6a-1a23-4572-b5ee-129962616b25",
        "ingested": "2025-09-10T08:12:28Z",
        "kind": "asset",
        "original": "{\"architecture\":\"x86_64\",\"authMethod\":\"TenantToken\",\"browserName\":\"Island\",\"browserUpdateStatus\":\"UpToDate\",\"browserVersion\":\"1.72.30\",\"chassisType\":\"Laptop\",\"chromiumVersion\":\"139.0.7258.128\",\"country\":\"India\",\"countryCode\":\"IN\",\"cpuModel\":\"Intel(R) Xeon(R) Gold 5220R CPU @ 2.20GHz\",\"createdDate\":\"2025-08-21T08:38:14.478259Z\",\"deviceType\":\"Laptop\",\"diskEncrypted\":false,\"email\":\"john.doe@example.com\",\"extensionVersion\":\"1.12546.6\",\"externalIpAddress\":\"89.160.20.112\",\"id\":\"7748cf6a-1a23-4572-b5ee-129962616b25\",\"internalIpAddress\":\"10.50.6.126\",\"isArchived\":false,\"isDefaultBrowser\":false,\"isVirtualMachine\":true,\"islandPlatform\":\"Browser\",\"lastSeen\":\"2025-08-31T04:19:55.342111Z\",\"macAddresses\":\"00:50:56:81:c9:17 | 02:42:7e:fe:2e:0b | 00:50:56:81:82:be\",\"machineId\":\"iNUa5F_2xgA1L51ZX5_YCXX7b7Z\",\"machineModel\":\"VMware Virtual Platform\",\"machineName\":\"ub22-50-6-126.manage.local\",\"manufacturer\":\"VMware, Inc.\",\"osCodeName\":\"Ubuntu 22.04.5 LTS\",\"osDomain\":\"\",\"osFirewallEnabled\":true,\"osPlatform\":\"Linux\",\"osScreenLockEnabled\":true,\"osUserName\":\"serviceuser\",\"osVersion\":\"22.04\",\"policyUpdateTime\":\"2025-07-08T14:17:18.527794Z\",\"ramSize\":16,\"serialNumber\":\"\",\"status\":\"Active\",\"storageCapacity\":48,\"syncEnabled\":true,\"tenantId\":\"elastic-testing\",\"updatedDate\":\"2025-08-31T04:19:55.345783Z\",\"userId\":\"auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486\",\"userName\":\"John Doe\",\"windowsLicenseStatus\":\"Unlicensed\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "id": "iNUa5F_2xgA1L51ZX5_YCXX7b7Z",
        "ip": [
            "89.160.20.112"
        ],
        "mac": [
            "00-50-56-81-C9-17",
            "02-42-7E-FE-2E-0B",
            "00-50-56-81-82-BE"
        ],
        "name": "ub22-50-6-126.manage.local",
        "os": {
            "name": "serviceuser",
            "platform": "Linux",
            "version": "22.04"
        },
        "type": "Laptop"
    },
    "input": {
        "type": "cel"
    },
    "island_browser": {
        "device": {
            "architecture": "x86_64",
            "auth_method": "TenantToken",
            "browser_name": "Island",
            "browser_update_status": "UpToDate",
            "browser_version": "1.72.30",
            "chassis_type": "Laptop",
            "chromium_version": "139.0.7258.128",
            "country": "India",
            "country_code": "IN",
            "cpu_model": "Intel(R) Xeon(R) Gold 5220R CPU @ 2.20GHz",
            "created_date": "2025-08-21T08:38:14.478Z",
            "device_type": "Laptop",
            "disk_encrypted": false,
            "email": "john.doe@example.com",
            "extension_version": "1.12546.6",
            "external_ip_address": "89.160.20.112",
            "id": "7748cf6a-1a23-4572-b5ee-129962616b25",
            "internal_ip_address": "10.50.6.126",
            "is_archived": false,
            "is_default_browser": false,
            "is_virtual_machine": true,
            "island_platform": "Browser",
            "last_seen": "2025-08-31T04:19:55.342Z",
            "mac_addresses": "00:50:56:81:c9:17 | 02:42:7e:fe:2e:0b | 00:50:56:81:82:be",
            "machine_id": "iNUa5F_2xgA1L51ZX5_YCXX7b7Z",
            "machine_model": "VMware Virtual Platform",
            "machine_name": "ub22-50-6-126.manage.local",
            "manufacturer": "VMware, Inc.",
            "os_code_name": "Ubuntu 22.04.5 LTS",
            "os_firewall_enabled": true,
            "os_platform": "Linux",
            "os_screen_lock_enabled": true,
            "os_user_name": "serviceuser",
            "os_version": "22.04",
            "policy_update_time": "2025-07-08T14:17:18.527Z",
            "ram_size": 16,
            "status": "Active",
            "storage_capacity": 48,
            "sync_enabled": true,
            "tenant_id": "elastic-testing",
            "updated_date": "2025-08-31T04:19:55.345Z",
            "user_id": "auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486",
            "user_name": "John Doe",
            "windows_license_status": "Unlicensed"
        }
    },
    "organization": {
        "id": "elastic-testing"
    },
    "related": {
        "hosts": [
            "7748cf6a-1a23-4572-b5ee-129962616b25",
            "iNUa5F_2xgA1L51ZX5_YCXX7b7Z",
            "ub22-50-6-126.manage.local"
        ],
        "ip": [
            "89.160.20.112",
            "10.50.6.126"
        ],
        "user": [
            "john.doe@example.com",
            "serviceuser",
            "auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486",
            "John Doe"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "island_browser-device"
    ],
    "user": {
        "domain": "example.com",
        "email": "john.doe@example.com",
        "id": "auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486",
        "name": "John Doe"
    },
    "user_agent": {
        "name": "Island"
    }
}
```

#### Audit

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2025-09-09T13:29:38.000Z",
    "agent": {
        "ephemeral_id": "c47c8fe8-1c04-44de-8c4f-0151a17ec928",
        "id": "caf0149d-fb8e-45cc-991f-f2c6f4aa0524",
        "name": "elastic-agent-29545",
        "type": "filebeat",
        "version": "8.18.5"
    },
    "data_stream": {
        "dataset": "island_browser.audit",
        "namespace": "65876",
        "type": "logs"
    },
    "device": {
        "id": "7748cf6a-1a23-4572-b5ee-129962616b25"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "caf0149d-fb8e-45cc-991f-f2c6f4aa0524",
        "snapshot": false,
        "version": "8.18.5"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2025-09-09T09:24:36.278Z",
        "dataset": "island_browser.audit",
        "id": "0554e3ab-618a-4171-a5d7-33555ac4476b",
        "ingested": "2025-09-16T13:22:29Z",
        "kind": "event",
        "original": "{\"clientEventId\":\"d14e7489-e627-4cf8-bf89-daeb6c4b6a55\",\"compatibilityMode\":\"None\",\"country\":\"India\",\"countryCode\":\"IN\",\"createdDate\":\"2025-09-09T09:24:36.278692Z\",\"details\":\"{\\n  \\\"navigation_details\\\": {\\n    \\\"referrer\\\": \\\"https://google.com\\\",\\n    \\\"user_agent\\\": \\\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\\\"\\n  },\\n  \\\"policy_version_details\\\": {\\n    \\\"application_access_policy_version\\\": \\\"1\\\",\\n    \\\"browser_access_policy_version\\\": \\\"1\\\",\\n    \\\"browser_policy_version\\\": \\\"1\\\",\\n    \\\"dlp_policy_version\\\": \\\"1\\\",\\n    \\\"pam_policy_version\\\": \\\"1\\\"\\n  }\\n}\",\"deviceId\":\"7748cf6a-1a23-4572-b5ee-129962616b25\",\"devicePostureMatchingDetails\":\"Device meets all security requirements\",\"domainOrTenant\":\"example.com\",\"email\":\"john.doe@example.com\",\"frameId\":67890,\"frameUrl\":\"https://example.com/iframe\",\"id\":\"0554e3ab-618a-4171-a5d7-33555ac4476b\",\"incognito\":false,\"isIslandPrivateAccess\":false,\"keystrokes\":\"example search query\",\"machineId\":\"iNUa5F_2xgH0L51ZW5_YCFI7b7U\",\"machineName\":\"ub22-50-6-126.manage.local\",\"matchedDevicePosture\":\"Compliant\",\"matchedUserGroup\":\"Standard Users\",\"origin\":\"Island\",\"osPlatform\":\"Linux\",\"osUserName\":\"serviceuser\",\"processedDate\":\"2025-09-09T13:29:39.123456Z\",\"publicIp\":\"89.160.20.112\",\"region\":\"Asia\",\"ruleId\":\"rule-12345\",\"ruleName\":\"Standard Navigation Policy\",\"saasApplicationCategory\":\"Productivity\",\"saasApplicationId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"saasApplicationName\":\"Microsoft 365\",\"screenshotFileName\":\"screenshot_20250909_132938.png\",\"shortTopLevelUrl\":\"example.com\",\"sourceIp\":\"10.50.6.126\",\"submittedUrl\":\"https://example.com/page\",\"tabId\":935959881,\"tenantId\":\"elastic-testing\",\"timestamp\":\"2025-09-09T13:29:38.000Z\",\"topLevelUrl\":\"https://example.com\",\"type\":\"Navigation\",\"updatedDate\":\"2025-09-09T09:24:36.278693Z\",\"urlWebCategories\":[\"Business\",\"Technology\"],\"urlWebReputation\":85,\"userId\":\"auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486\",\"userName\":\"John Doe\",\"verdict\":\"Allowed\",\"verdictReason\":\"Navigation allowed by policy\",\"websiteTopLevelUrl\":\"https://example.com\",\"windowId\":12345}"
    },
    "file": {
        "name": "screenshot_20250909_132938.png"
    },
    "host": {
        "id": "iNUa5F_2xgH0L51ZW5_YCFI7b7U",
        "name": "ub22-50-6-126.manage.local",
        "os": {
            "platform": "Linux"
        }
    },
    "input": {
        "type": "cel"
    },
    "island_browser": {
        "audit": {
            "client_event_id": "d14e7489-e627-4cf8-bf89-daeb6c4b6a55",
            "compatibility_mode": "None",
            "country": "India",
            "country_code": "IN",
            "created_date": "2025-09-09T09:24:36.278Z",
            "details": {
                "navigation_details": {
                    "referrer": "https://google.com",
                    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                },
                "policy_version_details": {
                    "application_access_policy_version": "1",
                    "browser_access_policy_version": "1",
                    "browser_policy_version": "1",
                    "dlp_policy_version": "1",
                    "pam_policy_version": "1"
                }
            },
            "device_id": "7748cf6a-1a23-4572-b5ee-129962616b25",
            "device_posture_matching_details": "Device meets all security requirements",
            "domain_or_tenant": "example.com",
            "email": "john.doe@example.com",
            "frame_id": "67890",
            "frame_url": "https://example.com/iframe",
            "id": "0554e3ab-618a-4171-a5d7-33555ac4476b",
            "incognito": false,
            "is_island_private_access": false,
            "keystrokes": "example search query",
            "machine_id": "iNUa5F_2xgH0L51ZW5_YCFI7b7U",
            "machine_name": "ub22-50-6-126.manage.local",
            "matched_device_posture": "Compliant",
            "matched_user_group": "Standard Users",
            "origin": "Island",
            "os_platform": "Linux",
            "os_user_name": "serviceuser",
            "processed_date": "2025-09-09T13:29:39.123Z",
            "public_ip": "89.160.20.112",
            "region": "Asia",
            "rule_id": "rule-12345",
            "rule_name": "Standard Navigation Policy",
            "saas_application_category": "Productivity",
            "saas_application_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "saas_application_name": "Microsoft 365",
            "screenshot_file_name": "screenshot_20250909_132938.png",
            "short_top_level_url": "example.com",
            "source_ip": "10.50.6.126",
            "submitted_url": "https://example.com/page",
            "tab_id": "935959881",
            "tenant_id": "elastic-testing",
            "timestamp": "2025-09-09T13:29:38.000Z",
            "top_level_url": "https://example.com",
            "type": "Navigation",
            "updated_date": "2025-09-09T09:24:36.278Z",
            "url_web_categories": [
                "Business",
                "Technology"
            ],
            "url_web_reputation": 85,
            "user_id": "auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486",
            "user_name": "John Doe",
            "verdict": "Allowed",
            "verdict_reason": "Navigation allowed by policy",
            "website_top_level_url": "https://example.com",
            "window_id": "12345"
        }
    },
    "organization": {
        "id": "elastic-testing"
    },
    "related": {
        "hosts": [
            "7748cf6a-1a23-4572-b5ee-129962616b25",
            "iNUa5F_2xgH0L51ZW5_YCFI7b7U",
            "ub22-50-6-126.manage.local"
        ],
        "ip": [
            "89.160.20.112",
            "10.50.6.126"
        ],
        "user": [
            "john.doe@example.com",
            "serviceuser",
            "auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486",
            "John Doe"
        ]
    },
    "rule": {
        "id": "rule-12345",
        "name": "Standard Navigation Policy"
    },
    "service": {
        "name": "Microsoft 365"
    },
    "source": {
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "10.50.6.126",
        "nat": {
            "ip": "89.160.20.112"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "island_browser-audit"
    ],
    "url": {
        "domain": "example.com",
        "original": "https://example.com",
        "scheme": "https"
    },
    "user": {
        "domain": "example.com",
        "email": "john.doe@example.com",
        "id": "auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486",
        "name": "John Doe"
    }
}
```

#### Compromised Credential

An example event for `compromised_credential` looks as following:

```json
{
    "@timestamp": "2025-09-15T06:38:06.177Z",
    "agent": {
        "ephemeral_id": "1bc13c0a-9d03-40d6-8e50-5e78294c111e",
        "id": "ad1d3c39-3a1c-4004-91f0-aa1d27fd6242",
        "name": "elastic-agent-26694",
        "type": "filebeat",
        "version": "8.18.5"
    },
    "data_stream": {
        "dataset": "island_browser.compromised_credential",
        "namespace": "40655",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "ad1d3c39-3a1c-4004-91f0-aa1d27fd6242",
        "snapshot": false,
        "version": "8.18.5"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2024-09-21T09:46:00.000Z",
        "dataset": "island_browser.compromised_credential",
        "id": "cc-10364-ae99d-20364",
        "ingested": "2025-09-15T06:38:09Z",
        "kind": "event",
        "original": "{\"breachSource\":\"Ransomware Attack - April 2025\",\"compromisedDate\":\"2024-09-13T00:00:00Z\",\"createdDate\":\"2024-09-21T09:46:00Z\",\"email\":\"john.doe364@enterprise.io\",\"id\":\"cc-10364-ae99d-20364\",\"impactedDomain\":\"enterprise.io\",\"status\":\"Unresolved\",\"tenantId\":\"tenant-005-tech\",\"updatedDate\":\"2024-09-21T14:40:00Z\",\"username\":\"john.doe364\"}"
    },
    "input": {
        "type": "cel"
    },
    "island_browser": {
        "compromised_credential": {
            "breach_source": "Ransomware Attack - April 2025",
            "compromised_date": "2024-09-13T00:00:00.000Z",
            "created_date": "2024-09-21T09:46:00.000Z",
            "email": "john.doe364@enterprise.io",
            "id": "cc-10364-ae99d-20364",
            "impacted_domain": "enterprise.io",
            "status": "Unresolved",
            "tenant_id": "tenant-005-tech",
            "updated_date": "2024-09-21T14:40:00.000Z",
            "username": "john.doe364"
        }
    },
    "organization": {
        "id": "tenant-005-tech"
    },
    "related": {
        "user": [
            "john.doe364@enterprise.io",
            "john.doe364"
        ]
    },
    "source": {
        "registered_domain": "enterprise.io"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "island_browser-compromised_credential"
    ],
    "user": {
        "domain": "enterprise.io",
        "email": "john.doe364@enterprise.io",
        "name": "john.doe364"
    }
}
```

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following APIs:

- `User`: [Island Browser API](https://documentation.island.io/apidocs/get-all-browser-users-that-match-the-specified-simple-filter).
- `Device`: [Island Browser API](https://documentation.island.io/apidocs/get-a-list-of-all-devices-1).
- `Audit`: [Island Browser API](https://documentation.island.io/apidocs/get-all-timeline-audits-that-match-the-specified-simple-filter).
- `Compromised Credential`: [Island Browser API](https://documentation.island.io/apidocs/get-a-list-of-all-compromised-credentials).

#### ILM Policy

To facilitate user and device data, source data stream-backed indices `.ds-logs-island_browser.user-*` and `.ds-logs-island_browser.device-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-island_browser.user-default_policy` and `logs-island_browser.device-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
