# OpenAI ChatGPT Enterprise Integration for Elastic

## Overview

[OpenAI ChatGPT Enterprise](https://openai.com/chatgpt/enterprise/) is the enterprise offering of ChatGPT, providing workspace administration, security controls, and compliance capabilities for organizations. The [Compliance Logs Platform](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers) exposes the compliance events generated across a workspace or organization, including administrative activity, authentication, application access, and Codex activity.

This integration for Elastic allows you to collect ChatGPT Enterprise compliance logs using the OpenAI Compliance Logs Platform API, then visualize the data in Kibana.

### Compatibility

This integration is compatible with the OpenAI Compliance Logs Platform API for ChatGPT Enterprise customers.

### How it works

This integration periodically queries the OpenAI Compliance Logs Platform API to retrieve compliance logs. Collection is a two-step (chained) process: the integration first lists the available log files for the configured event type, then downloads each log file and emits every JSON Lines record it contains as an individual event.

## What data does this integration collect?

This integration collects log messages of the following type:

- `Audit Logs`: Collect administrative and workspace audit activity (event type: `AUDIT_LOG`) from the OpenAI Compliance Logs Platform. Each audit event captures the action performed, the acting principal, the outcome, and request metadata such as client IP and user agent.

### Supported use cases

Bringing OpenAI ChatGPT Enterprise Audit Logs into Elastic gives security and compliance teams a searchable, correlatable record of administrative and workspace activity. Audit events describe who performed which action, on which resource, from where, and whether the action succeeded, was blocked, or failed.

Use the `audit_log` data stream to monitor privileged administrative actions (role changes, application access grants, feature toggles, invitations, and workspace policy updates), investigate suspicious activity by user, IP, or geography, and track outcome trends over time. Bundled dashboards summarize activity volume, top actions, top users, action outcomes, and source geography for day-to-day monitoring and investigation.

## What do I need to use this integration?

### From OpenAI

To collect data through the OpenAI Compliance Logs Platform API, you need a **Compliance API key** authorized for enterprise logs and the **Workspace ID** or **Organization ID** whose compliance logs you want to collect.

1. Ensure your account has access to the [Compliance API for enterprise customers](https://help.openai.com/en/articles/9261474-compliance-api-for-enterprise-customers).
2. Generate a **Compliance API key** authorized for enterprise logs.
3. Obtain the **Workspace ID** (when Scope is `workspace`) or the **Organization ID** (when Scope is `organization`) whose logs will be collected.
4. Store these values securely for use in the integration configuration.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the OpenAI Compliance Logs Platform API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html)

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **OpenAI ChatGPT Enterprise**.
3. Select the **OpenAI ChatGPT Enterprise** integration from the search results.
4. Select **Add OpenAI ChatGPT Enterprise** to add the integration.
5. Enable and configure the collection method:

    * To **Collect ChatGPT Enterprise compliance logs**, you'll need to:

        - Configure the **URL** and **Compliance API key**.
        - Set the **Scope** (`workspace` or `organization`) and the corresponding **Workspace / Organization ID**.
        - Adjust the integration configuration parameters if required, including the Interval, Initial Interval, and HTTP Client Timeout to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **OpenAI ChatGPT Enterprise**, and verify the dashboard information is populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Audit Logs

The `audit_log` data stream provides administrative and workspace audit events from the OpenAI ChatGPT Enterprise Compliance Logs Platform.

#### Audit Log fields

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
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| openai_chatgpt_enterprise.audit_log.action_data.affected_connector_ids | Connector IDs whose workspace permissions were affected (APP_PUBLISH / WORKSPACE_TOGGLE_FEATURE). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.after | Pagination cursor for list actions (RFC3339 timestamp). | date |
| openai_chatgpt_enterprise.audit_log.action_data.after_string | Pagination cursor for list actions (Opaque token). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.agent_id | Workspace agent identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.alert_recipients.email | Recipient email for usage alerts (SUBSCRIPTION_SET_USAGE_ALERTS). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.alert_recipients.type | Recipient type. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.alert_thresholds.credits | Credit threshold amount. | long |
| openai_chatgpt_enterprise.audit_log.action_data.alert_thresholds.type | Threshold type. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.allow_all_in_workspace | Whether the app is visible to the whole workspace (APP_UPDATE_ACCESS_POLICY). | boolean |
| openai_chatgpt_enterprise.audit_log.action_data.allowed_ips | CIDR entries in the IP allowlist (WORKSPACE_SET_\*_IP_ALLOWLIST). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.already_exists | True if a shared conversation already existed (CONVERSATION_SHARE). | boolean |
| openai_chatgpt_enterprise.audit_log.action_data.app_id | App / connector identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.app_name | App / connector friendly name. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.auth_user_id | Auth user ID of a memory owner (DELETE_MEMORY). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.automation_id | Automation identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.before | Pagination cursor upper bound for list actions (RFC3339 timestamp). | date |
| openai_chatgpt_enterprise.audit_log.action_data.before_string | Pagination cursor upper bound for list actions (Opaque token). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.changed_fields | List of fields changed by the request. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.changed_fields_by_connector | Map of connector ID -\> changed fields (keys are connector IDs). | flattened |
| openai_chatgpt_enterprise.audit_log.action_data.classification | FedRAMP banner classification string (WORKSPACE_SET_FEDRAMP_BANNER). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.client_id | Codex remote-control client identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.codex_environment_id | Codex environment identifier (GET_CODE_ENVIRONMENT). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.context_plugin_id | Plugin whose UI initiated the action. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.conversation_id | Conversation identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.created_at | Creation time (epoch seconds). | date |
| openai_chatgpt_enterprise.audit_log.action_data.created_by_user_id | Auth user ID that created the service account (nullable). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.credential_id | Credential / personal access token identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.credential_name | User-provided credential name. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.credential_type | Credential type. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.cursor | Pagination cursor (list actions). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.deactivated_at | Service account deletion time (epoch seconds) or null. | date |
| openai_chatgpt_enterprise.audit_log.action_data.domain_id | Managed domain identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.domains | Allowed action domains for a GPT (may be null to clear). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.email_address | Single email address (invite actions). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.email_addresses | List of email addresses (invite / group actions). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.enabled | Enabled / active state after the change. | boolean |
| openai_chatgpt_enterprise.audit_log.action_data.environment_id | Environment identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.event_type | Compliance event category: filter list (array) or resolved category (download, string). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.expires_at | Credential expiration time (epoch seconds) or null. | date |
| openai_chatgpt_enterprise.audit_log.action_data.feature | Feature / flag identifier toggled (WORKSPACE_TOGGLE_FEATURE / WORKSPACE_SET_SHARING_PERMISSION). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.file_format | File output mode. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.file_id | File identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.gpt_id | GPT identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.group_id | Group identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.hostname | Domain hostname added (DOMAIN_CREATE). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.id | Resource identifier (GPT / project) for the action. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.include_summary | Whether recording summary sections are included (DOWNLOAD_RECORDING_TRANSCRIPT). | boolean |
| openai_chatgpt_enterprise.audit_log.action_data.installation_policy | Plugin installation policy after the update. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.installation_policy_before | Plugin installation policy before the update. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.installed_by_default_role_ids | Role IDs the plugin is installed for by default (after). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.installed_by_default_role_ids_before | Role IDs the plugin was installed for by default (before). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.knowledge_app_type | App backend / type provisioned (APP_CREATE). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.limit | Requested page size (list actions). | long |
| openai_chatgpt_enterprise.audit_log.action_data.log_file_id | Compliance log file identifier (download actions). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.markdown | FedRAMP banner markdown body. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.memory_context_id | Memory context identifier (DELETE_MEMORY). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.memory_id | Memory identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.message_id | Message identifier (rating actions). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.name | Resource / service-account / credential name. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.new_name | New / updated name. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.new_role | Role assigned to the user (USER_ROLE_UPDATED). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.new_workspace_permissions_by_connector | Map of connector ID -\> permission snapshot after the change. | flattened |
| openai_chatgpt_enterprise.audit_log.action_data.old_name | Previous name before the change. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.order | Sort order (list directory actions). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.overage_limit_credits | Credit overage limit, integer or the string unlimited. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.owner_id | Owner filter / owner user ID (list agents etc.). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.owner_user_id | Auth user ID of the credential owner. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.plugin_id | Plugin identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.previous_enabled | Service account active state before the update. | boolean |
| openai_chatgpt_enterprise.audit_log.action_data.previous_name | Service account name before the update (nullable). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.previous_role | Previous role for a share target (nullable) (SKILL_SHARE). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.previous_workspace_permissions_by_connector | Map of connector ID -\> permission snapshot before the change. | flattened |
| openai_chatgpt_enterprise.audit_log.action_data.principal_id | Principal (user or group) identifier for a share target. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.principal_type | Principal type: user or group. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.project_id | Project identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.public_display_name | External display name (WORKSPACE_SET_IS_DISCOVERABLE). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.rating | Message rating. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.recording_id | Recording identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.remote_thread_id | Codex remote-control thread identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.requested_access_removals.recipient_type | Recipient type requested for removal (PROJECT_UPDATE_SHARING). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.requested_access_removals.user_id | User ID requested for removal. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.requested_access_updates.capabilities | Capabilities requested for the recipient. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.requested_access_updates.recipient_type | Recipient type requested to add/update. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.requested_access_updates.user_id | User ID requested to add/update. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.revoked_at | Revocation time (epoch seconds) or null. | date |
| openai_chatgpt_enterprise.audit_log.action_data.revoked_unified_sessions | Unified session IDs revoked (SESSION_REVOKE). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.role | Role granted / removed (manager or user; or invite role). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.room_id | Project chat room identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.scope_id | Connector scope identifier (DELETE_PROJECT_CONNECTOR_SCOPE). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.scopes | Product-access scopes on the credential (sorted, deduplicated). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.service_account_id | Service account auth user ID. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.session_id | Session identifier (SESSION_REVOKE). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.shared_conversation_id | Shared conversation identifier (CONVERSATION_SHARE / view). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.shared_to.capabilities | Capabilities granted to the recipient segment. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.shared_to.group_id | Group ID recipient (sharing). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.shared_to.recipient_type | Recipient type (UPDATE_SHARING). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.shared_to.type | Recipient segment type (CHANGE_VISIBILITY). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.sign_in_endpoint | SAML sign-in endpoint URL / SCIM connection identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.since_timestamp | Lower-bound timestamp filter (list actions). | date |
| openai_chatgpt_enterprise.audit_log.action_data.skill_id | Skill identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.skill_name | Skill name. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.source_surface | Admin surface that initiated the action (admin_apps or admin_plugins). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.state_changed | Whether the successful request performed the initial revoke transition. | boolean |
| openai_chatgpt_enterprise.audit_log.action_data.system_instruction | Workspace default system prompt (WORKSPACE_SET_SYSTEM_INSTRUCTION). | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.task_id | Codex task identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.textdoc_id | Canvas text document identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.third_party_gizmo_id | Third-party GPT identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.total_requested | Count of join requests approved (INVITE_ACCEPT_ALL). | long |
| openai_chatgpt_enterprise.audit_log.action_data.use_workspace_name_for_discovery | Whether the workspace name is reused for discovery. | boolean |
| openai_chatgpt_enterprise.audit_log.action_data.user_id | Auth user ID targeted by the action. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.value | Generic value payload (boolean/string) for toggle/set actions. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.value_bool | Boolean form of action_data.value (populated when the changed value is a boolean). | boolean |
| openai_chatgpt_enterprise.audit_log.action_data.workspace_access_state | Skill workspace access state: restricted / discoverable / enabled. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.workspace_id | Workspace identifier. | keyword |
| openai_chatgpt_enterprise.audit_log.action_data.workspace_policy | Workspace policy document or identifier (WORKSPACE_SET_POLICY). | keyword |
| openai_chatgpt_enterprise.audit_log.action_privilege | Privilege level for the action: ADMIN or STANDARD_USER. | keyword |
| openai_chatgpt_enterprise.audit_log.action_result | Outcome of the action: SUCCESS, BLOCKED, or ERROR. | keyword |
| openai_chatgpt_enterprise.audit_log.actor.redacted_id | Redacted identifier of the API key (present when actor.type = API_KEY). | keyword |
| openai_chatgpt_enterprise.audit_log.actor.type | Type of actor that performed the action (e.g. ACCOUNT_USER, API_KEY). | keyword |
| openai_chatgpt_enterprise.audit_log.app_id | Identifier of the connected app / connector. | keyword |
| openai_chatgpt_enterprise.audit_log.client_id | Codex client identifier associated with the event. | keyword |
| openai_chatgpt_enterprise.audit_log.event_details.detail_type | Discriminator identifying the specific Codex event-details schema. | keyword |
| openai_chatgpt_enterprise.audit_log.principal.type | Principal that owns the event (e.g. CHATGPT_WORKSPACE). | keyword |
| openai_chatgpt_enterprise.audit_log.request_metadata.client_ip_details.asn | Autonomous System Number resolved from the client IP. | keyword |
| openai_chatgpt_enterprise.audit_log.request_metadata.client_ip_details.city | City resolved from the client IP. | keyword |
| openai_chatgpt_enterprise.audit_log.request_metadata.client_ip_details.country | Country resolved from the client IP. | keyword |
| openai_chatgpt_enterprise.audit_log.request_metadata.client_ip_details.latitude | Latitude resolved from the client IP. | keyword |
| openai_chatgpt_enterprise.audit_log.request_metadata.client_ip_details.longitude | Longitude resolved from the client IP. | keyword |
| openai_chatgpt_enterprise.audit_log.request_metadata.client_ip_details.region | Region / state resolved from the client IP. | keyword |
| openai_chatgpt_enterprise.audit_log.request_metadata.client_ip_details.region_code | Region / state code resolved from the client IP. | keyword |
| openai_chatgpt_enterprise.audit_log.request_metadata.client_ja4 | JA4 TLS fingerprint of the client (may be empty). | keyword |
| openai_chatgpt_enterprise.audit_log.type | Top-level event category (APP_LOG, APP_AUTH_LOG, AUDIT_LOG, AUTH_LOG, CODEX_LOG, CODEX_SECURITY_LOG). | keyword |
| openai_chatgpt_enterprise.audit_log.workspace_id | Workspace identifier associated with the event. | keyword |


### Example event

An example event for `audit_log` looks as following:

```json
{
    "@timestamp": "2026-07-09T11:05:09.077Z",
    "agent": {
        "ephemeral_id": "d4290824-0b37-43b5-b718-bd38f7ba6230",
        "id": "ad657795-fbcc-4049-a6ac-d65abc851b66",
        "name": "elastic-agent-57701",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "openai_chatgpt_enterprise.audit_log",
        "namespace": "43110",
        "type": "logs"
    },
    "destination": {
        "domain": "api.chatgpt.com"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "ad657795-fbcc-4049-a6ac-d65abc851b66",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "list_workspace_log_files",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "openai_chatgpt_enterprise.audit_log",
        "id": "92b7dea7-9ff4-485e-b0a0-74efa627f15b",
        "ingested": "2026-07-19T18:48:30Z",
        "kind": "event",
        "original": "{\"event_id\":\"92b7dea7-9ff4-485e-b0a0-74efa627f15b\",\"type\":\"AUDIT_LOG\",\"principal\":{\"id\":\"be545252-ad04-4cfa-9ca5-deca58416151\",\"type\":\"CHATGPT_WORKSPACE\"},\"actor\":{\"type\":\"API_KEY\",\"redacted_id\":\"sk-...RxIA\"},\"timestamp\":\"2026-07-09T11:05:09.077133Z\",\"action_result\":\"SUCCESS\",\"action_privilege\":\"ADMIN\",\"request_metadata\":{\"client_ip\":\"81.2.69.142\",\"client_ip_details\":{\"country\":\"GB\",\"city\":\"London\",\"region\":\"England\",\"region_code\":\"ENG\",\"asn\":\"\",\"latitude\":\"51.50853\",\"longitude\":\"-0.12574\"},\"client_user_agent\":\"python-requests/2.34.2\",\"client_ja3\":\"86dab2109182b6bbaa644647d7db2997\",\"client_ja4\":\"t13d1713h1_ab0a1bf427ad_8537cf56674e\",\"destination_hostname\":\"api.chatgpt.com\"},\"action_data\":{\"limit\":\"100\",\"after\":\"2026-07-09T10:24:53.814285Z\",\"event_type\":\"AUDIT_LOG\"},\"action\":\"LIST_WORKSPACE_LOG_FILES\"}",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "gen_ai": {
        "system": "openai"
    },
    "input": {
        "type": "cel"
    },
    "openai_chatgpt_enterprise": {
        "audit_log": {
            "action_data": {
                "after": "2026-07-09T10:24:53.814Z",
                "event_type": "AUDIT_LOG",
                "limit": 100
            },
            "action_privilege": "ADMIN",
            "action_result": "SUCCESS",
            "actor": {
                "redacted_id": "sk-...RxIA",
                "type": "API_KEY"
            },
            "principal": {
                "type": "CHATGPT_WORKSPACE"
            },
            "request_metadata": {
                "client_ip_details": {
                    "city": "London",
                    "country": "GB",
                    "latitude": "51.50853",
                    "longitude": "-0.12574",
                    "region": "England",
                    "region_code": "ENG"
                },
                "client_ja4": "t13d1713h1_ab0a1bf427ad_8537cf56674e"
            },
            "type": "AUDIT_LOG"
        }
    },
    "organization": {
        "id": "be545252-ad04-4cfa-9ca5-deca58416151"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ]
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.142"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "openai_chatgpt_enterprise-audit_log"
    ],
    "tls": {
        "client": {
            "ja3": "86dab2109182b6bbaa644647d7db2997"
        }
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Python Requests",
        "original": "python-requests/2.34.2",
        "version": "2.34"
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

* List compliance log files (endpoint: `GET /v1/compliance/workspaces/{workspace_id}/logs` or `GET /v1/compliance/organizations/{organization_id}/logs`)
* Download a compliance log file (endpoint: `GET /v1/compliance/workspaces/{workspace_id}/logs/{log_file_id}` or `GET /v1/compliance/organizations/{organization_id}/logs/{log_file_id}`)
