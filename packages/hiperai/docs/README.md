# HiperAI SecureAI

The HiperAI SecureAI integration collects security events, audit logs, AI governance violations, DLP alerts, and authentication activity from the [SecureAI](https://hiperai.com) enterprise AI security and governance platform.

## Overview

[HiperAI SecureAI](https://docs.hiperai.com) is an enterprise security, DLP, and governance platform for generative AI and LLM workflows. It provides:

- **Real-time AI usage monitoring** — Comprehensive audit logs for all LLM interactions
- **SMLTP policy enforcement** — Deterministic, cryptographically signed policy control for AI model access (Secure Model Link Transport Protocol)
- **Prompt injection detection** — Real-time detection and blocking of adversarial prompts
- **DLP for AI** — Sensitive data protection preventing PII, credentials, and confidential data from reaching AI models
- **Shadow AI discovery** — Detection of unauthorized AI tool usage across the enterprise

This integration enables SOC analysts and security teams to correlate AI-specific security events with traditional enterprise telemetry in Elastic Security.

## Compatibility

This integration has been tested with:
- SecureAI version 1.1.x and later
- Elastic Stack version 8.19.0 or 9.1.0 and later

## Setup

### Option A: Using Elastic Agent HTTP Endpoint (Recommended)

1. In Kibana, navigate to **Fleet** → **Integrations** → search for **HiperAI SecureAI**.
2. Click **Add HiperAI SecureAI** and configure the HTTP listener port (default: `8089`).
3. Deploy the agent policy to your Elastic Agent.
4. In the SecureAI admin console, navigate to **Integrations** → **Elastic SIEM**.
5. Configure the **Elastic URL** to point to the Elastic Agent HTTP endpoint:
   ```
   http://<agent-host>:8089
   ```
6. Set the **Elastic API Key** if you configured a secret header.
7. Select the **Event Categories** you want to forward.
8. Click **Test Connection** to verify.

### Option B: Direct Push to Elasticsearch

SecureAI can also push events directly to Elasticsearch without going through Elastic Agent. In this mode, the integration package still provides value through index templates, ingest pipelines, and field mappings.

#### Step 1: Obtain Your Elastic Cloud Endpoint

1. Log in to your Elastic Cloud account.
2. From the homepage, locate your desired deployment.
3. Find the Elasticsearch endpoint URL and copy it.

#### Step 2: Create an API Key in Elasticsearch

1. In Kibana, navigate to **Management** → **API Keys**.
2. Click **Create API key**.
3. Name it `secureai-siem-integration` and assign write privileges for the `logs-hiperai.events-*` index pattern.
4. Copy the Base64-encoded API key.

#### Step 3: Configure SecureAI

1. In the SecureAI admin console, navigate to **Integrations**.
2. Select the **Elastic SIEM** integration card.
3. Fill in the configuration:
   - **Integration Name**: `secureai-elastic`
   - **Elastic URL**: Your Elasticsearch endpoint URL
   - **Elastic API Key**: The Base64-encoded API key from Step 2
   - **Elastic Index**: `logs-hiperai.events-default`
   - **Event Categories**: Select the categories you want to forward
4. Click **Update** to save.

#### Step 4: Test the Connection

1. Click **Test Connection** in the integration settings.
2. Verify the test event appears in Kibana **Discover** under the `logs-hiperai.events-*` data view.

## Event Types

SecureAI forwards the following event types:

| Event Type | ECS Category | Description |
|---|---|---|
| `login_success` | `authentication` | Successful user authentication |
| `login_failed` | `authentication` | Failed authentication attempt |
| `logout` | `session` | User session ended |
| `chat_completion` | `api` | AI model chat completion request |
| `api_request` | `api` | API request processed |
| `policy_violation` | `intrusion_detection` | DLP or security policy violated |
| `security_incident` | `intrusion_detection` | Security incident detected |
| `smltp_violation` | `intrusion_detection` | SMLTP policy violation |
| `smltp_policy_applied` | `intrusion_detection` | SMLTP policy enforcement action |
| `smltp_entitlement_denied` | `intrusion_detection` | Model access denied by entitlement |
| `audit_log` | `configuration` | Administrative or audit action |
| `data_access` | `api` | Data access event |
| `billing_event` | `api` | Billing or usage event |

## Event Categories

Events can be filtered by the following categories in the SecureAI configuration:

- **Authentication & Login** — Login, logout, SSO, and MFA events
- **Security & Violations** — Policy violations, DLP triggers, prompt injection detection
- **SMLTP & Policy** — SMLTP governance, entitlement enforcement, policy actions
- **API & Model Usage** — AI model requests, token usage, response tracking
- **Data Access & PHI** — Data access events, PII/PHI detection
- **System & Infrastructure** — Platform health, service events
- **Configuration Changes** — Administrative and configuration modifications
- **Billing & Usage Limits** — Usage tracking and billing events
- **Analytics & Intelligence** — Platform analytics summaries
- **LLM Analytics** — AI model performance and usage analytics
- **Platform Intelligence** — Security posture and trend analysis
- **SMLTP Analytics** — Policy enforcement statistics
- **OCR Analytics** — Document processing analytics

## Severity Mapping

SecureAI severity levels are mapped to ECS numeric severity:

| SecureAI Severity | ECS `event.severity` |
|---|---|
| `info` | `1` |
| `low` | `2` |
| `medium` | `3` |
| `high` | `4` |
| `critical` | `5` |

## Logs reference

### Events

The `events` dataset collects all security events from the SecureAI platform.

An example event for `events` looks as following:

```json
{
    "events": [
        {
            "@timestamp": "2026-09-01T14:30:00.000Z",
            "event": {
                "kind": "event",
                "module": "hiperai",
                "dataset": "hiperai.events",
                "action": "login_success",
                "provider": "secureai",
                "severity": 1,
                "category": [
                    "authentication"
                ],
                "outcome": "success"
            },
            "user": {
                "name": "analyst@example.com",
                "id": "usr-001"
            },
            "source": {
                "ip": "198.51.100.50"
            },
            "observer": {
                "vendor": "HiperAI",
                "product": "SecureAI",
                "type": "ai_security_gateway"
            },
            "message": "User logged in successfully",
            "hiperai": {
                "action": "login_success",
                "category": "authentication",
                "severity": "info",
                "session_id": "sess-abc123"
            }
        }
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| hiperai.action | The specific action within SecureAI that triggered this event (e.g., chat_completion, login_success, smltp_violation, smltp_policy_applied, entitlement_denied). | keyword |
| hiperai.activity | Detailed activity object from SecureAI containing additional context about the event, including type, description, severity, outcome, reason, resource_id, resource_type, and compliance_category. | flattened |
| hiperai.category | SecureAI event category. One of: authentication, security, smltp, api, data_access, system, configuration, billing, analytics. | keyword |
| hiperai.metadata | Additional metadata about the event, including tenant information, model parameters, integration context, and any other contextual data provided by SecureAI. | flattened |
| hiperai.session_id | The SecureAI session identifier associated with the event. | keyword |
| hiperai.severity | SecureAI severity label. One of: info, low, medium, high, critical. | keyword |
| input.type | Type of Filebeat input. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


## Further Reading

- [HiperAI SecureAI Documentation](https://docs.hiperai.com)
- [SecureAI Elastic SIEM Integration Guide](https://docs.hiperai.com/integrations/elastic-security)
- [GitHub: Hiper-AI](https://github.com/Hiper-AI)
