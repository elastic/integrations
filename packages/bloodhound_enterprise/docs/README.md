# SpecterOps BloodHound Enterprise

## Overview

[SpecterOps BloodHound Enterprise](https://bloodhoundenterprise.io/) identifies Active Directory and Azure AD attack paths. This integration collects those attack-path findings into Elastic.

The agent only stores findings. It does not open Security cases and it does not write alerts. The detection rule **BloodHound Enterprise Attack Path Finding** creates one alert per finding. The BloodHound finding case workflow, attached to that rule, groups those alerts into one Security case per environment, zone, and finding type. An optional finding refresh workflow removes alerts when a finding no longer appears in BloodHound polls.

### Compatibility

This integration requires:

- Kibana `^9.4.0`
- Elastic Agent or an Elastic Managed deployment with the CEL input enabled
- Elastic Security, so the detection rule can create alerts
- Network connectivity from the agent to BloodHound Enterprise

### How it works

On each polling interval, the findings CEL program:

1. Discovers BloodHound Enterprise domains and asset-group tags (zones).
2. Lists finding types for each selected domain and zone.
3. Loads finding-type metadata from `/api/v2/findings/{finding_type}` when the API returns it.
4. Pages open finding instances and publishes one document per instance to `logs-bloodhound_enterprise.finding-*`.

If BloodHound rejects the token or a request fails, that failure is published to `logs-bloodhound_enterprise.error-*` (data view **[Logs BloodHound Enterprise] Error**). Those documents are not findings, and the detection rule does not alert on them.

Optional filters (`selected_environment`, `bhe_zones`) limit which domains and zones are collected. Empty, `All`, or `*` values mean fetch-all. Unrecognized values are treated as fetch-all so misconfiguration does not block collection.

**Polling Interval** is only how often the agent asks BloodHound for findings. The default is `1h`. It does not create alerts or cases. The detection rule runs on its own 5-minute schedule and looks at findings ingested in the last 6 minutes. Because each finding document is timestamped when the agent collects it, the rule sees the documents from the latest poll.

## What data does this integration collect?

This integration collects the following data:

- **finding**: Attack-path finding documents. This is the stream the detection rule reads.
- **error**: Authentication and request failures. Open these in Discover with the **[Logs BloodHound Enterprise] Error** data view (`logs-bloodhound_enterprise.error-*`). They are not mixed into the finding documents.

### Supported use cases

- Collect BloodHound Enterprise attack-path findings into Elasticsearch
- Create Security alerts with the packaged detection rule
- Group those alerts into Security cases with the BloodHound finding case workflow
- Optionally keep case alert counts aligned when findings leave BloodHound with the finding refresh workflow
- Filter collection by environment/domain and BloodHound zone
- Inspect authentication and request failures in a separate error data view
- Visualize findings with the bundled Attack Path Overview dashboard

## What do I need to use this integration?

### From Elastic

- An Elastic deployment with Fleet and Elastic Security (Cases) enabled
- Kibana `^9.4.0`
- Elastic Agent or Elastic Managed support for the CEL input

### From BloodHound Enterprise

- A BloodHound Enterprise tenant URL (for example `https://yourtenant.bloodhoundenterprise.io`)
- BloodHound Enterprise API **Token ID** and **Token Key** (Administration → API Keys in BloodHound Enterprise)
- Network path from the Elastic Agent (or Elastic Managed runner) to the BloodHound Enterprise HTTPS endpoint

## How do I deploy this integration?

This integration supports both Elastic Agent-based and Elastic Managed installations.

### Elastic Managed installation

Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Elastic Managed integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Assign this integration to an agent policy whose agents can reach BloodHound Enterprise. Do **not** attach it only to Fleet Server unless that host also has the required network access.

## Setup

### Obtain BloodHound Enterprise credentials

1. Sign in to your BloodHound Enterprise tenant.
2. Open **Administration → API Keys**.
3. Create or select an API key and copy the **Token ID** and **Token Key**.

### Enable the integration in Elastic

1. In Kibana go to **Management → Integrations**.
2. Search for **SpecterOps BloodHound Enterprise**.
3. Select **Add SpecterOps BloodHound Enterprise** and choose an agent policy.
4. Configure the required settings:

| Setting | Required | Description |
|---------|----------|-------------|
| Base URL | Yes | BloodHound Enterprise tenant URL without a trailing slash |
| Token ID | Yes | BloodHound Enterprise API token ID |
| Token Key | Yes | BloodHound Enterprise API token secret |
| Polling Interval | Yes | How often the agent asks BloodHound for findings. Choose 5m, 1h, 2h, 6h, 12h, or 24h. Default `1h`. This does not create alerts or cases. |
| Selected environment | No | Comma-separated domain names, or empty/`All`/`*` for all |
| BloodHound Enterprise zones | No | Comma-separated zone names, or empty/`All`/`*` for all |

5. Select **Save and continue**.
6. Install and enable the **BloodHound Enterprise Attack Path Finding** detection rule.
7. Save the **BloodHound Enterprise finding case** workflow and add it on that rule's **Actions** tab so alerts group into one case per environment, zone, and finding type.
8. Optionally save the **BloodHound Enterprise finding refresh** workflow, leave it disabled until step 7 is working, then enable it to detach and delete alerts when a finding no longer appears in the latest poll (for example after it is accepted in BloodHound Enterprise).

### Validation

After the first poll completes:

1. **Fleet → Agents** — confirm the agent is healthy.
2. **Discover** — open `logs-bloodhound_enterprise.finding-*` and confirm finding documents. `event.id` is the finding instance.
3. **Discover** — open the **[Logs BloodHound Enterprise] Error** data view (`logs-bloodhound_enterprise.error-*`) only when checking failures. Those documents should not appear in the finding data view.
4. **Security → Alerts** — confirm one alert per new finding. Error documents must not appear as alerts.
5. **Security → Cases** — after the case workflow runs, confirm one case per environment, zone, and finding type. The first case title is the group name with no number. When that case holds 1000 alerts, the next alert opens `[2]`, then `[3]`, and the workflow keeps using the highest iteration.
6. **Security → Cases** (optional refresh workflow) — when a finding stops appearing in BloodHound polls, confirm its alert is removed from the case and deleted after the refresh workflow runs.

| Scenario | Expected behavior |
|----------|-------------------|
| New finding appears in BloodHound Enterprise | A finding document on the next poll, then one alert the first time that `event.id` is seen, then the case workflow attaches that alert to the matching case |
| Same finding is collected again | The document stays in Discover. No second alert for that `event.id` for one year |
| Finding accepted or otherwise absent from BloodHound polls | No new finding document for that instance; with the refresh workflow enabled, the open alert is detached from cases and deleted |
| BloodHound authentication or request failure | One document in `logs-bloodhound_enterprise.error-*`, and no alert |

## Troubleshooting

| Symptom | What to check |
|---------|----------------|
| Auth failures against BloodHound | Token ID/Key, Base URL (no trailing slash), agent egress allowlist, clock skew for HMAC signatures. The failure document is in **[Logs BloodHound Enterprise] Error**, not in the finding data view |
| No finding documents | Polling Interval has not elapsed yet, or the environment and zone filters match nothing |
| Alerts missing | The detection rule is installed and enabled. It looks back 6 minutes and runs every 5 minutes. Findings are timestamped at collection time |
| An error document became an alert | The installed rule is older than this package. Reinstall the package and confirm the rule query requires `event.id` and excludes `error.message` |
| Cases not created | The case workflow is saved and attached to the detection rule. The agent does not open cases |
| Case alert count stays high after findings are accepted in BloodHound | Enable the finding refresh workflow after the case workflow is attaching alerts |
| Unexpected domains/zones | `selected_environment` / `bhe_zones` filters; unrecognized values fetch all |
| Integration not listed | Package not uploaded or registry not refreshed; rebuild/upload or wait for EPR propagation |

For general Elastic ingest issues, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

Large BloodHound environments may require a longer Polling Interval. Prefer filtering by environment or zone. The collector requests 500 findings per page.

## Reference

### Inputs used

These inputs can be used with this integration:

<details>
<summary>cel</summary>

## Setup

For more details about the CEL input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html).

Before configuring the CEL input, make sure you have:

- Network connectivity to BloodHound Enterprise
- Valid BloodHound token ID and token key

### Collecting logs from CEL

Configure Base URL, Token ID, Token Key, and Polling Interval. Authentication to BloodHound Enterprise uses HMAC request signatures (`bhesignature`).

</details>

### API usage

This integration uses:

- BloodHound Enterprise REST API (`/api/v2/available-domains`, `/api/v2/domains/{id}/available-types`, `/api/v2/findings/{finding_type}`, `/api/v2/domains/{id}/details`)

### Logs reference

#### error

This is the `error` dataset. Documents are BloodHound authentication and request failures. In Discover, use the **[Logs BloodHound Enterprise] Error** data view, `logs-bloodhound_enterprise.error-*`.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | match_only_text |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |


#### finding

This is the `finding` dataset. One document per BloodHound attack-path finding instance.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| bloodhound_enterprise.accepted | Whether the finding risk has been accepted by an admin. | boolean |
| bloodhound_enterprise.asset_group_tag_id | Asset group tag identifier. | long |
| bloodhound_enterprise.attack_path.length | Number of hops/edges in the attack path. | long |
| bloodhound_enterprise.attack_path.relationships | List of edge relationship types in the attack path. | keyword |
| bloodhound_enterprise.category | BloodHound finding category (e.g. zone/tag name). | keyword |
| bloodhound_enterprise.domain_sid | Active Directory domain SID for the finding environment. This is an identifier, not the domain name. | keyword |
| bloodhound_enterprise.exposure_count | Number of exposed domain objects. | long |
| bloodhound_enterprise.exposure_percentage | Percentage of domain exposed to attack path. | float |
| bloodhound_enterprise.finding_type | Type of BloodHound finding (e.g. AttackPath). | keyword |
| bloodhound_enterprise.impact_count | Number of domain objects impacted. | long |
| bloodhound_enterprise.impact_percentage | Percentage of domain impacted by attack path. | float |
| bloodhound_enterprise.impact_score | Risk impact score assigned by BloodHound Enterprise (0.0 to 10.0). | float |
| bloodhound_enterprise.is_inherited | Whether the relationship is inherited. | boolean |
| bloodhound_enterprise.long_description | Long description of this finding type. | match_only_text |
| bloodhound_enterprise.long_remediation | Long remediation text for this finding type. | match_only_text |
| bloodhound_enterprise.principal.kind | BloodHound principal kind for the source principal (User, Group, Computer). | keyword |
| bloodhound_enterprise.principal_hash | Internal principal graph hash. | keyword |
| bloodhound_enterprise.references | References published with this finding type. | match_only_text |
| bloodhound_enterprise.remediation | Summary of remediation steps recommended by BloodHound Enterprise. | match_only_text |
| bloodhound_enterprise.short_description | Short description of this finding type. | match_only_text |
| bloodhound_enterprise.short_remediation | Short remediation text for this finding type. | match_only_text |
| bloodhound_enterprise.target.kind | BloodHound principal kind for the destination principal (User, Group, Computer). | keyword |
| bloodhound_enterprise.title | BloodHound finding title from the finding-type description. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.full.text | Multi-field of `host.os.full`. | match_only_text |
| input.type | Type of filebeat input. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.reference | Reference URL to additional information about the rule used to generate this event. The URL can point to the vendor's documentation about the rule. If that's not available, it can also be a link to a more general page describing this type of alert. | keyword |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

