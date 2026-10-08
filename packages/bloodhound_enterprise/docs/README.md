# SpecterOps BloodHound Enterprise

## Overview

[SpecterOps BloodHound Enterprise](https://bloodhoundenterprise.io/) identifies Active Directory and Azure AD attack paths. This integration synchronizes those attack-path findings into Elastic Security for investigation and remediation tracking.

On a schedule it polls the BloodHound Enterprise API, creates and updates Kibana Security Cases for open findings, attaches Security Alerts for at-risk principals, and removes stale cases when matching findings no longer exist.

### Compatibility

This integration requires:

- Kibana `^8.19.0 || ^9.1.0`
- Elastic Agent or an Elastic Managed deployment with the CEL input enabled
- Elastic Security with Cases enabled
- Network connectivity from the agent to BloodHound Enterprise, Kibana, and Elasticsearch

### How it works

On each interval, the Case & Alert Sync CEL program:

1. Discovers BloodHound Enterprise domains and asset-group tags (zones).
2. Lists existing Kibana Cases tagged for BloodHound Enterprise.
3. Compares available finding types against those cases.
4. Fetches remediation and severity details for findings that need sync.
5. Creates or updates Cases and attaches Security Alerts for affected principals.
6. Deletes Cases for findings that are no longer present in BloodHound Enterprise.

Optional filters (`selected_environment`, `bhe_zones`) limit which domains and zones are synced. Empty, `All`, or `*` values mean fetch-all. Unrecognized values are treated as fetch-all so misconfiguration does not block collection.

## What data does this integration collect?

This integration collects the following data:

- **case_sync**: Case & Alert Sync metadata events (domain discovery, case create/update/delete, alert attach) for troubleshooting. This is the primary stream.
- **finding**: Optional raw attack-path finding documents. Disabled by default. The Attack Path dashboard uses Security Alerts created by Case & Alert Sync, so this stream can stay off to avoid BloodHound API contention.

### Supported use cases

- Track BloodHound Enterprise attack-path findings as Elastic Security Cases
- Attach per-principal Security Alerts for investigation and remediation
- Filter sync by environment/domain and BloodHound zone
- Troubleshoot sync progress via `case_sync` data-stream events
- Visualize attack-path alerts with the bundled Attack Path Overview dashboard

## What do I need to use this integration?

### From Elastic

- An Elastic deployment with Fleet and Elastic Security (Cases) enabled
- Kibana `^8.19.0 || ^9.1.0`
- Elastic Agent or Elastic Managed support for the CEL input

### From BloodHound Enterprise

- A BloodHound Enterprise tenant URL (for example `https://yourtenant.bloodhoundenterprise.io`)
- BloodHound Enterprise API **Token ID** and **Token Key** (Administration → API Keys in BloodHound Enterprise)
- Network path from the Elastic Agent (or Elastic Managed runner) to the BloodHound Enterprise HTTPS endpoint

### From Kibana / Elasticsearch

- A Kibana URL reachable from the Elastic Agent
- A Kibana API key that can manage Cases and index Security alerts (see below)
- An Elasticsearch URL reachable from the agent (used when indexing Security Alerts)

## How do I deploy this integration?

This integration supports both Elastic Agent-based and Elastic Managed installations.

### Elastic Managed installation

Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Elastic Managed integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Assign this integration to an agent policy whose agents can reach BloodHound Enterprise, Kibana, and Elasticsearch. Do **not** attach it only to Fleet Server unless that host also has the required network access.

## Setup

### Create a Kibana API key

The same API key is sent to the Kibana Cases API and to Elasticsearch `_bulk` for `.alerts-security.alerts-<space>`. A key with only Cases privileges cannot index alerts.

1. In Kibana go to **Stack Management → API keys → Create API key**.
2. Name it (for example `bloodhound-integration`).
3. Choose **Restrict privileges** and use a role descriptor that covers Cases, Security Solution access for attaching alerts, and the alerts index. Replace `default` with the Kibana space this policy writes to:

```json
{
  "bloodhound_sync": {
    "cluster": [],
    "indices": [
      {
        "names": [".alerts-security.alerts-*"],
        "privileges": ["read", "write", "view_index_metadata"]
      }
    ],
    "applications": [
      {
        "application": "kibana-.kibana",
        "privileges": [
          "feature_securitySolutionCasesV3.all",
          "feature_siemV3.read"
        ],
        "resources": ["space:default"]
      }
    ]
  }
}
```

`feature_securitySolutionCasesV3.all` lets the program create, read, update, and delete cases and attach alerts. `feature_siemV3.read` grants the Security Solution access that attachment requires. On stacks where those feature ids are not listed, use the Cases **All** and Security **Read** feature privileges for the same space.

4. Copy the encoded key value. You will not see it again.

### Obtain BloodHound Enterprise credentials

1. Sign in to your BloodHound Enterprise tenant.
2. Open **Administration → API Keys**.
3. Create or select an API key and copy the **Token ID** and **Token Key**.

### Enable the integration in Elastic

1. In Kibana go to **Management → Integrations**.
2. Search for **SpecterOps BloodHound Enterprise**.
3. Select **Add SpecterOps BloodHound Enterprise** (or **Add BloodHound**) and choose an agent policy.
4. Configure the required settings:

| Setting | Required | Description |
|---------|----------|-------------|
| Base URL | Yes | BloodHound Enterprise tenant URL without a trailing slash |
| Token ID | Yes | BloodHound Enterprise API token ID |
| Token Key | Yes | BloodHound Enterprise API token secret |
| Kibana URL | Yes | URL the agent uses to reach Kibana |
| Kibana space | Yes | Space for Cases and Alerts (default `default`). The packaged dashboard reads `.alerts-security.alerts-default` |
| Kibana API Key | Yes | Encoded API key used for both the Kibana Cases API and the Elasticsearch alerts index |
| Elasticsearch URL | Yes | URL the agent uses to reach Elasticsearch for alert indexing |
| Interval | Yes | Delay between full Case & Alert Sync cycles (default `1h`, set on that stream) |
| Selected environment | No | Comma-separated domain names, or empty/`All`/`*` for all |
| BloodHound Enterprise zones | No | Comma-separated zone names, or empty/`All`/`*` for all |

5. Leave **Case & Alert Sync** (`case_sync`) enabled.
6. Keep **Attack Path Findings** (`finding`) disabled unless you explicitly need raw finding documents.
7. Select **Save and continue**.

**Local elastic-package stack tip:** when the agent runs inside the elastic-package Docker network, use internal hostnames such as `https://elastic-package-stack-kibana-1:5601` and `https://elasticsearch:9200`. For agents on external hosts, use publicly reachable URLs. Do not leave those hostnames in a production policy; Kibana URL and Elasticsearch URL have no default.

### Kibana space

Case & Alert Sync writes Kibana Cases and Security Alerts into the configured Kibana space (`default` unless you change **Kibana space**). Non-default spaces use the `/s/<space>` Cases API prefix and the `.alerts-security.alerts-<space>` alert index. The packaged Attack Path Overview dashboard and data view are built for the default space. If you select another space, point a data view at `.alerts-security.alerts-<space>` or the dashboard stays empty.

### Validation

After the first sync interval completes:

1. **Fleet → Agents** — confirm the agent (or Elastic Managed deployment) is healthy and the integration reports no CEL/auth errors.
2. **Security → Cases** — confirm cases tagged with `BloodHound Enterprise` plus the tenant slug derived from Base URL.
3. Open a case and confirm related Security Alerts for at-risk principals are attached.
4. Optional: in Discover, inspect `logs-bloodhound_enterprise.case_sync-*` for sync-step events (`bloodhound_enterprise.case_sync.step`, `bloodhound_enterprise.case_sync.info`, `bloodhound_enterprise.case_sync.error`).
5. Optional: open the **BloodHound Enterprise Attack Path Overview** dashboard and confirm alert visualizations populate.

| Scenario | Expected behavior |
|----------|-------------------|
| New finding appears in BloodHound Enterprise | New case created on the next interval |
| Finding unchanged | No duplicate cases (title-based deduplication) |
| Finding removed from BloodHound Enterprise | Stale case deleted on the next sync |
| All findings already in sync | Sync emits an informational "nothing to do" style health event |

## Troubleshooting

| Symptom | What to check |
|---------|----------------|
| Auth failures against BloodHound | Token ID/Key, Base URL (no trailing slash), agent egress allowlist, clock skew for HMAC signatures |
| Cases not created | Kibana URL from the agent network, API key Cases privileges, Case & Alert Sync enabled |
| Alerts missing | Elasticsearch URL reachability, alert index privileges, attach/bulk errors in `case_sync` events |
| Unexpected domains/zones | `selected_environment` / `bhe_zones` filters; unrecognized values fetch all |
| Integration not listed | Package not uploaded or registry not refreshed; rebuild/upload or wait for EPR propagation |

For general Elastic ingest issues, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

Enable **Enable request tracer** only temporarily for CEL HTTP debugging; it can log sensitive request metadata.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

Large BloodHound environments may require longer intervals. Prefer filtering by environment or zone rather than lowering page sizes unless Elastic Support advises otherwise.

## Reference

### Inputs used

These inputs can be used with this integration:

<details>
<summary>cel</summary>

## Setup

For more details about the CEL input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html).

Before configuring the CEL input, make sure you have:

- Network connectivity to BloodHound Enterprise, Kibana, and Elasticsearch
- Valid BloodHound token ID/key and Kibana API key
- Cases feature enabled in Elastic Security

### Collecting logs from CEL

Configure Base URL, credentials, Kibana URL, Elasticsearch URL, and Interval. Authentication to BloodHound Enterprise uses HMAC request signatures (`bhesignature`). Kibana calls use the configured API key.

</details>

### API usage

This integration uses:

- BloodHound Enterprise REST API (`/api/v2/available-domains`, domain finding types, finding metadata, domain details)
- Kibana Cases API (find, create/update, comments, delete)
- Elasticsearch bulk API for Security alert documents

### Logs reference

#### case_sync

This is the `case_sync` dataset. Events describe Case & Alert Sync steps for troubleshooting (discovery, case lifecycle, alert attachment).

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| bloodhound_enterprise.case_sync.attached_count | Number of alerts attached to the case in this step. | long |
| bloodhound_enterprise.case_sync.case_id | Kibana case ID created or resolved during this step. | keyword |
| bloodhound_enterprise.case_sync.case_key | Case title key used to match a BloodHound finding. | keyword |
| bloodhound_enterprise.case_sync.case_part | Overflow case part number when a case reaches the alert limit. | long |
| bloodhound_enterprise.case_sync.case_total_alerts | Total alerts on the Kibana case after attachment. | long |
| bloodhound_enterprise.case_sync.deleted_case_id | Kibana case ID deleted as stale. | keyword |
| bloodhound_enterprise.case_sync.domain | BloodHound domain name associated with this step. | keyword |
| bloodhound_enterprise.case_sync.error | Error message from a failed sync step. | keyword |
| bloodhound_enterprise.case_sync.finding_count | Number of findings queued for case and alert sync. | long |
| bloodhound_enterprise.case_sync.info | Informational status message for the current sync step. | keyword |
| bloodhound_enterprise.case_sync.instance_index | Index of the next finding instance to attach. | long |
| bloodhound_enterprise.case_sync.instances | Number of finding instances considered for alert attachment. | long |
| bloodhound_enterprise.case_sync.next_case_part | Overflow case part that will be opened next. | long |
| bloodhound_enterprise.case_sync.pending | Number of alerts indexed and waiting to be attached. | long |
| bloodhound_enterprise.case_sync.stale_count | Number of stale cases queued for deletion. | long |
| bloodhound_enterprise.case_sync.step | Numeric sync workflow step that produced this event. | long |
| bloodhound_enterprise.case_sync.story | Human-readable narrative describing the current sync step. | match_only_text |
| bloodhound_enterprise.case_sync.uri | Request path for the sync step. | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| error.message | Error message. | match_only_text |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text of the original event, copied from `message` before parsing. | keyword |
| event.outcome | Whether the sync step succeeded or failed. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


#### finding

This is the `finding` dataset. Optional raw BloodHound attack-path finding documents.

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
| bloodhound_enterprise.principal.kind | BloodHound principal kind for the source principal (User, Group, Computer). | keyword |
| bloodhound_enterprise.principal_hash | Internal principal graph hash. | keyword |
| bloodhound_enterprise.remediation | Summary of remediation steps recommended by BloodHound Enterprise. | match_only_text |
| bloodhound_enterprise.target.kind | BloodHound principal kind for the destination principal (User, Group, Computer). | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text of the original event, copied from `message` before parsing. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.reference | Reference URL to additional information about the rule used to generate this event. The URL can point to the vendor's documentation about the rule. If that's not available, it can also be a link to a more general page describing this type of alert. | keyword |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

