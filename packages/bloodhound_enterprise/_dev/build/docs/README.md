# SpecterOps BloodHound Enterprise

## Overview

[SpecterOps BloodHound Enterprise](https://bloodhoundenterprise.io/) identifies Active Directory and Azure AD attack paths. This integration (**package version 1.0.0**) collects those attack-path findings into Elastic with delta sync on the **finding** data stream and reconciliation metadata on **finding_sync**.

The agent stores findings and sync metadata. It does not open Security cases and it does not write alerts. The detection rule **BloodHound Enterprise Attack Path Finding** creates one alert per **newly opened** finding (`bloodhound_enterprise.change_type: opened`). The **bloodhound_enterprise finding case** workflow (`workflow/bloodhound_enterprise-finding-case.yml`), attached to that rule, groups those alerts into one Security case per environment, zone, and finding type and reopens a previously closed case when alerts return for the same group. The **bloodhound_enterprise finding refresh** workflow (`workflow/bloodhound_enterprise-finding-refresh.yml`) reads **`finding_sync`** for `finding_removed` events to detach and delete stale alerts (and close empty cases), and reads **`finding`** documents with **`change_type: updated`** to patch open alert fields.

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
4. Pages open finding instances from `GET /api/v2/domains/{domain_id}/details` (`finding`, `skip`, `limit`, `Accepted=eq:false`, zone, `sort_by` `updated_at` and `id`). **Between full open-id reconciles** (at most once every **`full_removal_period`**, currently **18 minutes**, hardcoded in CEL—not a Fleet setting), requests include `updated_at=gte:<watermark>` so BloodHound returns only new or changed rows. **On a full reconcile poll**, pagination omits that filter so every open instance id is enumerated. **Client-side delta** (`sync_by_type`) decides what to publish on `finding` (`opened` / `updated` only).
5. Publishes to `logs-bloodhound_enterprise.finding-*` **only** when an instance is new (`bloodhound_enterprise.change_type: opened`) or its BloodHound timestamp changed since last sync (`change_type: updated`). The **first** poll indexes every open instance as `opened`; later polls index only new or changed rows.
6. While reconciling each environment, zone, and finding type, writes **`finding_sync`** documents: a **checkpoint** when pagination for that type completes (`reconcile_mode` `full` or `incremental`, open ids, counts, `max_updated_at`, `poll_completed_at`, and `full_reconcile_at` on full passes) and **`finding_removed`** when an instance id was tracked as open but is missing from BloodHound on a **full** reconcile (incremental polls do not emit per-instance removals).
7. At the end of each poll, compares agent sync state to the finding types returned from `available-types`. When an entire finding type is gone from BloodHound for an environment and zone, emits bulk **`finding_removed`** sync events for every instance id still held for that type and a **checkpoint** with zero open ids to `logs-bloodhound_enterprise.finding_sync-*`.
8. When a configured environment and zone has no open finding types or no open instances in a poll, publishes a **collection_status** document to the finding index with `bloodhound_enterprise.environment`, `bloodhound_enterprise.zone`, `source.domain`, `bloodhound_enterprise.category`, and `bloodhound_enterprise.collection_message` naming where no data was returned (no `event.id`, so the detection rule does not alert on it).

If BloodHound rejects the token, a request fails, or a filter names a domain or zone that does not exist in your tenant, that outcome is published to `logs-bloodhound_enterprise.finding-*` with **`event.type: error`**. Those documents are not findings, and the detection rule does not alert on them.

Optional filters (`selected_environment`, `bhe_zones`) limit which domains and zones are collected. Empty, `All`, or `*` mean collect all available domains or zones. Matching is case-insensitive. An unrecognized name is **skipped**, logged to the finding data stream with `event.type: error`, and does **not** expand collection to all domains or zones. If you list both valid and invalid names, collection continues for the valid ones only.

**Polling Interval** (Fleet) is how often the agent **starts** a reconcile (default `24h`; options include `5m` through `24h`). It is independent of **`full_removal_period`**, which controls how often a **full** open-id census runs (default in package CEL: **18m**).

**First run** indexes all open findings as `opened` and performs a **full** open-id reconcile (baseline checkpoints). **Later runs** index only **new or changed** findings (`opened` or `updated`) on incremental polls; **at most once per `full_removal_period`** the collector runs a **full** reconcile and can emit **`finding_removed`** for resolved or accepted instances. Between full passes, incremental polls use `updated_at=gte` only and do **not** emit per-instance removals.

Checkpoints land on `finding_sync` for workflows and ops. The agent keeps `global_last_full_reconcile_at` in CEL state (mirrored from full checkpoint times); it **does not read Elasticsearch** for watermarks. **Alert cleanup requires `finding_removed` on `finding_sync`**, not absence of rows on `finding`. The detection rule creates alerts only for `opened` findings; enable the refresh workflow so it removes alerts when `finding_removed` sync events arrive (keep workflow **`sync_lookback` ≥ 36h** so removals are not missed).

### Bundled Kibana assets

| Asset | Purpose |
|-------|---------|
| **BloodHound Enterprise Attack Path Finding** (detection rule) | One alert per **`change_type: opened`** finding |
| **Attack Path Overview** (dashboard) | Visualize ingested findings |
| **Finding sync** (data view) | Discover queries on `logs-bloodhound_enterprise.finding_sync-*` |
| **Logs BloodHound Enterprise** (data views) | Findings and error documents on the finding stream |

## What data does this integration collect?

This integration collects the following data:

- **finding**: Attack-path finding documents for **new or changed** instances (`bloodhound_enterprise.change_type` `opened` or `updated`). The packaged detection rule reads this stream and alerts only on **`opened`**.
- **finding_sync**: Sync checkpoints and **`finding_removed`** events (per instance or when a whole finding type drops off `available-types`). Used by the refresh workflow and for operational visibility; not used by the detection rule.
- Collector failures on **`finding`** use **`event.type: error`** (filter `event.type:error` in Discover on `logs-bloodhound_enterprise.finding-*`).

### Supported use cases

- Collect BloodHound Enterprise attack-path findings into Elasticsearch
- Create Security alerts with the packaged detection rule
- Group those alerts into Security cases with the bloodhound_enterprise finding case workflow
- Reconcile alert lifecycle with the bloodhound_enterprise finding refresh workflow (`finding_sync` removals and `updated` finding patches)
- Filter collection by environment/domain and BloodHound zone
- Inspect authentication and request failures with `event.type: error` on the finding data stream
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
| Polling Interval | Yes | How often the agent reconciles BloodHound findings. Choose 5m, 1h, 2h, 6h, 12h, or 24h. Default `24h`. Only new/changed instances are indexed to the finding data stream. Full open-id reconciliation cadence is fixed in CEL (`full_removal_period`, currently 18m), not this setting. |
| Selected environment | No | Comma-separated domain names, or empty/`All`/`*` for all. Case-insensitive. Unknown names are skipped and logged to the finding data stream with `event.type: error` |
| BloodHound Enterprise zones | No | Comma-separated zone names, or empty/`All`/`*` for all. Case-insensitive. Unknown names are skipped and logged to the finding data stream with `event.type: error` |

5. Select **Save and continue**.
6. Install and enable the **BloodHound Enterprise Attack Path Finding** detection rule.
7. Import **`workflow/bloodhound_enterprise-finding-case.yml`**, save it, and add it on that rule's **Actions** tab so alerts group into one case per environment, zone, and finding type.
8. Optionally import **`workflow/bloodhound_enterprise-finding-refresh.yml`**, leave it disabled until step 7 is working, then enable it (default schedule **24h**; you can run it more often than the poll). It removes open alerts when **`finding_removed`** sync events appear in **`finding_sync`**, closes cases that have no alerts left, and updates open alert fields when **`change_type: updated`** finding documents are ingested. Configure **`sync_lookback`** (default **36h**) so removals are not missed. When alerts return, the case workflow reuses a closed case and sets it back to **open**.

### Validation

After the first poll completes:

1. **Fleet → Agents** — confirm the agent is healthy.
2. **Discover** — open `logs-bloodhound_enterprise.finding-*` and confirm finding documents with `bloodhound_enterprise.change_type` `opened` or `updated`. `event.id` is the finding instance.
3. **Discover** — open `logs-bloodhound_enterprise.finding_sync-*` and confirm **checkpoint** documents (`reconcile_mode` `full` or `incremental`) after each finding type finishes reconciling. After a **full** poll, look for **`finding_removed`** when instances disappear or are accepted in BloodHound. The first poll is always **full** and may have many **`opened`** findings but few removals until findings are resolved later.
4. **Discover** — filter `logs-bloodhound_enterprise.finding-*` with `event.type: error` when checking collector failures.
5. **Security → Alerts** — confirm one alert per **`opened`** finding only (not for `updated` or sync events). Error documents must not appear as alerts.
6. **Security → Cases** — after the case workflow runs, confirm one case per environment, zone, and finding type. The first case title is the group name with no number. When that case holds 1000 alerts, the next alert opens `[2]`, then `[3]`, and the workflow keeps using the highest iteration.
7. **Security → Cases** (optional refresh workflow) — after **`finding_removed`** sync events, confirm the open alert is detached from the case and deleted when the refresh workflow runs.

| Scenario | Expected behavior |
|----------|-------------------|
| New finding appears in BloodHound Enterprise | A finding document with `change_type: opened` on the next poll, one alert for that `event.id`, then the case workflow attaches that alert to the matching case |
| Same finding unchanged on the next poll | No new finding document (delta sync). No new alert; rule suppression applies to that `event.id` |
| Finding changes in BloodHound (`updated_at`) | A finding document with `change_type: updated`; no new alert; refresh workflow can patch the open alert when enabled |
| Finding accepted or otherwise absent from BloodHound | A `finding_removed` event on `finding_sync` on the next **full** reconcile poll (within **`full_removal_period`** of the last full pass, **18m** in the shipped CEL); with the refresh workflow enabled, the open alert is detached from cases and deleted |
| Entire finding type removed from `available-types` | Bulk `finding_removed` events and a zero-open checkpoint on `finding_sync` at poll end |
| BloodHound authentication or request failure | One document in `logs-bloodhound_enterprise.finding-*` with `event.type: error`, and no alert |
| Invalid `selected_environment` or `bhe_zones` name | Error-typed finding document(s) for each unknown name; that name is not collected. If every configured name is invalid, no finding documents that poll |

## Troubleshooting

| Symptom | What to check |
|---------|----------------|
| Auth failures against BloodHound | Token ID/Key, Base URL (no trailing slash), agent egress allowlist, clock skew for HMAC signatures. The failure document is in **[Logs BloodHound Enterprise] Error**, not in the finding data view |
| No finding documents | Polling Interval has not elapsed yet, filters match nothing (including when every configured domain or zone name is invalid), or auth/API errors stopped the poll |
| Alerts missing | The detection rule is installed and enabled. It requires `bloodhound_enterprise.change_type: opened`. Only the first sighting of an instance creates an alert |
| No `finding_sync` documents | Poll still running (checkpoints appear when each type finishes), or an older package without delta sync—reinstall **1.0.0** and wait for a full poll |
| An error document became an alert | The installed rule is older than this package. Reinstall and confirm the rule requires `event.type:info` and `change_type:opened` |
| Cases not created | The case workflow is saved and attached to the detection rule. The agent does not open cases |
| Case alert count stays high after findings are accepted in BloodHound | Enable the finding refresh workflow; confirm `bloodhound_enterprise.sync_kind:finding_removed` on `finding_sync` after a **full** reconcile (`reconcile_mode:full` checkpoints). Incremental polls alone will not remove alerts. Check workflow `sync_lookback` (default 36h) covers your poll interval plus **`full_removal_period`** (18m) |
| When was the last full reconcile? | Discover on `finding_sync`: `sync_kind:checkpoint` and `reconcile_mode:full`, sort by `bloodhound_enterprise.full_reconcile_at` descending. ES|QL: `STATS latest_full = MAX(bloodhound_enterprise.full_reconcile_at)` on that filter |
| Typo or unknown domain/zone in filters | Check names in BloodHound Enterprise; matching is case-insensitive. Unknown values appear in **[Logs BloodHound Enterprise] Error** and are skipped—they do not fetch all |
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

Configure Base URL, Token ID, Token Key, and Polling Interval. Optional **Selected environment** and **BloodHound Enterprise zones** limit scope. Authentication to BloodHound Enterprise uses HMAC request signatures (`bhesignature`). Sync watermarks and open-id lists are held in agent state (`sync_by_type`, `global_last_full_reconcile_at`); optional SSL YAML configures HTTPS to BloodHound.

</details>

### API usage

This integration uses:

- BloodHound Enterprise REST API (`/api/v2/available-domains`, `/api/v2/domains/{id}/available-types`, `/api/v2/findings/{finding_type}`, `/api/v2/domains/{id}/details`)

### Logs reference

#### finding_sync

This is the `finding_sync` dataset. Documents are **sync checkpoints** and **`finding_removed`** events produced by the agent during delta reconcile. In Discover, use `logs-bloodhound_enterprise.finding_sync-*`. The detection rule does not read this stream; the **finding refresh** workflow uses **`finding_removed`** events here to remove stale alerts.

| Field | Description |
|---|---|
| `bloodhound_enterprise.sync_kind` | `checkpoint` or `finding_removed` |
| `bloodhound_enterprise.reconcile_mode` | `full` or `incremental` (checkpoints only) |
| `bloodhound_enterprise.full_reconcile_at` | When a full open-id census completed (checkpoints with `reconcile_mode: full`) |
| `bloodhound_enterprise.type_key` | Stable key `domain\|zone\|finding_type` |
| `bloodhound_enterprise.finding_type` | BloodHound finding type name |
| `bloodhound_enterprise.category` | Zone (asset group tag) name |
| `bloodhound_enterprise.domain_name` | Environment (domain) name |
| `bloodhound_enterprise.max_updated_at` | Latest BloodHound `updated_at` seen for the type (checkpoints) |
| `bloodhound_enterprise.open_finding_ids` | Open instance ids after the poll (checkpoints) |
| `bloodhound_enterprise.open_finding_count` | Count of open ids (checkpoints) |
| `bloodhound_enterprise.poll_completed_at` | When reconciliation finished for the type |
| `event.id` | BloodHound instance id (`finding_removed` only) |

On **incremental** checkpoints, `open_finding_ids` reflects the last **full** census (not ids seen only on that incremental page).

#### Discover examples (`finding_sync`)

Last full reconcile time (approximate; per type may differ slightly within one poll):

```text
event.dataset: "bloodhound_enterprise.finding_sync"
  AND bloodhound_enterprise.sync_kind: "checkpoint"
  AND bloodhound_enterprise.reconcile_mode: "full"
```

Sort by **`bloodhound_enterprise.full_reconcile_at`** descending.

See **Exported fields** in the package for the full mapping.

#### finding

This is the `finding` dataset. Documents represent **new or changed** BloodHound attack-path finding instances (`bloodhound_enterprise.change_type` `opened` or `updated`), **collection_status** operational rows when a scope had no open types or instances, or **error** documents when collection failed. The detection rule targets normal findings with `change_type: opened` only.

| Field | Description |
|---|---|
| `bloodhound_enterprise.change_type` | `opened` (new instance), `updated` (timestamp changed), or absent on `collection_status` / `error` |
| `bloodhound_enterprise.finding_type` | BloodHound finding type name; `collection_status` uses this literal for status rows |
| `bloodhound_enterprise.finding_layout` | `relationship`, `single_principal`, or `unknown` (instance shape from BloodHound JSON) |
| `bloodhound_enterprise.environment` / `bloodhound_enterprise.zone` | BloodHound environment and zone on findings and collection status |
| `event.type` | `info` for findings; `error` for collector/filter failures |
| `event.url` | BloodHound graph / investigation link when present |

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

