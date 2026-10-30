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

{{fields "error"}}

#### finding

This is the `finding` dataset. One document per BloodHound attack-path finding instance.

{{fields "finding"}}
