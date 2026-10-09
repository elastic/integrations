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

{{fields "case_sync"}}

#### finding

This is the `finding` dataset. Optional raw BloodHound attack-path finding documents.

{{fields "finding"}}
