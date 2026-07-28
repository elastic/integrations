# XM Cyber Integration

## Overview

[XM Cyber](https://www.xmcyber.com) is a **Continuous Threat Exposure Management (CTEM)** and attack path management platform. It continuously simulates attacker movement across hybrid environments including on-premises, cloud, and identity infrastructure — combining vulnerabilities, misconfigurations, and overly permissive access into prioritized attack paths that lead to **critical assets**.

This integration collects data from the XM Cyber REST API using scheduled polling. It provides visibility into your organization's security posture across your environment.

### Compatibility

The XM Cyber integration is compatible with the API version **v2**.

### How it works

The integration uses the Elastic Agent CEL (Common Expression Language) input to poll the XM Cyber REST API on a configurable schedule. Each poll:

1. Authenticates with a two-step flow: exchanges the API key for a short-lived Bearer access token via `POST /api/auth`
2. Fetches data from the configured endpoint.
3. Emits each record as an individual event for ingestion and enrichment via the built-in ingest pipeline

## What data does this integration collect?

The XM Cyber integration collects the following types of data:

| Data stream | Description | Endpoint |
|---|---|---|
| `audit_trail` | Audit Records | `/api/audit-trail/auditRecords` |
| `vulnerability` | CVE records from XM Cyber's Vulnerability Risk Management (VRM) feed, including CVSS v2/v3/v4 scores, EPSS metrics, CISA KEV / in-the-wild exploitation flags, and per-CVE counts of devices, products, and critical assets at risk | `/api/v2/vrm/public/vulnerabilities` |
| `entity_inventory` | Inventory of entities (devices, identities, and cloud resources) tracked by XM Cyber, enriched with OS, network, agent, and cloud-account metadata. | `/api/entityInventory/entities` |
| `risk_score` | Organization-level security grade (A–F), numeric risk score, trend data, and per-scenario breakdowns | `/api/scenarios/v2/scenarios/riskScore` |
| `device` | Device inventory from XM Cyber VRM: identity (device id, name, type), network and directory context (IP, subnet, FQDN, domain, OU, OS), choke-point and critical-asset flags, aggregate vulnerability counts and max CVSS scores, XM Cyber risk score, per-device installed applications with active CVEs and remediation hints | `/api/v2/vrm/public/devices` |
| `product` | **Product-level** aggregates from VRM: one event per software product with fleet-wide counts (devices where it appears, choke-point presence, affected critical assets, products critical assets at risk, vulnerability count), vendor, and reported operating systems. | `/api/v2/vrm/public/products` |

### Supported use cases

- **Audit and compliance monitoring**: Track administrative and user activity within your XM Cyber tenant — including console logins, sensor scan results, and configuration changes — and correlate it with the rest of your security telemetry to support compliance reviews and incident investigations.
- **Risk-based vulnerability prioritization**: Rank CVEs by CVSS impact, EPSS exploit probability, and CISA KEV / in-the-wild exploitation flags to focus remediation effort where it actually reduces business risk.
- **Attack-path-aware exposure analysis**: Correlate detected CVEs with XM Cyber's attack-technique simulations to identify which vulnerabilities act as choke points or stepping stones to crown-jewel assets.
- **Asset and exposure visibility**: Maintain a unified inventory of the devices, identities, and cloud resources XM Cyber discovers across hybrid environments — with OS, network, agent, and cloud-account context — to support asset management, attack-surface monitoring, and prioritization of critical assets.
- **Security posture tracking**: Monitor your organization's XM Cyber risk score over time and correlate score changes with security events.
- **Hybrid device inventory**: Track which assets XM Cyber has discovered, how they are classified, and how they are labeled across on-premises and cloud footprints.
- **Exposure-aware asset triage**: Use choke-point and critical-asset signals together with per-device vulnerability counts and max CVSS to prioritize which hosts warrant review first.
- **Application-level context**: Inspect installed products under each device, including active CVEs, closed CVEs, and suggested safe versions where the API provides them.
- **Software exposure across the fleet**: Rank products by `product_vulnerabilities`, `devices_found_on`, and `choke_points_found_on`, and slice by `product_operating_systems` to align remediation with platform mix.
- **Critical-asset risk from products**: Use `affected_critical_assets` and `products_critical_assets_at_risk` with vendor and OS context to prioritize patch and upgrade work.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From XM Cyber

- **XM Cyber tenant**: An active XM Cyber deployment with access to `https://<your-org>.clients.xmcyber.com`
- **API key**: An XM Cyber API key associated with a user holding at minimum the **Security Analyst** role. Create one in **Settings → API / Integrations** in your XM Cyber admin console (refer to the XM Cyber customer portal at https://customers.xmcyber.com for current navigation steps)
- **Elastic Agent**: Version 8.18+ or 9.0+ with Fleet enrollment

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Configure

1. In Kibana, navigate to **Fleet → Integrations** and search for **XM Cyber**
2. Click **Add XM Cyber**
3. Configure the integration settings:
   - **URL**: Your XM Cyber base URL, for example `https://your-org.clients.xmcyber.com`
   - **API Key**: Your XM Cyber API key.
   - **Interval**: How often to poll for new data (default: `24h`).
   - **Initial interval**: How far back to fetch risk score data, in days (e.g. `30`, `90`, `200`). Default: `30`.
4. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **XM Cyber**, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **XM Cyber**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for each data stream, to provide a view of the most recent, active XM Cyber data. Use the relevant destination alias from the table below to access the latest data, whether for use in dashboards, rules, or elsewhere.
Destinations indices are aliased to `logs-xm_cyber_latest.<data_stream_name>`.

| Source Data stream                 | Destination Index Pattern                        | Destination Alias                       |
|:-----------------------------------|:-------------------------------------------------|-----------------------------------------|
| `logs-xm_cyber.vulnerability-*`           | `logs-xm_cyber_latest.dest_vulnerability-*`             | `logs-xm_cyber_latest.vulnerability`           |

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Troubleshooting

- **Authentication failures**: Verify the API key is valid and the URL includes the full `https://` prefix with no trailing slash
- **No data collected**: Check the Elastic Agent logs for CEL program errors. Ensure your XM Cyber user has the Security Analyst role and API access is enabled in your tenant settings
- **Rate limiting**: XM Cyber API rate limits are not publicly documented. If you observe HTTP 429 responses in agent logs, increase the collection interval

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Reference

### Audit Trail

#### Audit Trail fields

{{fields "audit_trail"}}

### Example event

#### Audit Trail

{{event "audit_trail"}}

### Vulnerability

#### Vulnerability fields

{{fields "vulnerability"}}

### Example event

#### Vulnerability

{{event "vulnerability"}}

### Entity Inventory

#### Entity Inventory fields

{{fields "entity_inventory"}}

### Example event

#### Entity Inventory

{{event "entity_inventory"}}

### Risk Score

#### Risk Score fields

{{fields "risk_score"}}

### Example event

#### Risk Score

{{event "risk_score"}}

### Device

#### Device fields

{{fields "device"}}

### Example event

#### Device

{{event "device"}}

### Product

#### Product fields

{{fields "product"}}

### Example event

#### Product

{{event "product"}}

### Inputs used

{{ inputDocs }}

### API usage

These XM Cyber REST API endpoints are used by this integration:

| Endpoint | Method | Data stream | Description |
|---|---|---|---|
| `/api/auth` | POST | all | Exchange API key for Bearer access token |
| `/api/refresh-token` | POST | all | Refresh an expired access token |
| `/api/audit-trail/auditRecords` | GET | `audit_trail` | Audit Records |
| `/api/v2/vrm/public/vulnerabilities` | GET | `vulnerabilities` | Paginated exposure rows (attack techniques / CVE context) |
| `/api/entityInventory/entities` | GET | `entity_inventory` | List entities (devices, identities, cloud resources) tracked by XM Cyber |
| `/api/scenarios/v2/scenarios/riskScore` | GET | `risk_score` | Organization risk score and grade |
| `/api/v2/vrm/public/devices` | GET | `device` | Paginated device inventory with vulnerability aggregates and per-application CVE context |
| `/api/v2/vrm/public/products` | GET | `product` | Paginated product-level exposure aggregates (counts and OS list per product) |

### ILM Policy

To facilitate vulnerability data stream-backed indices `.ds-logs-xm_cyber.vulnerability-*` is allowed to contain duplicates from each polling interval. ILM policies `logs-xm_cyber.vulnerability-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
