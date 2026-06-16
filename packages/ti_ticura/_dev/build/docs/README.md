# Ticura Threat Intelligence Integration

## Overview

The [Ticura](https://www.ticura.io) platform delivers the industry's only real-time view of global cyber threat intelligence that is objective, auditable, and continuously optimized to protect each subscriber's unique environment — at a fraction of the cost of legacy approaches.

Ticura's threat intelligence feeds are aggregated from hundreds of different public, private, and community sources, enriched using AI, and tailored to your specific needs. The IoC Scoring Algorithm applies a qualitative classification that changes dynamically over time.

This intelligence can be queried through a threat intelligence feed and delivered directly to Firewall, SOAR, SIEM, EDR, and other security platforms — for example, Elastic Security.

---

## Requirements

To use this integration, you need:

- Access to the Ticura web application
- An active Ticura subscription with at least one configured feed
- A supported Elastic Stack version with Elastic Security enabled

This integration supports two deployment modes: **agentless** (recommended for Elastic Cloud) and **agent-based** (for on-premises or self-managed deployments).

### Agentless deployment (Elastic Cloud)

No additional installation is required. The integration runs on Elastic-managed infrastructure. Select **Agentless** when adding the integration in Kibana.

### Agent-based deployment (on-premises / self-managed)

Elastic Agent must be installed. If you have none, check the [Elastic Agent installation instructions](https://www.elastic.co/docs/reference/fleet/install-elastic-agents). You can install only one Elastic Agent per host. Elastic Agent is required to stream data from the REST API and ship events to Elastic, where they are processed via the integration's ingest pipelines.

---

## Setup

### Generate a Ticura Threat Intelligence Feed

1. Register for a Ticura account at https://app.ticura.io
2. Create a Threat Intelligence feed based on your requirements and save the provided API key.

### Configure the Integration in Elastic

1. Open Kibana and navigate to **Integrations**.
2. Search for **Ticura**.
3. Select **Add Ticura**.
4. Enter your feed name into **Advanced Options** → **Namespace** — this becomes part of the data-stream name (`logs-ti_ticura.ecs-{namespace}`), so each Ticura feed you configure ends up in its own queryable index. Use lowercase ASCII; the value also appears in the CEL request-tracer filename, the dashboard's `Namespace` control, and any saved searches.
5. Enter your API key into **Ticura API key**.
6. Select your **Download Interval** and your **Agent**, then click **Save and continue** to enable the integration.

After the integration is enabled, indicators are periodically retrieved and ingested into Elastic.

---

## Data Streams

### Threat Intelligence

Each ingested event represents a single indicator of compromise (IOC) and includes metadata such as type, confidence, and scoring information.

### Supported Indicator Types

- IPv4 addresses
- IPv6 addresses
- Ports
- Domains
- URLs
- File hashes (MD5, SHA-1, SHA-256)

### Indicator Removal and Lifecycle

The integration is designed so that indicators Ticura no longer publishes are **automatically removed** from your Elasticsearch indices — you do not need to manage this manually.

The cleanup uses three independent layers:

1. **Pipeline-set expiry flag** — when Ticura sets `ages_out` on an indicator and that timestamp passes, the ingest pipeline sets `threat.indicator.expired: true`. The bundled dashboard excludes anything where this flag is true, so source-expired indicators disappear at the next poll regardless of poll interval.
2. **ILM tier filter** — the bundled dashboard also restricts to `_tier: "data_hot"`, so the previous backing index (still queryable but now in warm tier) is hidden as soon as a new rollover happens. This catches indicators Ticura silently removed from the feed (without flipping `ages_out`).
3. **ILM deletion** — backing indices are rolled over every 24 hours and physically deleted 1 day after rollover. An indicator dropped by Ticura is therefore guaranteed to be gone from storage within approximately 48 hours.

All indicators are retrieved into data streams named `logs-ti_ticura.ecs-{namespace}` and processed via the integration's ingest pipeline. Each indicator is stored with its `ticura.uuid` as the document `_id`, so re-ingests of the same indicator overwrite in place instead of duplicating.

**Important — keep the download interval below 24 hours** so every indicator still in the feed is re-ingested before the backing index rolls over and the previous copy ages out.

If you need to retain dropped indicators for longer (for example, for forensic queries against retired IOCs), increase `delete.min_age` in the ILM policy `logs-ti_ticura.ecs-default_policy`.

---

## Dashboards

Three dashboards are bundled, all scoped to `event.module: ti_ticura`, `_tier: "data_hot"`, and `not threat.indicator.expired: true`. The default time range on each is set wide (≥ 30 days) because `@timestamp` reflects per-indicator observation time (`threat.indicator.last_seen` → `first_seen`), which can be days or weeks old for still-active IOCs. The "currently active" semantics is enforced by the scope filters, not by the time range.

### Overview

Strategic view of the current feed: counts and distributions by type, country, industry, actor, malware family, MITRE technique, and feed source.

The dashboard has nine interactive controls at the top, with **hierarchical chaining** — each control's options are filtered by selections made to its left:

| Control | Field | Use |
|---------|-------|-----|
| Indicator Type | `ticura.main_type` | IPV4 / IPV6 / DOMAIN / URL / HASH |
| Risk Category | `ticura.risk_category` | low / medium / high / critical |
| Threat Type | `additional_info.threat_types` | `Command and Control Server`, `Phishing`, `Malware`, … |
| MITRE Technique | `threat.technique.id` | Filter by ATT&CK technique (T1190, T1486, …) |
| Country | `threat.indicator.geo.country_iso_code` | Country of origin (GeoIP-derived) |
| Threat Actor | `merged.actors` | Attribution to a known actor |
| Inbound Only | `ticura.is_inbound` | Limit to indicators flagged as inbound-only |
| Namespace | `data_stream.namespace` | Per-feed isolation when multiple feeds are configured |
| Severity (range slider) | `event.severity` | Slide to a min/max severity window |

### Triage

Tactical view focused on what to act on right now:

| Panel | Source field(s) | Purpose |
|-------|-----------------|---------|
| Active indicators | count | Total count under the current scope |
| Currently online | `additional_info.online.is_online:true` count | The most actionable subset — indicators confirmed live by Ticura |
| Inbound-only threats | `ticura.is_inbound:true` count | Threats Ticura specifically flagged as ingress |
| Sinkhole indicators | `additional_info.sinkhole.owner:*` count | Routed to a known sinkhole; valuable investigative context |
| Indicator subtype distribution | `ticura.sub_type` | DOMAIN / HASHSHA256 / IPV4PORT / IPV4 / HASHSHA1 / HASHMD5 / IPV6 / EMAIL |
| Severity distribution | `event.severity` bucketed 0–99 | Where the volume sits — informs alert thresholds |
| Hash type breakdown | `ticura.sub_type` (file indicators only) | SHA-256 / SHA-1 / MD5 mix |
| Confidence × Risk category | `ticura.{risk,confidence}Category` cross-tab | Priority quadrants — high-conf + high-risk indicators feed detection rules; low-conf + high-risk indicators need triage |
| CVE-referenced indicators | `ticura.cve` count | Volume of vuln-linked IOCs |
| Top CVE references | `ticura.cve` | Which CVEs lead |
| Top 15 ASN organizations | `threat.indicator.as.organization.name` | Pattern recognition — which hosting providers keep showing up |
| Top 15 MITRE ATT&CK techniques | `threat.technique.{id, name}` | Technique-level prioritization with names |
| Inbound-only detail | top by severity, with country | Drill into the ~hundred inbound-only IOCs |
| Sinkhole-routed indicators | by sinkhole owner | Drill into which indicators are routed where |
| Online indicators by type | `additional_info.online.is_online:true` split by `threat.indicator.type` | Which IOC types are currently live |

### Trends

Strategic time-series view of how the feed is evolving:

| Panel | Source field(s) | Purpose |
|-------|-----------------|---------|
| Indicator velocity | `threat.indicator.modified_at` per day, stacked by `threat.indicator.type` | Daily update rate, broken out by IOC type |
| New indicators per day | `threat.indicator.first_seen` | Fresh-intel velocity (line chart) |
| Indicators expiring per day | `ticura.ages_out` | Forward-looking expiry wave (bar chart) |
| Top 30 countries by indicator count | `threat.indicator.geo.country_iso_code` | Geographic distribution (richer than the Overview pie) |
| Feed quality matrix | `threat.feed.name` × {count, avg risk, avg confidence, online count} | Which feeds deliver the highest-quality intel |
| Risk category trend over time | `ticura.risk_category` split, percentage-stacked area | Are we seeing more critical IOCs over time? |
| Threat type proportions over time | `additional_info.threat_types` split, percentage-stacked area | Shifting threat-type mix |
| Geo coverage (countries seen) | distinct `threat.indicator.geo.country_iso_code` | How many distinct countries the feed currently spans |
| Top 15 cities | `threat.indicator.geo.city_name` | City-level concentration of indicators |
| Continent breakdown | `threat.indicator.geo.continent_name` | Indicator distribution by continent |
| World indicator clusters (map) | `threat.indicator.geo.location` | Geographic clustering of IP indicators on a world map |

---

## Saved Searches (for SOC analysts)

The integration ships nine pre-built saved searches under **Discover**. They are filterable, exportable, and ready to be embedded into custom dashboards or used as the source for Indicator Match detection rules.

| Saved search | What it shows |
|--------------|---------------|
| `[Ticura] High-risk indicators (last 24h)` | Severity ≥ 70, modified in the last 24 hours, not expired — sorted by severity. |
| `[Ticura] Active C2 indicators` | `additional_info.threat_types` contains `Command and Control`, not expired. Ready for outbound-connection detection. |
| `[Ticura] Active phishing URLs` | `threat.indicator.type: url` AND `additional_info.threat_types` contains *"Phishing"*, not expired. |
| `[Ticura] Active malware file hashes` | `threat.indicator.type: file`, not expired. Covers SHA-256, SHA-1, MD5. |
| `[Ticura] Critical-risk indicators in EU` | Severity ≥ 80 attributed to an EU member state via GeoIP. |
| `[Ticura] Inbound-only threat indicators` | `ticura.is_inbound: true` — threats targeting your environment from outside. |
| `[Ticura] Indicators with MITRE ATT&CK enrichment` | `threat.technique.id` populated; useful for pivoting from the MITRE matrix to specific IOCs. |
| `[Ticura] Recently first-seen indicators` | Sorted by `threat.indicator.first_seen`. Fresh threat-intel monitoring. |
| `[Ticura] Indicators expiring in next 24h` | `ticura.ages_out <= now+24h` and not yet expired. Worth a quick triage glance. |

---

## ECS Field Mapping

The integration maps indicators to the Elastic Common Schema using the `threat.indicator.*` field set.

### Core Indicator Fields

| ECS Field | Description |
|----------|-------------|
| `threat.indicator.type` | Indicator type (for example, `ipv4-addr`, `url`, `file`, `domain-name`) |
| `threat.indicator.description` | Short description of the indicator |
| `threat.indicator.first_seen` | Time when the indicator was first observed |
| `threat.indicator.last_seen` | Most recent observation time |
| `threat.indicator.modified_at` | Time when the indicator was last updated by Ticura (`@timestamp` is derived from `last_seen`/`first_seen`, not from this field) |
| `threat.indicator.confidence` | Confidence level assigned to the indicator |
| `threat.indicator.provider` | Indicator provider (`Ticura`) |
| `threat.indicator.expired` | True when the indicator has passed `ticura.ages_out` |

### Indicator Values

| Indicator Type | ECS Field |
|---------------|-----------|
| IPv4 / IPv6 address | `threat.indicator.ip` |
| Port (with IP) | `threat.indicator.port` |
| Domain | `threat.indicator.url.domain` |
| URL | `threat.indicator.url.full` (plus `scheme`, `domain`, `path`, … when Ticura supplies them) |
| File hash | `threat.indicator.file.hash.{md5, sha1, sha256, ...}` |

### File Hash Mapping

| ECS Field | Hash Type |
|----------|-----------|
| `threat.indicator.file.hash.md5` | MD5 |
| `threat.indicator.file.hash.sha1` | SHA-1 |
| `threat.indicator.file.hash.sha256` | SHA-256 |

### Scoring and Classification

| ECS Field | Description |
|----------|-------------|
| `event.risk_score` | Numeric risk score (0–100), supplied directly by Ticura (equals `ticura.risk`) |
| `event.severity` | Numeric severity (0–99, ECS-clamped) — mirrored from `ticura.risk` |
| `threat.indicator.marking.tlp` | Traffic Light Protocol marking, if provided |
| `threat.indicator.reference` | Reference or source URL |
| `tags` | Tags associated with the indicator |

### Metadata Fields

| ECS Field | Value |
|----------|-------|
| `event.kind` | `enrichment` |
| `event.category` | `["threat"]` |
| `event.type` | `["indicator"]` |
| `event.dataset` | `ti_ticura.ecs` |
| `event.module` | `ti_ticura` |
| `event.provider` | `Ticura` |
| `observer.vendor` | `Ticura` |
| `observer.product` | `Ticura` |
| `ecs.version` | `9.3.0` |

---

### Enrichment Applied by the Pipeline

| Enrichment | Source | ECS Field(s) Populated |
|------------|--------|------------------------|
| Event time | `threat.indicator.last_seen`, falling back to `threat.indicator.first_seen` | `@timestamp` (so Discover shows real per-indicator temporal distribution; `modified_at` is deliberately not used because Ticura assigns it batch-uniformly per scoring run) |
| Expiry flag | `ticura.ages_out` versus ingest time | `threat.indicator.expired` (boolean — true when the IOC is past its scheduled expiry) |
| GeoIP | `threat.indicator.ip` | `threat.indicator.geo.{country_name, city_name, location, ...}` |
| ASN | `threat.indicator.ip` | `threat.indicator.as.number`, `threat.indicator.as.organization.name` |
| Hash type | `ticura.sub_type` (`HASHSHA256` / `HASHMD5` / `HASHSHA1`) | `threat.indicator.file.hash.{sha256, md5, sha1}` (defensive fallback when the source omits the typed field) |

GeoIP and ASN lookups use the GeoLite2 databases bundled with Elasticsearch — no external API calls or keys required.

---

### MITRE ATT&CK Mapping

The integration mirrors Ticura's MITRE ATT&CK enrichment into the canonical ECS `threat.*` field set so Elastic Security's MITRE matrix, detection rules, and timeline views pick it up automatically.

| ECS Field | Source |
|-----------|--------|
| `threat.technique.id` / `name` / `reference` | `ticura.technique.id` / `name` / `reference` |
| `threat.technique.subtechnique.id` / `name` / `reference` | `ticura.technique.subtechnique.*` |
| `threat.software.id` / `name` / `type` / `platforms` / `alias` / `reference` | `ticura.software.*` |
| `threat.group.id` / `name` / `reference` | `ticura.group.*` |

---

### Indicator Field Shapes by Type

Different indicator types populate different ECS fields. The integration always sets `threat.indicator.type` for filtering.

**IPv4 / IPv6 indicators** (`ticura.main_type: IPV4` / `IPV6`)
- `threat.indicator.ip` — the address
- `threat.indicator.port` — only set when `ticura.sub_type: IPV4PORT`
- `threat.indicator.geo.{country_iso_code, country_name, city_name, region_name, location}` — GeoIP-enriched
- `threat.indicator.as.{number, organization.name}` — ASN-enriched

**Domain indicators** (`ticura.main_type: DOMAIN`)
- `threat.indicator.url.domain` — the domain name
- `threat.indicator.name` — same as the domain
- `dns.{question, answers, resolved_ip, type, response_code}` — present when the source includes DNS resolution data

**URL indicators** (`ticura.main_type: URL`)
- `threat.indicator.url.full` — the full URL
- `threat.indicator.url.{domain, scheme, path, original, …}` — additional URL components are populated only when Ticura includes them in the feed; the pipeline stores them as-is and does not decompose `url.full`

**Hash indicators** (`ticura.main_type: HASH`)
- `threat.indicator.type: file`
- `threat.indicator.file.hash.{sha256, sha1, md5}` — populated based on `ticura.sub_type` (`HASHSHA256` / `HASHSHA1` / `HASHMD5`)
- `threat.indicator.file.{name, size}` — when the source includes them

---

### Ticura-Specific Enrichment Fields (`ticura.*`)

These are preserved alongside the ECS-mapped fields for per-field provenance (see *Field Provenance* below).

| Field | Type | Description |
|-------|------|-------------|
| `ticura.uuid` | keyword | Stable Ticura indicator ID (used as document `_id`). |
| `ticura.main_type` / `sub_type` | keyword | High-level type and subtype as classified by Ticura. |
| `ticura.risk` / `risk_category` | long / keyword | Numeric 0–100 risk and its categorical label (low / medium / high / critical). |
| `ticura.confidence` / `confidence_category` | long / keyword | Numeric 0–100 confidence and label. |
| `ticura.is_inbound` | boolean | True for threats originating outside, targeting the protected environment. |
| `ticura.ages_out` | date | Scheduled expiry timestamp. Used by the pipeline to set `threat.indicator.expired`. |
| `ticura.feed_ingest_timestamp` | date | Pipeline-set; when this document was processed. Updated on every re-ingest. |
| `ticura.countries` / `industries` / `actors` | keyword | Ticura-supplied attribution lists. |
| `ticura.cve` | keyword | Associated CVE identifiers. |
| `ticura.filter_cats` | nested | Filter categorization metadata. |
| `ticura.technique.*` / `software.*` / `group.*` | group | MITRE ATT&CK enrichment, mirrored to canonical `threat.*` for Elastic Security. |

### Supplemental Enrichment Fields (`additional_info.*`)

| Field | Type | Description |
|-------|------|-------------|
| `additional_info.valid_from` | date | First time the indicator was considered valid. |
| `additional_info.threat_types` | keyword | Labels like `Command and Control Server`, `Phishing`, `Malware`. Used by the analyst saved searches. |
| `additional_info.dns_first_seen` / `dns_last_seen` | date | Earliest / most recent DNS resolution observed for the indicator. |
| `additional_info.malware.name` | keyword | Malware family name. |
| `additional_info.online.is_online` / `last_online` | boolean / date | Online-status enrichment. |
| `additional_info.sinkhole.owner` | keyword | Set for indicators routed to a known sinkhole. |
| `additional_info.countries` / `industries` / `actors` / `cve` | keyword | Supplemental attribution lists (also merged into `merged.*` for convenient querying). |

The `merged.{countries, industries, actors}` fields are deduplicated, sorted unions of the `ticura.*` and `additional_info.*` equivalents — query these when you don't care which source the attribution came from.

---

### ILM Policy Tuning

The integration ships a single ILM policy `logs-ti_ticura.ecs-default_policy` with the following defaults:

```
hot:    rollover at max_age: 24h
warm:   min_age: 0s
delete: min_age: 1d
```

This is **tuned for re-asserting threat-intel feeds** — re-ingests of the same `ticura.uuid` overwrite in place, while indicators Ticura removes from the feed age out within ~48h. If you need different retention semantics:

- **Keep "removed" indicators queryable longer**: increase `delete.min_age` (for example, to `7d` to retain a week of dropped-indicator history in the warm tier).
- **Reduce storage overhead during normal operation**: there isn't any with this policy — only one backing index is in hot at a time.
- **More aggressive removal**: set `hot.rollover.max_age` shorter (for example, `12h`) so dropped indicators are gone from storage within ~24h.

Edit the policy via Kibana's **Stack Management → Index Lifecycle Policies**. Changes apply immediately; existing backing indices pick up the new phase definitions on the next ILM poll (default 10 min).

---

### Field Provenance

Every document carries `event.dataset: ti_ticura.ecs`, `event.module: ti_ticura`, and `observer.vendor: Ticura` for whole-event provenance.

For ECS-canonical fields that the integration may populate by mapping from Ticura-specific fields (for example, `threat.technique.*`, `event.severity`), the original Ticura-namespaced field (`ticura.technique.*`, `ticura.risk`, …) is **always preserved alongside**. The mapping uses `override: false`, so a value Ticura supplied directly in the ECS namespace is **never** overwritten.

You can therefore distinguish three cases per field:

| ECS field | Ticura mirror | Meaning |
|-----------|---------------|---------|
| set | absent | Ticura supplied this directly in the ECS namespace; pipeline did not enrich. |
| set | present, equal | Pipeline mirrored from the Ticura namespace into ECS. |
| set | present, different | Ticura supplied two values; the ECS-canonical value wins. The Ticura mirror shows the alternate. |

When `preserve_original_event: true` is enabled in the integration settings, the full raw JSON delivered by Ticura is also retained in `event.original` as an audit trail.

---

## Data Access and Security

- Each feed is unique to the subscriber.
- Access is controlled using subscription-specific credentials. The API key is sent only over HTTPS, redacted from request-trace logs, and removed from any persisted in-memory state by the CEL input.
- Feed content reflects the configuration defined during the Ticura feed setup.

---

## Notes

- Indicator relevance and confidence can change over time.
- The volume of ingested indicators depends on your feed configuration.
- Indicators are mapped to ECS `threat.indicator.*` and are ready for use by Elastic Security's prebuilt threat-intel Indicator Match rules, or any custom Indicator Match rules you build.
