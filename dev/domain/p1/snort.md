# snort

## Product Domain (Snort IDS/IPS)

Snort is a widely deployed open-source network intrusion detection system (NIDS) and intrusion prevention system (IPS) maintained by Cisco. Deployed passively on mirrored network segments or inline on traffic paths, Snort inspects live packets against signature-based rules, protocol decoders, and preprocessor logic to detect malicious activity, policy violations, and protocol anomalies. In IPS mode it can actively drop or reset malicious sessions; in IDS mode it generates alerts for downstream analysis and incident response.

Snort has a long history as the de facto standard for open-source network IDS, with extensive community and commercial rule sets (including Cisco Talos signatures). Organizations deploy Snort at network perimeters, data-center boundaries, and critical internal segments to gain visibility into north-south and east-west traffic. Snort 3 introduced a modern Lua-based configuration model, multi-threaded packet processing, and structured JSON alert output, while Snort 2.x remains common in legacy and embedded deployments such as pfSense.

Security teams use Snort for real-time threat detection, compliance logging, forensic investigation, and feeding SIEM platforms with normalized network security events. The engine's alert outputs capture rule metadata, classification, priority, and packet-level context—including source/destination endpoints, protocol details, and optional base64-encoded payload data—enabling correlation of alerts with the underlying traffic that triggered them.

## Data Collected (brief)

The integration collects Snort alert logs via Elastic Agent **logfile** or **UDP/syslog** input into a single **log** data stream (`snort.log`). Supported source formats include Snort 3 JSON (`alert_json`), legacy Alert Fast, Alert Full (multiline), pfSense CSV, and syslog-wrapped alerts. Events are parsed into ECS fields (source/destination, network, rule, observer, event) with Snort-specific packet metadata retained under `snort.*` (generator ID, IP/TCP/UDP/ICMP header details). Typical alert content includes rule ID, name, classification, priority/severity, action, protocol, and endpoint addresses/ports.

## Expected Audit Log Entities

The single **log** data stream ingests Snort IDS/IPS alert telemetry — network security events, not identity-centric audit logs. All supported formats (JSON, Alert Fast, Alert Full, CSV, pfSense CSV, syslog-wrapped) produce `event.kind: alert` with `event.category: network`. There are no separate metrics or inventory streams.

Actor and target are inferred from the packet 5-tuple (`src_addr`/`dst_addr` or legacy `->` notation → `source.*`/`destination.*`), well-known ports, `network.direction`, and rule metadata. There is no authenticated user principal. ECS `*.target.*` fields are **not populated** (no row in `target_fields_audit.csv`). `destination.user.*` / `destination.host.*` are **not used** (absent from `destination_identity_hits.csv`). `target_enhancement_packages.csv` classifies snort as **moderate_candidate_network_dest** with `pipeline_dest_network: true` but no Tier-A ECS target mapping.

**`event.action` is absent from all fixtures and pipelines.** Snort's richest action signals — IPS disposition (`json.action`: `allow`/`block`), rule signature message (`json.msg` → `rule.description`), and pfSense CSV disposition (`Allow`) — are mapped to `event.type` or discarded with `_tmp` cleanup instead. See Event action sections below.

| Stream / format | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| **log** — Snort 3 JSON | no | no | `json.action` (`allow`/`block`) | high | Renamed to `_tmp.action` (`json.yml` L199–202); `event.type: ["allowed"]` when `allow` (`default.yml` L158–167); `"action":"allow"` in `test-log-json.log-expected.json` originals |
| **log** — Snort 3 JSON (detection) | no | no | `rule.description` ← `json.msg` | high | `"ICMP Traffic Detected"`, `"(http_inspect) gzip decompression failed"`, `"(icmp4) ICMP ping Nmap"` in JSON fixtures (`json.yml` L62–65) |
| **log** — pfSense CSV | no | no | `_tmp.action` (CSV last field: `Allow`) | high | Grok captures disposition (`plaintext.yml` L11); `event.type: ["allowed"]` in `test-log-pfsense.log-expected.json` |
| **log** — Alert Fast / Alert Full / default CSV / syslog | no | no | `rule.description` ← grok `msg` | high | Signature text only — no IPS disposition field (e.g. `"Pinging..."` in `sample_event.json`; `"ET SCAN Sipvicious User-Agent Detected"` in pfSense original) |
| **log** — all formats (fallback) | no | no | `rule.id` ← `sid` | partial | Numeric signature ID when message absent; less human-readable |

### Event action (semantic)

What operation or activity does each stream record?

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| IDS/IPS rule triggered (signature match) | detection | high | `rule.description`, `rule.id`, `rule.category` on every alert (e.g. `"Pinging..."` sid `1000015` in `sample_event.json`; `"Attempted Administrator Privilege Gain"` WriteAndX in `test-log-json.log-expected.json`) | All formats — primary security "what happened" |
| IPS traffic allowed (passive/IDS) | detection | high | Vendor `json.action: allow` or pfSense `Allow` → `event.type: ["allowed"]` | JSON and pfSense CSV only |
| IPS traffic blocked/denied | detection | high | Vendor `json.action: block` → `event.type: ["denied"]` | JSON only — no `block` fixture; pipeline L164–167 in `default.yml` |
| Network scan / reconnaissance detected | detection | high | Rule text + category (e.g. `"Detection of a Network Scan"` UPnP in `test-log-fast.log-expected.json`; `"ET SCAN Sipvicious User-Agent Detected"` in pfSense original) | Alert Fast / pfSense |
| Protocol anomaly / preprocessor alert | detection | medium | Preprocessor gid + msg (e.g. gid `119` `"(http_inspect) gzip decompression failed"` in `test-log-json.log-expected.json`; gid `116` ICMP Nmap ping) | JSON primarily |
| Same-src/dst traffic anomaly | detection | medium | `"BAD-TRAFFIC same SRC/DST"` rule in `test-log-pfsense.log-expected.json` / `test-log-fast.log-expected.json` | pfSense / Alert Fast |

Plaintext Alert Fast, Alert Full, default CSV, and syslog formats carry **no IPS disposition field** — only signature metadata describes the action.

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| `event.action` | no | n/a | — | — | Absent from `sample_event.json` and all `*-expected.json` |
| `json.action` (vendor, removed post-pipeline) | no (→ `event.type`) | partial | `allow`, `block` | yes | `json.yml` L199–202 → `_tmp.action`; `default.yml` L158–167 appends `allowed`/`denied` to `event.type`; `_tmp` removed L230–235 |
| `_tmp.action` (pfSense CSV grok) | no (→ `event.type`) | partial | `Allow` (normalize to `allow`) | yes | `plaintext.yml` L11; `event.type: ["allowed"]` in `test-log-pfsense.log-expected.json` |
| `rule.description` | no | n/a | `"Pinging..."`, `"ICMP Traffic Detected"`, `"(http_inspect) gzip decompression failed"`, `"ET CINS Active Threat Intelligence Poor Reputation IP TCP group 95"` | yes | `json.msg` / grok `msg` → `rule.description` (`json.yml` L62–65; `plaintext.yml` L21–22); all fixtures |
| `rule.id` | no | n/a | `"1000015"`, `"10000001"`, `"2403488"` | partial (alternate) | `sid` → `rule.id` (`json.yml` L72–76); numeric; pair with `rule.description` for readability |
| `rule.category` | no | n/a | `"Misc activity"`, `"Attempted Administrator Privilege Gain"`, `"Misc Attack"` | partial (alternate) | Classification string — broader than per-signature action (`json.yml` L56–60) |
| `event.type` / `event.category` | n/a (wrong ECS field for verb) | partial | `allowed`, `denied`; category `network` | no (keep as type/category) | Currently absorbs IPS disposition that belongs in `event.action` per ECS Event field-set |
| `event.kind` | n/a | n/a | `alert` | no | Static set (`default.yml` L113–116); event class, not verb |

### Actor (semantic)

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| Flow / alert origin (default) | host | — | high | `source.ip`, `source.port`, `source.address`; packet origin in every fixture (e.g. `10.50.10.88 → 175.16.199.1` ICMP in `sample_event.json`; `10.100.20.59:57263 → 10.100.10.190:22` TCP in `test-log-csv.log-expected.json`) | All formats |
| Outbound client / scan origin | host | — | high | Internal host with ephemeral source port toward external or service port; `network.direction: outbound` (e.g. `192.168.88.10:1029 → 175.16.199.1:53` DNS query in `test-log-fast.log-expected.json`; `192.168.15.10:1035 → 175.16.199.1:1900` UPnP scan in same fixture) | Alert Fast / JSON |
| Inbound attack / external origin | host | — | high | External `source.ip` with service port toward internal `destination.*`; `network.direction: inbound` (e.g. `89.160.20.114:80 → 192.168.3.35:1047` HTTP in `test-log-json.log-expected.json`; `175.16.199.1:80 → 192.168.115.10:1051` in `test-log-fast.log-expected.json`) | Alert Fast / JSON |
| Lateral / internal attack | host | — | high | Both RFC1918 endpoints; `network.direction: internal` (e.g. `10.11.21.101:50084 → 10.11.21.11:445` WriteAndX attempt in `test-log-json.log-expected.json`; `192.168.202.110 → 192.168.27.27` Nmap ICMP ping in same fixture) | JSON / Alert Fast |
| DNS responder / server-side flow | host or service | — | medium | DNS server appears as `source.*` with `source.port: 53` (e.g. `10.100.10.1:53 → 10.100.10.190:36635` in `test-log-full.log-expected.json`; `175.16.199.1:53 → 10.100.10.190:54757` inbound DNS in `test-log-fast.log-expected.json`) | When responder is source side |
| Layer-2 origin | host | — | medium | `source.mac` when present (e.g. `52-54-00-70-78-9F` in `test-log-json.log-expected.json`; `00-25-90-3A-05-13` in `test-log-csv.log-expected.json`) | JSON / CSV formats |
| Geo-enriched external endpoint | host | — | medium | `source.geo.*`, `source.as.*` on public IPs (e.g. `89.160.20.114` Sweden/Bredband2 in `test-log-json.log-expected.json`; `175.16.199.1` China in `test-log-fast.log-expected.json`) | Optional geoip enrichment |
| Snort sensor / syslog wrapper | — | — | high | Not the actor — `observer.name` (`dev`), `process.name` (`snort`) from syslog prefix in `test-log-syslog.log-expected.json` and `sample_event.json`; static `observer.vendor`/`observer.product`/`observer.type` in `default.yml` | Syslog-wrapped alerts |

No **user** actor is populated in fixtures; `user.name` / `user.id` are absent from all pipeline expected output.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `source.ip` | Flow/alert origin host | yes | yes | high | `json.src_addr` / grok `source.address` → `source.ip` (`json.yml` L35–37; `plaintext.yml` L21–24; `default.yml` L72–76; all fixtures) |
| `source.port` | Flow/alert origin port | yes | yes | high | `json.src_port` / grok → `source.port` (`json.yml` L17–22; `plaintext.yml` CSV/FAST patterns) |
| `source.address` | Pre-conversion address string | yes | yes | high | Intermediate field before IP conversion (`default.yml` L72–76) |
| `source.mac` | L2 origin | yes | yes | high | `json.eth_src` / CSV MAC grok → normalized `source.mac` (`json.yml` L44–47; `default.yml` L87–101; JSON/CSV fixtures) |
| `source.geo.*`, `source.as.*` | Enriched origin | yes | yes | medium | geoip on `source.ip` (`default.yml` L169–207; inbound attack fixture with `89.160.20.114`) |
| `snort.gid` | Rule generator ID | yes (vendor) | n/a | low | `json.gid` / grok → `snort.gid` (`json.yml` L78–83; `plaintext.yml` L21); rule metadata, not traffic actor |
| `snort.tcp.*`, `snort.udp.*`, `snort.icmp.*`, `snort.ip.*` | Packet header context | yes (vendor) | n/a | high | Protocol-specific fields from JSON or Alert Full grok (`json.yml` L84–159; `plaintext.yml` L13–17); packet metadata, not entity identity |
| `observer.name`, `observer.product`, `observer.vendor`, `observer.type` | Sensor identity | yes | n/a | high | Static sets in `default.yml` L14–25; syslog `OBSERVER` grok for `observer.name` (`plaintext.yml` L30); identifies IDS sensor, not traffic actor |
| `observer.ingress.interface.name` | Capture interface | yes | n/a | medium | `json.iface` → `observer.ingress.interface.name` (`json.yml` L203–207; JSON fixtures) |
| `process.name` | Syslog program name | yes | n/a | high | Syslog grok `SYSLOGPROG` (`plaintext.yml` L32); wrapper metadata, not actor |
| `related.ip` | Correlation | yes | yes | high | Appends `source.ip` and `destination.ip` (`default.yml` L218–229) |

### Target (semantic)

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 — Network protocol / service | Application protocol or well-known service on destination port | SSH, DNS, HTTP, SMB, DHCP, … | service | — | high | `network.protocol` from `json.service` (`json.yml` L178–183; e.g. `netbios-ssn` on `:445`, `http` on inbound alert); `destination.port` — `:22` SSH in `test-log-csv.log-expected.json`, `:53` DNS in `test-log-fast.log-expected.json`, `:445` SMB in `test-log-json.log-expected.json` | JSON sets `network.protocol`; plaintext formats rely on port + `network.transport` |
| 2 — Host / endpoint | IP/MAC peer receiving or serving traffic | Internal victim, external server, resolver, broadcast | host | — | high | `destination.ip`, `destination.port`, `destination.mac` ← `dst_addr`/grok (`json.yml` L23–42; `plaintext.yml` L21–24); e.g. victim `192.168.3.35` on inbound HTTP alert, `10.11.21.11:445` on lateral SMB, `255.255.255.255:68` DHCP broadcast | Default for all alert formats |
| 2 — Rule-implied asset class | Signature classification describing attacked asset type | Windows endpoint, server | general | windows-endpoint, server | medium | `rule.category` + `rule.description` hint at asset type but do not replace IP/port (e.g. `Attempted Administrator Privilege Gain` / WriteAndX to `:445` in `test-log-json.log-expected.json`; `Detection of a Network Scan` UPnP rule in `test-log-fast.log-expected.json`) | Alert metadata only |
| 3 — Detection rule / payload | Triggered signature and optional packet payload | Snort rule, base64 payload | general | ids_rule, packet_payload | medium | `rule.id`, `rule.description`, `rule.category`, `rule.version` ← `sid`/`msg`/`class` (`json.yml` L56–77; grok in `plaintext.yml`); `json.b64_data` stripped at ingest (`json.yml` L8–11) — payload not retained in ECS output | Layer 3 content largely absent post-pipeline |

**Same src/dst anomaly:** actor and target collapse to the same IP when both sides match (e.g. `175.16.199.1 → 175.16.199.1` ICMP and pfSense `BAD-TRAFFIC same SRC/DST` in `test-log-fast.log-expected.json` / `test-log-pfsense.log-expected.json`).

### Target (ECS candidates)

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `destination.ip` | 2 | host | yes | yes | context-only (network peer) | yes → `host.target.ip` | `json.dst_addr` / grok → `destination.ip` (`json.yml` L29–33; `default.yml` L77–82); victim/server peer on alerts |
| `destination.port` | 1/2 | service/host | yes | yes | context-only | partial → `host.target.port` | `json.dst_port` / grok → `destination.port`; well-known ports imply service layer (`:22`, `:53`, `:445`, `:80`) |
| `destination.address` | 2 | host | yes | yes | context-only | yes → `host.target.ip` | Pre-conversion address string (`default.yml` L77–82) |
| `destination.mac` | 2 | host | yes | yes | context-only | yes → `host.target.mac` | `json.eth_dst` / CSV MAC grok → normalized `destination.mac` (JSON/CSV fixtures) |
| `destination.geo.*`, `destination.as.*` | 2 | host | yes | yes | context-only | no | geoip on `destination.ip` (`default.yml` L174–217; `sample_event.json`) |
| `network.protocol` | 1 | service | yes | yes | context-only | partial → `service.target.name` | `json.service` when not `unknown` (`json.yml` L178–183; e.g. `netbios-ssn`, `http`) |
| `network.transport` | 1 | service | yes | yes | context-only | no | `json.proto` / grok `{TCP\|UDP\|ICMP}` (`json.yml` L173–177; all fixtures) |
| `network.direction` | — | — | yes | yes | context-only | no | `network_direction` processor on internal networks (`default.yml` L151–153); aids actor/target role inference |
| `rule.id`, `rule.description`, `rule.category`, `rule.version` | 3 | general | yes | yes | context-only | no | Signature metadata from JSON/grok (`json.yml` L56–77; `plaintext.yml` L21–29) |
| `snort.gid` | 3 | general | yes (vendor) | n/a | context-only | no | Generator ID — identifies rule subsystem, not target entity (`json.yml` L78–83) |
| `snort.tcp.*`, `snort.icmp.*`, `snort.udp.*`, `snort.ip.*`, `snort.eth.length` | — | — | yes (vendor) | n/a | — | no | Packet header details; forensic context, not entity target |
| `event.severity` | 3 | general | yes | yes | context-only | no | `json.priority` / grok Priority (`json.yml` L192–197; all formats) |

### Gaps and mapping notes

- **`event.action` not mapped** — vendor `json.action` (`allow`/`block`) and pfSense CSV disposition (`Allow`) are consumed only to set `event.type` (`allowed`/`denied`) then discarded with `_tmp` cleanup; signature text in `rule.description` is the de-facto action label but also not copied to `event.action`. Recommended primary mapping: `json.action` / pfSense disposition for IPS mode; `rule.description` for IDS-only plaintext formats.
- **No ECS `*.target.*` fields** — victim/server endpoints live under `destination.*` as network flow peers; `target_enhancement_packages.csv` flags snort as **moderate_candidate_network_dest** for potential `host.target.ip` / port migration on alert victims.
- **`destination.*` is network context, not de-facto user/host audit target** — unlike firewall auth or email integrations, Snort never maps login-target or recipient identity to `destination.user.*`; all destination fields are 5-tuple peers from packet headers.
- **No user identity anywhere** — `user.*`, `destination.user.*`, and `related.user` are absent from pipelines, fields.yml, and all fixtures; Snort alerts carry no authenticated principal.
- **`json.b64_data` stripped at ingest** — base64 packet payload is removed (`json.yml` L8–11) and not available as a Layer 3 content target in ECS output; only `event.original` retains the raw log.
- **`observer.*` / `process.name`** identify the Snort sensor or syslog wrapper, not the traffic actor or target.
- **`snort.gid`** (generator ID) distinguishes which Snort subsystem fired the rule (e.g. gid 1 = rule engine, gid 119 = http_inspect) — rule metadata, not actor/target entity.
- **DNS direction** — query events treat resolver as `destination.*:53`; answer/responder events may reverse roles with `source.port: 53`; actor/target follow packet direction, not semantic client/server labels.
- **Plaintext formats lack `network.protocol` and IPS disposition** — Alert Fast, Alert Full, CSV, and syslog formats populate `network.transport` but not `network.protocol` or `json.action`; service inference relies on `destination.port` and rule description.

### Per-stream notes

All formats share the single **log** data stream and `default.yml` pipeline, branching to `json.yml` (JSON starting with `{`) or `plaintext.yml` (Alert Fast, Alert Full, CSV, pfSense CSV, syslog). **JSON** (`alert_json`) provides the richest vendor namespace (`snort.tcp.*`, `snort.icmp.*`, `network.protocol`, `observer.ingress.interface.name`, MAC addresses) and the only IPS disposition field (`json.action` → `event.type`). **Alert Full** adds multiline packet header details under `snort.*`. **CSV/pfSense** formats include MAC, extended TCP/IP fields, and pfSense-specific disposition (`Allow`). **Syslog-wrapped** alerts add `observer.name` and `process.name` from the syslog prefix. Action semantics: JSON/pfSense carry IPS allow/block; all other plaintext formats rely solely on `rule.description` for the detection verb.

## Example Event Graph

These examples come from the single **log** data stream (`snort.log`). Snort alerts are network IDS/IPS telemetry — audit-adjacent security events inferred from packet 5-tuples and rule metadata, not identity-centric audit logs. `event.action` is absent from all fixtures; action labels below are derived from `rule.description` (signature text).

### Example 1: Outbound ICMP ping detection (syslog Alert Fast)

**Stream:** `snort.log` · **Fixture:** `packages/snort/data_stream/log/sample_event.json`

```
Host 10.50.10.88 → Pinging... → Host 175.16.199.1
```

#### Actor

| Field | Value |
| --- | --- |
| id | 10.50.10.88 |
| type | host |
| ip | 10.50.10.88 |

**Field sources:**
- `id ← source.ip`
- `ip ← source.ip`

#### Event action

| Field | Value |
| --- | --- |
| action | Pinging... |
| source_field | `rule.description` |
| source_value | `Pinging...` |

Not mapped to ECS `event.action` today — signature message from grok `msg` in Alert Fast format.

#### Target

| Field | Value |
| --- | --- |
| id | 175.16.199.1 |
| type | host |
| geo | Changchun, China |
| ip | 175.16.199.1 |

**Field sources:**
- `id ← destination.ip`
- `geo ← destination.geo.city_name, destination.geo.country_name`
- `ip ← destination.ip`

#### Mermaid (optional)

```mermaid
flowchart LR
  A["Actor: 10.50.10.88"] --> E["Pinging..."]
  E --> T["Target: 175.16.199.1"]
```

### Example 2: Lateral SMB WriteAndX privilege-gain attempt (Snort 3 JSON)

**Stream:** `snort.log` · **Fixture:** `packages/snort/data_stream/log/_dev/test/pipeline/test-log-json.log-expected.json`

```
Host 10.11.21.101 → OS-WINDOWS Microsoft Windows raw WriteAndX InData pointer adjustment attempt → SMB service 10.11.21.11:445
```

#### Actor

| Field | Value |
| --- | --- |
| id | 10.11.21.101 |
| type | host |
| ip | 10.11.21.101 |

**Field sources:**
- `id ← source.ip`
- `ip ← source.ip`, `source.port` (50084)

#### Event action

| Field | Value |
| --- | --- |
| action | OS-WINDOWS Microsoft Windows raw WriteAndX InData pointer adjustment attempt |
| source_field | `rule.description` |
| source_value | `OS-WINDOWS Microsoft Windows raw WriteAndX InData pointer adjustment attempt` |

Not mapped to ECS `event.action` today. IPS disposition `allow` from vendor `json.action` is mapped to `event.type: ["allowed"]` instead.

#### Target

| Field | Value |
| --- | --- |
| id | 10.11.21.11:445 |
| type | service |
| sub_type | netbios-ssn |
| ip | 10.11.21.11 |

**Field sources:**
- `id ← destination.ip, destination.port`
- `sub_type ← network.protocol`
- `ip ← destination.ip`

#### Mermaid (optional)

```mermaid
flowchart LR
  A["Actor: 10.11.21.101"] --> E["WriteAndX attempt"]
  E --> T["Target: 10.11.21.11:445 (SMB)"]
```

### Example 3: Inbound HTTP preprocessor alert (Snort 3 JSON)

**Stream:** `snort.log` · **Fixture:** `packages/snort/data_stream/log/_dev/test/pipeline/test-log-json.log-expected.json`

```
Host 89.160.20.114 → (http_inspect) gzip decompression failed → HTTP service 192.168.3.35:1047
```

#### Actor

| Field | Value |
| --- | --- |
| id | 89.160.20.114 |
| type | host |
| geo | Linköping, Sweden |
| ip | 89.160.20.114 |

**Field sources:**
- `id ← source.ip`
- `geo ← source.geo.city_name, source.geo.country_name`
- `ip ← source.ip`, `source.port` (80)

#### Event action

| Field | Value |
| --- | --- |
| action | (http_inspect) gzip decompression failed |
| source_field | `rule.description` |
| source_value | `(http_inspect) gzip decompression failed` |

Not mapped to ECS `event.action` today. Preprocessor alert from `snort.gid` 119 (http_inspect); vendor `json.action: allow` → `event.type: ["allowed"]`.

#### Target

| Field | Value |
| --- | --- |
| id | 192.168.3.35:1047 |
| type | service |
| sub_type | http |
| ip | 192.168.3.35 |

**Field sources:**
- `id ← destination.ip, destination.port`
- `sub_type ← network.protocol`
- `ip ← destination.ip`

#### Mermaid (optional)

```mermaid
flowchart LR
  A["Actor: 89.160.20.114 (SE)"] --> E["gzip decompression failed"]
  E --> T["Target: 192.168.3.35:1047 (HTTP)"]
```

## ES|QL Entity Extraction

**Package type: agent-backed** (policy template `snort`, single `log` data stream per `manifest.yml`). Router: **`data_stream.dataset == "snort.log"`** for all formats (Snort 3 JSON, Alert Fast/Full, CSV, pfSense CSV, syslog-wrapped). Pass 4 is **fill-gaps-only**: detection flags (`actor_exists`, `target_exists`, `action_exists`) run first for query semantics; **mapped columns use column-level preserve** (`<col> IS NOT NULL`), not `CASE(actor_exists, <col>, …)` — a populated `entity.target.name` must not block `host.target.ip` from `destination.ip` (Pass 4 §10). Ingest does not populate `host.*`, ECS `*.target.*`, or `event.action` today — fallbacks promote **`source.*`** / **`destination.*`** (5-tuple peers) to `host.*` / `host.target.*`, **`network.protocol`** to `service.target.name` (JSON), and **`rule.description`** to `event.action` and Layer 3 `entity.target.name`. No authenticated user principal in any fixture.

### Dataset inventory

| data_stream.dataset | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `snort.log` | IDS/IPS alerts (all formats) | host | host, service, general (signature) | full |

### Field mapping plan

#### Actor mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `host.ip` | `source.ip` | `data_stream.dataset == "snort.log" AND source.ip IS NOT NULL` | high | **column-level preserve** (`host.ip IS NOT NULL`); **vendor fallback** — flow origin (all fixtures) |
| `host.ip` | `source.address` | `data_stream.dataset == "snort.log" AND source.ip IS NULL AND source.address IS NOT NULL` | high | **vendor fallback** — pre-conversion address |
| `host.id` | `source.ip` | `data_stream.dataset == "snort.log" AND source.ip IS NOT NULL` | high | **column-level preserve** (`host.id IS NOT NULL`); **vendor fallback** — Pass 3 actor `id` = source endpoint |
| `host.id` | `source.mac` | `data_stream.dataset == "snort.log" AND source.ip IS NULL AND source.mac IS NOT NULL` | medium | **vendor fallback** — L2-only origin (`test-log-json.log-expected.json`) |

#### Target mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `host.target.ip` | `destination.ip` | `data_stream.dataset == "snort.log" AND destination.ip IS NOT NULL` | high | **column-level preserve** (`host.target.ip IS NOT NULL`); **de-facto destination.*** — session peer / victim |
| `host.target.ip` | `destination.address` | `data_stream.dataset == "snort.log" AND destination.ip IS NULL AND destination.address IS NOT NULL` | high | **de-facto destination.*** — pre-conversion |
| `host.target.ip` | `destination.mac` | `data_stream.dataset == "snort.log" AND destination.ip IS NULL AND destination.mac IS NOT NULL` | medium | **de-facto destination.*** — wireless peer MAC |
| `service.target.name` | `network.protocol` | `data_stream.dataset == "snort.log" AND network.protocol IS NOT NULL AND network.protocol != "unknown"` | high | **column-level preserve** (`service.target.name IS NOT NULL`); **vendor fallback** — JSON service layer (e.g. `netbios-ssn`, `http`) |
| `entity.target.name` | `rule.description` | `data_stream.dataset == "snort.log" AND rule.description IS NOT NULL` | high | **column-level preserve** (`entity.target.name IS NOT NULL`); **vendor fallback** — Layer 3 Snort signature artifact (Pass 2) |

#### Event action mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `event.action` | `rule.description` | `data_stream.dataset == "snort.log" AND rule.description IS NOT NULL` | high | **column-level preserve** (`event.action IS NOT NULL`); **vendor fallback** — signature message (`json.msg` / grok `msg`; all formats); absent in fixtures today |

### Detection flags (mandatory — run first)

`actor_exists` omits `user.*` and `service.*` — no user principal and no service actor in Snort fixtures. `target_exists` checks official `*.target.*` columns only (ingest does not populate them today). **Actor/target/action `EVAL` blocks use column-level preserve** (`<col> IS NOT NULL`) — not `CASE(actor_exists, <col>, …)` / `CASE(target_exists, <col>, …)` — so one populated sibling column does not block fallbacks on empty columns (Pass 4 §10).

```esql
| EVAL
  actor_exists = host.id IS NOT NULL OR host.ip IS NOT NULL OR host.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
```

### Combined ES|QL — actor fields

```esql
| EVAL
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "snort.log" AND source.ip IS NOT NULL, source.ip,
    data_stream.dataset == "snort.log" AND source.ip IS NULL AND source.address IS NOT NULL, source.address,
    null
  ),
  host.id = CASE(
    host.id IS NOT NULL, host.id,
    data_stream.dataset == "snort.log" AND source.ip IS NOT NULL, TO_STRING(source.ip),
    data_stream.dataset == "snort.log" AND source.ip IS NULL AND source.mac IS NOT NULL, source.mac,
    null
  )
```

### Combined ES|QL — event action

```esql
| EVAL
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "snort.log" AND rule.description IS NOT NULL, rule.description,
    null
  )
```

### Combined ES|QL — target fields

```esql
| EVAL
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    data_stream.dataset == "snort.log" AND destination.ip IS NOT NULL, destination.ip,
    data_stream.dataset == "snort.log" AND destination.ip IS NULL AND destination.address IS NOT NULL, destination.address,
    data_stream.dataset == "snort.log" AND destination.ip IS NULL AND destination.mac IS NOT NULL, destination.mac,
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "snort.log" AND network.protocol IS NOT NULL AND network.protocol != "unknown", network.protocol,
    null
  ),
  entity.target.name = CASE(
    entity.target.name IS NOT NULL, entity.target.name,
    data_stream.dataset == "snort.log" AND rule.description IS NOT NULL, rule.description,
    null
  )
```

### Full pipeline fragment (optional)

```esql
FROM logs-*
| EVAL
  actor_exists = host.id IS NOT NULL OR host.ip IS NOT NULL,
  target_exists = host.target.ip IS NOT NULL OR service.target.name IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
| EVAL
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "snort.log" AND source.ip IS NOT NULL, source.ip,
    data_stream.dataset == "snort.log" AND source.ip IS NULL AND source.address IS NOT NULL, source.address,
    null
  ),
  host.id = CASE(
    host.id IS NOT NULL, host.id,
    data_stream.dataset == "snort.log" AND source.ip IS NOT NULL, TO_STRING(source.ip),
    data_stream.dataset == "snort.log" AND source.ip IS NULL AND source.mac IS NOT NULL, source.mac,
    null
  ),
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "snort.log" AND rule.description IS NOT NULL, rule.description,
    null
  ),
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    data_stream.dataset == "snort.log" AND destination.ip IS NOT NULL, destination.ip,
    data_stream.dataset == "snort.log" AND destination.ip IS NULL AND destination.address IS NOT NULL, destination.address,
    data_stream.dataset == "snort.log" AND destination.ip IS NULL AND destination.mac IS NOT NULL, destination.mac,
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "snort.log" AND network.protocol IS NOT NULL AND network.protocol != "unknown", network.protocol,
    null
  ),
  entity.target.name = CASE(
    entity.target.name IS NOT NULL, entity.target.name,
    data_stream.dataset == "snort.log" AND rule.description IS NOT NULL, rule.description,
    null
  )
| KEEP @timestamp, data_stream.dataset, event.kind, event.action, host.ip, host.id, host.target.ip, service.target.name, entity.target.name, rule.id, network.direction
```

### Streams excluded

*(none — single `log` stream; all formats share `snort.log` and 5-tuple extraction)*

### Gaps and limitations

- **No user identity** — `user.*`, `destination.user.*` absent from pipelines and fixtures; columns intentionally omitted.
- **IPS disposition not in `event.action` fallback** — vendor `json.action` / pfSense CSV disposition map to `event.type` (`allowed`/`denied`) at ingest and are removed with `_tmp`; `MV_FIRST(event.type)` is a poor verb substitute — prefer ingest mapping to `event.action`.
- **Plaintext formats lack `network.protocol`** — Alert Fast/Full, CSV, syslog; `service.target.name` fallback omitted when field absent (port-based service inference not wired).
- **`host.target.port`** — `destination.port` indexed but not promoted (not in mandatory Pass 4 column set); enhancement candidate per Pass 2.
- **Same src/dst anomaly** — actor and target can share the same IP (`test-log-fast.log-expected.json`, pfSense `BAD-TRAFFIC`); no ES|QL guard without extra fields.
- **`json.b64_data` stripped** — packet payload unavailable at query time (`json.yml` L8–11).
- **`observer.*` / `process.name`** — Snort sensor / syslog wrapper, not traffic actor or target.
- **`entity.target.type` / `entity.target.sub_type`** — omitted; `network.protocol` covers service sub-type where present; never emit `target.entity.type`.
- **Pass 2 enhancement alignment** — ingest-time `event.action` ← `json.action` / pfSense disposition and `host.target.*` ← `destination.*` remain preferred; Pass 4 fills gaps without overwriting populated values.
- **Column-level preserve (§10)** — `actor_exists` / `target_exists` / `action_exists` are query-time helpers only; mapped columns use `<col> IS NOT NULL` as the first `CASE` branch so `entity.target.name` from `rule.description` does not block `host.target.ip` ← `destination.ip`. No `CASE(col, col, …)` fallback branches — `host.*` / `*.target.*` are not ingest-populated today; only vendor/ECS peer fields appear in fallbacks.
- **Pass 4 CASE syntax** — all `CASE` use odd-arity defaults (`null`) or paired `(boolean, value)` branches only; column-level **3-arg** / **5-arg** / **7-arg** / **9-arg** preserve (`<col> IS NOT NULL`, not `CASE(actor_exists, <col>, …)` or `CASE(target_exists, <col>, …)`). Never **4-arg** `CASE(flag, col, bare_field, null)` (bare field parses as a condition). Full pipeline fragment aligned with combined `EVAL` blocks (multi-fallback chains + `network.protocol != "unknown"`).
