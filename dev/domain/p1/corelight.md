# corelight

## Product Domain

Corelight is a network detection and response (NDR) platform built on open-source network security monitoring (NSM) foundations—primarily Zeek (formerly Bro) for deep protocol analysis and Suricata for signature-based intrusion detection. Corelight sensors are deployed passively on network taps or SPAN ports to inspect live traffic, reconstruct application-layer sessions, and emit high-fidelity metadata about connections, protocols, files, and security-relevant behaviors without inline blocking.

As an NSM platform, Corelight goes beyond simple flow logging by parsing dozens of protocols at line speed and generating structured Zeek logs for DNS, HTTP, TLS, SSH, RDP, VPN, files, software inventory, and custom notices. Corelight augments Zeek with proprietary analytics such as SSH/RDP/VPN inferences, threat-intel matching, and Suricata IDS alert enrichment. Security teams use Corelight for threat hunting, incident investigation, compliance visibility, and feeding SIEM platforms with normalized network telemetry across on-premises and cloud environments.

The Elastic integration does not ingest data via Elastic Agent; Corelight sensors export logs directly to Elasticsearch using Corelight-maintained ECS mappings (index templates, ingest pipelines, and ILM policies). The integration package installs Kibana dashboards that visualize the exported `logs-corelight-*` data for security posture assessment, log hunting, IP interrogation, and protocol-specific analysis workflows.

## Data Collected (brief)

Corelight sensors export Zeek and Suricata telemetry directly to Elasticsearch (Sensor > Export > Export to Elastic) after installing [Corelight ECS templates](https://github.com/corelight/ecs-templates). This integration provides **dashboards only**—no Elastic Agent data streams—and expects data in `logs-corelight-*` indices mapped to ECS.

Typical log types (`event.dataset`) include **conn** (connection metadata), **dns**, **http**, **tls** / **x509** (SSL and certificate details), **files** (extracted file hashes and MIME metadata), **software**, **notice** (Zeek security notices), **intel** (indicator matches), **ssh** / **rdp** / **vpn** (with Corelight inferences), **suricata_corelight** (Suricata IDS alerts with rule signature metadata), and AWS VPC flow logs. Events carry source/destination endpoints, network protocol details, observer/sensor identity, and Zeek- or Suricata-specific fields under ECS-aligned namespaces. Bundled dashboards cover connections, DNS, HTTP, SSL/x509, files, software, notices, intel, remote-access inferences, Suricata alerts, VPN activity, and security posture.

## Expected Audit Log Entities

Evidence is from `packages/corelight/docs/README.md`, bundled dashboards under `packages/corelight/kibana/dashboard/`, and saved searches under `packages/corelight/kibana/search/`. This integration is **dashboards-only**—Corelight sensors export Zeek/Suricata telemetry directly to `logs-corelight-*` via [Corelight ECS templates](https://github.com/corelight/ecs-templates) maintained outside this repo; there are no Elastic Agent data streams, ingest pipelines, or package test fixtures here.

Log types (`event.dataset`) include **conn**, **dns**, **http**, **tls** / **x509**, **files**, **software**, **notice**, **intel**, **ssh**, **rdp**, **vpn**, **suricata_corelight**, and AWS VPC flow enrichment on conn (`capture_source: vpcflow`). These are **network security monitoring (NSM) telemetry** and audit-adjacent security events (notices, Suricata alerts, intel matches)—not identity-centric audit logs. There is no authenticated user principal in dashboard field usage.

ECS `*.target.*` fields are **not populated** (no row in `target_fields_audit.csv`). `destination.user.*` / `destination.host.*` are **not used** (absent from `destination_identity_hits.csv` and all dashboard ES\|QL). `target_enhancement_packages.csv` classifies corelight as **none**. Actor and target are inferred from flow direction (`source.*`/`destination.*`), Zeek originator/responder semantics (`conn.local_orig`/`conn.local_resp`, `files.tx_hosts`/`files.rx_hosts`), well-known ports, inference tags, and rule/notice metadata.

**`event.action` is absent from all dashboard ES\|QL and saved searches** — no `event.action` field reference anywhere under `packages/corelight/`. Ingest pipelines live in [Corelight ECS templates](https://github.com/corelight/ecs-templates) / [ecs-mapping](https://github.com/corelight/ecs-mapping) (external); per-stream action semantics are carried by `event.dataset`, protocol fields, Zeek notice classes, Suricata rule metadata, and inference tags instead. See Event action sections below.

| Stream (`event.dataset`) | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| **conn** | no | unverifiable (external) | `network.protocol` + `network.transport` (connection observed) | medium | Connections dashboard filters `event.dataset: conn`, charts `network.protocol`/`source.ip`/`destination.ip` (`corelight-eff0434c-*.json`) |
| **conn** (vpcflow) | no | unverifiable | `capture_source: vpcflow` + `network.direction` (VPC flow accepted/rejected) | medium | AWS VPC Flow dashboard filters `capture_source: vpcflow`, ES\|QL on `network.direction` (`corelight-caf92ff9-*.json`) |
| **dns** | no | unverifiable | `dns.question.type` + `dns.response_code` (e.g. `A`, `NXDOMAIN`) | high | DNS dashboard ES\|QL on `dns.question.type`, `dns.response_code`, `dns.question.name` (`corelight-58885f47-*.json`, `corelight-8546a96c-*.json`) |
| **http** | no | unverifiable | `http.request.method` (+ optional `url.path`) | high | HTTP dashboard control on `http.request.method`; IP Interrogation ES\|QL `GET` + URI (`corelight-8c5f15f7-*.json`, `corelight-3a4a279f-*.json`) |
| **tls** / **x509** | no | unverifiable | TLS handshake / certificate observation (`ssl.validation_status`, `tls.cipher`) | medium | SSL and x509 / Secure Channel Insights dashboards (`corelight-e4a93cfe-*.json`, `corelight-45197477-*.json`) |
| **files** | no | unverifiable | file transfer observed (`files.tx_hosts`/`files.rx_hosts`) | medium | Files dashboard "Top Transmitting/Receiving Hosts" (`corelight-0cfc8a95-*.json`) |
| **software** | no | unverifiable | — (no per-event action; inventory sync) | high | Software dashboard on `host_header` + `software.name`/`software.type` — state snapshot, not verb (`corelight-40bbc19b-*.json`) |
| **notice** | no | unverifiable | `notice.note` (Zeek notice class, e.g. `SSL::Certificate_Expired`, `ATTACK::*`, `MeterpreterDetection::Meterpreter_Detected`) | high | Notices dashboard ES\|QL groups by `notice.note`, `notice.message` (`corelight-f7da14f0-*.json`, `corelight-7c0946bc-*.json`) |
| **intel** | no | unverifiable | threat-intel match (`intel.seen.indicator` + `intel.seen.where`) | high | Intel dashboard ES\|QL on `intel.seen.indicator`, `intel.seen.indicator_type`, `intel.seen.where` (`corelight-323b0f27-*.json`) |
| **ssh** | no | unverifiable | SSH session + `ssh.inferences` (PKA, KS, AUTO, CTS) | high | SSH Inferences Overview ES\|QL on `ssh.inferences`, `ssh.hassh` (`corelight-45197477-*.json`, `corelight-65a5fa91-*.json`) |
| **rdp** | no | unverifiable | `rdp.result` (`Success`, `SSL_NOT_ALLOWED_BY_SERVER`) + `event.outcome` | high | RDP Inferences / Remote Activity dashboards filter `rdp.result`, `event.outcome` (`corelight-f4864774-*.json`, `corelight-2d4dc345-*.json`) |
| **vpn** | no | unverifiable | `vpn.inferences` (RW, FW, COM, NSP, SK) + `vpn.name` | high | VPN Insights ES\|QL on `vpn.inferences`, `vpn.name` (`corelight-023162b6-*.json`, `corelight-f4864774-*.json`) |
| **suricata_corelight** | no | unverifiable | `rule.name` + `rule.signature_id` (IDS signature triggered) | high | Suricata IDS Alert Overview ES\|QL on `rule.name`, `rule.signature_id`, `event.severity` (`corelight-f1208ffe-*.json`) |

### Event action (semantic)

What operation or activity does each stream record?

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| Network connection observed | connection | high | `network.protocol`, `network.transport`, `source.ip`/`destination.ip` on conn events | **conn** — default NSM "what happened" |
| VPC flow accepted/rejected | connection | medium | `capture_source: vpcflow`, `network.direction`, cloud instance fields | **conn** (vpcflow enrichment) |
| DNS query / response | data_access | high | `dns.question.type` (`A`, `PTR`, `AXFR`, …), `dns.response_code` (`NXDOMAIN`, …) | **dns** |
| HTTP request observed | data_access | high | `http.request.method` with `url.path` | **http** |
| TLS handshake / certificate check | data_access | medium | `tls.server.subject`, `ssl.validation_status`, `tls.cipher` | **tls**, **x509** |
| File transfer observed | data_access | medium | `files.tx_hosts`/`files.rx_hosts`, `file.name`/`file.hash.sha256` | **files** |
| Software package detected | — | high | `software.name`/`software.type`/`software.version.*` on `host_header` | **software** — inventory sync; no per-event verb |
| Zeek security notice raised | detection | high | `notice.note` e.g. `SSL::Certificate_Expired`, `SSL::Invalid_Server_Cert`, `ATTACK::*`, `MeterpreterDetection::Meterpreter_Detected` | **notice** |
| Threat-intel indicator matched | detection | high | `intel.seen.indicator`, `intel.seen.indicator_type`, `intel.seen.where` | **intel** |
| SSH session / client behavior inferred | connection | high | `ssh.inferences` (`PKA`, `KS`, `AUTO`, `CTS`), `ssh.hassh` | **ssh** |
| RDP authentication attempt | authentication | high | `rdp.result` (`Success`, `SSL_NOT_ALLOWED_BY_SERVER`); `event.outcome` (`success`/`failure`) | **rdp** |
| VPN tunnel / exfiltration inferred | connection | high | `vpn.inferences` (`RW`, `FW`, `COM`, `NSP`, `SK`), `vpn.name` | **vpn** |
| Suricata IDS rule triggered | detection | high | `rule.name`, `rule.signature_id`, `event.severity` | **suricata_corelight** |

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from dashboard evidence) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| `event.action` | no | n/a | — | — | Absent from all dashboard ES\|QL under `packages/corelight/` |
| `event.dataset` | no (→ dataset label) | partial | `conn`, `dns`, `http`, `notice`, `suricata_corelight`, … | partial | Log-type discriminator used in every dashboard filter; coarse action proxy |
| `notice.note` | no | n/a | `SSL::Certificate_Expired`, `ATTACK::*`, `MeterpreterDetection::Meterpreter_Detected` | yes | Notices dashboard ES\|QL (`corelight-f7da14f0-*.json`, `corelight-7c0946bc-*.json`) |
| `notice.message` | no | n/a | Human-readable notice text | partial (alternate) | Notices dashboard control (`corelight-f7da14f0-*.json`) |
| `rule.name` | no | n/a | Suricata signature name (CVE-filtered in dashboard) | yes | Suricata IDS Alert Overview ES\|QL (`corelight-f1208ffe-*.json`) |
| `rule.signature_id` | no | n/a | Suricata SID | partial (alternate) | Same dashboard; less human-readable than `rule.name` |
| `http.request.method` | no | n/a | `GET`, `POST`, … | yes | HTTP dashboard + IP Interrogation ES\|QL (`corelight-8c5f15f7-*.json`, `corelight-3a4a279f-*.json`) |
| `dns.question.type` | no | n/a | `A`, `PTR`, `AXFR`, `IXFR`, `ANY`, `TXT` | yes | DNS / Name Resolution dashboards (`corelight-58885f47-*.json`, `corelight-8546a96c-*.json`) |
| `dns.response_code` | no | n/a | `NXDOMAIN`, … | partial | DNS dashboard NXDOMAIN panels (`corelight-8546a96c-*.json`) |
| `rdp.result` | no | n/a | `Success`, `SSL_NOT_ALLOWED_BY_SERVER` | yes | RDP Inferences dashboards (`corelight-f4864774-*.json`, `corelight-2d4dc345-*.json`) |
| `ssh.inferences` | no | n/a | `PKA`, `KS`, `AUTO`, `CTS` | yes | SSH Inferences Overview ES\|QL (`corelight-45197477-*.json`) |
| `vpn.inferences` | no | n/a | `RW`, `FW`, `COM`, `NSP`, `SK` | yes | VPN Insights ES\|QL (`corelight-023162b6-*.json`) |
| `intel.seen.indicator` | no | n/a | Matched IOC value | partial | Intel dashboard table (`corelight-323b0f27-*.json`) |
| `network.protocol` | no | n/a | `dns`, `ssl`, `ssh`, … | partial | Connections / protocol dashboards; coarse protocol observation |
| `event.type` | no (classification field) | partial | — | no (keep as type) | Referenced on Intel dashboard (`corelight-323b0f27-*.json`); not a verb substitute for `event.action` |
| `event.outcome` | no (outcome, not action) | partial | `success`, `failure` | no | RDP auth outcome (`corelight-f4864774-*.json`); complements but does not replace action |
| `event.severity` | no | n/a | Suricata alert severity | partial | Suricata dashboard ES\|QL (`corelight-f1208ffe-*.json`); severity, not operation name |

**Mapping note:** "Mapped today?" reflects fields present in indexed `logs-corelight-*` data per dashboard ES\|QL. Ingest pipelines live in [Corelight ECS templates](https://github.com/corelight/ecs-templates) / [ecs-mapping](https://github.com/corelight/ecs-mapping), not in this integration package — pipeline source → ECS steps and `event.action` population cannot be verified from repo evidence. Corelight's external mapping spreadsheet documents `event.category`, `event.kind`, and related ECS typing per log type.

### Actor (semantic)

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| Flow / protocol initiator | host | — | high | `source.ip`, `source.port`; Connections dashboard filters `event.dataset: conn` and charts `source.ip`/`destination.ip` (`corelight-eff0434c-*.json`); DNS dashboard aggregates by `source.ip` as originator (`corelight-58885f47-*.json`) | Default for conn, dns, http, tls, ftp, smb |
| Outbound vs inbound orientation | host | — | medium | `conn.local_orig: true` / `conn.local_resp: false` on outbound flows; Connections dashboard "Top Outbound/Inbound Data Flows by Originator" (`corelight-eff0434c-*.json`) | conn only |
| Suricata IDS alert source | host | — | high | `source.ip`; Origin Summary ES\|QL groups hits by `source.ip` (`corelight-f1208ffe-*.json`); Security Posture counts unique source IPs on `suricata_corelight` (`corelight-7c0946bc-*.json`) | suricata_corelight |
| Zeek notice subject | host | — | high | `source.ip`; Notices dashboard filter on `source.ip`; ES\|QL on `notice.note`/`notice.message` (`corelight-f7da14f0-*.json`, `corelight-7c0946bc-*.json`) | notice |
| Threat intel observed host | host | — | high | `source.ip`; Intel dashboard ES\|QL stats by `source.ip`, `destination.ip`, `intel.seen.indicator` (`corelight-323b0f27-*.json`) | intel |
| SSH client / initiator | host | — | high | `source.ip`; SSH Inferences Overview ES\|QL groups by `source.ip`, `destination.ip`, `ssh.inferences` (PKA, KS, AUTO, CTS) (`corelight-45197477-*.json`, `corelight-65a5fa91-*.json`) | ssh |
| RDP client | host | — | high | `source.ip`; RDP Inferences Overview filters `rdp.result`, charts auth by endpoint pair (`corelight-2d4dc345-*.json`, `corelight-f4864774-*.json`) | rdp |
| VPN client / initiator | host | — | high | `source.ip`; VPN Insights ES\|QL groups by `source.ip`, `vpn.inferences` (RW, FW, COM, NSP, SK) (`corelight-023162b6-*.json`, `corelight-f4864774-*.json`) | vpn |
| File transfer originator | host | — | high | `files.tx_hosts` (Zeek tx_host); Files dashboard "Top Transmitting (tx_host) Hosts" (`corelight-0cfc8a95-*.json`); session endpoints also in `source.ip` | files |
| Software inventory host | host | — | high | `host_header` (Zeek host); Software dashboard control on `host_header` with `software.name`/`software.type` (`corelight-40bbc19b-*.json`) | software |
| AWS VPC flow originator | host | — | medium | `source.ip` plus `orig_inst.id`/`orig_inst.name`/`orig_inst.vpc_id`; AWS VPC Flow dashboard filters `capture_source: vpcflow` (`corelight-caf92ff9-*.json`) | conn (vpcflow) |
| HTTP client software | general | client_software | low | `user_agent.original` reflects client application, not authenticated user; HTTP dashboard ES\|QL on `user_agent.original` (`corelight-8c5f15f7-*.json`) | http |
| Corelight sensor | — | — | high | Not the actor — every dashboard filters `observer.vendor: Corelight` and scopes by `observer.hostname` | All streams |

No **user** actor is populated in dashboard field usage; `user.name` / `user.id` / `user.email` are absent from all bundled dashboards and ES\|QL. `rdp.cookie` is labeled "Connecting User" in RDP dashboard ES\|QL (`corelight-2d4dc345-*.json`) but is an RDP session cookie, not an ECS user identity.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `source.ip` | Flow/alert origin host | yes (external ECS templates) | yes | high | Used in all dashboards; Connections, DNS, Suricata, Intel, SSH, RDP, VPN ES\|QL |
| `source.port` | Flow origin port | yes (external) | yes | high | Connections dashboard controls (`corelight-eff0434c-*.json`) |
| `source.bytes` | Flow volume (origin side) | yes (external) | yes | high | Connections outbound panels; VPN Insights byte charts (`corelight-023162b6-*.json`) |
| `source.geo.country_iso_code` | Enriched origin | yes (external) | yes | medium | Connections inbound panels (`corelight-eff0434c-*.json`) |
| `conn.local_orig` / `conn.local_resp` | Internal originator/responder orientation | yes (external) | yes | high | Connections outbound/inbound panels; Name Resolution Insights conn ES\|QL (`corelight-eff0434c-*.json`, `corelight-8546a96c-*.json`) |
| `files.tx_hosts` | File transmitter (Zeek tx_host) | yes (external) | yes | high | Files dashboard "Top Transmitting (tx_host) Hosts" (`corelight-0cfc8a95-*.json`) |
| `host_header` | Software-inventory host | yes (external) | yes | high | Software dashboard host control (`corelight-40bbc19b-*.json`) |
| `orig_inst.id` / `orig_inst.name` / `orig_inst.vpc_id` | Cloud-side flow originator | yes (external) | yes | medium | AWS VPC Flow cloud-enrichment ES\|QL (`corelight-caf92ff9-*.json`) |
| `ssh.inferences` | SSH client behavior hint | yes (external) | n/a | high | SSH Inferences Overview ES\|QL (`corelight-45197477-*.json`) |
| `rdp.cookie` | RDP session identifier | yes (external) | partial | medium | Labeled "Connecting User" in dashboard but is session cookie, not `user.*` (`corelight-2d4dc345-*.json`) |
| `rdp.result` / `event.outcome` | RDP auth outcome | yes (external) | yes | high | RDP Inferences / Remote Activity dashboards (`corelight-f4864774-*.json`) |
| `vpn.inferences` / `vpn.name` | VPN client behavior / type | yes (external) | n/a | high | VPN Insights dashboard (`corelight-023162b6-*.json`) |
| `user_agent.original` | HTTP client software | yes (external) | partial | medium | Client software string, not security principal (`corelight-8c5f15f7-*.json`) |
| `observer.hostname` / `observer.vendor` | Sensor identity | yes (external) | n/a | high | Scope filter on all dashboards; not traffic actor |
| `suricata.alert.metadata_original` | Suricata alert metadata | yes (external) | n/a | medium | CVE filter on Suricata dashboard (`corelight-f1208ffe-*.json`) |

**Mapping note:** "Mapped today?" reflects fields present in indexed `logs-corelight-*` data per dashboard ES\|QL. Ingest pipelines live in [Corelight ECS templates](https://github.com/corelight/ecs-templates), not in this integration package — pipeline source → ECS steps cannot be verified from repo evidence.

### Target (semantic)

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 — Network protocol / service | Application protocol or well-known service on destination port | DNS, HTTP, TLS, SSH, RDP, … | service | — | high | `network.protocol`, `network.transport`, `destination.port` — DNS `:53`, HTTP `:80`, TLS `:443`; Notices dashboard ES\|QL on `network.transport`/`destination.port` (`corelight-f7da14f0-*.json`) | All protocol and alert events |
| 2 — Host / endpoint | IP peer receiving or serving traffic | Internal server, external host, resolver | host | — | high | `destination.ip`, `destination.port`; Connections charts `destination.geo.country_iso_code` (`corelight-eff0434c-*.json`); Suricata Security Posture "Unique Dest. IPs" (`corelight-7c0946bc-*.json`) | Default for conn, dns, http, alerts |
| 2 — Cloud instance (VPC flow) | EC2/instance peer on enriched conn | Cloud VM / ENI | host | — | medium | `destination.ip` plus `resp_inst.id`/`resp_inst.name`/`resp_inst.vpc_id` (`corelight-caf92ff9-*.json`) | conn (vpcflow) |
| 2 — File receiver | Host receiving transferred file | Internal/external host | host | — | high | `files.rx_hosts` (Zeek rx_host); Files dashboard "Top Receiving (rx_host) Hosts" (`corelight-0cfc8a95-*.json`) | files |
| 3 — Named resource / content | Domain, URL, file, certificate, IOC | FQDN, HTTP path, file hash, x509 DN | general | domain, url, file, certificate, indicator | high | `dns.question.name`, `dest_host`, `url.path`, `file.name`/`file.mime_type`, `tls.server.subject`, `intel.seen.indicator` — DNS (`corelight-58885f47-*.json`), HTTP (`corelight-8c5f15f7-*.json`), Files (`corelight-0cfc8a95-*.json`), Intel (`corelight-323b0f27-*.json`) | Per log type |
| 3 — Detection rule / notice | Triggered signature or Zeek notice | Suricata rule, Zeek notice class | general | ids_rule, notice | high | `rule.signature_id`, `rule.name`, `event.severity` (`corelight-f1208ffe-*.json`); `notice.note` e.g. `ATTACK::*`, `SSL::Certificate_Expired`, `MeterpreterDetection::Meterpreter_Detected` (`corelight-7c0946bc-*.json`) | suricata_corelight, notice |
| 3 — Session correlation | Cross-log pivot keys | Zeek uid, community_id, file uid | general | session_id | high | `event.id`, `network.community_id`, `log.id.fuid` — Log Hunting dashboard controls (`corelight-ff07e65c-*.json`) | conn, files, http |

Software inventory (`software.name`, `software.type`, `software.version.*`) is a Layer 3 artifact detected **on** the Layer 2 host (`host_header`), not a separate endpoint.

### Target (ECS candidates)

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `destination.ip` | 2 | host | yes (external) | yes | context-only (network peer) | yes → `host.target.ip` | All dashboards; Suricata, Intel, SSH, RDP ES\|QL |
| `destination.port` | 1/2 | service/host | yes (external) | yes | context-only | partial → `host.target.port` | Connections, DNS, Notices, Intel dashboards |
| `destination.domain` | 3 | general | yes (external) | yes | context-only | partial → `entity.target.name` | TLS/SSL dashboards (`corelight-e4a93cfe-*.json`, `corelight-45197477-*.json`) |
| `destination.geo.country_iso_code` | 2 | host | yes (external) | yes | context-only | no | Connections outbound/inbound panels (`corelight-eff0434c-*.json`) |
| `destination.bytes` | 2 | host | yes (external) | yes | context-only | no | AWS VPC Flow dashboard (`corelight-caf92ff9-*.json`) |
| `network.protocol` / `network.transport` | 1 | service | yes (external) | yes | context-only | partial → `service.target.name` | Connections, Notices ES\|QL |
| `dns.question.name` / `dns.question.type` | 3 | general | yes (external) | yes | context-only | partial | DNS / Name Resolution dashboards (`corelight-58885f47-*.json`, `corelight-8546a96c-*.json`) |
| `dest_host` | 3 | general | yes (external) | yes | context-only | partial → `entity.target.name` | HTTP Host header; HTTP dashboard ES\|QL (`corelight-8c5f15f7-*.json`) |
| `url.path` / `http.request.method` | 3 | general | yes (external) | yes | context-only | partial | IP Interrogation / Log Hunting HTTP ES\|QL (`corelight-3a4a279f-*.json`) |
| `tls.server.subject` / `tls.cipher` / `ssl.validation_status` | 3 | general | yes (external) | yes | context-only | partial | SSL and x509 / Secure Channel Insights (`corelight-e4a93cfe-*.json`, `corelight-45197477-*.json`) |
| `file.name` / `file.mime_type` / `file.hash.sha256` | 3 | general | yes (external) | yes | context-only | partial | Files dashboard; x509 expiring-certs ES\|QL (`corelight-0cfc8a95-*.json`, `corelight-7c0946bc-*.json`) |
| `file.x509.subject.distinguished_name` | 3 | general | yes (external) | yes | context-only | partial | SSL and x509 dashboard (`corelight-e4a93cfe-*.json`) |
| `files.rx_hosts` | 2 | host | yes (external) | yes | context-only | yes → `host.target.hostname` | Files dashboard receiver panels (`corelight-0cfc8a95-*.json`) |
| `intel.seen.indicator` / `.indicator_type` / `.where` | 3 | general | yes (external) | yes | context-only | partial → `entity.target.id` | Intel dashboard table and Security Posture (`corelight-323b0f27-*.json`, `corelight-7c0946bc-*.json`) |
| `rule.signature_id` / `rule.name` / `rule.category` / `event.severity` | 3 | general | yes (external) | yes | context-only | no | Suricata IDS Alert Overview (`corelight-f1208ffe-*.json`) |
| `notice.note` / `notice.message` | 3 | general | yes (external) | yes | context-only | partial | Notices / Security Posture dashboards (`corelight-f7da14f0-*.json`, `corelight-7c0946bc-*.json`) |
| `resp_inst.id` / `resp_inst.name` / `resp_inst.vpc_id` | 2 | host | yes (external) | yes | context-only | partial → `host.target.id` | AWS VPC Flow cloud-enrichment ES\|QL (`corelight-caf92ff9-*.json`) |
| `software.name` / `software.type` / `software.version.*` | 3 | general | yes (external) | yes | context-only | partial | Software dashboard (`corelight-40bbc19b-*.json`) |
| `network.community_id` / `event.id` / `log.id.fuid` | 3 | general | yes (external) | yes | context-only | no | Log Hunting correlation controls (`corelight-ff07e65c-*.json`) |
| `rdp.auth_successful` / `rdp.result` | 2/3 | host / general | yes (external) | yes | context-only | no | Remote Activity Insights RDP panels (`corelight-f4864774-*.json`) |

### Gaps and mapping notes

- **No ECS `*.target.*` fields** — endpoint peers live under `destination.*` and Zeek-specific `files.tx_hosts`/`files.rx_hosts` as network context; `target_enhancement_packages.csv` classifies corelight as **none** (no package pipeline evidence for Tier-A migration).
- **`destination.*` is network context, not de-facto user/host audit target** — unlike firewall auth or email logs, Corelight never maps login-target or recipient identity to `destination.user.*`; all destination fields are flow 5-tuple peers or service ports.
- **Dashboard-only evidence ceiling** — ingest mapping is maintained in [Corelight ECS templates](https://github.com/corelight/ecs-templates) / [ecs-mapping](https://github.com/corelight/ecs-mapping); this repo cannot trace pipeline source → ECS field steps or validate fixtures.
- **`event.action` gaps** — `event.action` is absent from all dashboard ES\|QL; strongest action candidates are **`notice.note`** (Zeek notice class on **notice**), **`rule.name`** (Suricata signature on **suricata_corelight**), **`http.request.method`** (**http**), **`dns.question.type`** (**dns**), **`rdp.result`** (**rdp**), and **`ssh.inferences`/`vpn.inferences`** (remote-access streams). Recommended primary mapping: `event.action` ← `notice.note` on notices; `event.action` ← `rule.name` on Suricata alerts; `event.action` ← `http.request.method` on HTTP; protocol streams could use normalized `event.dataset` or `network.protocol` as coarse fallback until vendor-specific verbs are mapped.
- **`event.type` / `event.outcome` vs `event.action`** — RDP dashboards use `event.outcome` for auth success/failure and Intel dashboard references `event.type`; these are outcome/classification fields, not operation verbs per ECS Event field-set.
- **`rdp.cookie` vs `user.*`** — RDP dashboard labels `rdp.cookie` as "Connecting User" but it is a session cookie, not an authenticated principal; do not map to `user.name`/`user.id`.
- **`user_agent.original` vs `user.*`** — HTTP User-Agent strings populate client software correctly; must not be interpreted as user actor.
- **`ssh.inferences: AUTO`** — indicates scripted/automated client behavior, not absence of a human user identity (which is never captured).
- **`observer.*`** identifies the Corelight sensor on every dashboard; it is not the traffic actor or target.
- **Software inventory** — `host_header` + `software.*` describe state observed on a host, not an audit event with caller/target principals.

### Per-stream notes

Bundled dashboards cover conn, dns, http, tls/x509, files, software, notice, intel, ssh, rdp, vpn, suricata_corelight, and vpcflow-enriched conn.

- **conn** — Action: connection observed (`network.protocol`/`network.transport`). Host actor (`source.ip`) and host/service target (`destination.ip`/`destination.port`). Outbound/inbound orientation via `conn.local_orig`/`conn.local_resp`.
- **conn** (vpcflow) — Action: VPC flow log with `capture_source: vpcflow` and `network.direction`. Cloud instance enrichment on `orig_inst.*`/`resp_inst.*`.
- **dns** — Action: DNS query type + response code. `dns.question.name`/`dns.question.type` are primary action/detail fields.
- **http** — Action: HTTP method + URI path. `user_agent.original` is client software, not user actor.
- **tls** / **x509** — Action: TLS handshake / certificate validation. Layer 3 cert and cipher fields dominate.
- **files** — Action: file transfer (`files.tx_hosts`/`files.rx_hosts`). Layer 3 file hash/MIME metadata.
- **software** — No per-event action; inventory sync semantics — host + detected package snapshot.
- **notice** — Action: Zeek notice class (`notice.note`). Primary security "what happened" alongside Suricata alerts.
- **intel** — Action: threat-intel indicator match (`intel.seen.*`). Targets matched IOCs rather than endpoints alone.
- **ssh** / **rdp** / **vpn** — Action: remote-access session + Corelight inference tags. RDP adds auth outcome via `rdp.result`/`event.outcome`.
- **suricata_corelight** — Action: IDS signature rule triggered (`rule.name`, `rule.signature_id`, `event.severity`). Layer 3 detection metadata.

Log Hunting / IP Interrogation dashboards pivot across streams via `event.id`, `network.community_id`, and `log.id.fuid`.

## Example Event Graph (illustrative — no package fixtures)

**Package type: assets-only** — `packages/corelight/manifest.yml` has no `policy_templates:` and no `data_stream/` directory; this repo ships **Kibana dashboards and saved searches only**. Corelight sensors export Zeek/Suricata telemetry to customer `logs-corelight-*` indices via [Corelight ECS templates](https://github.com/corelight/ecs-templates) (outside this package). Patterns below are **field/schema illustrations** from bundled dashboard ES|QL and filter literals — **not** single indexed documents. Do not treat dashboard JSON as sample events.

`event.action` is absent from all dashboard ES|QL under `packages/corelight/`; action labels below come from vendor fields or filter literals only.

### Pattern 1: Zeek TLS certificate notice

**Log type:** `notice` · **Evidence:** `packages/corelight/kibana/dashboard/corelight-7c0946bc-acd0-4ec3-ab3b-8a92853f4a3b.json` (Tier B — filter literal `SSL::Certificate_Expired`); `packages/corelight/kibana/dashboard/corelight-f7da14f0-85db-48e8-a591-1f650af0f618.json` (Tier B — ES|QL on `notice.note`, `source.ip`, `destination.ip`, `network.transport`, `destination.port`)

```
host (source.ip) → SSL::Certificate_Expired (notice.note) → tls service (destination.ip, network.transport, destination.port)
```

#### Actor (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | host — from `source.ip` in Notices dashboard ES|QL |

#### Event action (schema)

| Field | Source |
| --- | --- |
| action | derived label from Zeek notice class |
| source_field | `notice.note` |
| source_value | `SSL::Certificate_Expired` (Security Posture dashboard filter literal) |

#### Target (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | service — responder inferred from `destination.ip`, `network.transport`, `destination.port` (Notices ES|QL concatenates transport/port) |

### Pattern 2: DNS NXDOMAIN response

**Log type:** `dns` · **Evidence:** `packages/corelight/kibana/dashboard/corelight-8546a96c-86c9-4edf-9d46-88338d6ac40e.json` (Tier B — `dns.response_code == "NXDOMAIN"`, `source.ip`, `destination.ip`, `dns.question.name`); `packages/corelight/kibana/dashboard/corelight-58885f47-95e1-4242-a1ee-783de69ace17.json` (Tier B — DNS dashboard NXDOMAIN panel)

```
host (source.ip) → NXDOMAIN (dns.response_code) → domain (dns.question.name, destination.domain)
```

#### Actor (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | host — from `source.ip` in Name Resolution Insights ES|QL |

#### Event action (schema)

| Field | Source |
| --- | --- |
| action | derived label from DNS response code |
| source_field | `dns.response_code` |
| source_value | `NXDOMAIN` (dashboard ES|QL filter literal) |

#### Target (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | general — queried name from `dns.question.name`; `destination.domain` also referenced in DNS dashboard ES|QL |

### Pattern 3: Suricata IDS signature triggered

**Log type:** `suricata_corelight` · **Evidence:** `packages/corelight/kibana/dashboard/corelight-f1208ffe-d168-46d1-9531-24de523d1bfb.json` (Tier B — ES|QL on `source.ip`, `rule.name`, `rule.signature_id`, `event.severity`)

```
host (source.ip) → IDS signature triggered (rule.name) → ids rule (rule.name, rule.signature_id)
```

#### Actor (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | host — from `source.ip` in Suricata IDS Alert Overview ES|QL |

#### Event action (schema)

| Field | Source |
| --- | --- |
| action | derived label — signature triggered |
| source_field | `rule.name` |
| source_value | — (per-event signature name not hard-coded in dashboard asset) |

#### Target (schema)

| Field | Source in indexed data (not a sample value) |
| --- | --- |
| type | general — detection object from `rule.name`, `rule.signature_id` |

## ES|QL Entity Extraction

**Package type: assets-only (Tier B).** Field paths inferred from bundled dashboard ES|QL only; this package defines no ingest pipelines or test fixtures in-repo. `manifest.yml` has no `policy_templates:` and no `data_stream/` — do **not** route on `data_stream.dataset` from this integration (some VPC panels reference `data_stream.dataset == "corelight.conn"` in customer indices; that value is **not** defined by this package). Primary router: **`event.dataset`** (Zeek log type), as in dashboard filters (`event.dataset == "conn"`, `"dns"`, `"notice"`, etc.). Scope with `FROM logs-corelight-*` and optionally `observer.vendor == "Corelight"`. NSM telemetry: actor is **host** (`source.ip`); targets are **host** / **service** / **general** by stream. Pass 4 is **fill-gaps-only**: detection flags (`actor_exists`, `target_exists`, `action_exists`) run first for query semantics; **mapped columns use column-level preserve** (`<col> IS NOT NULL`), not `CASE(actor_exists, <col>, …)` / `CASE(action_exists, event.action, …)` — so HTTP `entity.name` or a populated `entity.target.name` does not block `host.ip` ← `source.ip` or `host.target.ip` ← `destination.ip` (§10 — no identity no-op). Confidence **medium** or **low** (Tier B, not package-fixture verified).

### Dataset inventory

| `event.dataset` (router) | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `conn`, `ssh`, `rdp`, `vpn` | connection / remote access | host | host, service | partial |
| `conn` + `capture_source == "vpcflow"` | VPC flow enrichment | host | host (cloud instance) | partial |
| `dns` | DNS query/response | host | general (domain) | partial |
| `http` | HTTP request | host, general (client software) | general (url/domain) | partial |
| `tls`, `x509` | TLS/cert observation | host | service, host | partial |
| `files` | file transfer | host | host, general (file) | partial |
| `notice`, `intel`, `suricata_corelight` | detection | host | service, general | partial |
| `software` | inventory sync | — | — | none |

### Field mapping plan

**Detection predicate (tuned):** `actor_exists` omits `user.*` — no user principal in dashboard ES|QL. `target_exists` uses standard `*.target.*` columns per Pass 4 v2. **Mapped columns use column-level preserve** (`<col> IS NOT NULL`), not `CASE(actor_exists, <col>, …)` — HTTP `entity.name` can satisfy `actor_exists` while `host.ip` is still empty.

#### Actor mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `host.ip` | `source.ip` | `event.dataset IN ("conn", "dns", "http", "tls", "x509", "notice", "intel", "ssh", "rdp", "vpn", "suricata_corelight", "files") AND source.ip IS NOT NULL` | medium | **column-level preserve** (`host.ip IS NOT NULL`); **fallback** `source.ip` — de-facto flow originator (Tier B) |
| `entity.name` | `user_agent.original` | `event.dataset == "http" AND user_agent.original IS NOT NULL` | low | **column-level preserve** (`entity.name IS NOT NULL`); **fallback** client software — not `user.name` |

#### Target mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `host.target.ip` | `destination.ip` | `event.dataset IN ("conn", "dns", "http", "tls", "x509", "notice", "intel", "ssh", "rdp", "vpn", "suricata_corelight") AND destination.ip IS NOT NULL` | medium | **column-level preserve**; **fallback** de-facto network peer |
| `host.target.id` | `resp_inst.id` | `event.dataset == "conn" AND capture_source == "vpcflow" AND resp_inst.id IS NOT NULL` | medium | **column-level preserve**; **fallback** AWS VPC Flow dashboard (`corelight-caf92ff9-*.json`) |
| `host.target.name` | `files.rx_hosts` | `event.dataset == "files" AND files.rx_hosts IS NOT NULL` | medium | **column-level preserve**; **fallback** Zeek rx_host (Files dashboard) |
| `service.target.name` | `network.protocol` | `event.dataset IN ("conn", "notice", "tls", "rdp") AND network.protocol IS NOT NULL` | medium | **column-level preserve**; **fallback** protocol/service layer |
| `entity.target.name` | `dns.question.name` | `event.dataset == "dns" AND dns.question.name IS NOT NULL` | medium | **column-level preserve**; **fallback** queried FQDN |
| `entity.target.name` | `dest_host` | `event.dataset == "http" AND dest_host IS NOT NULL` | medium | **column-level preserve**; **fallback** HTTP Host header |
| `entity.target.name` | `intel.seen.indicator` | `event.dataset == "intel" AND intel.seen.indicator IS NOT NULL` | medium | **column-level preserve**; **fallback** matched IOC |
| `entity.target.name` | `rule.name` | `event.dataset == "suricata_corelight" AND rule.name IS NOT NULL` | medium | **column-level preserve**; **fallback** Suricata signature |
| `entity.target.name` | `notice.note` | `event.dataset == "notice" AND notice.note IS NOT NULL` | medium | **column-level preserve**; **fallback** Zeek notice class |
| `entity.target.type` | literals | per `event.dataset` (dns/http/intel/suricata/notice) | low | **column-level preserve**; **semantic literal** in fallback only |

#### Event action mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `event.action` | `notice.note` | `event.dataset == "notice" AND notice.note IS NOT NULL` | medium | **column-level preserve** (`event.action IS NOT NULL`); **fallback** — `event.action` absent from dashboards |
| `event.action` | `rule.name` | `event.dataset == "suricata_corelight" AND rule.name IS NOT NULL` | medium | **column-level preserve**; **fallback** |
| `event.action` | `http.request.method` | `event.dataset == "http" AND http.request.method IS NOT NULL` | medium | **column-level preserve**; **fallback** |
| `event.action` | `dns.question.type` | `event.dataset == "dns" AND dns.question.type IS NOT NULL` | medium | **column-level preserve**; **fallback** (coarse; `dns.response_code` alternate) |
| `event.action` | `rdp.result` | `event.dataset == "rdp" AND rdp.result IS NOT NULL` | medium | **column-level preserve**; **fallback** |
| `event.action` | `ssh.inferences` | `event.dataset == "ssh" AND ssh.inferences IS NOT NULL` | medium | **column-level preserve**; **fallback** |
| `event.action` | `vpn.inferences` | `event.dataset == "vpn" AND vpn.inferences IS NOT NULL` | medium | **column-level preserve**; **fallback** |

### Detection flags (mandatory — run first)

Network-only integration: `actor_exists` excludes `user.*` (no authenticated principal in dashboard field usage). **Actor/target/action `EVAL` blocks use column-level preserve** (`<col> IS NOT NULL`) — not `CASE(actor_exists, <col>, …)` / `CASE(action_exists, event.action, …)` — so one populated sibling column does not block fallbacks on empty columns (Pass 4 §10).

```esql
| EVAL
  actor_exists = host.id IS NOT NULL OR host.ip IS NOT NULL OR host.name IS NOT NULL
    OR service.id IS NOT NULL OR service.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
```

### Optional classification helpers

`entity.target.type` literals apply only when `entity.target.type` is null (fallback branch in target `EVAL` below).

### Combined ES|QL — actor fields

```esql
| EVAL
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    event.dataset IN ("conn", "dns", "http", "tls", "x509", "notice", "intel", "ssh", "rdp", "vpn", "suricata_corelight", "files") AND source.ip IS NOT NULL, source.ip,
    null
  ),
  entity.name = CASE(
    entity.name IS NOT NULL, entity.name,
    event.dataset == "http" AND user_agent.original IS NOT NULL, user_agent.original,
    null
  )
```

### Combined ES|QL — event action

```esql
| EVAL
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    event.dataset == "notice" AND notice.note IS NOT NULL, notice.note,
    event.dataset == "suricata_corelight" AND rule.name IS NOT NULL, rule.name,
    event.dataset == "http" AND http.request.method IS NOT NULL, http.request.method,
    event.dataset == "dns" AND dns.question.type IS NOT NULL, dns.question.type,
    event.dataset == "rdp" AND rdp.result IS NOT NULL, rdp.result,
    event.dataset == "ssh" AND ssh.inferences IS NOT NULL, ssh.inferences,
    event.dataset == "vpn" AND vpn.inferences IS NOT NULL, vpn.inferences,
    null
  )
```

### Combined ES|QL — target fields

Uses `user.target.*` / `host.target.*` / `service.target.*` / `entity.target.*` only — never `target.user.*` or `target.entity.type`.

```esql
| EVAL
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    event.dataset IN ("conn", "dns", "http", "tls", "x509", "notice", "intel", "ssh", "rdp", "vpn", "suricata_corelight") AND destination.ip IS NOT NULL, destination.ip,
    null
  ),
  host.target.id = CASE(
    host.target.id IS NOT NULL, host.target.id,
    event.dataset == "conn" AND capture_source == "vpcflow" AND resp_inst.id IS NOT NULL, resp_inst.id,
    null
  ),
  host.target.name = CASE(
    host.target.name IS NOT NULL, host.target.name,
    event.dataset == "files" AND files.rx_hosts IS NOT NULL, files.rx_hosts,
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    event.dataset IN ("conn", "notice", "tls", "rdp") AND network.protocol IS NOT NULL, network.protocol,
    null
  ),
  entity.target.name = CASE(
    entity.target.name IS NOT NULL, entity.target.name,
    event.dataset == "dns" AND dns.question.name IS NOT NULL, dns.question.name,
    event.dataset == "http" AND dest_host IS NOT NULL, dest_host,
    event.dataset == "intel" AND intel.seen.indicator IS NOT NULL, intel.seen.indicator,
    event.dataset == "suricata_corelight" AND rule.name IS NOT NULL, rule.name,
    event.dataset == "notice" AND notice.note IS NOT NULL, notice.note,
    null
  ),
  entity.target.type = CASE(
    entity.target.type IS NOT NULL, entity.target.type,
    event.dataset == "dns", "domain",
    event.dataset == "http", "url",
    event.dataset == "intel", "indicator",
    event.dataset == "suricata_corelight", "ids_rule",
    event.dataset == "notice", "notice",
    null
  )
```

### Full pipeline fragment (optional)

```esql
FROM logs-corelight-*
| EVAL
  actor_exists = host.id IS NOT NULL OR host.ip IS NOT NULL OR host.name IS NOT NULL
    OR service.id IS NOT NULL OR service.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
| EVAL
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    event.dataset IN ("conn", "dns", "http", "tls", "x509", "notice", "intel", "ssh", "rdp", "vpn", "suricata_corelight", "files") AND source.ip IS NOT NULL, source.ip,
    null
  ),
  entity.name = CASE(
    entity.name IS NOT NULL, entity.name,
    event.dataset == "http" AND user_agent.original IS NOT NULL, user_agent.original,
    null
  ),
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    event.dataset == "notice" AND notice.note IS NOT NULL, notice.note,
    event.dataset == "suricata_corelight" AND rule.name IS NOT NULL, rule.name,
    event.dataset == "http" AND http.request.method IS NOT NULL, http.request.method,
    event.dataset == "dns" AND dns.question.type IS NOT NULL, dns.question.type,
    event.dataset == "rdp" AND rdp.result IS NOT NULL, rdp.result,
    event.dataset == "ssh" AND ssh.inferences IS NOT NULL, ssh.inferences,
    event.dataset == "vpn" AND vpn.inferences IS NOT NULL, vpn.inferences,
    null
  ),
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    event.dataset IN ("conn", "dns", "http", "tls", "x509", "notice", "intel", "ssh", "rdp", "vpn", "suricata_corelight") AND destination.ip IS NOT NULL, destination.ip,
    null
  ),
  host.target.id = CASE(
    host.target.id IS NOT NULL, host.target.id,
    event.dataset == "conn" AND capture_source == "vpcflow" AND resp_inst.id IS NOT NULL, resp_inst.id,
    null
  ),
  host.target.name = CASE(
    host.target.name IS NOT NULL, host.target.name,
    event.dataset == "files" AND files.rx_hosts IS NOT NULL, files.rx_hosts,
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    event.dataset IN ("conn", "notice", "tls", "rdp") AND network.protocol IS NOT NULL, network.protocol,
    null
  ),
  entity.target.name = CASE(
    entity.target.name IS NOT NULL, entity.target.name,
    event.dataset == "dns" AND dns.question.name IS NOT NULL, dns.question.name,
    event.dataset == "http" AND dest_host IS NOT NULL, dest_host,
    event.dataset == "intel" AND intel.seen.indicator IS NOT NULL, intel.seen.indicator,
    event.dataset == "suricata_corelight" AND rule.name IS NOT NULL, rule.name,
    event.dataset == "notice" AND notice.note IS NOT NULL, notice.note,
    null
  ),
  entity.target.type = CASE(
    entity.target.type IS NOT NULL, entity.target.type,
    event.dataset == "dns", "domain",
    event.dataset == "http", "url",
    event.dataset == "intel", "indicator",
    event.dataset == "suricata_corelight", "ids_rule",
    event.dataset == "notice", "notice",
    null
  )
| KEEP @timestamp, event.dataset, event.action, source.ip, destination.ip, host.ip, host.target.ip, host.target.id, host.target.name, service.target.name, entity.target.name, entity.target.type, entity.name
```

### Streams excluded

- **`software`** — inventory snapshot on `host_header` + `software.*`; no per-event actor/target chain (Software dashboard `corelight-40bbc19b-*.json`).
- **Events without `source.ip` in dashboard field usage** — omit actor `host.ip` fallback rather than guess.

### Gaps and limitations

- **Column-level preserve (§10)** — `actor_exists` / `target_exists` / `action_exists` are query-time helpers only; mapped columns use `<col> IS NOT NULL` as the first `CASE` branch. Anti-patterns: `CASE(actor_exists, host.ip, source.ip, null)` when HTTP `entity.name` is set but `host.ip` is empty; `CASE(action_exists, event.action, notice.note, null)` (4 args — `notice.note` becomes a **condition**, not a value). Use 5-arg: `CASE(event.action IS NOT NULL, event.action, event.dataset == "notice" AND notice.note IS NOT NULL, notice.note, null)`. Never `CASE(col, col, …)` identity branches.
- **ES|QL `CASE` arity** — arguments are **(condition, value)** pairs; odd count → last arg is default. Wrong: `CASE(user.name IS NOT NULL, user.name, user.full_name, null)` (4 args). Right: `CASE(user.name IS NOT NULL, user.name, user.full_name)` (3 args).
- **No `data_stream.dataset` from this package** — router uses `event.dataset` per dashboard ES|QL only; ingest mapping is external ([Corelight ECS templates](https://github.com/corelight/ecs-templates)).
- **`user.*` / `user.target.*` omitted** — no `user.id` / `user.name` in dashboard ES|QL; `rdp.cookie` and `user_agent.original` must not map to user actor/target.
- **`host.name` / `host.id` (actor) omitted** — no hostname or host-id fields in dashboard ES|QL for flow originator; vpcflow uses `resp_inst.id` → `host.target.id` only.
- **`destination.*` is network context** — mapped to `host.target.*` as de-facto peer, not audit user/host target (aligned with Pass 2 **Enhancement candidate?** = none).
- **`event.action` not indexed in dashboards** — fallback uses vendor fields; omit action `EVAL` if customer export already populates `event.action` differently.
- **`conn` / `tls` / `x509` / `files` action** — no single dashboard verb; `network.protocol` or file hash fields omitted from action block to avoid coarse false positives.
- **Field presence unverified** — Tier B dashboard references only; downgrade or omit mappings if indexed layout differs from customer export.
