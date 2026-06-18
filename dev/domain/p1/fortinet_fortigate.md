# fortinet_fortigate

## Product Domain

FortiGate is Fortinet's next-generation firewall (NGFW) platform, running the FortiOS operating system on physical appliances, virtual machines, and cloud instances. Positioned at network perimeters and internal segmentation boundaries, FortiGate enforces stateful firewall policies that allow or deny traffic based on source, destination, application, user identity, and security profile. Beyond basic packet filtering, FortiGate provides Unified Threat Management (UTM) capabilities—intrusion prevention (IPS), antivirus, web filtering, application control, DNS filtering, and SSL/TLS inspection—applied inline as traffic traverses the device.

FortiGate is a central component of Fortinet's Security Fabric, integrating with FortiAnalyzer, FortiManager, FortiClient, and other Fortinet products for centralized logging, policy orchestration, and endpoint telemetry. Deployments commonly span branch offices, data centers, and cloud environments, with high-availability (HA) clustering, virtual domains (VDOMs) for multi-tenant isolation, and IPsec/SSL VPN for remote access and site-to-site connectivity. Administrators configure policies, profiles, and routing through the GUI or CLI, and the device generates detailed syslog records for every security-relevant decision.

From a security operations perspective, FortiGate logs are the primary audit trail for perimeter defense: which sessions were permitted or blocked, which UTM modules triggered on a flow, who authenticated via VPN or admin login, and what system or configuration events occurred. Security teams rely on these logs for SIEM correlation, threat hunting, compliance auditing, incident investigation, and monitoring VPN health, policy effectiveness, and UTM detection coverage across the estate.

## Data Collected (brief)

The integration collects FortiGate syslog via Elastic Agent over **TCP**, **UDP**, or **logfile** input into a single **log** data stream (`fortinet_fortigate.log`). Log types include:

| Category | Description |
|---|---|
| **Traffic** | Firewall allow/deny decisions with session metadata (source/destination IPs and ports, interfaces, policy ID, bytes/packets, NAT) |
| **UTM** | Security profile events—application control, web filter, IPS, antivirus, DNS filter, DLP, and related subtypes |
| **Event** | System events, HA failover, configuration changes, and operational alerts |
| **Authentication** | VPN, administrator, and user login/logout events |

Events are parsed from FortiOS key-value syslog format (tested on FortiOS 6.x and 7.x) into ECS fields (`source`, `destination`, `network`, `observer`, `rule`, `url`, `dns`, `tls`, etc.) with vendor-specific details retained under `fortinet.firewall.*`. A bundled Kibana dashboard ("Fortinet FortiGate Overview") visualizes traffic, UTM, and authentication activity.

## Expected Audit Log Entities

FortiGate syslog is session- and flow-centric across a single **`log`** data stream. **`fortinet.firewall.type=traffic`** and **`utm`/`dns`** are audit-adjacent network telemetry (allow/deny decisions, UTM detections); **`type=event`** covers VPN, FSSO/user auth, FortiClient endpoint, HA, config, and system events; admin **`login`** events are routed to a dedicated login sub-pipeline when the message contains "login"/"logged in". The integration has rich actor identity on flows and auth events but **no ECS `*.target.*` fields** are populated today (`dev/target-fields-audit/out/target_fields_audit.csv` — no rows for this package). The target-fields audit classified this package as **`strong_candidate`** with **`pipeline_dest_identity=true`**, **`pipeline_actor=true`**, and **`fixture_strong=true`** (`dev/target-fields-audit/out/target_enhancement_packages.csv`). **`destination.user.name`** is the sole **`destination.user.*`** pipeline mapping, listed in **`destination_identity_hits.csv`**. **`event.action`** is populated for **traffic**, **UTM/DNS**, and **login** sub-types but **absent for most `type=event` logs** where `fortinet.firewall.action` retains the vendor operation name unmapped. Evidence: `packages/fortinet_fortigate/data_stream/log/sample_event.json`, `data_stream/log/_dev/test/pipeline/test-fortinet.log-expected.json`, `test-fortinet-7-4.log-expected.json`, and ingest pipelines `default.yml`, `traffic.yml`, `utm.yml`, `event.yml`, `login.yml`.

### Event action (semantic)

FortiGate logs carry two related action concepts: **`action`** (session outcome or operational verb) and **`eventtype`** (UTM module event name). The pipeline maps these to ECS `event.action` differently per sub-type.

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| `accept`, `deny`, `close`, `start`, `server-rst`, `client-rst`, `ip-conn`, `timeout` | data_access / network | high | `event.action` ← `fortinet.firewall.action` in traffic fixtures (`test-fortinet.log-expected.json`: `deny`, `accept`, `close`; `test-fortinet-7-4.log-expected.json`: `timeout`) | **`traffic`** — session lifecycle / firewall policy outcome; not an admin operation |
| `app-ctrl-all`, `dns-query`, `dns-response`, `signature`, `ssl-anomalies`, `ssl-negotiation`, `ssl-exempt`, `ftgd_blk`, `ftgd_allow`, `infected`, `dlp`, `ssh-channel`, `cifs-filefilter`, `voip`, `anomaly` | detection / data_access | high | `event.action` ← `fortinet.firewall.eventtype` via `default.yml:375-380` rename when unset; `sample_event.json` (`app-ctrl-all`), fixtures (`dns-query`, `signature`, `ssl-anomalies`, `ftgd_blk`, `infected`, `dlp`) | **`utm`/`dns`** — UTM module event name; parallel `fortinet.firewall.action` holds pass/block/detect outcome |
| `login` | authentication | high | Static `event.action: login` in `login.yml:8-12`; admin SSH/HTTPS login fixtures (`test-fortinet.log-expected.json`, `test-fortinet-7-4.log-expected.json`) | **`login`** sub-pipeline (message-triggered); overrides vendor `action=login` on same field |
| `FSSO-logon`, `FSSO-logoff`, `auth-logon`, `auth-logout` | authentication | high (vendor) | `fortinet.firewall.action` only — **no** `event.action` in fixtures (`test-fortinet.log-expected.json` FSSO-logon/logoff events) | **`event`** (`subtype=user`) — user auth lifecycle; enhancement gap |
| `negotiate`, `tunnel-up`, `tunnel-stats`, `authentication`, `add`, `close`, `connect`, `disconnect` | authentication / network | high (vendor) | `fortinet.firewall.action` in VPN/endpoint fixtures; `event.action` absent (`test-fortinet.log-expected.json`, `test-fortinet-7-4.log-expected.json`) | **`event`** (`subtype=vpn`, `endpoint`) — VPN tunnel lifecycle |
| `perf-stats`, `object-add`, `object-remove`, `Health Check`, `SLA`, `Cellular Connected` | administration / configuration_change | medium (vendor) | Vendor `action` in `test-fortinet-6-2.log-expected.json`, `test-fortinet-7-4.log-expected.json`; no ECS `event.action` | **`event`** (`subtype=system`, `update`, perf/HA/cellular) — operational telemetry |

Traffic and UTM streams have consistent `event.action` coverage. **`type=event`** logs are the primary gap: FortiOS uses the `action` KV field for operational verbs but the pipeline only backfills `event.action` from `fortinet.firewall.eventtype` (UTM-specific), leaving VPN, FSSO, FortiClient, and system events without ECS action.

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| `fortinet.firewall.action` → `event.action` | yes (**traffic** only) | yes | `accept`, `deny`, `close`, `start`, `server-rst`, `client-rst` | no | `traffic.yml:8-12` `set` when `type=traffic`; deny/accept/close fixtures |
| `fortinet.firewall.eventtype` → `event.action` | yes (**utm**/**dns**, fallback) | yes | `app-ctrl-all`, `dns-query`, `dns-response`, `signature`, `ssl-anomalies`, `infected`, `dlp` | no | `default.yml:375-380` rename when `ctx.event?.action == null`; `sample_event.json`, UTM fixtures |
| Static `"login"` → `event.action` | yes (**login** sub-pipeline) | yes | `login` | no | `login.yml:8-12`; SSH/HTTPS admin login fixtures |
| `fortinet.firewall.action` (retained, **event** type) | **no** | n/a | `FSSO-logon`, `FSSO-logoff`, `negotiate`, `tunnel-up`, `add`, `auth-logon`, `perf-stats` | **yes** | Vendor field populated in `type=event` fixtures; never copied to `event.action` — event pipeline (`event.yml`) does not set action |
| `fortinet.firewall.action` (retained, **utm** outcome) | partial | partial | `pass`, `block`, `blocked`, `detected`, `dropped`, `exempt`, `passthrough` | partial | Session/UTM **outcome** on same field name as traffic session action; drives `event.type`/`event.outcome` in `utm.yml` but not `event.action` when `eventtype` already set |
| `fortinet.firewall.subtype` | no | n/a | — | no | Log sub-category (`forward`, `vpn`, `app-ctrl`, `user`); complements action, not a substitute |
| `fortinet.firewall.logdesc` → `rule.description` | no | n/a | — | partial | Human-readable event summary (e.g. "FSSO logon authentication status"); useful display, not normalized action |
| `event.type` / `event.category` / `event.outcome` | n/a | partial | Derived (`allowed`, `denied`, `connection`, `authentication`, …) | no | Enrichment keyed on action fields; do not substitute for `event.action` |

**Step 2b — per-stream check:**

| Stream | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `log` — traffic (`type=traffic`) | yes | yes | `fortinet.firewall.action` | high | `traffic.yml:8-12`; accept/deny/close in all traffic fixture files |
| `log` — UTM/DNS (`type=utm`/`dns`) | yes | yes (via `eventtype` rename) | `fortinet.firewall.eventtype` | high | `default.yml:375-380`; `sample_event.json` (`app-ctrl-all`); dns-query/signature/ssl fixtures |
| `log` — login (message-triggered) | yes | yes | static `login` | high | `login.yml:8-12`; SSH/HTTPS login fixtures in `test-fortinet.log-expected.json` |
| `log` — event (`type=event`) | **no** (fixtures) | **no** | `fortinet.firewall.action` | high | FSSO-logon, negotiate, tunnel-up, add, auth-logon in vendor field only; `eventtype` rename never fires (field absent on event logs) |

### Actor (semantic)

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| Flow originator (internal endpoint) | host | — | high | `source.ip`, `source.port`, `source.mac`, `source.bytes`/`source.packets` ← `srcip`/`srcport`/`srcmac`/`sentbyte`/`sentpkt` (`traffic.yml`, `utm.yml`); deny/accept/close samples in `test-fortinet.log-expected.json` | **`traffic`**, **`utm`/`dns`** — default actor for forward/local traffic |
| Source hostname | host | — | high | `host.name` ← lowercase `fortinet.firewall.srcname` (`default.yml`); `HOSTNAME-FOR-PC` → `hostname-for-pc` in traffic deny fixture (`test-fortinet.log-expected.json`) | **`traffic`** — enriches source-side endpoint; also in `related.hosts` |
| Identity-aware flow user | user | — | high | `source.user.name` ← `user` or `unauthuser`; `source.user.group.name` ← `group` (`traffic.yml`, `utm.yml`); `elasticuser`/`elasticuser2` in webfilter/app-ctrl/SSL fixtures; Kerberos `unauthuser="USER-NAME"` → `source.user.name` in traffic deny fixture | **`traffic`**, **`utm`/`dns`** — authenticated or passively identified user on the initiating side |
| VPN remote client | host | — | high | After `remip`/`locip` swap (`event.yml` script): remote peer → `source.ip`/`source.port`; IPsec negotiate and SSL tunnel-up samples (`test-fortinet.log-expected.json`, `test-fortinet-7-4.log-expected.json`) | **`event`** (`subtype=vpn`) — swap makes remote client the actor |
| VPN XAuth user | user | — | high | `source.user.name` ← `fortinet.firewall.xauthuser` when `subtype=vpn` (`event.yml`); `someuser` on SSL tunnel-up, `user1` on IPsec tunnel-stats (`test-fortinet.log-expected.json`, `test-fortinet-7-4.log-expected.json`) | **`event`** (`subtype=vpn`) — explicit VPN user identity when XAuth is set |
| FSSO / user logon-off subject | user | — | high | `source.user.name` ← `user`; `source.ip` ← `srcip` (`event.yml`); FSSO-logon `elasticouser`, FSSO-logoff `elasticadmin` fixtures | **`event`** (`subtype=user`, actions `FSSO-logon`/`FSSO-logoff`/`auth-logon`/`auth-logout`) |
| FortiClient connecting user | user | — | high | `source.user.name` ← `user` (`event.yml`); `skubas`/`elastico` on FortiClient add/close (`test-fortinet-7-4.log-expected.json`, `test-fortinet.log-expected.json`) | **`event`** (`subtype=endpoint`) — user is actor; endpoint device is target (vendor fields) |
| Administrator / portal login user | user | — | high | `user.name`, `source.user.name` ← dissected from message or `fortinet.firewall.user`; `user.roles`/`source.user.roles` ← `adminprof` or role prefix (`login.yml`, `default.yml`); `philipp`/`Super_User` successful login, SSH/HTTPS failure fixtures | **`login`** (message-triggered sub-pipeline) and **`event`** (`subtype=system` with login desc) |
| Admin login client endpoint | host | — | high | `source.ip`, `source.port` from message dissect or `userfrom="JSON(192.168.0.10)"` dissect (`login.yml`); `192.168.0.10` in successful login fixture | **`login`** |
| HTTP client user-agent | general | http_client | moderate | `user_agent.original` ← `fortinet.firewall.agent` (`utm.yml`); `curl/7.47.0` in virus sample (`test-fortinet-7-4.log-expected.json`) | **`utm`** — client software context, not a security principal |
| Email sender (filter subtypes) | general | email_sender | moderate | `email.from.address`/`email.sender.address` ← `from`/`sender` (`utm.yml`); pipeline only, no fixture | **`utm`** (email-filter subtypes) |

System/HA/update/perf events (`subtype=system`, `update`, `perf-stats`) often have no distinct human actor beyond the logging **`observer.*`** appliance identity.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `source.ip`, `source.port`, `source.mac` | Flow/VPN client endpoint | yes | yes | high | `traffic.yml`, `utm.yml`, `event.yml`; populated in traffic/UTM/VPN fixtures |
| `source.user.name` | Identity-aware flow user, VPN XAuth user, FSSO/user auth subject | yes | yes | high | ← `user`/`unauthuser` (`traffic.yml`, `utm.yml`); ← `xauthuser` when `subtype=vpn` (`event.yml`); FSSO-logon fixture |
| `source.user.group.name` | User group on flow/VPN | yes | yes | high | ← `group` (`traffic.yml`, `utm.yml`, `event.yml`); `elasticgroup`/`somegroup` in fixtures |
| `source.user.roles` | Admin profile / dissected role | yes | yes | high | ← `adminprof` or grok `_tmp.user.roles` (`login.yml`); `Super_User`, `Administrator` in login fixtures |
| `user.name` | Canonical admin/flow user copy | yes | yes | high | Copied from `source.user.name` in `default.yml`; set from dissect in `login.yml` |
| `user.roles` | Admin profile | yes | yes | high | ← `fortinet.firewall.adminprof` (`login.yml`) |
| `host.name` | Source-side hostname | yes | partial | high | ← lowercase `srcname` (`default.yml`); maps source hostname, not a generic host actor field per ECS |
| `user_agent.original` | HTTP client software | yes | yes | moderate | ← `agent` (`utm.yml`) |
| `related.user` | Enrichment array | yes | yes | high | Appends `source.user.name` and `destination.user.name` (`default.yml:747-755`) |
| `fortinet.firewall.unauthusersource` | Kerberos/passive ID source | yes (vendor) | n/a | moderate | Retained vendor field; `kerberos` on traffic deny with `unauthuser` fixture |
| `fortinet.firewall.authserver` | External auth server name on UTM flows | yes (vendor) | n/a | moderate | Present in webfilter fixtures (`elasticauth`); not mapped to ECS actor |
| `fortinet.firewall.xauthuser` | VPN XAuth username (vendor copy) | yes (vendor) | n/a | high | Also copied to `source.user.name` for `subtype=vpn`; tunnel-stats fixture |
| `observer.name`, `observer.serial_number`, `observer.product`, `observer.vendor`, `observer.type` | Logging FortiGate appliance | yes | yes | high | Set in `default.yml`; all fixtures — observer identity, not the human actor |

### Target (semantic)

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2 — Resource / object | Session remote peer (IP/MAC/NAT) | Remote host / server | host | — | high | `destination.ip`, `destination.port`, `destination.mac`, `destination.nat.ip`, `destination.address` ← `dstname` (`traffic.yml`, `utm.yml`, `event.yml`); forward allow/deny/UTM samples | **`traffic`**, **`utm`/`dns`** — network peer; primary Layer 2 target for flows |
| 2 — Resource / object | Inspected application / protocol | Network service | service | — | high | `network.application`, `network.protocol`, `network.transport` ← `app`/`service`/`proto` (`traffic.yml`, `utm.yml`); Skype/HTTPS/DNS/SSL samples | **`traffic`**, **`utm`/`dns`** |
| 2 — Resource / object | Destination-side user identity on flow | Remote/unauth user | user | — | moderate | `destination.user.name` ← `dstunauthuser` (`traffic.yml:115-117`); appended to `related.user` (`default.yml:752-755`); **no pipeline fixture** | **`traffic`** only — de-facto target user when FortiOS reports destination-side unauthenticated identity |
| 2 — Resource / object | VPN local firewall endpoint (post-swap) | FortiGate VPN interface | host | — | high | After `remip`/`locip` swap: local endpoint → `destination.ip`/`destination.port` (`event.yml`); IPsec negotiate where remip≠locip | **`event`** (`subtype=vpn`) |
| 2 — Resource / object | VPN tunnel resource | VPN tunnel | service | — | high | `fortinet.firewall.vpntunnel`, `fortinet.firewall.tunnelip`, `fortinet.firewall.tunneltype`, `fortinet.firewall.tunnelid` (`event.yml`; vendor-retained); tunnel-up, tunnel-stats, IPsec progress logs | **`event`** (`subtype=vpn`) |
| 2 — Resource / object | FortiClient managed endpoint | Endpoint device | host | — | high | `fortinet.firewall.name`, `fortinet.firewall.ip`, `fortinet.firewall.fctuid` (vendor-only); `VAN-200957-PC`/`skubas` FortiClient add/close fixtures | **`event`** (`subtype=endpoint`) — user is actor, endpoint is target |
| 2 — Resource / object | FortiGate management plane (admin access target) | Management service | service | — | high | `destination.ip` on admin login events where `dstip` present (`event.yml`, login context); SSH/HTTPS login failure samples with `dstip=10.123.26.24x` | **`login`**, auth-related **`event`** |
| 2 — Resource / object | Config / address objects | Address or group | host | — | moderate | `fortinet.firewall.addr`, `fortinet.firewall.addrgrp`, `destination.address` ← `daddr`/`dst_host` (`event.yml`); sparse fixture coverage | **`event`** (`subtype=system` config changes) |
| 2 — Resource / object | External auth / FSSO server | Auth server | general | auth_server | moderate | `fortinet.firewall.authserver`, `fortinet.firewall.server` (vendor-only); FSSO-logon `server="elasticserver"` fixture | **`event`** (`subtype=user`), **`utm`** (`authserver` on identity-aware flows) |
| 3 — Content / artifact | Web destination URL | HTTP URL | general | url | high | `url.domain`, `url.path`, `url.full` ← `hostname`/`url` (`utm.yml`, `traffic.yml`); dailymotion, elastic.co, proxy-policy deny with `url=` | **`utm`/`dns`**, proxy-policy **`traffic`** |
| 3 — Content / artifact | DNS query / response | DNS name | general | dns_name | high | `dns.question.name`, `dns.resolved_ip`, `dns.question.type` (`utm.yml`); dns-query/dns-response fixtures | **`utm`** (`subtype=dns`) |
| 3 — Content / artifact | Antivirus / DLP file | File object | general | file | high | `file.name`, `file.size`, `file.extension` ← `filename`/`infectedfilename`/`matchedfilename` (`utm.yml`); `eicar.com` virus fixture | **`utm`** (antivirus/DLP subtypes) |
| 3 — Content / artifact | Email recipient | Mailbox user | user | — | moderate | `email.to.address` ← `recipient`/`dstcollectedemail` (`utm.yml`, `traffic.yml`); pipeline only | **`utm`** (email-filter), **`traffic`** (collected email) |
| 3 — Content / artifact | TLS server certificate | X.509 cert | general | tls_certificate | moderate | `tls.server.x509.*`, `tls.server.issuer` ← `scertcname`/`scertissuer` (`utm.yml`); `sample_event.json`, SSL anomaly samples | **`utm`** (SSL inspection) |

Layer 1 (invoked cloud/SaaS platform) does not apply — FortiGate is on-premises/network-edge telemetry, not a cloud API audit log. System/update/HA events target the FortiGate itself (`observer.name`, `observer.serial_number`) with no separate ECS target entity.

### Target (ECS candidates)

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `destination.ip`, `destination.port`, `destination.mac`, `destination.nat.ip` | 2 | host | yes | partial | context-only (network peer) | no | ← `dstip`/`dstport`/`dstmac`/`tranip` (`traffic.yml`, `utm.yml`); network session far-end — correct for flow semantics, not audit `host.target.*` |
| `destination.address` | 2 | host | yes | partial | `host.target.name` | yes | ← `dstname`/`daddr`/`dst_host` (`traffic.yml`, `event.yml`); hostname/FQDN of peer — de-facto host target name |
| `destination.domain` | 2 | host | yes | partial | `host.target.name` | yes | ← `tls.client.server_name` via SNI (`utm.yml:528-533`); remote server name on UTM flows |
| `destination.user.name` | 2 | user | yes (pipeline) | yes | `user.target.name` | **yes** | ← `fortinet.firewall.dstunauthuser` (`traffic.yml:115-117`); **de-facto Layer 2 user target** — destination-side unauthenticated identity on identity-aware traffic policies; appended to `related.user` (`default.yml:751-755`); **listed in `destination_identity_hits.csv`**. **No test fixture** includes `dstunauthuser`; mapping is pipeline-proven only |
| `destination.user.email` | 2 | user | no | n/a | `user.target.email` | **yes** | Declared in `ecs.yml`; **never populated** — `fortinet.firewall.dstcollectedemail` maps to `email.to.address` instead (`traffic.yml:105-108`, `utm.yml`) |
| `destination.user.group.name` | 2 | user | no | n/a | `user.target.group.name` | yes | Declared in `ecs.yml`; no pipeline mapping; no vendor `dstgroup` rename found |
| `fortinet.firewall.dstunauthusersource` | 2 | user | yes (vendor) | n/a | context / `user.target.*` | partial | Vendor field in `fields.yml`; passive-ID source for destination-side user (analogous to `unauthusersource` on source); not ECS-mapped |
| `network.application`, `network.protocol`, `network.transport` | 2 | service | yes | yes | `service.target.name` | yes | ← `app`/`service`/`proto` (`traffic.yml`, `utm.yml`); inspected application layer |
| `url.*` | 3 | general | yes | yes | context-only | no | `uri_parts`/`hostname`/`url` (`utm.yml`, `traffic.yml`); web content artifact |
| `dns.question.name`, `dns.resolved_ip` | 3 | general | yes | yes | context-only | no | ← `qname`/`ipaddr` (`utm.yml`); DNS filter content |
| `file.name`, `file.size`, `file.extension` | 3 | general | yes | yes | context-only | no | ← `filename`/`infectedfilename`/`matchedfilename` (`utm.yml`) |
| `email.to.address` | 2/3 | user | yes | yes | `user.target.email` | yes | ← `recipient`/`dstcollectedemail` (`utm.yml`, `traffic.yml`); email recipient as de-facto user target |
| `tls.server.x509.*`, `tls.server.issuer` | 3 | general | yes | yes | context-only | no | ← `scertcname`/`scertissuer`/cert fields (`utm.yml`) |
| `fortinet.firewall.vpntunnel`, `.tunnelip`, `.tunneltype`, `.tunnelid`, `.assignip` | 2 | service | yes (vendor) | n/a | `service.target.name` | yes | Vendor-retained VPN tunnel identity; tunnel-up/tunnel-stats fixtures |
| `fortinet.firewall.name`, `.ip`, `.fctuid` | 2 | host | yes (vendor) | n/a | `host.target.name` | yes | FortiClient endpoint target; add/close fixtures (`test-fortinet-7-4.log-expected.json`) |
| `fortinet.firewall.addr`, `.addrgrp` | 2 | host | yes (vendor) | n/a | `entity.target.id` | yes | Config-change address/group objects (`event.yml`); vendor-only |
| `fortinet.firewall.authserver`, `.server` | 2 | general | yes (vendor) | n/a | `service.target.name` | yes | External auth/FSSO server reference; not ECS-mapped |
| `fortinet.firewall.slatargetid` | 2 | general | yes (vendor) | n/a | `entity.target.id` | yes | SLA target ID in fields.yml / `test-fortinet-7-4.log-expected.json`; vendor-only |
| `observer.name`, `observer.serial_number` | — | host | yes | n/a | context-only | no | Logging appliance identity (`default.yml`); observer, not acted-upon target |

### Gaps and mapping notes

- **No ECS `user.target.*`, `host.target.*`, `service.target.*`, or `entity.target.*`** — target-fields audit confirms zero mapped official target fields; enhancement priority is **`strong_candidate`**.
- **`destination.user.*` de-facto target analysis:**
  - **`destination.user.name`** ← `fortinet.firewall.dstunauthuser` (`traffic.yml:115-117`) is the **only populated `destination.user.*` field**. Semantically it is a **de-facto Layer 2 user target**: the destination-side unauthenticated user identity FortiOS reports on identity-aware **traffic** policies (reverse/internal flows), **not** a network-flow far-end IP. Distinct from actor-side `source.user.name` ← `user`/`unauthuser`. **`Mapping correct? yes`** for audit-target semantics when populated. **`Enhancement candidate: yes`** → migrate to `user.target.name`. Listed in **`destination_identity_hits.csv`** (lines 94–95). **No test fixture** includes `dstunauthuser`; evidence is pipeline-only.
  - **`destination.user.email`** — declared in `ecs.yml` but **never populated**. `fortinet.firewall.dstcollectedemail` routes to **`email.to.address`** (`traffic.yml:105-108`) instead — email recipient semantics overlap with user-target email; consider dual-mapping to `user.target.email`.
  - **`destination.user.group.name`** — declared in `ecs.yml`; **no pipeline mapping** and no vendor rename found.
  - **`related.user`** aggregates both actor (`source.user.name`) and de-facto target user (`destination.user.name`) without role distinction (`default.yml:745-755`) — useful for correlation but obscures actor vs target analytics.
- **`event.action` gaps — `type=event` logs:** `fortinet.firewall.action` carries rich operational verbs (`FSSO-logon`, `negotiate`, `tunnel-up`, `add`, `auth-logon`, `perf-stats`, …) but the pipeline never copies them to `event.action`. Only the **`eventtype` → `event.action`** fallback exists (`default.yml:375-380`), which UTM logs use but event logs lack. **Recommended enhancement:** `set` or `rename` `fortinet.firewall.action` → `event.action` in `event.yml` (or default pipeline for `type=event`) when `event.action` is null — same pattern as `traffic.yml`.
- **Dual `action` semantics on UTM:** `event.action` holds the UTM module event name (`eventtype`, e.g. `app-ctrl-all`) while `fortinet.firewall.action` retains session outcome (`pass`, `block`, `detected`). Both are valid; do not collapse into one field without preserving outcome in `event.type`/`event.outcome`.
- **`host.name`** maps **`srcname`** (source-side hostname) — actor-side enrichment, not a target field; do not interpret as `host.target.*`.
- **`source.user.name`** from `unauthuser` on Kerberos-identified flows (`unauthusersource="kerberos"`) is the **actor** (initiating user), correctly distinct from **`destination.user.name`** (`dstunauthuser`) for reverse-destination identity.
- **VPN `remip`/`locip` swap** (`event.yml`) inverts source/destination: remote client becomes actor (`source.*`), local FortiGate VPN endpoint becomes `destination.ip` — network-context destination, semantically the VPN service endpoint rather than an external target host.
- **Admin login** events populate actor (`user.name`, `source.ip`) and `event.action: login`, but the accessed management plane is only partially captured as `destination.ip` when `dstip` is present; **`observer.*`** represents the FortiGate appliance, not the admin's target service.
- **Vendor-only target identity** retained under `fortinet.firewall.*`: VPN tunnel metadata, FortiClient endpoint (`name`/`ip`/`fctuid`), config objects (`addr`/`addrgrp`), auth servers (`authserver`/`server`), SLA target ID — best sources for future ECS target migration.
- **Alignment with target-fields audit:** `strong_candidate` with `pipeline_dest_identity=true` and `pipeline_actor=true` matches evidence — rich flow/auth actor identity via `source.user.*`, single de-facto `destination.user.name` target mapping, zero official `*.target.*` fields, strong fixture coverage except `dstunauthuser`.

### Per-stream notes

#### `log` — traffic (`fortinet.firewall.type=traffic`)

Default actor is the **flow originator** (`source.ip`, optional `source.user.name`, `host.name`). Primary target is the **session peer** (`destination.ip`/`port`) and **inspected service** (`network.application`). **`event.action`** ← `fortinet.firewall.action` records session lifecycle (`accept`, `deny`, `close`, …). **`destination.user.name`** ← `dstunauthuser` is the de-facto destination-side user target when FortiOS reports it on reverse/internal identity-aware flows — the primary **`destination.user.*`** audit-target field for this integration. Proxy-policy traffic may add **`url.*`** as Layer 3 content.

#### `log` — UTM / DNS (`type=utm` or `type=dns`)

Same flow actor/target pattern as traffic. **`event.action`** ← `fortinet.firewall.eventtype` (e.g. `app-ctrl-all`, `dns-query`, `signature`) via default-pipeline fallback; **`fortinet.firewall.action`** retains pass/block outcome separately. UTM adds Layer 3 targets: **`url.*`**, **`dns.question.name`**, **`file.*`**, **`tls.server.x509.*`**, and email-filter **`email.to.address`**. Identity-aware UTM populates **`source.user.name`** and retains **`fortinet.firewall.authserver`** vendor-side. No **`destination.user.*`** mapping in UTM pipeline — destination user identity is traffic-only.

#### `log` — event (`type=event`)

Semantics vary by **`subtype`**: **`vpn`** — remote client actor after IP swap, tunnel resource as vendor target, **`fortinet.firewall.action`** (`negotiate`, `tunnel-up`) unmapped to `event.action`; **`user`** — FSSO/auth logon subject as actor, actions (`FSSO-logon`, `auth-logon`) vendor-only; **`endpoint`** — FortiClient user as actor, endpoint device as vendor target; **`system`**/**`update`** — often no human actor, FortiGate itself is contextual target. **`event.action` gap** is largest here — operational verbs exist in vendor `action` but not ECS.

#### `log` — login (message-triggered sub-pipeline)

True admin authentication audit: **administrator user** actor (`user.name`, `user.roles`), **client host** (`source.ip`), **`event.action: login`** (static). Target is the **FortiGate management plane** (partially `destination.ip`). Distinct from flow-level `source.user.name` on traffic logs.

## Example Event Graph

Examples below come from the single **`fortinet_fortigate.log`** data stream. Traffic and UTM events are audit-adjacent network telemetry (firewall/UTM decisions); the admin **login** example is a true authentication audit log.

### Example 1: Firewall traffic denied

**Stream:** `fortinet_fortigate.log` · **Fixture:** `packages/fortinet_fortigate/data_stream/log/_dev/test/pipeline/test-fortinet.log-expected.json`

```
Host (10.10.10.10) → deny → Remote host (67.43.156.13:161, snmp)
```

#### Actor

| Field | Value |
| --- | --- |
| id | 10.10.10.10 |
| type | host |
| ip | 10.10.10.10 |

**Field sources:**
- `id` ← `source.ip`
- `ip` ← `source.ip`

#### Event action

| Field | Value |
| --- | --- |
| action | deny |
| source_field | `event.action` |
| source_value | deny |

#### Target

| Field | Value |
| --- | --- |
| id | 67.43.156.13 |
| name | snmp |
| type | service |
| ip | 67.43.156.13 |
| geo | Bhutan |

**Field sources:**
- `id` ← `destination.ip`
- `name` ← `network.protocol` (mapped from FortiOS `service="SNMP"`)
- `ip` ← `destination.ip`
- `geo` ← `destination.geo.country_name`

#### Mermaid (optional)

```mermaid
flowchart LR
  A["Actor: 10.10.10.10"] --> E["deny"]
  E --> T["Target: 67.43.156.13 snmp"]
```

### Example 2: Web filter blocks denied URL category

**Stream:** `fortinet_fortigate.log` · **Fixture:** `packages/fortinet_fortigate/data_stream/log/_dev/test/pipeline/test-fortinet.log-expected.json`

```
User (elasticuser, 192.168.2.1) → ftgd_blk → URL (elastic.co/config/)
```

#### Actor

| Field | Value |
| --- | --- |
| name | elasticuser |
| type | user |
| ip | 192.168.2.1 |

**Field sources:**
- `name` ← `source.user.name`
- `ip` ← `source.ip`

#### Event action

| Field | Value |
| --- | --- |
| action | ftgd_blk |
| source_field | `event.action` |
| source_value | ftgd_blk |

#### Target

| Field | Value |
| --- | --- |
| name | elastic.co/config/ |
| type | general |
| sub_type | url |
| ip | 67.43.156.13 |
| geo | Bhutan |

**Field sources:**
- `name` ← `url.domain`, `url.path`
- `ip` ← `destination.ip` (remote web server peer on the blocked HTTPS session)
- `geo` ← `destination.geo.country_name`

#### Mermaid (optional)

```mermaid
flowchart LR
  A["Actor: elasticuser"] --> E["ftgd_blk"]
  E --> T["Target: elastic.co/config/"]
```

### Example 3: Administrator login to FortiGate

**Stream:** `fortinet_fortigate.log` · **Fixture:** `packages/fortinet_fortigate/data_stream/log/_dev/test/pipeline/test-fortinet.log-expected.json`

```
User (philipp, 192.168.0.10) → login → FortiGate management (firewallhost01)
```

#### Actor

| Field | Value |
| --- | --- |
| name | philipp |
| type | user |
| ip | 192.168.0.10 |

**Field sources:**
- `name` ← `user.name`, `source.user.name`
- `ip` ← `source.ip` (dissected from message `userfrom="JSON(192.168.0.10)"`)

#### Event action

| Field | Value |
| --- | --- |
| action | login |
| source_field | `event.action` |
| source_value | login |

#### Target

| Field | Value |
| --- | --- |
| name | firewallhost01 |
| type | service |

**Field sources:**
- `name` ← `observer.name` (FortiGate appliance management plane accessed by the admin session; fixture has no `destination.ip`)

#### Mermaid (optional)

```mermaid
flowchart LR
  A["Actor: philipp"] --> E["login"]
  E --> T["Target: firewallhost01"]
```

## ES|QL Entity Extraction

**Package type: agent-backed** (single `log` data stream from `manifest.yml`). Router: **`data_stream.dataset == "fortinet_fortigate.log"`** with secondary **`fortinet.firewall.type`** (`traffic`, `utm`, `dns`, `event`) and **`event.action == "login"`** for admin auth. Pass 4 is **fill-gaps-only**: detection flags (`actor_exists`, `target_exists`, `action_exists`) run first; every output column uses preserve-first `CASE` with valid arity — **3-arg** `CASE(col IS NOT NULL, col, fallback)` or **5-arg** `CASE(exists_flag, col, boolean_condition, fallback, null)` (never 4-arg with a bare field as the third argument). No ECS `*.target.*` fields are populated at ingest today; fallbacks lift de-facto **`destination.*`** / vendor fields into `host.target.*`, `user.target.*`, `service.target.*`, and `entity.target.*`. **`destination.user.name`** maps to **`user.target.name`** in the fallback branch only (traffic, `dstunauthuser`). Admin **login** → **`service.target.name`** from `observer.name` (Pass 3), not self-referential user.

### Dataset inventory

| data_stream.dataset | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `fortinet_fortigate.log` (traffic) | firewall session | user, host | host, service, user (dst) | full |
| `fortinet_fortigate.log` (utm/dns) | UTM/IPS | user, host | host, service, general (url/file) | partial |
| `fortinet_fortigate.log` (event) | VPN/auth/system | user, host | host, service | partial |
| `fortinet_fortigate.log` (login) | admin auth | user, host | service | full |

### Field mapping plan

#### Actor mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `user.name` | `user.name` | `user.name IS NOT NULL` | high | **preserve existing** — column-level; `actor_exists` excludes `source.user.name` so flow identity can fall through |
| `user.name` | `source.user.name` | `data_stream.dataset == "fortinet_fortigate.log" AND source.user.name IS NOT NULL` | high | **vendor fallback** — flow/VPN/FSSO/admin when `user.name` empty |
| `host.ip` | `source.ip` | `data_stream.dataset == "fortinet_fortigate.log" AND source.ip IS NOT NULL` | high | **vendor fallback** — flow/VPN client endpoint |
| `host.name` | `host.name` ← `fortinet.firewall.srcname` | `fortinet.firewall.type == "traffic"` | high | **ingest-only — no ES|QL** — pipeline sets `host.name`; no alternate query-time source |

#### Target mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `service.target.name` | `service.target.name` | `data_stream.dataset == "fortinet_fortigate.log"` | high | **preserve existing** |
| `service.target.name` | `observer.name` | `data_stream.dataset == "fortinet_fortigate.log" AND event.action == "login"` | high | **semantic fallback** — FortiGate management plane (Pass 3) |
| `service.target.name` | `network.application` | `data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type IN ("traffic", "utm", "dns") AND network.application IS NOT NULL` | high | **vendor fallback** — inspected application |
| `service.target.name` | `fortinet.firewall.vpntunnel` | `data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.subtype == "vpn" AND fortinet.firewall.vpntunnel IS NOT NULL` | high | **vendor fallback** — VPN tunnel resource |
| `host.target.ip` | `host.target.ip` | `data_stream.dataset == "fortinet_fortigate.log"` | high | **preserve existing** |
| `host.target.ip` | `destination.ip` | `data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type IN ("traffic", "utm", "dns") AND destination.ip IS NOT NULL` | high | **de-facto destination.*** network peer |
| `host.target.name` | `host.target.name` | `data_stream.dataset == "fortinet_fortigate.log"` | high | **preserve existing** |
| `host.target.name` | `destination.address` | `data_stream.dataset == "fortinet_fortigate.log" AND destination.address IS NOT NULL` | high | **de-facto destination.*** — dstname/FQDN |
| `host.target.name` | `destination.domain` | `data_stream.dataset == "fortinet_fortigate.log" AND destination.domain IS NOT NULL` | medium | **de-facto destination.*** — TLS SNI on UTM |
| `user.target.name` | `user.target.name` | `data_stream.dataset == "fortinet_fortigate.log"` | high | **preserve existing** |
| `user.target.name` | `destination.user.name` | `data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type == "traffic" AND destination.user.name IS NOT NULL` | medium | **de-facto destination.user.*** → `user.target.name` (`dstunauthuser`); pipeline-only, no fixture |
| `user.target.email` | `user.target.email` | `data_stream.dataset == "fortinet_fortigate.log"` | high | **preserve existing** |
| `user.target.email` | `email.to.address` | `data_stream.dataset == "fortinet_fortigate.log" AND email.to.address IS NOT NULL` | high | **de-facto destination.*** email recipient |
| `entity.target.name` | `entity.target.name` | `data_stream.dataset == "fortinet_fortigate.log"` | high | **preserve existing** |
| `entity.target.name` | `url.domain` | `data_stream.dataset == "fortinet_fortigate.log" AND url.domain IS NOT NULL` | high | **vendor fallback** — web filter URL target |

#### Event action mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `event.action` | `event.action` | `data_stream.dataset == "fortinet_fortigate.log"` | high | **preserve existing** — traffic, UTM/DNS, login |
| `event.action` | `fortinet.firewall.action` | `data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type == "event" AND fortinet.firewall.action IS NOT NULL` | high | **vendor fallback** — FSSO/VPN/system verbs not copied at ingest |

### Detection flags (mandatory — run first)

`actor_exists` checks official actor ECS columns only — **`source.user.name` is excluded** so flow identity on `source.user.*` still falls through to `user.name`. `target_exists` checks official `*.target.*` columns only (ingest does not populate them today).

```esql
| EVAL
  actor_exists = user.id IS NOT NULL OR user.name IS NOT NULL OR user.email IS NOT NULL
    OR host.id IS NOT NULL OR host.ip IS NOT NULL OR host.name IS NOT NULL
    OR service.id IS NOT NULL OR service.name IS NOT NULL
    OR entity.id IS NOT NULL OR entity.name IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR user.target.email IS NOT NULL
    OR host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
```

### Combined ES|QL — actor fields

```esql
| EVAL
  user.name = CASE(
    user.name IS NOT NULL, user.name,
    data_stream.dataset == "fortinet_fortigate.log" AND source.user.name IS NOT NULL, source.user.name,
    null
  ),
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "fortinet_fortigate.log" AND source.ip IS NOT NULL, source.ip,
    null
  )
```

### Combined ES|QL — event action

```esql
| EVAL
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type == "event" AND fortinet.firewall.action IS NOT NULL, fortinet.firewall.action,
    null
  )
```

### Combined ES|QL — target fields

```esql
| EVAL
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "fortinet_fortigate.log" AND event.action == "login", observer.name,
    data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type IN ("traffic", "utm", "dns") AND network.application IS NOT NULL, network.application,
    data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.subtype == "vpn" AND fortinet.firewall.vpntunnel IS NOT NULL, fortinet.firewall.vpntunnel,
    null
  ),
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type IN ("traffic", "utm", "dns") AND destination.ip IS NOT NULL, destination.ip,
    null
  ),
  host.target.name = CASE(
    host.target.name IS NOT NULL, host.target.name,
    data_stream.dataset == "fortinet_fortigate.log" AND destination.address IS NOT NULL, destination.address,
    data_stream.dataset == "fortinet_fortigate.log" AND destination.domain IS NOT NULL, destination.domain,
    null
  ),
  user.target.name = CASE(
    user.target.name IS NOT NULL, user.target.name,
    data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type == "traffic" AND destination.user.name IS NOT NULL, destination.user.name,
    null
  ),
  user.target.email = CASE(
    user.target.email IS NOT NULL, user.target.email,
    data_stream.dataset == "fortinet_fortigate.log" AND email.to.address IS NOT NULL, email.to.address,
    null
  ),
  entity.target.name = CASE(
    entity.target.name IS NOT NULL, entity.target.name,
    data_stream.dataset == "fortinet_fortigate.log" AND url.domain IS NOT NULL, url.domain,
    null
  )
```

### Full pipeline fragment (optional)

```esql
FROM logs-*
| EVAL
  actor_exists = user.name IS NOT NULL OR host.ip IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR host.target.ip IS NOT NULL OR service.target.name IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
| EVAL
  user.name = CASE(
    user.name IS NOT NULL, user.name,
    data_stream.dataset == "fortinet_fortigate.log" AND source.user.name IS NOT NULL, source.user.name,
    null
  ),
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "fortinet_fortigate.log" AND source.ip IS NOT NULL, source.ip,
    null
  ),
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type == "event" AND fortinet.firewall.action IS NOT NULL, fortinet.firewall.action,
    null
  ),
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type IN ("traffic", "utm", "dns") AND destination.ip IS NOT NULL, destination.ip,
    null
  ),
  host.target.name = CASE(
    host.target.name IS NOT NULL, host.target.name,
    data_stream.dataset == "fortinet_fortigate.log" AND destination.address IS NOT NULL, destination.address,
    data_stream.dataset == "fortinet_fortigate.log" AND destination.domain IS NOT NULL, destination.domain,
    null
  ),
  user.target.name = CASE(
    user.target.name IS NOT NULL, user.target.name,
    data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type == "traffic" AND destination.user.name IS NOT NULL, destination.user.name,
    null
  ),
  user.target.email = CASE(
    user.target.email IS NOT NULL, user.target.email,
    data_stream.dataset == "fortinet_fortigate.log" AND email.to.address IS NOT NULL, email.to.address,
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "fortinet_fortigate.log" AND event.action == "login", observer.name,
    data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.type IN ("traffic", "utm", "dns") AND network.application IS NOT NULL, network.application,
    data_stream.dataset == "fortinet_fortigate.log" AND fortinet.firewall.subtype == "vpn" AND fortinet.firewall.vpntunnel IS NOT NULL, fortinet.firewall.vpntunnel,
    null
  ),
  entity.target.name = CASE(
    entity.target.name IS NOT NULL, entity.target.name,
    data_stream.dataset == "fortinet_fortigate.log" AND url.domain IS NOT NULL, url.domain,
    null
  )
| KEEP @timestamp, data_stream.dataset, fortinet.firewall.type, event.action, user.name, host.ip, host.target.ip, host.target.name, user.target.name, user.target.email, service.target.name, entity.target.name
```

### Streams excluded

*(none — single dataset with `fortinet.firewall.type` sub-routing)*

### Gaps and limitations

- **`destination.user.name`** (`dstunauthuser`) — pipeline-proven (`traffic.yml`) but **no test fixture**; verify in production before relying on `user.target.name` fallback.
- **`user.target.email`** — `destination.user.email` never populated; fallback uses `email.to.address` only when present.
- **`type=event` action fallback** — ES|QL can surface `fortinet.firewall.action`; ingest enhancement still recommended (`event.yml`).
- **`host.name` ← `srcname`** — **ingest-only**; omitted from actor `EVAL` (no alternate query-time source). Source-side hostname enrichment, not `host.target.*`.
- **FortiClient endpoint targets** — `fortinet.firewall.name`/`ip`/`fctuid` vendor-only; omitted from ES|QL until ingest maps them.
- **VPN remip/locip swap** — post-swap `destination.ip` is local FortiGate VPN endpoint, not external target host.
- **`entity.target.type` / `target.entity.type`** — omitted; stream-level `CASE` routing is sufficient; never emit misnamed `target.entity.type`.
