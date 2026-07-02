# cisco_secure_email_gateway

## Product Domain

Cisco Secure Email Gateway (formerly Cisco Email Security Appliance, or ESA) is an enterprise email security platform that sits in the mail path to inspect, filter, and enforce policy on inbound and outbound email. Its lineage traces to IronPort (acquired by Cisco in 2007) and it runs on AsyncOS, a purpose-built operating system for high-volume SMTP processing. The gateway is a core control point in the email security domain: it protects organizations against spam, phishing, business email compromise (BEC), malware, ransomware, and data loss by applying multi-layered filtering before messages reach mailboxes or leave the organization.

The platform combines reputation-based filtering (SenderBase), anti-spam engines, dual anti-virus scanning (Sophos and McAfee), Outbreak Filters for zero-day threats, Advanced Malware Protection (AMP) with file reputation and sandbox analysis, content and DLP policies, and email authentication checks (SPF, DKIM, DMARC). Threat decisions are informed by Cisco Talos intelligence. Deployments span on-premises hardware appliances, virtual appliances (ESAV), cloud gateways (Cisco Secure Email Cloud Gateway), and hybrid models, with centralized management available through the web GUI, CLI, or Cisco Secure Email and Web Manager.

From a security operations perspective, the gateway generates rich telemetry about every message it handles: SMTP connection identifiers, filtering verdicts, quarantine actions, attachment analysis results, bounce and delivery outcomes, and administrative activity. Security teams rely on this data for threat detection, mail-flow troubleshooting, compliance auditing, and correlating email-borne attacks with broader SIEM and endpoint telemetry. Because email remains the primary vector for credential theft and malware delivery, gateway logs are a critical signal in any email-security monitoring program.

## Data Collected (brief)

This integration collects Cisco Secure Email Gateway appliance logs into a single **log** data stream via Elastic Agent TCP/UDP syslog listeners or logfile input (for FTP-pushed files). Twelve log categories are parsed into ECS: **AMP** (`amp`), **Anti-Spam** (`antispam`), **Anti-Virus** (`antivirus`), **Text Mail** (`mail_logs`), **Consolidated Event** (`consolidated_event`), **Content Scanner** (`content_scanner`), **Authentication** (`authentication`), **GUI/HTTP** (`gui_logs`), **System** (`system`), **Status** (`status`), **Error** (`error_logs`), and **Bounce** (`bounces`). Events include mail-flow metadata (sender, recipient, subject, message IDs, ICID/DCID/RID), security verdicts (AMP/AV/AS/DLP/DMARC/SPF/DKIM), attachment hashes and dispositions, bounce and delivery status, admin login and config-change activity, and appliance performance metrics (CPU, RAM, queue depth).

## Expected Audit Log Entities

The integration exposes a single **`cisco_secure_email_gateway.log`** data stream. Twelve syslog categories route to dedicated sub-pipelines (`default.yml`). **True admin audit** categories are `authentication`, `gui_logs`, and `system` (login/logout, GUI HTTP access, CLI config commits). **Audit-adjacent mail-security** categories are `consolidated_event` (CEF), `mail_logs`, `amp`, `antivirus`, `antispam`, `content_scanner`, `bounces`, and `error_logs` — they record filtering verdicts, delivery outcomes, and attachment analysis rather than human admin actions. **`status`** is appliance performance telemetry (CPU, queue depth, recipient counters) with no caller identity and no per-event action; actor/target audit semantics do not apply.

**`event.action` is absent in all fixtures and pipelines** — no ingest step sets or renames to `event.action` (grep across `packages/cisco_secure_email_gateway/`). Some categories partially substitute `event.type`, `event.category`, and `event.outcome` (authentication session start/end, GUI web access, antivirus `vulnerability` category, error_logs `error` type) but these describe event class, not the operation verb. Rich vendor action fields exist under `cisco_secure_email_gateway.log.action`, `.act`, `.message_status`, `.connection_status`, `.disposition`, and related paths — all remain vendor-only.

No ECS `user.target.*`, `host.target.*`, `service.target.*`, or `entity.target.*` fields are populated (`target_fields_audit.csv` has no row for this package). Recipients are mapped to `email.to.address`, not `destination.user.*` (`destination_identity_hits.csv` has no row). `destination.ip` / `destination.port` appear only on downstream SMTP delivery failures in `mail_logs` (`pipeline_text_mail_logs.yml`). Evidence from `sample_event.json`, pipeline test fixtures under `data_stream/log/_dev/test/pipeline/`, and ingest pipelines under `data_stream/log/elasticsearch/ingest_pipeline/`. Target-fields audit classifies this package as **`moderate_candidate_network_dest`** (`target_enhancement_packages.csv`: `pipeline_dest_network=true`, no `pipeline_dest_identity`).

### Event action (semantic)

What operation or activity does each category record?

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| `logged-on` / `authenticated` | authentication | high | `cisco_secure_email_gateway.log.action` grok in `pipeline_authentication.yml`; pipeline sets `event.type: [start]` when action is `logged on` or `authenticated` — not copied to `event.action` | **`authentication`** |
| `logged-out` / session timeout | authentication | high | `log.action: logged out` in `test-common-gui-log.log-expected.json`; auth/gui pipelines set `event.type: [end]` | **`authentication`**, **`gui_logs`** |
| `GET` / HTTP access | administration | high | `http.request.method` + `url.path` grok in `pipeline_gui_logs.yml`; `event.category: [web]`, `event.type: [access]` | **`gui_logs`** HTTP req lines |
| `changed` (passphrase/config object) | configuration_change | high | `Passphrase has been changed for user admin` → `log.action: changed` in gui fixture | **`gui_logs`** |
| `commit-changes` | configuration_change | high | `User admin commit changes:…` grok in `pipeline_system.yml` → `cisco_secure_email_gateway.log.commit_changes` | **`system`** |
| `QUARANTINED` / `DELIVERED` / `ABORTED` / `DQ` | detection | high | CEF `act=` → `cisco_secure_email_gateway.log.act` (`pipeline_consolidated_event.yml` L209–210); fixtures: `QUARANTINED`, `DELIVERED`, `ABORTED`, `DQ` | **`consolidated_event`** — gateway enforcement action on message |
| `queued-for-delivery` / `delivery-start` / `message-done` | data_access | medium | `cisco_secure_email_gateway.log.message_status` grok (`queued`, `Delivery start`, `Message done`, `finished`) in `pipeline_text_mail_logs.yml` | **`mail_logs`** mail-flow lifecycle |
| `New` / `Start` / `close` (SMTP ICID/DCID) | data_access | medium | `cisco_secure_email_gateway.log.connection_status` grok (`New`, `Start`, `close`) in text-mail fixtures | **`mail_logs`** — connection events, not message verdict |
| `restart` (service) | configuration_change | medium | `cisco_secure_email_gateway.log.vendor_action: restart` when URL rep config changes (`test-common-text-mail.log-expected.json`) | **`mail_logs`**, **`content_scanner`** |
| `file-reputation-query` / `retrospective-verdict` | detection | medium | AMP grok lead patterns in `pipeline_amp.yml`; disposition `MALICIOUS`, verdict `MALICIOUS` in amp fixtures | **`amp`** — file/attachment analysis stages |
| `Virus` / `Error` / `CLEAN` (AV scan result) | detection | high | `cisco_secure_email_gateway.log.type` + `.antivirus_result` grok in `pipeline_antivirus.yml`; fixtures: `Virus 'CXmail/Phish-O'`, `Error 'Encrypted'`, `Result 'CLEAN'` | **`antivirus`** |
| `HardBounce` / bounce generation | data_access | medium | `cisco_secure_email_gateway.log.bounce_type` grok in `pipeline_bounce.yml` | **`bounces`** |
| `giving-up-on-message` / delivery failure | data_access | medium | Error/delivery-failure grok patterns; `event.type: [error]` on **`error_logs`** only | **`error_logs`**, **`mail_logs`** SMTP failure lines |
| (none — aggregate counters) | — | — | Status grok captures CPU/RAM/queue/recipient counters only | **`status`** — no per-event action |

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| `cisco_secure_email_gateway.log.action` | no | n/a | `logged-out`, `logged-on`, `changed` (normalize spaces/hyphens) | **yes** | Grok in `pipeline_authentication.yml`, `pipeline_gui_logs.yml`; values `logged out`, `changed`, `The HTTPS session has been established successfully.` in gui fixture — pipeline maps to `event.type`/`event.category` only |
| `http.request.method` + `url.path` | no | n/a | `GET` (or composite `GET /login`) | **yes** | `pipeline_gui_logs.yml` L11, L26–35; fixture `GET xxx.png`, `GET /login` context via `log.destination` |
| `cisco_secure_email_gateway.log.act` | no | n/a | `QUARANTINED`, `DELIVERED`, `ABORTED`, `DQ` | **yes** | CEF `act=` rename (`pipeline_consolidated_event.yml` L209–210); consolidated-event expected JSON |
| `cisco_secure_email_gateway.log.message_status` | no | n/a | `queued-for-delivery`, `delivery-start`, `message-done`, `finished` | **yes** | Grok in `pipeline_text_mail_logs.yml`; fixtures `queued`, `Delivery start`, `Message done` |
| `cisco_secure_email_gateway.log.connection_status` | no | n/a | `new-smtp-icid`, `start`, `close` | **yes** | ICID/DCID grok; fixtures `New`, `Start`, `close` |
| `cisco_secure_email_gateway.log.vendor_action` | no | n/a | `restart`, `Starting` | **yes** | mail_logs/content_scanner grok; fixture `Triggering restart of URL Reputation client service` |
| `cisco_secure_email_gateway.log.commit_changes` | no | n/a | `commit-changes` | **yes** | System grok `commit changes:%{GREEDYDATA:…}`; fixture `Added a second CLI log for examples` |
| `cisco_secure_email_gateway.log.disposition` / `.verdict` | no | n/a | `MALICIOUS`, `LOWRISK` (lowercase) | **yes** | AMP pipeline KV/grok; amp fixtures `Disposition = MALICIOUS`, `Verdict: MALICIOUS` |
| `cisco_secure_email_gateway.log.type` + `.antivirus_result` | no | n/a | `virus-detected`, `scan-clean`, `scan-error` (derive from type + result) | **yes** | Antivirus grok; fixtures `Virus 'CXmail/Phish-O'`, `Result 'CLEAN'`, `Error 'Encrypted'` |
| `cisco_secure_email_gateway.log.bounce_type` | no | n/a | `hard-bounce`, `soft-bounce` (from bounce_type value) | **yes** | Bounce grok `^%{WORD:bounce_type}:` |
| `cisco_secure_email_gateway.log.event_class_id` | no | n/a | `ESA_CONSOLIDATED_LOG_EVENT` | partial | CEF header parse; event-type label, not per-message enforcement verb — prefer `log.act` |
| `event.type` | yes (partial substitute) | partial | `[start]`, `[end]`, `[access]`, `change`, `[error]` | no | Auth/gui/mail_logs/error pipelines set `event.type` instead of `event.action` — different ECS semantics |
| `event.category` | yes (partial substitute) | partial | `authentication`, `web`, `session`, `vulnerability` | no | Auth/gui/antivirus pipelines; category ≠ action verb |
| `event.outcome` | yes (partial substitute) | yes | `success`, `failure` | no | Auth pipeline L28–37 from `log.outcome`; outcome complements action, does not replace it |

**Per-category action check (Step 2b):**

| Stream (category) | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `authentication` | no | no | `cisco_secure_email_gateway.log.action` | high | `pipeline_authentication.yml`; `event.type` start/end only |
| `gui_logs` | no | no | `log.action` or `http.request.method` | high | `pipeline_gui_logs.yml`; gui expected JSON |
| `system` | no | no | derived from `commit_changes` text | medium | `pipeline_system.yml` |
| `consolidated_event` | no | no | `cisco_secure_email_gateway.log.act` | high | `pipeline_consolidated_event.yml` L209–210 |
| `mail_logs` | no | no | `message_status` / `connection_status` / `vendor_action` | medium | `pipeline_text_mail_logs.yml` |
| `amp` | no | no | grok lead verb or `disposition`/`verdict` | medium | `pipeline_amp.yml` |
| `antivirus` | no | no | `log.type` + `antivirus_result` | high | `pipeline_antivirus.yml` |
| `antispam` | no | no | case-daemon `result` text | low | `pipeline_anti_spam.yml` |
| `content_scanner` | no | no | `vendor_action` | medium | `pipeline_content_scanner.yml` |
| `bounces` | no | no | `bounce_type` | high | `pipeline_bounce.yml` |
| `error_logs` | no | no | delivery-failure message pattern | low | `pipeline_error_logs.yml`; `event.type: [error]` only |
| `status` | no | no | (none — metrics) | n/a | `pipeline_status.yml` |

### Actor (semantic)

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| ESA admin user | user | — | high | `user.name` from `authentication`, `gui_logs`, `system` grok patterns; `related.user` append. Fixtures: `test-common-gui-log.log-expected.json` (admin login/logout, passphrase change), `test-common-system.log-expected.json` (CLI commit). | Admin categories only |
| Admin client workstation | host | — | high | `client.ip` ← GUI `req:<IP> user:…` (`pipeline_gui_logs.yml`); `host.ip` ← `SourceIP:`, auth attempt `from <IP>`, session source (`pipeline_authentication.yml`, `pipeline_gui_logs.yml`). Distinct from SMTP peers. Fixtures: `test-common-gui-log.log-expected.json`. | `authentication`, `gui_logs` |
| Mail sender | user | — | high | `email.from.address` ← CEF `suser` (`pipeline_consolidated_event.yml`); mail_logs `From: <…>` grok (`pipeline_text_mail_logs.yml`); bounce `From:<…>` (`pipeline_bounce.yml`). Fixtures: `test-common-consolidated-event.log-expected.json`, `test-common-text-mail.log-expected.json`. | Mail categories; CEF `suser` may be a domain, not a mailbox |
| SMTP connecting host | host | — | high | `source.ip` / `source.domain` ← CEF `sourceAddress`/`src`, `sourceHostName`/`shost` (`pipeline_consolidated_event.yml`). Fixtures: consolidated-event expected JSON (`source.ip: 1.128.3.4`, `source.domain: unknown`). | **`consolidated_event`** primarily |
| SMTP peer (text mail, vendor-only IP) | host | — | medium | ICID/DCID connection logs store peer IP in `cisco_secure_email_gateway.log.address` / `.interface` with `related.ip` append only — **not** promoted to `source.ip` (`pipeline_text_mail_logs.yml`). Fixture: New SMTP ICID event in `test-common-text-mail.log-expected.json`. | **`mail_logs`** — actor endpoint exists in vendor fields only |
| ESA appliance (automated enforcement) | service | — | high | CEF `deviceExternalId` → `host.id`; `cisco_secure_email_gateway.log.appliance.*` (vendor/product/version). Appliance performs automated actions (`act=QUARANTINED`, `DELIVERED`). Fixture: `test-common-consolidated-event.log-expected.json`. | **`consolidated_event`** — gateway as enforcing service, not human actor |
| AV engine vendor label | service | — | medium | `observer.vendor` ← AV engine name in grok (`pipeline_antivirus.yml`, e.g. `sophos`). Fixture: `test-common-antivirus.log-expected.json`. | **`antivirus`** only — scan engine identity, not admin caller |

**No actor identity:** **`status`** — aggregate counters and resource utilization only. Many **`amp`**, **`antispam`**, and **`content_scanner`** events reference MID/file context without sender IP or admin user.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `user.name` | Admin principal | yes | yes | high | Grok in `pipeline_authentication.yml`, `pipeline_gui_logs.yml`, `pipeline_system.yml`; `related.user` append; fixtures above |
| `client.ip` | GUI HTTP client | yes | yes | high | `req:<IP> user:…` grok (`pipeline_gui_logs.yml` L11); `related.ip` append |
| `host.ip` | Admin auth/GUI source IP | yes | partial | high | Auth/gui grok → `host.ip` (`pipeline_authentication.yml`, `pipeline_gui_logs.yml`); semantically a client endpoint, not the ESA appliance host |
| `email.from.address` | Mail sender | yes | partial | high | CEF `suser` rename (`pipeline_consolidated_event.yml` L391–394); mail_logs/bounce grok; fixture values like `example.com` are domains, not full RFC5322 addresses |
| `source.ip` | SMTP connecting host | yes | yes | high | CEF `sourceAddress`/`src` convert (`pipeline_consolidated_event.yml` L365–378); consolidated-event fixtures |
| `source.domain` | SMTP HELO/rDNS hostname | yes | yes | medium | CEF `sourceHostName`/`shost` urldecode → `source.domain` (L353–363) |
| `host.id` | ESA appliance identifier | yes | partial | high | CEF `deviceExternalId` → `host.id` (L454–456); identifies observer/appliance, not admin client or mail sender |
| `cisco_secure_email_gateway.log.address` | SMTP peer IP (text mail) | yes (vendor) | n/a | medium | ICID/DCID grok stores connecting/delivery peer IP; only `related.ip`, not `source.ip` (`pipeline_text_mail_logs.yml` L15, L21, L109–114) |
| `cisco_secure_email_gateway.log.esa.helo.ip` | HELO IP (CEF extension) | yes (vendor) | n/a | medium | Parsed from consolidated CEF; appended to `related.ip` only (consolidated pipeline) |
| `cisco_secure_email_gateway.log.session` | Admin session ID | yes (vendor) | n/a | high | Retained in auth/gui logs; not mapped to ECS session fields |
| `cisco_secure_email_gateway.log.privilege` | Admin privilege level | yes (vendor) | n/a | high | GUI login events (`test-common-gui-log.log-expected.json`) |
| `observer.vendor` | AV engine name | yes | partial | medium | Antivirus grok captures engine vendor (`sophos`), not Cisco ESA product identity (`pipeline_antivirus.yml`) |
| `related.user` | Actor cross-reference | yes | partial | high | Appends `user.name` and mail addresses via `default.yml` email array normalization; does not distinguish actor vs recipient |

### Target (semantic)

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 — Platform / cloud service | Email security gateway enforcing policy | Cisco Secure Email Gateway (ESA) | service | — | high | CEF `appliance.vendor/product/version`; `host.id` from `deviceExternalId`; automated `act=QUARANTINED`/`DELIVERED`. Fixture: consolidated-event expected JSON. | Observer/enforcement plane for all mail categories |
| 1 — Platform / scan engine | Inline AV engine invoked on message | Sophos / McAfee AV engine | service | — | medium | `observer.vendor` in antivirus logs; engine name in message text. Fixture: `test-common-antivirus.log-expected.json`. | Sub-service within ESA pipeline |
| 2 — Resource / object | Mail recipient mailbox | Recipient address / domain | user | — | high | `email.to.address` ← CEF `duser`, mail_logs/bounce/error `To: <…>` grok. Fixtures: consolidated-event, text-mail, error-log expected JSON. | Primary acted-upon user identity |
| 2 — Resource / object | Email message under inspection | Message (MID) | general | email_message | high | `email.message_id` (MID/ESAMID) across amp, mail_logs, consolidated_event, bounce, antivirus. `sample_event.json` MID=5. | Central correlation ID for all mail-security events |
| 2 — Resource / object | Attachment or body file scanned | File attachment | general | file | high | `file.name`, `file.hash.sha256`, `email.attachments.file.*` in AMP, AV, mail_logs SHA patterns. Fixtures: `test-common-amp.log-expected.json`, `test-common-antivirus.log-expected.json`, `test-common-mail-file-upload.log-expected.json`. | Layer 2 when attachment is the inspected object |
| 2 — Resource / object | GUI policy page or config object | Web path / config object | general | web_resource, configuration | high | `cisco_secure_email_gateway.log.destination` (`/login`, `/mail_policies/…`); `url.path` on HTTP access; `cisco_secure_email_gateway.log.object` + `commit_changes` for admin changes. Fixtures: `test-common-gui-log.log-expected.json`, `test-common-system.log-expected.json`. | Admin audit targets |
| 2 — Resource / object | Downstream SMTP delivery host | Remote MTA | host | — | high | `destination.ip` / `destination.port` on send failures (`pipeline_text_mail_logs.yml` L27). Fixture: text-mail SMTP error to `1.128.3.4:0`. | Network peer **and** delivery target on failure events |
| 2 — Resource / object | Internal gateway service restarted | ESA subsystem service | service | — | medium | `cisco_secure_email_gateway.log.object` for services (`URL Reputation client service`, `content_scanner`). Fixtures: text-mail, content-scanner expected JSON. | System/config events |
| 3 — Content / artifact | Message subject, RID, verdict metadata | Subject line / per-recipient ID | general | email_subject, mail_recipient | high | `email.subject`, `cisco_secure_email_gateway.log.subject`; `cisco_secure_email_gateway.log.recipient_id` (RID) when address absent. Fixtures: text-mail, bounce patterns in `pipeline_bounce.yml`. | Supplements Layer 2 message/recipient identity |

### Target (ECS candidates)

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `email.to.address` | 2 | user | yes | partial | `user.target.email` | yes | CEF `duser` → `email.to.address` (`pipeline_consolidated_event.yml` L328–331); mail_logs/bounce grok; values may be domains; no `user.target.*` or `destination.user.*` |
| `email.from.address` | 2 | user | yes | partial | context (sender, not target) | no | Mapped as sender/actor in mail flow; listed here because CEF conflates envelope identity — not a target field |
| `email.message_id` | 2 | general (email_message) | yes | yes | `entity.target.id` / custom | partial | MID across all mail pipelines; primary audit object ID; no official ECS target mapping |
| `email.subject` | 3 | general (email_subject) | yes | yes | context | no | CEF `msg` gsub or mail_logs grok |
| `file.name`, `file.hash.sha256`, `email.attachments.file.*` | 2–3 | general (file) | yes | yes | `file.*` / `entity.target.*` | partial | AMP/AV/mail_logs pipelines; attachment is acted-upon artifact |
| `cisco_secure_email_gateway.log.destination` | 2 | general (web_resource) | yes (vendor) | n/a | `url.path` / `service.target.*` | yes | GUI admin target path; vendor-only except overlapping `url.path` on HTTP req logs |
| `url.path` | 2 | general (web_resource) | yes | yes | context | no | HTTP GET path from GUI access grok (`pipeline_gui_logs.yml`) |
| `cisco_secure_email_gateway.log.object`, `.commit_changes` | 2 | general (configuration) | yes (vendor) | n/a | `entity.target.name` | yes | Config object changed (`Passphrase`, CLI commit text); vendor-only |
| `destination.ip`, `destination.port` | 2 | host | yes | partial | `host.target.ip` / network context | yes | Downstream MTA on SMTP delivery failure; network peer semantics per ECS Destination, but recipient context in same event (`email.to.address`) |
| `cisco_secure_email_gateway.log.recipient_id` | 3 | general (mail_recipient) | yes (vendor) | n/a | `user.target.id` (custom) | yes | Per-recipient RID; supplements `email.to.address` when address missing |
| `host.id` | 1 | service | yes | partial | `observer.serial_number` / `host.id` | no | Appliance ID; enforcement platform scope, not Layer 2 object |
| `cisco_secure_email_gateway.log.appliance.*` | 1 | service | yes (vendor) | n/a | `observer.product` / `service.target.name` | yes | CEF vendor/product/version parsed; not mapped to `observer.product` or `cloud.service.name` |
| `cisco_secure_email_gateway.log.act`, `.disposition`, ESA verdict fields | 3 | general (verdict) | yes (vendor) | n/a | context | no | Action/verdict metadata (`QUARANTINED`, `MALICIOUS`); enriches message target |
| `destination.user.*` / `destination.host.*` (de-facto) | — | — | no | n/a | — | no | Not used; recipients use `email.to.address` instead |

### Gaps and mapping notes

- **`event.action` never populated:** No pipeline step sets `event.action` despite rich vendor action fields across all categories. Primary enhancement per category: `log.action` (admin auth/GUI), `log.act` (CEF consolidated events), `message_status`/`connection_status` (mail flow), `disposition`/`verdict` (AMP), `type`+`antivirus_result` (AV), `bounce_type` (bounces). `event.type`/`event.category`/`event.outcome` partially cover auth and GUI semantics but are not substitutes for `event.action`.
- **No official ECS target fields:** Aligns with `target_enhancement_packages.csv` (`moderate_candidate_network_dest`, all ECS target tiers false). Primary enhancement: promote `email.to.address` → `user.target.email` (or `destination.user.email`) and `email.message_id` → `entity.target.id` for mail-security correlation.
- **Recipients not under `destination.user.*`:** Unlike `checkpoint_email` and similar integrations, CEF `duser` maps to `email.to.address` only. Semantically the mail recipient is the Layer 2 user target, but ECS target buckets are empty.
- **`destination.ip` is network dest, not user dest:** `pipeline_dest_network=true` in target-fields audit. On SMTP send failures, `destination.ip` is the downstream MTA while `email.to.address` holds the recipient — both are target-relevant but only the latter is a user identity field.
- **`host.ip` vs `host.id` ambiguity:** Admin client IP lands in `host.ip`; appliance serial lands in `host.id`. Both use the `host.*` namespace for different entity types — do not treat `host.ip` as the ESA appliance.
- **`email.from.address` / `email.to.address` partial mapping:** CEF `suser`/`duser` often contain domains or friendly-from values, not full mailbox addresses (`example.com` in consolidated-event fixture). Mapping is intentional but semantically partial for ECS `email.*` field sets.
- **SMTP peer IP gap in `mail_logs`:** Connecting host IP for ICID events stays in `cisco_secure_email_gateway.log.address` with `related.ip` only — not `source.ip`. Actor host identity is vendor-only for text-mail connection events.
- **`observer.vendor` captures AV engine, not ESA:** Antivirus grok sets `observer.vendor: sophos` (engine vendor), not `Cisco`. ESA product identity remains in `cisco_secure_email_gateway.log.appliance.*` without ECS `observer.product` mapping.
- **`related.user` conflates roles:** Appends admin `user.name` and normalized mail addresses without distinguishing actor vs recipient.
- **Passphrase-change actor/target overlap:** GUI event `"Passphrase has been changed for user admin"` maps `user.name: admin` — the same field represents both actor and affected user; no separate target ECS field.
- **`status` metrics:** Queue/recipient counter dimensions are aggregation subjects, not per-event audit targets; no caller identity and no per-event action in schema or fixtures.

### Per-stream notes

**`authentication` / `gui_logs` / `system`:** Admin audit stream. Actor is **`user.name`** (admin) plus **`client.ip`** or **`host.ip`** (workstation). Targets are GUI paths (`cisco_secure_email_gateway.log.destination`, `url.path`) and config objects (`cisco_secure_email_gateway.log.object`, `commit_changes`). **Action:** vendor `log.action` (`logged on`, `logged out`, `changed`) or HTTP method for GUI access — none mapped to `event.action`; auth uses `event.type` start/end and `event.outcome` instead.

**`consolidated_event`:** CEF mail-security summary. Actor is mail **sender** (`email.from.address` ← `suser`) and SMTP **connecting host** (`source.ip`). Target is **recipient** (`email.to.address` ← `duser`), **message** (`email.message_id`), and **attachments** (vendor `ESAAttachmentDetails`). ESA appliance (`host.id`, `appliance.*`) is the enforcing Layer 1 service. **Action:** CEF `act` → `log.act` (`QUARANTINED`, `DELIVERED`, `ABORTED`, `DQ`) — primary `event.action` candidate, not mapped today.

**`mail_logs` / `bounces` / `error_logs`:** Text-format mail flow. Same sender/recipient/message/file target patterns; bounces add `email.from.address` + `email.to.address` + RID. `destination.ip` appears on delivery-failure lines only. **Action:** `message_status`/`connection_status` for lifecycle events; `bounce_type` for bounces; delivery-failure text for errors — all vendor-only.

**`amp` / `antivirus` / `antispam` / `content_scanner`:** Filtering-engine telemetry keyed by MID and file hash. Target is the **message** and **attachment**; sender/recipient often absent. Antivirus adds **`observer.vendor`** for engine name. **Action:** AMP disposition/verdict; AV scan type + result (`Virus`, `CLEAN`, `Error`); content_scanner `vendor_action` (e.g. `restart`) — none mapped to `event.action`.

**`status`:** Appliance health metrics only — actor/target audit semantics and per-event action do not apply.

## Example Event Graph

Examples below come from the single **`cisco_secure_email_gateway.log`** data stream, drawn from pipeline test fixtures across **`gui_logs`** (true admin audit), **`consolidated_event`** (audit-adjacent mail enforcement), and **`antivirus`** (audit-adjacent scan telemetry). `event.action` is absent in all fixtures; actions are derived from vendor fields and noted as not mapped to ECS today.

### Example 1: Admin GUI HTTP asset request

**Stream:** `cisco_secure_email_gateway.log` · **Fixture:** `packages/cisco_secure_email_gateway/data_stream/log/_dev/test/pipeline/test-common-gui-log.log-expected.json`

```
Admin user (client) → GET → GUI web resource (xxx.png)
```

#### Actor

| Field | Value |
| --- | --- |
| id | 2v10z5fEuDsvhdbVE6Ck |
| name | admin |
| type | user |
| ip | 1.128.3.4 |

**Field sources:**
- `id` ← `event.id`
- `name` ← `user.name`
- `ip` ← `client.ip`

#### Event action

| Field | Value |
| --- | --- |
| action | GET |
| source_field | `http.request.method` |
| source_value | GET |

**Not mapped to ECS `event.action` today** — pipeline sets `event.category: [web]` and `event.type: [access]` instead.

#### Target

| Field | Value |
| --- | --- |
| name | xxx.png |
| type | general |
| sub_type | web_resource |

**Field sources:**
- `name` ← `url.path`

#### Mermaid (optional)

```mermaid
flowchart LR
  A["Actor: admin (1.128.3.4)"] --> E["GET"]
  E --> T["Target: xxx.png"]
```

### Example 2: Inbound message quarantined by policy

**Stream:** `cisco_secure_email_gateway.log` · **Fixture:** `packages/cisco_secure_email_gateway/data_stream/log/_dev/test/pipeline/test-common-consolidated-event.log-expected.json` (ESAMID 238746 — distinct sender and recipient)

The first consolidated-event row uses the same domain for CEF `suser` and `duser` (`example.com`), which would read as “sender quarantines to themselves.” This example uses a later event where `irobot@example.com` ≠ `alfombra@example.com`.

```
Mail sender (irobot@example.com) → QUARANTINED → inbound message for alfombra@example.com
```

#### Actor

| Field | Value |
| --- | --- |
| name | irobot@example.com |
| type | user |
| ip | 81.2.69.192 |

**Field sources:**
- `name` ← `email.from.address` (CEF `suser`)
- `ip` ← `source.ip` (SMTP connecting host; CEF `ESAHeloIP`)

#### Event action

| Field | Value |
| --- | --- |
| action | QUARANTINED |
| source_field | `cisco_secure_email_gateway.log.act` |
| source_value | QUARANTINED |

**Not mapped to ECS `event.action` today** — CEF `act=` is retained as vendor field only.

#### Target

| Field | Value |
| --- | --- |
| id | 238746 |
| name | IE : Crayons |
| type | general |
| sub_type | email_message |

**Field sources:**
- `id` ← `email.message_id` (ESAMID)
- `name` ← `email.subject` (message `"IE : Crayons"`)
- `sub_type` ← inbound mail object quarantined before delivery

**Scope context (not target):** intended recipient **alfombra@example.com** (`email.to.address`, CEF `duser`); mail policy **DEFAULT** (`cisco_secure_email_gateway.log.cs1`).

#### Mermaid (optional)

```mermaid
flowchart LR
  A["Actor: irobot@example.com"] --> E["QUARANTINED"]
  E --> T["Target: message 238746 (alfombra@example.com)"]
```

### Example 3: Antivirus engine detects phishing attachment

**Stream:** `cisco_secure_email_gateway.log` · **Fixture:** `packages/cisco_secure_email_gateway/data_stream/log/_dev/test/pipeline/test-common-antivirus.log-expected.json`

```
AV scan engine → Virus → email attachment
```

#### Actor

| Field | Value |
| --- | --- |
| name | sophos |
| type | service |

**Field sources:**
- `name` ← `observer.vendor` (inline AV engine identity, not human admin)

#### Event action

| Field | Value |
| --- | --- |
| action | Virus |
| source_field | `cisco_secure_email_gateway.log.type` |
| source_value | Virus |

**Not mapped to ECS `event.action` today** — pipeline sets `event.category: vulnerability` only; scan result detail is in `cisco_secure_email_gateway.log.antivirus_result` (`CXmail/Phish-O`).

#### Target

| Field | Value |
| --- | --- |
| id | 66842418 |
| name | Payment.html |
| type | general |
| sub_type | file |

**Field sources:**
- `id` ← `email.message_id` (MID)
- `name` ← `file.name`

#### Mermaid (optional)

```mermaid
flowchart LR
  A["Actor: sophos (AV engine)"] --> E["Virus"]
  E --> T["Target: Payment.html (MID 66842418)"]
```

## ES|QL Entity Extraction

**Package type: agent-backed** (`policy_templates`, single `data_stream/log` with Tier A fixtures). Router: **`data_stream.dataset == "cisco_secure_email_gateway.log"`**; secondary discriminator: **`cisco_secure_email_gateway.log.category.name`** (twelve syslog categories, one dataset). Pass 4 is **fill-gaps-only**: detection flags run first; mapped columns use **column-level** `CASE(col IS NOT NULL, col, condition, fallback, null)` (or **3-arg** `CASE(col IS NOT NULL, col, fallback)` in narrow pipeline fragments) — not `CASE(actor_exists, user.id, …)` / `CASE(target_exists, col, …)` when other actor/target signals can be set while `col` is empty (`actor_exists` includes `client.ip` / `user.name`; mail `user.id` fallbacks must not be blocked). Admin categories (**authentication**, **gui_logs**, **system**) map human actors; mail-security categories map sender + SMTP host actors and recipient/message targets; **`status`** is excluded (metrics). Auth login → **`service.target.name`** `"Cisco Secure Email Gateway"` (Pass 3 platform target), not self-referential admin user; GUI HTTP access → **`entity.target.name`** ← `url.path` (Pass 3 web resource). **Pass 4 (tautology cleanup):** no `CASE(col, col, …)` identity fallbacks; admin **`user.name`** and authentication **`host.ip`** are **ingest-only — no ES|QL** (pipelines grok them at index time with no alternate query-time source).

### Dataset inventory

| data_stream.dataset | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `cisco_secure_email_gateway.log` (authentication, gui_logs, system) | admin audit | user, host | service, general (web/config) | full |
| `cisco_secure_email_gateway.log` (consolidated_event, mail_logs, bounces) | mail security | user, host | user, general (message/file) | partial |
| `cisco_secure_email_gateway.log` (amp, antivirus, antispam, content_scanner) | filter telemetry | service | general (file/message) | partial |
| `cisco_secure_email_gateway.log` (error_logs) | delivery errors | user, host | host, user | partial |
| `cisco_secure_email_gateway.log` (status) | metrics | — | — | none |

### Field mapping plan

#### Actor mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `user.id` | `user.name` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("authentication", "gui_logs", "system")` | high | **column-level preserve** (`user.id IS NOT NULL`); fallback admin surrogate when `user.id` empty |
| `user.name` | — | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("authentication", "gui_logs", "system")` | high | **ingest-only — no ES\|QL** — grok → `user.name` at ingest; no alternate query-time source |
| `user.name` | `email.from.address` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("consolidated_event", "mail_logs", "bounces")` | high | **vendor fallback** — mail sender (may be domain-only) |
| `user.email` | `email.from.address` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("consolidated_event", "mail_logs", "bounces", "error_logs")` | high | **vendor fallback** |
| `host.ip` | `client.ip` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "gui_logs"` | high | **preserve existing** / fallback GUI client |
| `host.ip` | — | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "authentication"` | high | **ingest-only — no ES\|QL** — auth grok → `host.ip` at ingest |
| `host.ip` | `source.ip` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("consolidated_event", "error_logs")` | high | **vendor fallback** — SMTP connecting host |
| `service.name` | `observer.vendor` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "antivirus"` | medium | **vendor fallback** — AV engine (sophos), not human admin |

#### Target mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `service.target.name` | `"Cisco Secure Email Gateway"` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "authentication" AND cisco_secure_email_gateway.log.action IN ("logged on", "authenticated")` | low | **semantic literal** — admin login to appliance (Pass 3) |
| `entity.target.name` | `url.path` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "gui_logs" AND url.path IS NOT NULL` | high | **vendor fallback** — GUI web resource (Pass 3 Example 1) |
| `user.target.email` | `email.to.address` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND email.to.address IS NOT NULL` | high | **de-facto destination** — CEF `duser`; not `destination.user.*` |
| `entity.target.id` | `email.message_id` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND email.message_id IS NOT NULL` | high | **vendor fallback** — MID/ESAMID |
| `entity.target.name` | `email.subject` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND email.subject IS NOT NULL` | high | **vendor fallback** — message display name |
| `entity.target.name` | `file.name` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("amp", "antivirus") AND file.name IS NOT NULL` | high | **vendor fallback** — scanned attachment (Pass 3 Example 3) |
| `entity.target.name` | `cisco_secure_email_gateway.log.object` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "system"` | high | **vendor fallback** — config object on CLI commit |
| `host.target.ip` | `destination.ip` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND destination.ip IS NOT NULL` | high | **de-facto destination** — downstream MTA on delivery failure |

#### Event action mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `event.action` | `http.request.method` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "gui_logs" AND http.request.method IS NOT NULL` | high | **vendor fallback** — GUI HTTP access (Pass 3 Example 1) |
| `event.action` | `cisco_secure_email_gateway.log.action` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("authentication", "gui_logs") AND cisco_secure_email_gateway.log.action IS NOT NULL` | high | **vendor fallback** — admin session verbs |
| `event.action` | `cisco_secure_email_gateway.log.act` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "consolidated_event"` | high | **vendor fallback** — CEF enforcement (`QUARANTINED`, `DELIVERED`) |
| `event.action` | `cisco_secure_email_gateway.log.type` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "antivirus"` | high | **vendor fallback** — scan stage (`Virus`, `Result`, `Error`) |
| `event.action` | `cisco_secure_email_gateway.log.message_status` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "mail_logs"` | medium | **vendor fallback** — mail-flow lifecycle |
| `event.action` | `cisco_secure_email_gateway.log.bounce_type` | `data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "bounces"` | high | **vendor fallback** |

`actor_exists` omits `host.id` and `source.ip` — `host.id` is appliance serial on CEF events; `source.ip` alone must not block mail-sender fallbacks to `user.name` / `user.email`.

### Detection flags (mandatory — run first)

```esql
| EVAL
  actor_exists = user.id IS NOT NULL OR user.name IS NOT NULL OR user.email IS NOT NULL
    OR client.ip IS NOT NULL OR host.ip IS NOT NULL
    OR service.name IS NOT NULL OR observer.vendor IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR user.target.email IS NOT NULL
    OR host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
```

### Optional classification helpers (when needed)

Set in **fallback** only when `NOT target_exists`:

```esql
| EVAL
  entity.target.type = CASE(
    entity.target.type IS NOT NULL, entity.target.type,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "authentication" AND cisco_secure_email_gateway.log.action IN ("logged on", "authenticated"), "service",
    data_stream.dataset == "cisco_secure_email_gateway.log" AND email.to.address IS NOT NULL, "user",
    data_stream.dataset == "cisco_secure_email_gateway.log" AND file.name IS NOT NULL, "general",
    data_stream.dataset == "cisco_secure_email_gateway.log" AND url.path IS NOT NULL, "general",
    null
  ),
  entity.target.sub_type = CASE(
    entity.target.sub_type IS NOT NULL, entity.target.sub_type,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "authentication" AND cisco_secure_email_gateway.log.action IN ("logged on", "authenticated"), null,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND email.message_id IS NOT NULL, "email_message",
    data_stream.dataset == "cisco_secure_email_gateway.log" AND file.name IS NOT NULL, "file",
    data_stream.dataset == "cisco_secure_email_gateway.log" AND url.path IS NOT NULL, "web_resource",
    null
  )
```

### Combined ES|QL — actor fields

```esql
| EVAL
  user.id = CASE(
    user.id IS NOT NULL, user.id,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("authentication", "gui_logs", "system"), user.name,
    null
  ),
  user.name = CASE(
    user.name IS NOT NULL, user.name,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("consolidated_event", "mail_logs", "bounces"), email.from.address,
    null
  ),
  user.email = CASE(
    user.email IS NOT NULL, user.email,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("consolidated_event", "mail_logs", "bounces", "error_logs") AND email.from.address IS NOT NULL, email.from.address,
    null
  ),
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "gui_logs", client.ip,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("consolidated_event", "error_logs"), source.ip,
    null
  ),
  service.name = CASE(
    service.name IS NOT NULL, service.name,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "antivirus", observer.vendor,
    null
  )
```

### Combined ES|QL — event action

```esql
| EVAL
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "gui_logs" AND http.request.method IS NOT NULL, http.request.method,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "consolidated_event" AND cisco_secure_email_gateway.log.act IS NOT NULL, cisco_secure_email_gateway.log.act,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "antivirus" AND cisco_secure_email_gateway.log.type IS NOT NULL, cisco_secure_email_gateway.log.type,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "mail_logs" AND cisco_secure_email_gateway.log.message_status IS NOT NULL, cisco_secure_email_gateway.log.message_status,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "bounces" AND cisco_secure_email_gateway.log.bounce_type IS NOT NULL, cisco_secure_email_gateway.log.bounce_type,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("authentication", "gui_logs") AND cisco_secure_email_gateway.log.action IS NOT NULL, cisco_secure_email_gateway.log.action,
    null
  )
```

### Combined ES|QL — target fields

```esql
| EVAL
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "authentication" AND cisco_secure_email_gateway.log.action IN ("logged on", "authenticated"), "Cisco Secure Email Gateway",
    null
  ),
  user.target.email = CASE(
    user.target.email IS NOT NULL, user.target.email,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND email.to.address IS NOT NULL, email.to.address,
    null
  ),
  entity.target.id = CASE(
    entity.target.id IS NOT NULL, entity.target.id,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND email.message_id IS NOT NULL, email.message_id,
    null
  ),
  entity.target.name = CASE(
    entity.target.name IS NOT NULL, entity.target.name,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("amp", "antivirus") AND file.name IS NOT NULL, file.name,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND email.subject IS NOT NULL, email.subject,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "gui_logs" AND url.path IS NOT NULL, url.path,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "system", cisco_secure_email_gateway.log.object,
    null
  ),
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND destination.ip IS NOT NULL, destination.ip,
    null
  )
```

### Full pipeline fragment (optional)

```esql
FROM logs-*
| EVAL
  actor_exists = user.id IS NOT NULL OR user.name IS NOT NULL OR user.email IS NOT NULL
    OR client.ip IS NOT NULL OR host.ip IS NOT NULL
    OR service.name IS NOT NULL OR observer.vendor IS NOT NULL,
  target_exists = user.target.id IS NOT NULL OR user.target.name IS NOT NULL OR user.target.email IS NOT NULL
    OR host.target.id IS NOT NULL OR host.target.ip IS NOT NULL OR host.target.name IS NOT NULL
    OR service.target.id IS NOT NULL OR service.target.name IS NOT NULL
    OR entity.target.id IS NOT NULL OR entity.target.name IS NOT NULL,
  action_exists = event.action IS NOT NULL
| EVAL
  user.id = CASE(
    user.id IS NOT NULL, user.id,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("authentication", "gui_logs", "system"), user.name,
    null
  ),
  user.name = CASE(
    user.name IS NOT NULL, user.name,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("consolidated_event", "mail_logs", "bounces"), email.from.address,
    null
  ),
  user.email = CASE(
    user.email IS NOT NULL, user.email,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("consolidated_event", "mail_logs", "bounces", "error_logs") AND email.from.address IS NOT NULL, email.from.address,
    null
  ),
  host.ip = CASE(
    host.ip IS NOT NULL, host.ip,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "gui_logs", client.ip,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("consolidated_event", "error_logs"), source.ip,
    null
  ),
  service.name = CASE(
    service.name IS NOT NULL, service.name,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "antivirus", observer.vendor,
    null
  ),
  event.action = CASE(
    event.action IS NOT NULL, event.action,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "gui_logs" AND http.request.method IS NOT NULL, http.request.method,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "consolidated_event" AND cisco_secure_email_gateway.log.act IS NOT NULL, cisco_secure_email_gateway.log.act,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "antivirus" AND cisco_secure_email_gateway.log.type IS NOT NULL, cisco_secure_email_gateway.log.type,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "mail_logs" AND cisco_secure_email_gateway.log.message_status IS NOT NULL, cisco_secure_email_gateway.log.message_status,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "bounces" AND cisco_secure_email_gateway.log.bounce_type IS NOT NULL, cisco_secure_email_gateway.log.bounce_type,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("authentication", "gui_logs") AND cisco_secure_email_gateway.log.action IS NOT NULL, cisco_secure_email_gateway.log.action,
    null
  ),
  service.target.name = CASE(
    service.target.name IS NOT NULL, service.target.name,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "authentication" AND cisco_secure_email_gateway.log.action IN ("logged on", "authenticated"), "Cisco Secure Email Gateway",
    null
  ),
  user.target.email = CASE(
    user.target.email IS NOT NULL, user.target.email,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND email.to.address IS NOT NULL, email.to.address,
    null
  ),
  entity.target.id = CASE(
    entity.target.id IS NOT NULL, entity.target.id,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND email.message_id IS NOT NULL, email.message_id,
    null
  ),
  entity.target.name = CASE(
    entity.target.name IS NOT NULL, entity.target.name,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name IN ("amp", "antivirus") AND file.name IS NOT NULL, file.name,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND email.subject IS NOT NULL, email.subject,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "gui_logs" AND url.path IS NOT NULL, url.path,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND cisco_secure_email_gateway.log.category.name == "system", cisco_secure_email_gateway.log.object,
    null
  ),
  host.target.ip = CASE(
    host.target.ip IS NOT NULL, host.target.ip,
    data_stream.dataset == "cisco_secure_email_gateway.log" AND destination.ip IS NOT NULL, destination.ip,
    null
  )
| KEEP @timestamp, data_stream.dataset, cisco_secure_email_gateway.log.category.name, event.action, user.name, user.email, host.ip, user.target.email, entity.target.id, entity.target.name, service.target.name
```

### Streams excluded

- **`cisco_secure_email_gateway.log` where `cisco_secure_email_gateway.log.category.name == "status"`** — appliance health/queue metrics; no caller identity, no per-event action.

### Gaps and limitations

- **`event.action` at ingest** — never populated today; Pass 4 supplies query-time fallback only when `action_exists` is false. Long GUI `log.action` strings (e.g. HTTPS session established) are passed through verbatim — prefer `http.request.method` branch when present.
- **`email.from.address` / `email.to.address`** — often domain-only or multi-valued arrays (`example.com` in fixtures); partial RFC5322 semantics.
- **`mail_logs` SMTP peer** — connecting IP in `cisco_secure_email_gateway.log.address` only; not promoted to `source.ip` / `host.ip` at ingest.
- **`host.ip` vs `host.id`** — admin client vs appliance serial share `host.*` namespace; `host.id` excluded from `actor_exists`.
- **Pass 4 tautology cleanup** — admin `user.name` and authentication `host.ip` omitted from actor `EVAL` (ingest-only; no `CASE(col, col, …)`); mail `user.name` ← `email.from.address`, GUI `host.ip` ← `client.ip`, CEF/error `host.ip` ← `source.ip` only.
- **Pass 4 CASE syntax** — combined actor/target/classification blocks use column-level `CASE(col IS NOT NULL, col, …)` (not `CASE(actor_exists|target_exists, col, …)`); consolidated_event pipeline fragment uses **3-arg** `CASE(event.action IS NOT NULL, event.action, cisco_secure_email_gateway.log.act)` — not **4-arg** `CASE(action_exists, event.action, cisco_secure_email_gateway.log.act, null)` where `log.act` parses as a boolean condition.
- **Passphrase change** — `user.name` represents both actor and affected user; no separate `user.target.*` today.
- **`destination.user.*` not used** — recipients via `email.to.address` → `user.target.email` instead.
- **Pass 2 enhancement alignment** — ingest-time `event.action` and `user.target.*` promotion remain preferred; Pass 4 fills gaps without overwriting populated values.
- **`amp` / `antispam` / `content_scanner` action fallbacks** — disposition/verdict/vendor_action omitted from `event.action` CASE (low confidence); document only in Pass 2 action tables.
