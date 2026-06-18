# linux

## Product Domain

Linux host observability covers the health, performance, and security posture of servers running the Linux kernel. Operators need visibility into resource utilization, kernel subsystems, running services, network activity, and interactive user sessions to keep infrastructure reliable and to detect anomalies. This domain spans system logs (syslog, journald, audit), time-series metrics from `/proc` and other kernel interfaces, and security-relevant signals such as login sessions, open sockets, and connection-tracking state.

The Elastic **Linux Metrics** integration targets the metrics slice of that domain. It runs on Elastic Agent and collects low-level, Linux-specific measurements directly from the local host—primarily via `/proc`, systemd/logind, and netfilter conntrack interfaces. Unlike cross-platform system integrations, it emphasizes kernel- and distro-specific counters that matter on Linux: memory fragmentation, KSM deduplication, RAID array health, per-disk I/O, entropy pool availability, and protocol-level network summaries.

Collection is agent-based and always scoped to the machine where the agent runs; no remote `hosts` configuration is required. In containerized deployments, the host's proc filesystem can be exposed through the `system.hostfs` setting (for example `/hostfs`). Data is indexed as ECS-aligned metrics and visualized in Kibana dashboards such as the Host Services Overview, supporting alerting and troubleshooting for Linux infrastructure teams.

While broader Linux observability also includes log and endpoint-security pipelines (handled by separate integrations such as System, Auditd, or Elastic Defend), this package complements those sources with granular host metrics that expose kernel and service state not always visible in log lines alone.

## Data Collected (brief)

Metrics only (no logs or security events). Eleven data streams:

| Data stream | Description |
|---|---|
| **conntrack** | Netfilter connection-tracking performance counters |
| **entropy** | Available cryptographic entropy (bits and pool percentage) |
| **iostat** | Per-disk I/O statistics (equivalent to `iostat -x`) |
| **ksm** | Kernel Samepage Merging statistics |
| **memory** | Linux-specific memory metrics (Huge Pages, paging) |
| **network_summary** | Global network I/O counters by protocol (TCP, UDP, ICMP, IP) |
| **pageinfo** | Memory paging and fragmentation stats from `/proc/pagetypeinfo` and buddyinfo |
| **raid** | Software RAID device status, disk counts, sync progress |
| **service** | systemd unit state, resource usage (CPU, memory, network), and uptime |
| **socket** | New TCP socket events with local/remote endpoints and owning process |
| **users** | Logged-in users and sessions via systemd logind/dbus |

All streams include standard ECS host, cloud, and container metadata where applicable.

## Expected Audit Log Entities

The **Linux Metrics** integration collects **metrics only** (`type: metrics` on all eleven data streams per `data_stream/*/manifest.yml`; no log inputs, ingest pipelines, `sample_event.json`, or `*-expected.json` fixtures under `packages/linux/`). It does not emit audit logs, authentication events, or administrative action records. All streams are periodic host telemetry or state snapshots—not discrete auditable actions. Actor/target semantics below describe **security-adjacent identity and endpoint signals** useful for correlation, not principals or objects from an audit trail. For true Linux audit telemetry, use separate integrations (System auth logs, Auditd, Sysmon for Linux, Elastic Defend). No ECS `*.target.*` fields are declared or populated (`out/target_fields_audit.csv` has no `linux` row). The target-fields audit classified this package as **`none`** for actor/target enhancement (`out/target_enhancement_packages.csv`). `linux` does not appear in `out/destination_identity_hits.csv` (no `destination.user.*` / `destination.host.*` usage).

**`event.action` is absent across all streams.** No ECS `event.action` declaration in any `fields/ecs.yml` or `fields/base-fields.yml`; grep of `packages/linux/` finds no pipeline or fixture mapping. Declared event fields are limited to `event.module`, `event.dataset`, and `event.duration` (`data_stream/*/fields/base-fields.yml`, `ecs.yml`). Metrics streams have **no per-event verb** — state gauges and counters describe *what is*, not *what happened*.

### Event action (semantic)

No stream records a discrete security or administrative action. All eleven data streams are `type: metrics` with `event.kind: metric` semantics (implicit via data stream type; not declared as ECS `event.kind` in field schemas).

| Action (normalized label) | Classification | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- |
| *(none — metrics-only)* | n/a | high | No `event.action` in package; no log inputs or audit API | **All 11 streams** — periodic polls or gauge snapshots, not action events |
| Implicit TCP socket observation | detection | low | `docs/README.md` Socket: "reports an event for each new TCP socket" via `/proc` polling | **`linux.socket`** — discovery of new sockets, not a named operation; no vendor action field |
| Session state snapshot | n/a | high | `system.users.state`, `system.users.type` (`users/fields/fields.yml`) | **`linux.users`** — current logind session metadata, not login/logout events |
| Service state snapshot | n/a | high | `system.service.state`, `system.service.sub_state`, `system.service.load_state` (`service/fields/fields.yml`) | **`linux.service`** — systemd unit state gauge, not start/stop/restart actions |
| RAID sync status | n/a | high | `system.raid.sync_action` (`raid/fields/fields.yml`) | **`linux.raid`** — current sync operation label on array (e.g. `resync`), not a discrete audit event |

### Event action (ECS candidates)

| ECS / vendor field | Mapped to `event.action` today? | Mapping correct? | Recommended `event.action` value (from fixtures) | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- |
| `event.action` | no | n/a | — | no | Not declared in any `ecs.yml`; no ingest pipeline |
| `event.module` | no | n/a | `linux` (constant) | no | `base-fields.yml` — module identifier, not an operation verb |
| `event.dataset` | no | n/a | e.g. `linux.socket` (constant per stream) | no | `base-fields.yml` — stream identifier, not an operation verb |
| `system.raid.sync_action` | no | n/a | — (no fixtures) | no | `raid/fields/fields.yml` — RAID array sync-state dimension, not an auditable action |
| `system.service.state` / `.sub_state` / `.load_state` | no | n/a | — (no fixtures) | no | `service/fields/fields.yml` — unit state gauges, not lifecycle events |
| `system.users.state` / `.type` | no | n/a | — (no fixtures) | no | `users/fields/fields.yml` — session metadata, not auth actions |
| *(inferred)* `tcp-socket-opened` | no | n/a | — | no | **`linux.socket`** — README describes new-socket detection but agent emits no action label; mapping would be speculative |

No enhancement to `event.action` is recommended for this package. Metrics-only design; action semantics belong in log-based integrations (System auth, Auditd, Sysmon for Linux, Elastic Defend).

#### Per-stream `event.action` check

| Stream | `event.action` in fixtures? | Pipeline maps to `event.action`? | Primary action candidate | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| conntrack | no (no fixtures) | no (no pipeline) | — | high | Kernel counter gauges only |
| entropy | no | no | — | high | Entropy pool gauge |
| iostat | no | no | — | high | Per-disk I/O metrics |
| ksm | no | no | — | high | KSM page-sharing counters |
| memory | no | no | — | high | Memory/paging gauges |
| network_summary | no | no | — | high | Protocol-level network counters |
| pageinfo | no | no | — | high | Buddy/page-type gauges |
| raid | no | no | `system.raid.sync_action` (state label, not action) | high | `raid/fields/fields.yml` |
| service | no | no | `system.service.state` (state gauge, not action) | high | `service/fields/fields.yml` |
| socket | no | no | — (implicit socket discovery only) | high | `docs/README.md`; no action field in schema |
| users | no | no | `system.users.state` (session state, not action) | high | `users/fields/fields.yml` |

### Actor (semantic)

| Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- |
| Monitored host | host | — | high | `host.*`, `agent.*`, `cloud.*`, `container.*` on all streams (`data_stream/*/fields/agent.yml`, `base-fields.yml`) | **All 11 streams** — collection scope where the agent runs; not an audit principal |
| Interactive logind session | user | — | low | `system.users.id`, `system.users.type`, `system.users.state`, `system.users.remote`, `system.users.leader` (`users/fields/fields.yml`; `docs/README.md` Users) | **`linux.users`** — logind session snapshot; **no** ECS `user.name`/`user.id` on this stream |
| Remote session origin | host | — | low | `source.ip`, `source.port` (`users/fields/ecs.yml`); `system.users.remote_host` (`users/fields/fields.yml`) | **`linux.users`** — client endpoint when `system.users.remote=true`; username not in schema |
| Socket-owning user | user | — | moderate | `user.id`, `user.full_name` (`socket/fields/ecs.yml`; `docs/README.md` Socket) | **`linux.socket`** — UID/username of process owning a new TCP socket when resolvable from `/proc` |
| Socket-owning process | general | process | high | `process.pid`, `process.name`, `process.executable`, `system.socket.process.cmdline` (`socket/fields/ecs.yml`, `fields.yml`) | **`linux.socket`** — strongest actor surrogate; one doc per newly detected TCP socket |
| systemd unit (workload) | service | systemd unit | high | `system.service.name`, `systemd.unit`, `systemd.fragment_path` (`service/fields/fields.yml`) | **`linux.service`** — monitored daemon; not a human actor |
| Service main process | general | process | moderate | `process.pid`, `process.name`, `process.ppgid`, `process.working_directory` (`service/fields/ecs.yml`) | **`linux.service`** — unit main process when agent resolves it |

**No actor identity:** `conntrack`, `entropy`, `iostat`, `ksm`, `memory`, `network_summary`, `pageinfo`, `raid` — kernel, disk, and aggregate network counters only; `host.*` metadata is collection context, not a security principal.

### Actor (ECS candidates)

| ECS / vendor field | Role | Mapped today? | Mapping correct? | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| `host.name`, `host.hostname`, `host.id`, `host.ip` | Collection host identity | unknown (no fixtures) | n/a | high | Declared on `service/fields/ecs.yml`; `agent.yml` / `base-fields.yml` on all streams |
| `agent.id`, `agent.name` | Elastic Agent collector | unknown (no fixtures) | n/a | high | `data_stream/*/fields/agent.yml` |
| `cloud.*`, `container.*` | Deployment scope | unknown (no fixtures) | n/a | moderate | `agent.yml` on all streams |
| `user.id`, `user.full_name` | Socket owner UID/name | unknown (no fixtures) | partial | moderate | `socket/fields/ecs.yml` — process owner, not proven login principal; no ingest pipeline to verify |
| `process.pid`, `process.name`, `process.executable` | Socket-owning process | unknown (no fixtures) | yes | high | `socket/fields/ecs.yml` |
| `system.socket.process.cmdline` | Socket process command line | unknown (no fixtures) | n/a | high | `socket/fields/fields.yml` — vendor-only |
| `user.name` | Service unit owner | unknown (no fixtures) | partial | moderate | `service/fields/ecs.yml` — may reflect systemd unit user, not interactive actor |
| `process.*` (service stream) | Service main process | unknown (no fixtures) | yes | moderate | `service/fields/ecs.yml` |
| `system.users.id`, `system.users.type`, `system.users.state`, `system.users.leader` | Logind session metadata | unknown (no fixtures) | n/a | high | `users/fields/fields.yml` — vendor-only; session ID, not ECS user |
| `system.users.remote_host` | Remote client hostname/IP string | unknown (no fixtures) | n/a | moderate | `users/fields/fields.yml` — vendor-only |
| `source.ip`, `source.port` | Remote session client endpoint | unknown (no fixtures) | partial | low | `users/fields/ecs.yml` — network peer of remote session, not audit actor |
| `service.type` | Metric module label | unknown (no fixtures) | n/a | high | `ecs.yml` on streams — collector module type, not workload identity |

No ingest pipelines exist; ECS fields are populated by Elastic Agent at collection time. **Mapped today?** cannot be fixture-verified.

### Target (semantic)

| Layer | Description | Entity | Classification | Entity type (if general) | Confidence | Evidence | Per-stream notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2 — Resource / object | Monitored host (measurement subject) | Local Linux server | host | — | high | `host.name` on all streams | **Most streams** — measured object, not an audit target of an action |
| 2 — Resource / object | Remote TCP peer | Remote host / endpoint | host | — | moderate | `system.socket.remote.ip`, `system.socket.remote.port`, optional `system.socket.remote.host` | **`linux.socket`** — far-end of newly observed connection; network context, not authorization target |
| 3 — Content / artifact | Remote DNS enrichment | Resolved hostname / eTLD+1 | general | dns-name | low | `system.socket.remote.host`, `system.socket.remote.etld_plus_one` (`socket/fields/fields.yml`; reverse lookup off by default in `socket/manifest.yml`) | **`linux.socket`** — optional PTR enrichment |
| 2 — Resource / object | Remote login source | Client of remote session | host | — | low | `system.users.remote_host`, `source.ip` | **`linux.users`** — when `system.users.remote=true`; session client, not acted-upon resource |
| 2 — Resource / object | systemd service | Monitored unit | service | systemd unit | high | `system.service.name`, `system.service.state`, `system.service.sub_state`, `systemd.unit` | **`linux.service`** — health/resource measurement target |
| 2 — Resource / object | Block device | Disk / partition | general | disk | moderate | `linux.iostat.name` (dimension) + I/O gauges (`iostat/fields/fields.yml`) | **`linux.iostat`** — performance dimension, not security object |
| 2 — Resource / object | Software RAID array | md device | general | storage-array | moderate | `system.raid.name`, `system.raid.level`, `system.raid.status` (`raid/fields/fields.yml`) | **`linux.raid`** — array health dimension |

**No meaningful audit target:** `conntrack`, `entropy`, `ksm`, `memory`, `network_summary`, `pageinfo` — aggregate kernel/network/memory gauges with no per-entity acted-upon object. Layer 1 (platform/cloud service) does not apply; this is on-host kernel telemetry, not a SaaS API invocation.

### Target (ECS candidates)

| ECS / vendor field | Layer | Classification | Mapped today? | Mapping correct? | ECS target bucket | Enhancement candidate? | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `host.name`, `host.hostname` | 2 | host | unknown (no fixtures) | n/a | context-only | no | Measurement subject on all streams; not `host.target.*` |
| `system.socket.remote.ip`, `system.socket.remote.port` | 2 | host | unknown (no fixtures) | partial | context-only | no | `socket/fields/fields.yml` — network peer endpoint, not audit target |
| `system.socket.local.ip`, `system.socket.local.port` | 2 | host | unknown (no fixtures) | n/a | context-only | no | `socket/fields/fields.yml` — local bind endpoint |
| `system.socket.remote.host`, `system.socket.remote.etld_plus_one` | 3 | general | unknown (no fixtures) | n/a | context-only | no | `socket/fields/fields.yml` — optional DNS artifact |
| `system.users.remote_host` | 2 | host | unknown (no fixtures) | partial | context-only | no | `users/fields/fields.yml` — remote client string; no `destination.host.*` mapping |
| `source.ip`, `source.port` | 2 | host | unknown (no fixtures) | partial | context-only | no | `users/fields/ecs.yml` — session client endpoint; not de-facto audit target |
| `system.service.name`, `systemd.unit` | 2 | service | unknown (no fixtures) | n/a | context-only | no | `service/fields/fields.yml` — monitored unit dimension |
| `linux.iostat.name` | 2 | general | unknown (no fixtures) | n/a | context-only | no | `iostat/fields/fields.yml` — disk device dimension |
| `system.raid.name`, `system.raid.level`, `system.raid.status` | 2 | general | unknown (no fixtures) | n/a | context-only | no | `raid/fields/fields.yml` — RAID array dimension |

No `user.target.*`, `host.target.*`, `service.target.*`, `entity.target.*`, or `destination.*` identity fields anywhere in the package.

### Gaps and mapping notes

- **Metrics-only, no audit events:** All eleven streams are gauges/counters or poll-based socket snapshots. Per-event caller identity, authorization outcomes, and operation verbs are absent by design.
- **No `event.action` anywhere:** Not declared in field schemas, not populated by agent, no ingest pipeline to map vendor action fields. State labels (`system.service.state`, `system.users.state`, `system.raid.sync_action`) describe current conditions, not discrete actions — do not substitute for `event.action`.
- **No ingest pipelines or fixtures:** Cannot trace ECS population through pipeline steps; evidence is field declarations (`fields.yml`, `ecs.yml`) and README only.
- **`linux.users` lacks ECS user mapping:** Session metadata stays under `system.users.*`; `system.users.id` is a logind session ID, not `user.id`. No username field on this stream despite interactive-session semantics.
- **`source.ip` on users stream:** Declared for remote sessions but represents a network client endpoint, not a de-facto audit target; no `destination.user.*` / `destination.host.*` counterparts.
- **`user.id` / `user.full_name` on socket stream:** Process owner from `/proc`, useful for correlation but not proof of interactive login principal.
- **No ECS `*.target.*` fields:** Aligns with target-fields audit classification **`none`**. Enhancement to official target buckets is not applicable without log-based audit semantics.
- **Pair with log integrations:** System auth logs, Auditd, Sysmon for Linux, or Elastic Defend for audit-grade actor/target and `event.action` coverage.

### Per-stream notes

#### users

Polls systemd logind via D-Bus (`docs/README.md`). Audit-adjacent (interactive access visibility) but **not** login/logout events—periodic state only. Fields describe session metadata (`system.users.type`, `seat`, `scope`, `state`, `remote`) and root PID (`leader`) without ECS `user.*`. Remote sessions expose `system.users.remote_host` and `source.ip`/`source.port`. **`system.users.state`** is session state, not an `event.action` candidate.

#### socket

Event-like metric stream: one document per **new** TCP socket detected by polling `/proc` (kernel ≥ 2.6.14). Richest actor/target hints—`process.*`, `user.id`, `user.full_name`, local/remote IP/port, optional reverse DNS (`socket.reverse_lookup.enabled`, default false). Short polling interval recommended. Not a firewall or flow log; no bytes/packets, direction, or allow/deny outcome. **No `event.action`** — implicit socket discovery only; no vendor operation field to map.

#### service

Reports systemd unit load/activity state and resource usage (CPU, memory, network, task count). Measurement target is the named service (`system.service.name` / `systemd.unit`); `user.name` and `process.*` support correlation with auth or process audit logs. State fields (`system.service.state`, `.sub_state`, `.load_state`) are gauge snapshots, not discrete change events and not `event.action` candidates.

#### conntrack, entropy, ksm, memory, network_summary, pageinfo

Pure host/kernel telemetry. `host.*` metadata only; no user, service, or peer identity.

#### iostat, raid

Infrastructure measurement dimensions (disk device, RAID array). Useful for asset context but not security audit targets.

## Example Event Graph

The Linux Metrics integration has no `sample_event.json` or pipeline `*-expected.json` fixtures under `packages/linux/` (only a Kibana dashboard JSON). All eleven streams are **metrics-only**—periodic host telemetry and state snapshots, not audit logs or discrete security events. **No per-event graph — time-bucketed metrics only.** ECS `event.action` is absent across the package; no stream records a named operation verb suitable for an Actor → action → Target chain grounded in fixture data.

The streams with the richest audit-adjacent identity signals (`linux.socket`, `linux.users`, `linux.service`) still lack fixtures and `event.action`, so illustrative graphs cannot be cited here without inventing field values. For true Actor → event.action → Target examples on Linux hosts, use log-based integrations (System auth logs, Auditd, Sysmon for Linux, Elastic Defend).

## ES|QL Entity Extraction

**Package type: agent-backed** (policy template `system` + `linux/metrics` inputs per `manifest.yml`; eleven `data_stream/` directories, all `type: metrics`). Router: **`event.dataset`** (e.g. `linux.socket`, `linux.users` from `data_stream/*/fields/base-fields.yml`); scope with `FROM metrics-*` or `FROM metrics-linux-*`. **No Tier A fixtures** — no `sample_event.json`, `*-expected.json`, or ingest pipelines under `packages/linux/`; evidence is field declarations (`fields.yml`, `ecs.yml`) and README only. Pass 4 is **fill-gaps-only**, but this integration is **metrics-only**: periodic gauges and poll-based snapshots with **no `event.action`**, no discrete security/administration verbs, and no ECS `*.target.*` at collection (target-fields audit classification **`none`**). Pass 3 confirms **no per-event Actor → action → Target graph**. **No `EVAL` / `CASE` blocks are produced** — all eleven datasets under **Streams excluded**; do not promote `user.id` / `system.socket.remote.*` / `system.users.*` into audit actor/target columns. Cross-package queries use unscoped `FROM` (no `WHERE event.dataset` filter); embed `event.dataset == "linux.socket"` (etc.) in every CASE fallback branch when EVAL is added. **Pass 4 (CASE syntax + tautology):** Elastic Agent populates identity and peer fields at collection (`socket/fields/ecs.yml`, `users/fields/fields.yml`) with no alternate query-time vendor path — omit columns from ES|QL rather than **4-arg** `CASE(actor_exists, col, bare_field, null)` / `CASE(target_exists, col, bare_field, null)` (bare field parses as a **condition**, not a fallback) or **4-arg** `CASE(flag, col, col, null)` (identity no-op). Even valid **3-arg** `CASE(user.name IS NOT NULL, user.name, user.full_name)` on `linux.socket` is omitted: `user.full_name` is process-owner context, not audit `user.name`, and `actor_exists` true from `user.id` must not gate `user.name` via flag-based preserve.

### Dataset inventory

| data_stream.dataset / `event.dataset` | Stream role | Actor classification(s) | Target classification(s) | Extraction |
| --- | --- | --- | --- | --- |
| `linux.conntrack` | kernel metrics | — | — | none |
| `linux.entropy` | kernel metrics | — | — | none |
| `linux.iostat` | disk metrics | — | — | none |
| `linux.ksm` | kernel metrics | — | — | none |
| `linux.memory` | kernel metrics | — | — | none |
| `linux.network_summary` | network metrics | — | — | none |
| `linux.pageinfo` | kernel metrics | — | — | none |
| `linux.raid` | storage metrics | — | — | none |
| `linux.service` | systemd state | — | — | none |
| `linux.socket` | socket snapshot | — | — | none |
| `linux.users` | logind session state | — | — | none |

### Field mapping plan

No actor, target, or `event.action` destination columns are populated. Audit-adjacent fields on `linux.socket` / `linux.users` / `linux.service` describe measurement dimensions or correlation context (Pass 2), not principals or acted-upon resources in an audit trail. Query-time `CASE` on agent-populated `user.id`, `user.full_name`, `host.name`, or `system.socket.remote.*` would conflate process-owner / logind / network-peer context with audit actor/target identity. Columns below are **collection-time only — omit from ES|QL** (no alternate indexed source for audit extraction).

#### Actor mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| — | — | — | — | No audit actor on any stream; `host.*` is collection scope |
| `user.id` | — | `event.dataset == "linux.socket"` | high | **collection-time only — omit from ES\|QL** — `socket/fields/ecs.yml`; process owner from `/proc`, not login principal (Pass 2 partial); no vendor fallback path |
| `user.name` | — | `event.dataset == "linux.socket"` | high | **omit** — `user.full_name` only at collection; forbidden **4-arg** `CASE(actor_exists, user.name, user.full_name, null)` (3rd arg is condition); valid **3-arg** `CASE(user.name IS NOT NULL, user.name, user.full_name)` still omitted (metrics process-owner, not audit principal) |
| `user.full_name` | — | `event.dataset == "linux.socket"` | high | **collection-time only — omit from ES\|QL** — forbidden **4-arg** `CASE(actor_exists, user.full_name, user.full_name, null)` (tautology + flag-based preserve) |
| `host.name` / `host.hostname` | — | all datasets | high | **collection-time only — omit from ES\|QL** — measurement subject on all streams (`service/fields/ecs.yml`, `agent.yml`); not audit principal |
| `user.name` | — | `event.dataset == "linux.service"` | moderate | **collection-time only — omit from ES\|QL** — `service/fields/ecs.yml`; systemd unit user, not interactive actor |

#### Target mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| — | — | — | — | No audit target; peers/dimensions are context-only (Pass 2/3) |
| `host.target.ip` | — | `event.dataset == "linux.socket"` | high | **omit** — `system.socket.remote.ip` is network peer context, not `host.target.*`; forbidden **4-arg** `CASE(target_exists, host.target.ip, system.socket.remote.ip, null)` (`system.socket.remote.ip` parses as condition); use **5-arg** `CASE(host.target.ip IS NOT NULL, host.target.ip, event.dataset == "linux.socket", system.socket.remote.ip, null)` only if audit semantics applied — they do not on this stream |
| `host.target.*` | — | `event.dataset == "linux.users"` | high | **omit** — `source.ip` / `system.users.remote_host` are session client endpoints, not de-facto `host.target.*` (Pass 2) |
| `user.target.*` / `service.target.*` | — | all datasets | high | **omit** — no ECS `*.target.*` in package; wiring `user.id` or `system.service.name` into target columns duplicates measurement dimensions |

#### Event action mappings

| Output column | Source field(s) | Condition (dataset + optional) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| — | — | — | — | `event.action` absent from all field schemas; state labels (`system.service.state`, `system.users.state`, `system.raid.sync_action`) are gauges, not verbs |
| `event.action` | — | all datasets | high | **omit** — not declared in `ecs.yml` / `base-fields.yml`; field absent so no preserve branch; forbidden **4-arg** `CASE(action_exists, event.action, event.action, null)` (tautology); do not substitute state gauges |

### Detection flags (mandatory — run first)

Not applicable — all streams excluded (metrics-only; no defensible preserve-first fallback without misclassifying process owner, logind session metadata, or remote socket peer as audit actor/target). Do not emit detection flags solely to wrap tautological `CASE` on agent-populated columns.

### Combined ES|QL — actor fields

Not applicable — all streams excluded (metrics-only). Do not emit **4-arg** `CASE(actor_exists, user.id, user.id, null)`, `CASE(actor_exists, user.full_name, user.full_name, null)`, `CASE(actor_exists, host.name, host.name, null)`, or **4-arg** `CASE(user.name IS NOT NULL, user.name, user.full_name, null)` on `linux.socket` — collection-time fields with no defensible audit fallback (`socket/fields/ecs.yml`, `users/fields/fields.yml`).

### Combined ES|QL — event action

Not applicable — all streams excluded; no `event.action` candidate with fixture or pipeline evidence. Do not map `system.service.state`, `system.users.state`, or `system.raid.sync_action` into `event.action` fallback branches.

### Combined ES|QL — target fields

Not applicable — all streams excluded (metrics-only). Do not emit **4-arg** `CASE(target_exists, host.target.ip, system.socket.remote.ip, null)` or **5-arg** peer promotion to `host.target.ip`; do not promote `system.service.name` / `linux.iostat.name` to `service.target.*` / `entity.target.*`.

### Streams excluded

- **`linux.conntrack`**, **`linux.entropy`**, **`linux.ksm`**, **`linux.memory`**, **`linux.network_summary`**, **`linux.pageinfo`** — kernel/network/memory gauges; `host.*` metadata only.
- **`linux.iostat`**, **`linux.raid`** — disk/RAID measurement dimensions (`linux.iostat.name`, `system.raid.*`); not security audit targets.
- **`linux.service`** — systemd unit state and resource gauges (`system.service.state`, `systemd.unit`); no start/stop/restart `event.action`.
- **`linux.socket`** — one document per newly detected TCP socket (`docs/README.md`); `user.id` / `user.full_name` / `process.*` are process-owner correlation, not login principal; `system.socket.remote.*` is network peer context, not `host.target.*`.
- **`linux.users`** — logind session snapshot (`system.users.*`, optional `source.ip`); not login/logout events; no ECS `user.name` / `user.id`.

### Gaps and limitations

- **Metrics-only by design:** All eleven streams are `type: metrics` per `data_stream/*/manifest.yml`; pairing with System auth logs, Auditd, Sysmon for Linux, or Elastic Defend is required for audit-grade `event.action` and `*.target.*`.
- **No fixtures or ingest pipelines:** Cannot fixture-verify ES|QL sources; field declarations only — any `CASE` on `linux.socket` `user.*` would be heuristic and contradict Pass 2 **Mapping correct?** = partial for socket owner.
- **Target-fields audit `none`:** No `destination.*` or ECS `*.target.*` in package; query-time promotion would guess wrong.
- **`linux.users` `source.ip`:** Remote session client endpoint, not de-facto `host.target.ip`.
- **Pass 2 enhancement alignment:** Do not substitute `system.service.state` / `system.users.state` / `system.raid.sync_action` for `event.action` at query time.
- **No tautological CASE (Pass 4 #10):** `user.id`, `user.full_name`, and `host.name` on `linux.socket` and `host.*` on all streams are agent-populated at collection with no alternate vendor path; `system.socket.remote.*` and `linux.users` `source.ip` are peer/session context, not `host.target.*`. Emitting **4-arg** `CASE(actor_exists|target_exists, col, col, null)` or dataset-routed fallbacks that read the same column would be identity no-ops or violate Pass 2/3 metrics semantics.
- **Pass 4 CASE syntax:** No fenced `esql` blocks — metrics-only, all streams excluded per `esql-entity-mapping.md` linux example. Anti-patterns above document forbidden **4-arg** flag-based preserve and bare-field-as-condition forms only; no `target.user.*` / `target.entity.type`; no detection-flag wrapper `EVAL` solely to host tautological `CASE`.
