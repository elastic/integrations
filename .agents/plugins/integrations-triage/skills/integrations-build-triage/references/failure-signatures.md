# Known failure signatures

Match the `detail` column of `collect.sh` plus the test type. A match is 🟡 until it's re-proven on the current build. Status as of 2026-11-17 (9.7.0-SNAPSHOT, builds 52238 and 53431). Re-check "Tracked" with `scope.sh` / `gh issue view`.

## Pipeline / policy / script

| Test | Signature | Root cause | Owner | Tracked |
|---|---|---|---|---|
| pipeline | `Expected results are different`, diff is **array order only** | ES 9.6+ changed Painless `HashSet` iteration order | package owners: sort or `LinkedHashSet`. Don't just regenerate; that breaks older stacks | [integrations#22201](https://github.com/elastic/integrations/issues/22201) |
| pipeline | `Processor script … not supported`, `event.kind: pipeline_error` | `Map.Entry.setValue` on `ctx.entrySet()` is disallowed on 9.x. **Breaks real ingest** | package owners (`ctx.put`) | vectra_rux: none dedicated (#20180) |
| pipeline | expected `null` (doc dropped), doc now produced | unknown (ti_eset) | package owners | 🔍 |
| policy | `unexpected content in policy`: `condition: true` → `"true"`, `secret_references: [{}]` → `[]` | Kibana 9.7 policy compilation | elastic/kibana (Fleet): confirm it's intended | none filed |
| policy | OTel exporter fields added (`retry`, `sending_queue`, `include_source_on_error`) | Fleet injects ES exporter settings (kibana#288039) | elastic-package v0.127.0 strips them | fixed |
| script | `upgrading package policy … includes breaking changes … set acknowledge_breaking_changes` | Fleet now refuses unacknowledged breaking upgrades (kibana#301973); `upgrade_package_latest` can't acknowledge | elastic/elastic-package | none filed (network_traffic) |

## System

| Signature | Root cause | Owner | Tracked |
|---|---|---|---|
| `no data streams matching *-*-N appeared within 10m0s` / `test service … unexpectedly exited` (OTel inputs) + sender `connection refused` | Collector startup race: the ES exporter version probe has no auth, `retry_on_status` includes 401/403, so receivers listen about 15s late | upstream | fixed in otel-contrib#52470 (v0.165.0), awaiting [elastic-agent#17977](https://github.com/elastic/elastic-agent/pull/17977); hardening [kibana#300838](https://github.com/elastic/kibana/issues/300838) |
| collector rejects config: unknown/removed receiver keys | template uses removed kafkareceiver settings | package owners | [integrations#22185](https://github.com/elastic/integrations/issues/22185) |
| `errors found in documents stored in logs-generic-N` (elasticapm) | elasticapmintakereceiver forces ECS mode (otel-components#1468) | package owners: confirm, update test | none filed |
| `field "log.file.fingerprint" is undefined` / `<field>.text` undefined / other undeclared fields | 9.x filestream fingerprint; 9.7 `ecs@mappings` `.text` multi-fields | package owners | #20180, #22005 |
| `observed hit count 18 did not match expected 6` (N = k·M) | mock **serves page 1 again every 3rd poll** (atlassian_cloud), or short CEL `interval` with a mock that ignores the cursor | package owners: fix mock pagination / cursor | [integrations#22504](https://github.com/elastic/integrations/issues/22504); also closes 8.19 flakes |
| `could not find the expected hits` statsd_input, stuck at **7 of 9** (3→5→7 vs 3→6→9) | intended beats change [beats#53285](https://github.com/elastic/beats/pull/53285): idle timers no longer re-sent | package owners: `hit_count: 9` → `min_count: 7` | [integrations#22500](https://github.com/elastic/integrations/issues/22500) |
| statsd_input_otel **3 of 6** | TSDB `version_conflict_engine_exception` (duplicate `_id`) in the agent log | package owners / otel | #17716, #18735 (🟡) |
| `could not find the expected hits` (0) on Azure blob + `RESPONSE 400: The API version 2026-12-06 is not supported by Azurite` | the agent's Azure SDK is newer than Azurite | package owners: `--skipApiVersionCheck` (as in #20300) | [integrations#22499](https://github.com/elastic/integrations/issues/22499); also 8.19 flakes |
| `errors found in documents` + `GET http://svc-<pkg>-mock…: 404` + fingerprint `missing field` | mock rule pins a header containing the **package version** (`x-doppel-client: elastic/1.2.0`); the package was bumped | package owners: relax the mock match | none filed (doppel) |
| `errors found while examining elastic-agent.logs` + `ORA-12541` (oracle) | DB still in `configDB`; healthcheck `sqlplus -s` exits 0 on logon failure (vacuous). The single "hit" is the error event | package owners | [integrations#22502](https://github.com/elastic/integrations/issues/22502) |
| `400 minDoc must be >= 0 but got minDoc=-N` | ES snapshot search bug on logsdb | elasticsearch | [elastic-package#3877](https://github.com/elastic/elastic-package/issues/3877) (evidence added) |
| agent `invalid character(s) in name "…<Template Name>-…"`, unit STARTING→STOPPED | space in `policy_templates[].name` ends up in the OTel receiver ID | elastic-agent | elastic-agent#17590 closed; 14 packages dropped out 10-29 |
| memcached UDP: `publish event` but no `_bulk` | packetbeat OTel receiver stops at pcap EOF before UDP timers flush | elastic/beats | none filed. **Hidden since 11-04** by network_traffic's script failure |
| fim: 0 hits, the only fsnotify event at teardown | generator acts on SIGHUP before the watcher starts | package | fixed (#22428) |
| `gvm: … context deadline exceeded`, `go: command not found`, exit 127 | CI infra, no tests ran | retry | usually not in the issue list |

## Mechanics behind system-test races

- elastic-package sends `service_notify_signal` (SIGHUP) when Fleet reports the policy revision, not when the input is running. One-shot senders race agent and collector startup.
- Beats metricsets start after a random delay of up to `max_start_delay` (10s).
- Under the OTel runtime, all components share one collector config, so one invalid component kills every input on that agent.
- A failed metricbeat fetch is published as an event (`reporter.Error`), so it can satisfy `hit_count: 1`.
- Healthchecks that pipe into a CLI (`sqlplus -s`, `psql`, `curl` without `-f`) can pass vacuously. Check the exit code on failure.
