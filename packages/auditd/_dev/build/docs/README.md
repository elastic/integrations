# Auditd Logs Integration

The Auditd Logs integration collects and parses logs from the audit daemon (`auditd`).

## Compatibility

The integration was tested with logs from `auditd` on OSes like CentOS 6 and CentOS 7.

This integration is not available for Windows.

## Parser modes

The `parser_mode` setting controls how the Elastic Agent reads auditd log files.
Requires Elastic Agent 9.6.0 or later.

| Mode | Field schema | Use when |
|---|---|---|
| `none` | Raw lines in `message`; no parsing | You pre-process logs elsewhere |
| `parse` | `auditd.log.*` fields per record type | You use existing dashboards or rules on `auditd.log.*` |
| `coalesce` | `auditd.data.*` / ECS fields, one document per syscall group | You want parity with the `auditd_manager` integration |

**Coalesce mode** groups related audit records (SYSCALL, EXECVE, CWD, PATH, …) into a
single document whose field schema matches `logs-auditd_manager.auditd-*`. Switching an
existing policy to `coalesce` means documents no longer contain `auditd.log.*` fields,
so saved searches, visualisations, and detection rules written against `auditd.log.*`
will stop matching.

**Forwarded logs and `resolve_ids`.** The parser resolves numeric UIDs and GIDs to names
using the local `/etc/passwd` and `/etc/group` files. If logs were collected on a
different host, the resolved names will be wrong. There is currently no package-level
option to disable resolution; set `resolve_ids: false` directly in an advanced policy
override if needed.

**`log_format=ENRICHED` in `auditd.conf`.** Without this setting the kernel does not
embed resolved names in the log records, so `auditd.user.audit.name` and similar fields
will be absent. Detection rules that filter on resolved usernames will silently miss
events on hosts without `ENRICHED` logging enabled.

## Auditd Logs

{{event "log"}}

{{fields "log"}}
