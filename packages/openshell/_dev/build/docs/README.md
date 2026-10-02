# NVIDIA OpenShell

[NVIDIA OpenShell](https://docs.nvidia.com/openshell/) runs AI agents and other untrusted workloads inside policy-controlled sandboxes. A supervisor inside each sandbox mediates every outbound connection, HTTP request and SSH session against the sandbox policy and records the decision as an [OCSF](https://schema.ocsf.io/) event.

This integration collects the OCSF JSON export written by the OpenShell sandbox supervisor (or the Windows MXC gateway), normalizes it to the Elastic Common Schema (ECS), and keeps the OCSF-specific attributes under `openshell.ocsf.*`. The resulting events let you audit what sandboxed workloads tried to reach, which policy rule decided the outcome, and which process inside the sandbox initiated the activity.

## Data streams

The integration collects one data stream, `ocsf`, which contains every OCSF event class emitted by OpenShell:

| `class_uid` | OCSF class                  | What it records                                                         |
| ----------- | --------------------------- | ----------------------------------------------------------------------- |
| 4001        | Network Activity            | Allowed, denied and failed outbound connections (CONNECT, transparent TCP, DNS policy decisions) |
| 4002        | HTTP Activity               | Layer-7 request decisions for policy-inspected endpoints               |
| 4007        | SSH Activity                | SSH sessions accepted on the supervisor socket                          |
| 1007        | Process Activity            | Process events, when enabled by the supervisor                          |
| 2004        | Detection Finding           | Supervisor findings                                                     |
| 5019        | Device Config State Change  | Policy revisions loaded, published or detected by the supervisor        |
| 6002        | Application Lifecycle       | Supervisor lifecycle events                                             |
| 0           | Base Event                  | Relay open/close notifications and other operational events             |

Every event carries `observer.product: "OpenShell Sandbox Supervisor"`, the sandbox in `container.name` / `container.id`, and `event.code` set to the OCSF `class_uid`. Policy decisions are exposed as `event.action` (`allowed` / `denied`), `event.outcome`, `event.reason` (the OCSF `status_detail`, for example `transparent_tcp_policy_denied`) and `rule.name` / `rule.category` (the matching policy rule). Denied activity is categorized as `event.kind: alert`.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

OpenShell must have OCSF JSON export enabled. The export is opt-in and is written as JSON Lines, one OCSF record per line. Enable it globally or per sandbox:

```shell
openshell settings set --global --key ocsf_json_enabled --value true
# or
openshell settings set my-sandbox --key ocsf_json_enabled --value true
```

The setting takes effect on the next supervisor poll cycle (10 seconds by default). Leave `ocsf_schema_version` unset so records are written at the native OCSF 1.8.0 version; downgraded records are also parsed but lose the `container` object.

## Setup

### Linux sandbox supervisors

The supervisor writes records to `/var/log/openshell-ocsf.YYYY-MM-DD.log` inside the sandbox, rotating daily and keeping the three most recent files. Elastic Agent must be able to read that directory:

- With the Docker driver, mount the sandbox's `/var/log` on a volume that is also mounted into the Elastic Agent container, or run Elastic Agent in a sidecar container that shares the volume.
- With the Kubernetes driver, mount the sandbox pod's `/var/log` on a `hostPath` or shared volume and point the Elastic Agent DaemonSet at it.

Then add the integration to an agent policy and set **Paths** to the mounted location, for example `/var/lib/openshell/logs/*/openshell-ocsf.*.log`. The default path, `/var/log/openshell-ocsf.*.log`, matches an agent running inside the sandbox network namespace.

### Windows MXC gateways

Enable the ETW audit consumer and the durable JSONL sink on the gateway:

```toml
[openshell.drivers.mxc]
etw_audit = true
```

```powershell
$env:OPENSHELL_OCSF_JSON = "1"
$env:OPENSHELL_OCSF_LOG_DIR = "D:\OpenShell\audit"   # optional, defaults to %PROGRAMDATA%\OpenShell\logs
openshell-gateway --drivers mxc --config gateway.toml
```

Set **Paths** to the chosen directory, for example `C:\ProgramData\OpenShell\logs\openshell-ocsf.*.log`.

### Options

- **Preserve original event** keeps the raw JSON record in `event.original`.
- **Preserve duplicate custom fields** keeps the `openshell.ocsf.*` fields that were copied to ECS fields.

## Logs reference

### OCSF events

{{event "ocsf"}}

{{fields "ocsf"}}
