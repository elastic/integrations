{{- generatedHeader }}
# NVIDIA OpenShell

## Overview

[NVIDIA OpenShell](https://docs.nvidia.com/openshell/) runs AI agents and other untrusted workloads inside policy-controlled sandboxes. A supervisor inside each sandbox mediates outbound connections, HTTP requests, and SSH sessions against the sandbox policy and records the decision as an [OCSF](https://schema.ocsf.io/) event.

The NVIDIA OpenShell integration lets security teams audit what sandboxed workloads attempted to reach, which policy rule decided the outcome, and which process initiated the activity.

### Compatibility

The integration processes OCSF JSON Lines written by Linux OpenShell sandbox supervisors and Windows MXC gateways. It supports the native OCSF 1.8.0 records emitted by OpenShell. Downgraded OCSF records are also parsed, but they do not include the `container` object.

### How it works

Elastic Agent reads the OCSF JSON export from local or mounted log files. The ingest pipeline normalizes supported fields to the Elastic Common Schema (ECS) and retains OCSF-specific attributes under `openshell.ocsf.*`.

## What data does this integration collect?

The integration collects one `ocsf` data stream containing the OCSF event classes emitted by OpenShell:

| `class_uid` | OCSF class | What it records |
|---|---|---|
| 4001 | Network Activity | Allowed, denied, and failed outbound connections, including CONNECT, transparent TCP, and DNS policy decisions |
| 4002 | HTTP Activity | Layer-7 request decisions for policy-inspected endpoints |
| 4007 | SSH Activity | SSH sessions accepted on the supervisor socket |
| 1007 | Process Activity | Workload process launch and termination, mapped to `process.*`; the initiating process is mapped to `process.parent.*` |
| 2004 | Detection Finding | Supervisor findings, mapped to `rule.*` and, when ATT&CK data is present, `threat.*` |
| 5019 | Device Config State Change | Policy revisions loaded, published, or detected by the supervisor |
| 6002 | Application Lifecycle | Supervisor component start, stop, install, remove, and update events |
| 0 | Base Event | Relay open and close notifications and other operational events |

Every event includes the OpenShell supervisor in `observer.*`, the sandbox in `container.*`, and the OCSF `class_uid` in `event.code`. Policy decisions are exposed through `event.action`, `event.outcome`, `event.reason`, and `rule.*`. Denied activity and Detection Finding records are categorized as `event.kind: alert`.

### Supported use cases

- Audit network, HTTP, and SSH activity from sandboxed workloads.
- Investigate denied requests and the policy rules responsible for them.
- Correlate process activity with sandbox network behavior.
- Monitor supervisor findings, configuration changes, and application lifecycle events.

## What do I need to use this integration?

- An Elastic deployment and an installed Elastic Agent.
- An OpenShell Linux sandbox supervisor or Windows MXC gateway.
- OpenShell OCSF JSON export enabled.
- A filesystem path through which Elastic Agent can read the generated JSONL files.

## How do I deploy this integration?

### Agent-based deployment

Install Elastic Agent by following the [Elastic Agent installation instructions](docs-content://reference/fleet/install-elastic-agents.md), then add the NVIDIA OpenShell integration to the agent policy.

### Onboard and configure

Enable OCSF export globally or for one sandbox:

```shell
openshell settings set --global --key ocsf_json_enabled --value true
# or
openshell settings set my-sandbox --key ocsf_json_enabled --value true
```

The setting takes effect on the next supervisor poll cycle, which is 10 seconds by default. Leave `ocsf_schema_version` unset to emit native OCSF 1.8.0 records.

#### Linux sandbox supervisors

The supervisor writes records to `/var/log/openshell-ocsf.YYYY-MM-DD.jsonl` inside the sandbox. Earlier OpenShell releases used the `.log` extension. Files rotate daily, and the three most recent files are retained.

- With the Docker driver, mount the sandbox's `/var/log` on a volume that is also mounted into the Elastic Agent container, or run Elastic Agent in a sidecar container that shares the volume.
- With the Kubernetes driver, mount the sandbox pod's `/var/log` on a `hostPath` or shared volume and point the Elastic Agent DaemonSet at it.

Set **Paths** to the mounted location, for example `/var/lib/openshell/logs/*/openshell-ocsf.*.jsonl`. The default paths match an agent running inside the sandbox network namespace.

#### Windows MXC gateways

Enable the ETW audit consumer and durable JSONL sink:

```toml
[openshell.drivers.mxc]
etw_audit = true
```

```powershell
$env:OPENSHELL_OCSF_JSON = "1"
$env:OPENSHELL_OCSF_LOG_DIR = "D:\OpenShell\audit"   # optional
openshell-gateway --drivers mxc --config gateway.toml
```

If `OPENSHELL_OCSF_LOG_DIR` is not set, the gateway writes to `%PROGRAMDATA%\OpenShell\logs`. Set **Paths** to the selected directory, for example `C:\ProgramData\OpenShell\logs\openshell-ocsf.*.log`.

#### Options

- **Preserve original event** keeps the raw JSON record in `event.original`.

### Validation

1. Generate activity in an OpenShell sandbox.
2. Confirm that the configured JSONL file receives a new OCSF record.
3. In Kibana, open **Discover** and verify that events appear in `logs-openshell.ocsf-*`.
4. Confirm that `event.code`, `observer.product`, and `container.name` are populated.

## Troubleshooting

- **No events are collected:** Confirm that OCSF export is enabled, the configured path matches the generated file, and Elastic Agent can read the file or mounted directory.
- **Events have `event.kind: pipeline_error`:** Inspect `error.message` and `event.original`. Pipeline errors retain the raw record to help diagnose malformed JSON or incompatible values.
- **`container.*` is missing:** Ensure `ocsf_schema_version` is unset so OpenShell emits native OCSF 1.8.0 records.

## Performance and scaling

Collection uses the local `logfile` input. Deploy an Elastic Agent wherever OpenShell JSONL files are locally available or mounted, and distribute collection across agents when supervisors run on multiple hosts. Size storage and retention for the number of sandbox events generated, and monitor Agent and ingest-node utilization before increasing event volume.

## Reference

### Logs reference

#### OCSF events

An example event and the exported fields for the `ocsf` data stream follow.

{{ event "ocsf" }}

{{ fields "ocsf" }}
