# AegisBPF

The AegisBPF integration collects runtime-security enforcement events from the
[AegisBPF](https://github.com/ErenAri/Aegis-BPF) agent — a BPF-LSM agent that
enforces file and network policy with race-free, in-kernel `-EPERM`.

AegisBPF emits [OCSF](https://ocsf.io) 1.1.0 events (File Activity and Network
Activity). Run the agent with `--event-format ocsf` and `--log` pointed at a
file, then point this integration's filestream input at that file.

## Data streams

### event

The `event` data stream parses AegisBPF OCSF events and maps them to ECS: the
enforcement decision (`event.action: denied`/`allowed`, `event.outcome`), the
subject (`process.*`, `host.*`), and the target (`file.*`, `source.*`,
`destination.*`). AegisBPF-specific forensics (cgroup, kernel device id, OCSF
class/disposition) are preserved under the `aegisbpf.*` namespace.

{{fields "event"}}
