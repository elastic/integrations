# Containerd integration

This integration is used to collect metrics from [containerd runtime](https://containerd.io/).

It collects cpu, memory and blkio statistics about running containers controlled by containerd.

The current datasets are: `cpu`, `blkio` and `memory` and are enabled by default.

## Compatibility

The Containerd integration is currently tested with Containerd version v1.5.2.

## Prerequisites

`Containerd` daemon has to be configured to provide metrics before enabling containerd integration.

In the configuration file located in `/etc/containerd/config.toml` metrics endpoint needs to
be set and containerd daemon needs to be restarted.

```
[metrics]
    address = "127.0.0.1:1338"
```

## Integration-specific configuration notes

For cpu data stream if `Calculate cpu usage percentage` setting is set to true, cpu usage percentages will be calculated
and more specifically fields `containerd.cpu.usage.total.pct`, `containerd.cpu.usage.kernel.pct`, `containerd.cpu.usage.user.pct`.
Default value is true.

For memory data stream if `Calculate memory usage percentage` setting is set to true, memory usage percentages will be calculated
and more specifically fields `containerd.memory.usage.pct` and  `containerd.memory.workingset.pct`.
Default value is true.

## Metrics

### cpu

This is the `cpu` dataset of the `Containerd` package. It collects cpu related metrics
from containerd's metrics APIs.

{{fields "cpu"}}

{{event "cpu"}}


### memory

This is the `memory` dataset of the `Containerd` package. It collects memory related metrics
from containerd's metrics APIs.

{{fields "memory"}}

{{event "memory"}}

### blkio

This is the `blkio` dataset of the `Containerd` package. It collects blkio related metrics
from containerd's metrics APIs.

{{fields "blkio"}}

{{event "blkio"}}