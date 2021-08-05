# System Integration

The System integrations allows you to monitor your servers. Because the System integration
always applies to the local server, the `hosts` config option is not needed.

The default datasets are `cpu`, `load`, `memory`, `network`, `process`, and
`process_summary`. If _all_ datasets are disabled
and the System module is still enabled, fleet uses the default datasets.

Note that certain datasets may access `/proc` to gather process information,
and the resulting `ptrace_may_access()` call by the kernel to check for
permissions can be blocked by
[AppArmor and other LSM software](https://gitlab.com/apparmor/apparmor/wikis/TechnicalDoc_Proc_and_ptrace), even though the System module doesn't use `ptrace` directly.

In addition, when running inside a container the proc filesystem directory of the host
should be set using `system.hostfs` setting to `/hostfs`.  

## Compatibility

The System datasets collect different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Logs

### Application

The Windows `application` dataset provides events from the Windows
`Application` event log.

{{fields "application"}}

### System

The Windows `system` dataset provides events from the Windows `System`
event log.

{{fields "system"}}


### Security

The Windows `security` dataset provides events from the Windows
`Security` event log.

{{event "security"}}

{{fields "security"}}

### Auth

The `auth` dataset provides auth logs on linux and MacOS prior to 10.8.

{{fields "auth"}}

### syslog

The `syslog` dataset provides system logs on linux and MacOS.

{{fields "syslog"}}

## Metrics

### Core

The System `core` dataset provides usage statistics for each CPU core.

This dataset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

{{fields "core"}}

### CPU

The System `cpu` dataset provides CPU statistics.

This dataset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

{{fields "cpu"}}

### Disk IO

The System `diskio` dataset provides disk IO metrics collected from the
operating system. One event is created for each disk mounted on the system.

This dataset is available on:

- Linux
- macOS (requires 10.10+)
- Windows
- FreeBSD (amd64)

{{fields "diskio"}}

### Filesystem

The System `filesystem` dataset provides file system statistics. For each file
system, one document is provided.

This dataset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

{{fields "filesystem"}}

### Fsstat

The System `fsstat` dataset provides overall file system statistics.

This dataset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

{{fields "fsstat"}}

### Load

The System `load` dataset provides load statistics.

This dataset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD

{{fields "load"}}

### Memory

The System `memory` dataset provides memory statistics.

This dataset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

{{fields "memory"}}

### Network

The System `network` dataset provides network IO metrics collected from the
operating system. One event is created for each network interface.

This dataset is available on:

- FreeBSD
- Linux
- macOS
- Windows

{{fields "network"}}

### Process

The System `process` dataset provides process statistics. One document is
provided for each process.

This dataset is available on:

- FreeBSD
- Linux
- macOS
- Windows

{{fields "process"}}

### Process summary

The `process_summary` dataset collects high level statistics about the running
processes.

This dataset is available on:

- FreeBSD
- Linux
- macOS
- Windows

{{fields "process_summary"}}

### Socket summary

The System `socket_summary` dataset provides the summary of open network
sockets in the host system.

It collects a summary of metrics with the count of existing TCP and UDP
connections and the count of listening ports.

This dataset is available on:

- FreeBSD
- Linux
- macOS
- Windows

{{fields "socket_summary"}}

### Uptime

The System `uptime` dataset provides the uptime of the host operating system.

This dataset is available on:

- Linux
- macOS
- OpenBSD
- FreeBSD
- Windows

{{fields "uptime"}}
