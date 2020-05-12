# System Integration

The System module allows you to monitor your servers. Because the System module
always applies to the local server, the `hosts` config option is not needed.

The default metricsets are `cpu`, `load`, `memory`, `network`, `process`, and
`process_summary`. To disable a default metricset, comment it out in the
`modules.d/system.yml` configuration file. If _all_ metricsets are commented out
and the System module is enabled, {beatname_uc} uses the default metricsets.

Note that certain metricsets may access `/proc` to gather process information,
and the resulting `ptrace_may_access()` call by the kernel to check for
permissions can be blocked by
https://gitlab.com/apparmor/apparmor/wikis/TechnicalDoc_Proc_and_ptrace[AppArmor
and other LSM software], even though the System module doesn't use `ptrace`
directly.

## Compatibility

The System metricsets collect different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Metrics

### Core

The System `core` metricset provides usage statistics for each CPU core.

This metricset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

{{fields "core"}}


### CPU

The System `cpu` metricset provides CPU statistics.

This metricset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

{{fields "cpu"}}

### diskio

The System `diskio` metricset provides disk IO metrics collected from the
operating system. One event is created for each disk mounted on the system.

This metricset is available on:

- Linux
- macOS (requires 10.10+)
- Windows
- FreeBSD (amd64)

{{fields "diskio"}}

### entropy

This is the entropy metricset of the module system. 
It collects the amount of available entropy in bits. On kernel versions greater than 2.6, 
entropy will be out of a total pool size of 4096.

This Metricset is available on:

- linux

{{fields "entropy"}}

### filesystem

The System `filesystem` metricset provides file system statistics. For each file
system, one document is provided.

This metricset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

{{fields "filesystem"}}

### fsstat

The System `fsstat` metricset provides overall file system statistics.

This metricset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

{{fields "fsstat"}}

### load

The System `load` metricset provides load statistics.

This metricset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD

{{fields "load"}}

### memory

The System `memory` metricset provides memory statistics.

This metricset is available on:

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

{{fields "memory"}}

### network

The System `network` metricset provides network IO metrics collected from the
operating system. One event is created for each network interface.

This metricset is available on:

- FreeBSD
- Linux
- macOS
- Windows

{{fields "network"}}

### network_summary

The System `network_summary` metricset provides network IO metrics collected from the
operating system. These events are global and sorted by protocol.

This metricset is available on:

- Linux

{{fields "network_summary"}}

### process

The System `process` metricset provides process statistics. One document is
provided for each process.

This metricset is available on:

- FreeBSD
- Linux
- macOS
- Windows

{{fields "process"}}

### process_summary

The `process_summary` metricset collects high level statistics about the running
processes.

This metricset is available on:

- FreeBSD
- Linux
- macOS
- Windows

{{fields "process_summary"}}

### raid

This is the raid metricset of the module system. It collects stats about the raid.

This metricset is available on:

- Linux

{{fields "raid"}}

### service

The `service` metricset reports on the status of systemd services.

This metricset is available on:

- Linux

{{fields "service"}}

### socket

This metricset is available on Linux only and requires kernel 2.6.14 or newer.

The system `socket` metricset reports an event for each new TCP socket that it
sees. It does this by polling the kernel periodically to get a dump of all
sockets. You set the polling interval by configuring the `period` option.
Specifying a short polling interval with this metricset is important to avoid
missing short-lived connections.

{{fields "socket"}}

### socket_summary

The System `socket_summary` metricset provides the summary of open network
sockets in the host system.

It collects a summary of metrics with the count of existing TCP and UDP
connections and the count of listening ports.

This metricset is available on:

- FreeBSD
- Linux
- macOS
- Windows

{{fields "socket_summary"}}

### uptime

The System `uptime` metricset provides the uptime of the host operating system.

This metricset is available on:

- Linux
- macOS
- OpenBSD
- FreeBSD
- Windows

{{fields "uptime"}}

### users

The system/users metricset reports logged in users and associated sessions via dbus and logind, which is a systemd component. By default, the metricset will look in `/var/run/dbus/` for a system socket, although a new path can be selected with `DBUS_SYSTEM_BUS_ADDRESS`.

This metricset is available on:

- Linux

{{fields "users"}}