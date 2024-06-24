# System Integration

The System integration allows you to monitor servers, personal computers, and more.

Use the System integration to collect metrics and logs from your machines.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong,
and reference data when troubleshooting an issue.

For example, if you wanted to be notified when less than 10% of the disk space is still available, you
could install the System integration to send file system metrics to Elastic.
Then, you could view real-time updates to disk space used on your system in Kibana's _[Metrics System] Overview_ dashboard.
You could also set up a new rule in the Elastic Observability Metrics app to alert you when the percent free is
less than 10% of the total disk space.

## Data streams

The System integration collects two types of data: logs and metrics.

**Logs** help you keep a record of events that happen on your machine.
Log data streams collected by the System integration include application, system, and security events on
machines running Windows and auth and syslog events on machines running macOS or Linux.
See more details in the [Logs reference](#logs-reference).

**Metrics** give you insight into the state of the machine.
Metric data streams collected by the System integration include CPU usage, load statistics, memory usage,
information on network behavior, and more.
See more details in the [Metrics reference](#metrics-reference).

You can enable and disable individual data streams. If _all_ data streams are disabled and the System integration
is still enabled, Fleet uses the default data streams.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Each data stream collects different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.
Details on the permissions needed for each data stream are available in the [Metrics reference](#metrics-reference).

## Setup

For step-by-step instructions on how to set up an integration, see the
{{ url "getting-started-observability" "Getting started" }} guide.

## Troubleshooting

Note that certain data streams may access `/proc` to gather process information,
and the resulting `ptrace_may_access()` call by the kernel to check for
permissions can be blocked by
[AppArmor and other LSM software](https://gitlab.com/apparmor/apparmor/wikis/TechnicalDoc_Proc_and_ptrace), even though the System module doesn't use `ptrace` directly.

In addition, when running inside a container the proc filesystem directory of the host
should be set using `system.hostfs` setting to `/hostfs`.

### Windows Event ID clause limit

If you specify more than 22 query conditions (event IDs or event ID ranges), some
versions of Windows will prevent the integration from reading the event log due to
limits in the query system. If this occurs, a similar warning as shown below:

```
The specified query is invalid.
```

In some cases, the limit may be lower than 22 conditions. For instance, using a
mixture of ranges and single event IDs, along with an additional parameter such
as `ignore older`, results in a limit of 21 conditions.

If you have more than 22 conditions, you can work around this Windows limitation
by using a drop_event processor to do the filtering after filebeat has received
the events from Windows. The filter shown below is equivalent to
`event_id: 903, 1024, 2000-2004, 4624` but can be expanded beyond 22 event IDs.

```yaml
- drop_event.when.not.or:
  - equals.winlog.event_id: "903"
  - equals.winlog.event_id: "1024"
  - equals.winlog.event_id: "4624"
  - range:
      winlog.event_id.gte: 2000
      winlog.event_id.lte: 2004
```

## Logs reference

### Application

The Windows `application` data stream provides events from the Windows
`Application` event log.

#### Supported operating systems

- Windows

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "application"}}

### System

The Windows `system` data stream provides events from the Windows `System`
event log.

#### Supported operating systems

- Windows

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "system"}}


### Security

The Windows `security` data stream provides events from the Windows
`Security` event log.

#### Supported operating systems

- Windows

{{event "security"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "security"}}

### Auth

The `auth` data stream provides auth logs.

#### Supported operating systems

- macOS prior to 10.8
- Linux

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "auth"}}

### syslog

The `syslog` data stream provides system logs.

#### Supported operating systems

- macOS
- Linux

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "syslog"}}

## Metrics reference

### Core

The System `core` data stream provides usage statistics for each CPU core.

#### Supported operating systems

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

#### Permissions

This data should be available without elevated permissions.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "core"}}

### CPU

The System `cpu` data stream provides CPU statistics.

#### Supported operating systems

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

#### Permissions

This data should be available without elevated permissions.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "cpu"}}

### Disk IO

The System `diskio` data stream provides disk IO metrics collected from the
operating system. One event is created for each disk mounted on the system.

> Note: For retrieving Linux-specific disk I/O metrics, use the [Linux](https://docs.elastic.co/integrations/linux) integration.

#### Supported operating systems

- Linux
- macOS (requires 10.10+)
- Windows
- FreeBSD (amd64)

#### Permissions

This data should be available without elevated permissions.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "diskio"}}

### Filesystem

The System `filesystem` data stream provides file system statistics. For each file
system, one document is provided.

#### Supported operating systems

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

#### Permissions

This data should be available without elevated permissions.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "filesystem"}}

### Fsstat

The System `fsstat` data stream provides overall file system statistics.

#### Supported operating systems

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

#### Permissions

This data should be available without elevated permissions.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "fsstat"}}

### Load

The System `load` data stream provides load statistics.

#### Supported operating systems

- FreeBSD
- Linux
- macOS
- OpenBSD

#### Permissions

This data should be available without elevated permissions.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "load"}}

### Memory

The System `memory` data stream provides memory statistics.
> Note: For retrieving Linux-specific memory metrics, use the [Linux](https://docs.elastic.co/integrations/linux) integration.

#### Supported operating systems

- FreeBSD
- Linux
- macOS
- OpenBSD
- Windows

#### Permissions

This data should be available without elevated permissions.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "memory"}}

### Network

The System `network` data stream provides network IO metrics collected from the
operating system. One event is created for each network interface.

#### Supported operating systems

- FreeBSD
- Linux
- macOS
- Windows

#### Permissions

This data should be available without elevated permissions.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "network"}}

### Process

The System `process` data stream provides process statistics. One document is
provided for each process.

#### Supported operating systems

- FreeBSD
- Linux
- macOS
- Windows

#### Permissions

Process execution data should be available for an authorized user.
If running as less privileged user, it may not be able to read process data belonging to other users.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "process"}}

### Process summary

The `process_summary` data stream collects high level statistics about the running
processes.

#### Supported operating systems

- FreeBSD
- Linux
- macOS
- Windows

#### Permissions

General process summary data should be available without elevated permissions.
If the process data belongs to the other users, it will be counted as unknown value.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "process_summary"}}

### Socket summary

The System `socket_summary` data stream provides the summary of open network
sockets in the host system.

It collects a summary of metrics with the count of existing TCP and UDP
connections and the count of listening ports.

#### Supported operating systems

- FreeBSD
- Linux
- macOS
- Windows

#### Permissions

This data should be available without elevated permissions.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "socket_summary"}}

### Uptime

The System `uptime` data stream provides the uptime of the host operating system.

#### Supported operating systems

- Linux
- macOS
- OpenBSD
- FreeBSD
- Windows

#### Permissions

This data should be available without elevated permissions.

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "uptime"}}
