# Linux Integration

The Linux Metrics integration allows you to monitor Linux servers.

Use the Linux Metrics integration to collect low-level metrics.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

For example, you could install the Linux Metrics integration to send metrics to Elastic.
Then, you could view real-time changes to service status in Kibana's _[Metrics Linux] Host Services Overview_ dashboard.

## Data streams

The Linux Metrics integration collects one type of data: metrics.

**Metrics** give you insight into the state of the machine.
Metric data streams collected by the Linux Metrics integration include 
performance counter values, memory usage, entropy availability, and more.
See more details in the [Metrics reference](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Certain data streams may access `/proc` to gather process information, and the resulting `ptrace_may_access()`
call by the kernel to check for permissions can be blocked by [AppArmor and other LSM software](https://gitlab.com/apparmor/apparmor/wikis/TechnicalDoc_Proc_and_ptrace),
even though the System module doesn't use `ptrace` directly.

## Setup

For step-by-step instructions on how to set up an integration,
see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

Note: Because the Linux Metrics integration always applies to the local server, the `hosts` config option is not needed.

Note: When running inside a container the `proc` filesystem directory of the host
should be set using `system.hostfs` setting to `/hostfs`. 

## Metrics reference

### Conntrack

The `conntrack` module reports on performance counters for the Linux connection tracking component of netfilter. 
Conntrack uses a [hash table](http://people.netfilter.org/pablo/docs/login.pdf) to track the state of network connections.

### Iostat

The `iostat` module reports per-disk IO statistics that emulate `iostat -x` on Linux.

### KSM

The `KSM` module reports data from [Kernel Samepage Merging](https://www.kernel.org/doc/html/latest/admin-guide/mm/ksm.html). 
To take advantage of KSM, applications must use the `madvise` system call to mark memory regions for merging. KSM is not enabled on all distros, and KSM status is set with the `CONFIG_KSM` kernel flag.

### Memory

The `memory` data stream extends `system/memory` and adds Linux-specific memory metrics, including Huge Pages and overall paging statistics.

### Pageinfo

The `pageinfo` data stream reports on paging statistics as found in `/proc/pagetypeinfo`.

Reported metrics are broken down by page type: DMA, DMA32, Normal, and Highmem. These types are further broken down by order, which represents zones of 2^ORDER*PAGE_SIZE.
These metrics are divided into two reporting types:
* `buddyinfo` is summarized by page type (as in `/proc/buddyinfo`)
* `nodes` reports information broken down by memory migration type

This information can be used to determine memory fragmentation. 
The kernel [buddy algorithm](https://www.kernel.org/doc/gorman/html/understand/understand009.html) will always search for the smallest page order to allocate, and if none is available, a larger page order will be split into two "buddies." When memory is freed, the kernel will attempt to merge the "buddies." If the only available pages are at lower orders, this indicates fragmentation, as buddy pages cannot be merged.

### Entropy

This is the `entropy` data stream of the module system. 
It collects the amount of available entropy in bits. On kernel versions greater than 2.6, 
entropy will be out of a total pool size of 4096.

{{fields "entropy"}}

### Network summary

The Linux `network_summary` data stream provides network IO metrics collected from the
operating system. These events are global and sorted by protocol.

{{fields "network_summary"}}

### RAID

This is the raid data stream of the module system. It collects stats about the raid.

This data stream is available on:

- Linux

{{fields "raid"}}

### Service

The `service` data stream reports on the status of systemd services.

This data stream is available on:

- Linux

{{fields "service"}}

### Socket

Note: This data stream requires kernel 2.6.14 or newer.

The Linux `socket` data stream reports an event for each new TCP socket that it
sees. It does this by polling the kernel periodically to get a dump of all
sockets. You set the polling interval by configuring the `period` option.
Specifying a short polling interval with this data stream is important to avoid
missing short-lived connections.

{{fields "socket"}}

### Users

The `users` data stream reports logged in users and associated sessions via dbus and logind, which is a systemd component. By default, the data stream will look in `/var/run/dbus/` for a system socket, although a new path can be selected with `DBUS_SYSTEM_BUS_ADDRESS`.

{{fields "users"}}
