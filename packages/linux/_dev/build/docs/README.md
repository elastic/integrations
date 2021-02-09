# Linux Integration

The Linux integration allows you to monitor low-level metrics on linux servers. Because the System integration
always applies to the local server, the `hosts` config option is not needed.

Note that certain data streams may access `/proc` to gather process information,
and the resulting `ptrace_may_access()` call by the kernel to check for
permissions can be blocked by
[AppArmor and other LSM software](https://gitlab.com/apparmor/apparmor/wikis/TechnicalDoc_Proc_and_ptrace), even though the System module doesn't use `ptrace` directly.

In addition, when running inside a container the proc filesystem directory of the host
should be set using `system.hostfs` setting to `/hostfs`. 

## Metrics

### Conntrack

The conntrack module reports on performance counters for the linux connection tracking component of netfilter. 
Conntrack uses a [hash table](http://people.netfilter.org/pablo/docs/login.pdf) to track the state of network connections.

### Iostat

The iostat module reports per-disk IO statistics that emulate `iostat -x` on linux.

### KSM

The KSM module reports data from [Kernel Samepage Merging](https://www.kernel.org/doc/html/latest/admin-guide/mm/ksm.html). 
In order to take advantage of KSM, applications must use the `madvise` system call to mark memory regions for merging. KSM is not enabled on all distros, and KSM status is set with the `CONFIG_KSM` kernel flag.


### Memory

The memory data stream extends system/memory and adds linux-specific memory metrics, including Huge Pages and overall paging statistics.

### Pageinfo

The pageinfo data stream reports on paging statistics as found in `/proc/pagetypeinfo`.


Reported metrics are broken down by page type: DMA, DMA32, Normal, and Highmem. These types are further broken down by order, which represents zones of 2^ORDER*PAGE_SIZE.
These metrics are divided into two reporting types: `buddyinfo`, which is summarized by page type, as in `/proc/buddyinfo`. `nodes` reports info broken down by memory migration type.


This information can be used to determine memory fragmentation. 
The kernel [buddy algorithim](https://www.kernel.org/doc/gorman/html/understand/understand009.html) will always search for the smallest page order to allocate, and if none is available, a larger page order will be split into two "buddies." When memory is freed, the kernel will attempt to merge the "buddies." If the only available pages are at lower orders, this indicates fragmentation, as buddy pages cannot be merged.


### Entropy

This is the entropy data stream of the module system. 
It collects the amount of available entropy in bits. On kernel versions greater than 2.6, 
entropy will be out of a total pool size of 4096.

{{fields "entropy"}}

### Network summary

The linux `network_summary` data stream provides network IO metrics collected from the
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

This data stream requires kernel 2.6.14 or newer.

The Linux `socket` data stream reports an event for each new TCP socket that it
sees. It does this by polling the kernel periodically to get a dump of all
sockets. You set the polling interval by configuring the `period` option.
Specifying a short polling interval with this data stream is important to avoid
missing short-lived connections.

{{fields "socket"}}

### Users

The linux/users data stream reports logged in users and associated sessions via dbus and logind, which is a systemd component. By default, the data stream will look in `/var/run/dbus/` for a system socket, although a new path can be selected with `DBUS_SYSTEM_BUS_ADDRESS`.

{{fields "users"}}
