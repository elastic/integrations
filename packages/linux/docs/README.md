# System Integration

The Linux integration allows you to monitor low-level metrics on linux servers. Because the System integration
always applies to the local server, the `hosts` config option is not needed.

Note that certain datasets may access `/proc` to gather process information,
and the resulting `ptrace_may_access()` call by the kernel to check for
permissions can be blocked by
[AppArmor and other LSM software](https://gitlab.com/apparmor/apparmor/wikis/TechnicalDoc_Proc_and_ptrace), even though the System module doesn't use `ptrace` directly.


## Metrics

### Entropy

This is the entropy dataset of the module system. 
It collects the amount of available entropy in bits. On kernel versions greater than 2.6, 
entropy will be out of a total pool size of 4096.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| system.entropy.available_bits | The available bits of entropy | long |
| system.entropy.pct | The percentage of available entropy, relative to the pool size of 4096 | scaled_float |


### Network summary

The System `network_summary` dataset provides network IO metrics collected from the
operating system. These events are global and sorted by protocol.


**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| system.network_summary.icmp.* | ICMP counters | object |
| system.network_summary.ip.* | IP counters | object |
| system.network_summary.tcp.* | TCP counters | object |
| system.network_summary.udp.* | UDP counters | object |
| system.network_summary.udp_lite.* | UDP Lite counters | object |


### RAID

This is the raid dataset of the module system. It collects stats about the raid.

This dataset is available on:

- Linux

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| system.raid.blocks.synced | Number of blocks on the device that are in sync, in 1024-byte blocks. | long |
| system.raid.blocks.total | Number of blocks the device holds, in 1024-byte blocks. | long |
| system.raid.disks.active | Number of active disks. | long |
| system.raid.disks.failed | Number of failed disks. | long |
| system.raid.disks.spare | Number of spared disks. | long |
| system.raid.disks.states.* | map of raw disk states | object |
| system.raid.disks.total | Total number of disks the device consists of. | long |
| system.raid.level | The raid level of the device | keyword |
| system.raid.name | Name of the device. | keyword |
| system.raid.status | activity-state of the device. | keyword |
| system.raid.sync_action | Current sync action, if the RAID array is redundant | keyword |


### Service

The `service` dataset reports on the status of systemd services.

This dataset is available on:

- Linux

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| system.service.exec_code | The SIGCHLD code from the service's main process | keyword |
| system.service.load_state | The load state of the service | keyword |
| system.service.name | The name of the service | keyword |
| system.service.resources.cpu.usage.ns | CPU usage in nanoseconds | long |
| system.service.resources.memory.usage.bytes | memory usage in bytes | long |
| system.service.resources.network.in.bytes | bytes in | long |
| system.service.resources.network.in.packets | packets in | long |
| system.service.resources.network.out.bytes | bytes out | long |
| system.service.resources.network.out.packets | packets out | long |
| system.service.resources.tasks.count | number of tasks associated with the service | long |
| system.service.state | The activity state of the service | keyword |
| system.service.state_since | The timestamp of the last state change. If the service is active and running, this is its uptime. | date |
| system.service.sub_state | The sub-state of the service | keyword |


### Socket

This dataset requires kernel 2.6.14 or newer.

The system `socket` dataset reports an event for each new TCP socket that it
sees. It does this by polling the kernel periodically to get a dump of all
sockets. You set the polling interval by configuring the `period` option.
Specifying a short polling interval with this dataset is important to avoid
missing short-lived connections.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| network.direction | Direction of the network traffic. Recommended values are:   * inbound   * outbound   * internal   * external   * unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view. When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of your network perimeter. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.pid | Process id. | long |
| system.socket.local.ip | Local IP address. This can be an IPv4 or IPv6 address. | ip |
| system.socket.local.port | Local port. | long |
| system.socket.process.cmdline | Full command line | keyword |
| system.socket.remote.etld_plus_one | The effective top-level domain (eTLD) of the remote host plus one more label. For example, the eTLD+1 for "foo.bar.golang.org." is "golang.org.". The data for determining the eTLD comes from an embedded copy of the data from http://publicsuffix.org. | keyword |
| system.socket.remote.host | PTR record associated with the remote IP. It is obtained via reverse IP lookup. | keyword |
| system.socket.remote.host_error | Error describing the cause of the reverse lookup failure. | keyword |
| system.socket.remote.ip | Remote IP address. This can be an IPv4 or IPv6 address. | ip |
| system.socket.remote.port | Remote port. | long |
| user.full_name | User's full name, if available. | keyword |
| user.id | Unique identifier of the user. | keyword |


### Users

The system/users dataset reports logged in users and associated sessions via dbus and logind, which is a systemd component. By default, the dataset will look in `/var/run/dbus/` for a system socket, although a new path can be selected with `DBUS_SYSTEM_BUS_ADDRESS`.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| system.users.id | The ID of the session | keyword |
| system.users.leader | The root PID of the session | long |
| system.users.path | The DBus object path of the session | keyword |
| system.users.remote | A bool indicating a remote session | boolean |
| system.users.remote_host | A remote host address for the session | keyword |
| system.users.scope | The associated systemd scope | keyword |
| system.users.seat | An associated logind seat | keyword |
| system.users.service | A session associated with the service | keyword |
| system.users.state | The current state of the session | keyword |
| system.users.type | The type of the user session | keyword |

