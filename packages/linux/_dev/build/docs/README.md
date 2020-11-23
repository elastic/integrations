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

{{fields "entropy"}}

### Network summary

The System `network_summary` dataset provides network IO metrics collected from the
operating system. These events are global and sorted by protocol.

{{fields "network_summary"}}

### RAID

This is the raid dataset of the module system. It collects stats about the raid.

This dataset is available on:

- Linux

{{fields "raid"}}

### Service

The `service` dataset reports on the status of systemd services.

This dataset is available on:

- Linux

{{fields "service"}}

### Socket

This dataset requires kernel 2.6.14 or newer.

The system `socket` dataset reports an event for each new TCP socket that it
sees. It does this by polling the kernel periodically to get a dump of all
sockets. You set the polling interval by configuring the `period` option.
Specifying a short polling interval with this dataset is important to avoid
missing short-lived connections.

{{fields "socket"}}

### Users

The system/users dataset reports logged in users and associated sessions via dbus and logind, which is a systemd component. By default, the dataset will look in `/var/run/dbus/` for a system socket, although a new path can be selected with `DBUS_SYSTEM_BUS_ADDRESS`.

{{fields "users"}}
