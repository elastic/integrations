# Falco Integration
This integration allows for the shipping of [Falco](https://falco.org/) alerts to Elastic for observability and organizational awareness. Alerts can then be analyzed by using either the dashboard included with the integration or via the creation of a custom dashboard within Kibana.

## Data Streams
The Falco integration collects one type of data stream: logs.

**Logs** The Logs data stream collected by the Falco integration is comprised of Falco Alerts. See more details about Falco Alerts in [Falco's Outputs Documentation](https://falco.org/docs/outputs/). A complete list of potential fields used by this integration can be found in the [Logs reference](#logs-reference)

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Falco must be configured to output alerts to a supported output channel as defined in [Setup](#setup). The system will only receive fields output by Falco's rules. If a rule does not include a desired field the rule must be edited in Falco to add the field.

This integration is compatible with Falco version 0.37 and above, and should not be expected to perform successfully in lower versions. 

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

In order to capture alerts from Falco you **must** configure Falco to output Alerts as JSON to one of the supported channels: [Logfile](#logfile-input) or [TCP Syslog](#tcp-syslog-input).

**Required:** To configure Falco to output JSON, set the config properties `json_output=true` and `json_include_output_property=true` in Falco's config. See the examples in Falco's [Output Channels documentation](https://falco.org/docs/outputs/channels/#http-output).

### Logfile Input

The logfile input reads data from one or more Falco log files using the Elastic Agent. Use this input when the Elastic Agent will be deployed to the same machine as Falco or when Falco's log files are available via a mounted filesystem.

To use this input Falco must be configured to output alerts to a log file. See Falco's [File Output](https://falco.org/docs/outputs/channels/#file-output) documentation for details.

### TCP Syslog Input

The TCP Syslog input allows the Elastic Agent to receive Falco Alerts via remote syslog. Use this input when you want to send data via [Falco Sidekick](https://github.com/falcosecurity/falcosidekick).

To use this input you will need to deploy the Elastic Agent *first* and then configure and deploy Falco Sidekick to send Alerts to the Agent via Syslog. See [Syslog Output](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/syslog.md) and [Connecting Falco to Sidekick](https://github.com/falcosecurity/falcosidekick?tab=readme-ov-file#connect-falco) for more details.

## Logs Reference

### alerts

Falco alerts can contain a multitude of various fields pertaining to the type of activity on the host machine.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp with nanos. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Preserved Falco field | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Data stream / event dataset. | constant_keyword |  |
| event.module | The module the event belongs to. | constant_keyword |  |
| falco.container.mounts.dest |  | keyword |  |
| falco.container.mounts.mode |  | keyword |  |
| falco.container.mounts.propagation |  | keyword |  |
| falco.container.mounts.rdrw |  | keyword |  |
| falco.container.mounts.source |  | keyword |  |
| falco.hostname | Required field for integration | keyword |  |
| falco.output |  | text |  |
| falco.output_fields.client.ip | Falco copy of the ECS field of the same name | ip |  |
| falco.output_fields.container.cni_json | Container's CNI result field from the respective container status info. | object |  |
| falco.output_fields.container.duration | Number of nanoseconds since container.start_ts. | long | nanos |
| falco.output_fields.container.full_id | Preserved Falco field | text |  |
| falco.output_fields.container.healthcheck | The container's health check. Will be N/A if no health check configured. | text |  |
| falco.output_fields.container.id | The truncated container ID (first 12 characters) extracted from the Linux cgroups by Falco within the kernel | keyword |  |
| falco.output_fields.container.image | Preserved Falco field | text |  |
| falco.output_fields.container.image.digest | Preserved Falco field | text |  |
| falco.output_fields.container.image.full_id | Full container image ID, enriched as part of the container engine enrichment. | keyword |  |
| falco.output_fields.container.image.id | Container image ID. | keyword |  |
| falco.output_fields.container.image.name | Falco copy of the ECS field of the same name | text |  |
| falco.output_fields.container.image.repository | The container image repository. | keyword |  |
| falco.output_fields.container.image.tag | Preserved Falco field | text |  |
| falco.output_fields.container.ip | Preserved Falco field | text |  |
| falco.output_fields.container.liveness_probe | The container's liveness probe. Will be N/A if no liveness probe configured. | text |  |
| falco.output_fields.container.mounts | The raw text value for container mounts information | text |  |
| falco.output_fields.container.name | The container name | keyword |  |
| falco.output_fields.container.privileged | Preserved Falco field | boolean |  |
| falco.output_fields.container.readiness_probe | The container's readiness probe. Will be N/A if no readiness probe configured. | text |  |
| falco.output_fields.container.start_ts | Container start as epoch timestamp. | date_nanos |  |
| falco.output_fields.container.type | Preserved Falco field | text |  |
| falco.output_fields.destination.ip | Falco copy of the ECS field of the same name | ip |  |
| falco.output_fields.evt.abspath | Calculated absolute path. | text |  |
| falco.output_fields.evt.abspath_dst | Destination of the absolute path. | text |  |
| falco.output_fields.evt.abspath_src | Source of the absolute path. | text |  |
| falco.output_fields.evt.arg.flags | Preserved Falco field | text |  |
| falco.output_fields.evt.args | Aggregated string of all event arguments. | text |  |
| falco.output_fields.evt.asynctype | The type of event, if asyncronous. | keyword |  |
| falco.output_fields.evt.buffer | Binary buffer for events which have one. | binary |  |
| falco.output_fields.evt.buflen | Length of the binary buffer, if applicable. | unsigned_long |  |
| falco.output_fields.evt.category | Preserved Falco field | text |  |
| falco.output_fields.evt.count.error | Returns 1 for events that returned with an error | integer |  |
| falco.output_fields.evt.count.error_file | Returns 1 for events that returned with an error and are related to file I/O | integer |  |
| falco.output_fields.evt.count.error_memory | Returns 1 for events that returned with an error and are related to memory allocation. | integer |  |
| falco.output_fields.evt.count.error_net | Returns 1 for events that returned with an error and are related to network I/O | integer |  |
| falco.output_fields.evt.count.error_other | Returns 1 for events that returned with an error and are related to none of the previous categories. | integer |  |
| falco.output_fields.evt.count.exit | Returns 1 for exit events. | integer |  |
| falco.output_fields.evt.cpu | Number of the CPU where the event occurred. | integer |  |
| falco.output_fields.evt.deltatime | Delta between current event and previous. | long | nanos |
| falco.output_fields.evt.dir | Either an enter event (\>) or an exit event (\<). | keyword |  |
| falco.output_fields.evt.failed | Denotes if the event returned an error status. | boolean |  |
| falco.output_fields.evt.hostname | Preserved Falco field | text |  |
| falco.output_fields.evt.info | Contains either the event arguments, or the data decoded from them. | text |  |
| falco.output_fields.evt.io_dir | Type based on whether the event reads from or writes to FDs. | keyword |  |
| falco.output_fields.evt.is_async | Denotes whether the event is async or not. | boolean |  |
| falco.output_fields.evt.is_io | Denotes events that read or write to FDs. | boolean |  |
| falco.output_fields.evt.is_io_read | Denotes events that read from FDs. | boolean |  |
| falco.output_fields.evt.is_io_write | Denotes events that write to FDs. | boolean |  |
| falco.output_fields.evt.is_open_create | Denotes whether or not a file was created for open/openat/openat2/open_by_handle_at events. | boolean |  |
| falco.output_fields.evt.is_open_exec | Denotes whether or not a file was created with execute permissions for open/openat/openat2/open_by_handle_at or create events. | boolean |  |
| falco.output_fields.evt.is_open_read | Denotes whether or not the path was opened for reading for open/openat/openat2/open_by_handle_at events. | boolean |  |
| falco.output_fields.evt.is_open_write | Denotes whether or not the path was opened for writing for open/openat/openat2/open_by_handle_at events. | boolean |  |
| falco.output_fields.evt.is_syslog | Denotes events that are written to /dev/log | boolean |  |
| falco.output_fields.evt.is_wait | Denotes events that force the thread to wait. | boolean |  |
| falco.output_fields.evt.latency | Delta between an exit event and corresponding enter event. | long | nanos |
| falco.output_fields.evt.num | Preserved Falco field | integer |  |
| falco.output_fields.evt.plugininfo | Summary of the event if it came from a plugin-defined event source. | text |  |
| falco.output_fields.evt.pluginname | Name of the plugin that generated the event (if applicable). | keyword |  |
| falco.output_fields.evt.rawres | Return value of the event, as a number. | long |  |
| falco.output_fields.evt.res | Return value of the event. | text |  |
| falco.output_fields.evt.source | Preserved Falco field | text |  |
| falco.output_fields.evt.time | Preserved Falco field | date |  |
| falco.output_fields.evt.time.iso8601 | Time event occurred | date |  |
| falco.output_fields.evt.type | Preserved Falco field | text |  |
| falco.output_fields.evt.wait_latency | Time spent waiting for events to return, in cases where the thread is forced to wait. | long | nanos |
| falco.output_fields.fd.I4proto | The IP protocol of a socket. Can be 'tcp', 'udp', 'icmp' or 'raw'. | keyword |  |
| falco.output_fields.fd.cip | Preserved Falco field | ip |  |
| falco.output_fields.fd.cip.name | Preserved Falco field | text |  |
| falco.output_fields.fd.connected | Denotes if the socket is connected for TCP/UDP FDs. | boolean |  |
| falco.output_fields.fd.containerdirectory | Concatenation of the container ID and the directory name. | keyword |  |
| falco.output_fields.fd.containername | Concatenation of the container ID and the FD name. | keyword |  |
| falco.output_fields.fd.cport | Preserved Falco field | long |  |
| falco.output_fields.fd.cproto | For TCP/UDP FDs, the client protocol. | keyword |  |
| falco.output_fields.fd.dev | Device number containing the referenced file. | integer |  |
| falco.output_fields.fd.dev_major | Major device number containing the referenced file. | integer |  |
| falco.output_fields.fd.dev_minor | Minor device number containing the referenced file. | integer |  |
| falco.output_fields.fd.directory | Preserved Falco field | text |  |
| falco.output_fields.fd.filename | Preserved Falco field | text |  |
| falco.output_fields.fd.ino | Preserved Falco field | text |  |
| falco.output_fields.fd.is_server | Denotes if process owning the FD is the server endpoint in the connection. | boolean |  |
| falco.output_fields.fd.lip | Preserved Falco field | ip |  |
| falco.output_fields.fd.lip.name | Preserved Falco field | text |  |
| falco.output_fields.fd.lport | Preserved Falco field | long |  |
| falco.output_fields.fd.lproto | For TCP/UDP FDs, the local protocol. | keyword |  |
| falco.output_fields.fd.name | FD full name. If the fd is a file, this field contains the full path. If the FD is a socket, this field contain the connection tuple. | text |  |
| falco.output_fields.fd.name_changed | Denotes if the name of an FD changes due to an event. | boolean |  |
| falco.output_fields.fd.num | Unique number identifying the file descriptor. | long |  |
| falco.output_fields.fd.rip | Preserved Falco field | ip |  |
| falco.output_fields.fd.rip.name | Preserved Falco field | text |  |
| falco.output_fields.fd.rport | Preserved Falco field | long |  |
| falco.output_fields.fd.rproto | For TCP/UDP FDs, the remote protocol. | keyword |  |
| falco.output_fields.fd.sip | Preserved Falco field | ip |  |
| falco.output_fields.fd.sip.name | Preserved Falco field | text |  |
| falco.output_fields.fd.sockfamily | The socket family for socket events. Can be 'ip' or 'unix'. | keyword |  |
| falco.output_fields.fd.sport | Preserved Falco field | long |  |
| falco.output_fields.fd.sproto | For TCP/UDP FDs, the server protocol. | keyword |  |
| falco.output_fields.fd.type | Type of FD. Can be 'file', 'directory', 'ipv4', 'ipv6', 'unix', 'pipe', 'event', 'signalfd', 'eventpoll', 'inotify' 'signalfd' or 'memfd'. | keyword |  |
| falco.output_fields.fd.typechar | Type of FD as a single character. Can be 'f' for file, 4 for IPv4 socket, 6 for IPv6 socket, 'u' for unix socket, p for pipe, 'e' for eventfd, 's' for signalfd, 'l' for eventpoll, 'i' for inotify, 'b' for bpf, 'u' for userfaultd, 'r' for io_uring, 'm' for memfd ,'o' for unknown. | keyword |  |
| falco.output_fields.fd.uid | Unique identifier for the FD, created from the FD number and thread ID. | keyword |  |
| falco.output_fields.fdlist.cips | For poll events, client IP addresses in the fds argument. | ip |  |
| falco.output_fields.fdlist.cports | For poll events / TCP/UDP FDs, client TCP/UDP ports in the fds argument. | ip |  |
| falco.output_fields.fdlist.names | For poll events, FD names in the fds argument. | keyword |  |
| falco.output_fields.fdlist.sips | For poll events, server IP addresses in the fds argument. | ip |  |
| falco.output_fields.fdlist.sports | For poll events, server TCP/UDP ports in the fds argument. | ip |  |
| falco.output_fields.fs.path.name | For any event type that deals with a filesystem path, the path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed. | keyword |  |
| falco.output_fields.fs.path.source | For any event type that deals with a filesystem path, and specifically for a source and target like mv, cp, etc, the source path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed. | keyword |  |
| falco.output_fields.fs.path.target | For any event type that deals with a filesystem path, and specifically for a target and target like mv, cp, etc, the target path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed. | keyword |  |
| falco.output_fields.group.gid | Preserved Falco field | integer |  |
| falco.output_fields.group.name | Preserved Falco field | text |  |
| falco.output_fields.k8s.ns.name | Preserved Falco field | text |  |
| falco.output_fields.k8s.pod.cni_json | Kubernetes CNI result field from the respective pod status info. | object |  |
| falco.output_fields.k8s.pod.full_sandbox_id | Full, non-truncated Kubernetes pod sandbox ID. | keyword |  |
| falco.output_fields.k8s.pod.ip | Preserved Falco field | text |  |
| falco.output_fields.k8s.pod.labels | Preserved Falco field | text |  |
| falco.output_fields.k8s.pod.name | Preserved Falco field | text |  |
| falco.output_fields.k8s.pod.sandbox_id | Truncated Kubernetes pod sandbox ID (first 12 characters). | keyword |  |
| falco.output_fields.k8s.pod.uid | Preserved Falco field | text |  |
| falco.output_fields.output | Preserved Falco field | text |  |
| falco.output_fields.priority | Preserved Falco field | keyword |  |
| falco.output_fields.proc.args | Preserved Falco field | text |  |
| falco.output_fields.proc.cmdlenargs | Total length of command line args, excluding whitespace. | long |  |
| falco.output_fields.proc.cmdline | Preserved Falco field | text |  |
| falco.output_fields.proc.cmdnargs | Preserved Falco field | integer |  |
| falco.output_fields.proc.cwd | Preserved Falco field | text |  |
| falco.output_fields.proc.duration | Preserved Falco field | text |  |
| falco.output_fields.proc.env | Preserved Falco field | text |  |
| falco.output_fields.proc.exe | First command line argument, collected from args. | text |  |
| falco.output_fields.proc.exe_ino | The inode number of the executable file on disk. | long |  |
| falco.output_fields.proc.exe_ino_ctime | Last status change of executable file as epoch timestamp. | date_nanos |  |
| falco.output_fields.proc.exe_ino_ctime_duration_pidns_start | Number of nanoseconds between PID namespace start ts and ctime exe file if PID namespace start predates ctime. | long |  |
| falco.output_fields.proc.exe_ino_ctime_duration_proc_start | Number of nanoseconds between modifying status of executable image and spawning a new process using the changed executable image. | long |  |
| falco.output_fields.proc.exe_ino_mtime | Last modification time of executable file as epoch timestamp. | date_nanos |  |
| falco.output_fields.proc.exeline | Full command line, with exe as first argument. | text |  |
| falco.output_fields.proc.exepath | Preserved Falco field | text |  |
| falco.output_fields.proc.fdopencount | Number of open FDs for the process. | unsigned_long |  |
| falco.output_fields.proc.fdopenlimit | Maximum number of FDs the process can open. | long |  |
| falco.output_fields.proc.fdusage | Ratio between open FDs and maximum available FDs for the process. | double |  |
| falco.output_fields.proc.is_container_healthcheck | Denotes if this process is running as a part of the container's health check. | boolean |  |
| falco.output_fields.proc.is_container_liveness_probe | Denotes if this process is running as a part of the container's liveness probe. | boolean |  |
| falco.output_fields.proc.is_container_readiness_probe | Denotes if this process is running as a part of the container's readiness probe. | boolean |  |
| falco.output_fields.proc.is_exe_from_memfd | Denotes if this process' executable file is in upper layer in overlayfs. | boolean |  |
| falco.output_fields.proc.is_exe_upper_layer | Denotes if this process' executable file is in upper layer in overlayfs. | boolean |  |
| falco.output_fields.proc.is_exe_writable | Denotes if this process' executable file is writable by the same user that spawned the process. | boolean |  |
| falco.output_fields.proc.is_sid_leader | Preserved Falco field | boolean |  |
| falco.output_fields.proc.is_vpgid_leader | Preserved Falco field | boolean |  |
| falco.output_fields.proc.loginshellid | PID of the oldest shell among the ancestors of the current process, if applicable. | long |  |
| falco.output_fields.proc.name | Preserved Falco field | text |  |
| falco.output_fields.proc.nchilds | Number of alive (not leader) threads in the process generating the event currently has, excluding the leader thread. | unsigned_long |  |
| falco.output_fields.proc.nthreads | Number of alive threads in the process generating the event currently has, including the leader thread. | unsigned_long |  |
| falco.output_fields.proc.pcmdline | Preserved Falco field | text |  |
| falco.output_fields.proc.pexe | First command line argument of the parent process. | text |  |
| falco.output_fields.proc.pexepath | Preserved Falco field | text |  |
| falco.output_fields.proc.pid | Preserved Falco field | integer |  |
| falco.output_fields.proc.pid.ts | Preserved Falco field | text |  |
| falco.output_fields.proc.pidns_init_start_ts | Start of PID namespace as epoch timestamp. | date_nanos |  |
| falco.output_fields.proc.pname | Preserved Falco field | text |  |
| falco.output_fields.proc.ppid | Preserved Falco field | integer |  |
| falco.output_fields.proc.ppid.duration | Preserved Falco field | long |  |
| falco.output_fields.proc.ppid.ts | Preserved Falco field | text |  |
| falco.output_fields.proc.pvpid | Preserved Falco field | integer |  |
| falco.output_fields.proc.sid | Preserved Falco field | integer |  |
| falco.output_fields.proc.sid.exe | First command line argument of the current process's session leader. | text |  |
| falco.output_fields.proc.sid.exepath | Preserved Falco field | text |  |
| falco.output_fields.proc.sname | Preserved Falco field | text |  |
| falco.output_fields.proc.thread.cap_inheritable | Set of inheritable capabilities set. | keyword |  |
| falco.output_fields.proc.tty | Controlling terminal of the process. | long |  |
| falco.output_fields.proc.vmrss | Resident non-swapped memory for the process. | unsigned_long | byte |
| falco.output_fields.proc.vmsize | Total virtual memory for the process. | unsigned_long | byte |
| falco.output_fields.proc.vmswap | Swapped memory for the process. | unsigned_long |  |
| falco.output_fields.proc.vpgid | Preserved Falco field | integer |  |
| falco.output_fields.proc.vpgid.exe | First command line argument of the current process's group leader. | text |  |
| falco.output_fields.proc.vpgid.exepath | Preserved Falco field | text |  |
| falco.output_fields.proc.vpgid.name | Preserved Falco field | text |  |
| falco.output_fields.proc.vpid | Preserved Falco field | integer |  |
| falco.output_fields.process.group_leader.vpid | Preserved Falco field | long |  |
| falco.output_fields.process.parent.pid | Preserved Falco field | long |  |
| falco.output_fields.process.pid | Preserved Falco field | long |  |
| falco.output_fields.process.session_leader.pid | Preserved Falco field | long |  |
| falco.output_fields.proct.ppid.duration | Preserved Falco field | text |  |
| falco.output_fields.rule | Preserved Falco field | text |  |
| falco.output_fields.server.ip | Falco copy of the ECS field of the same name | ip |  |
| falco.output_fields.source.ip | Falco copy of the ECS field of the same name | ip |  |
| falco.output_fields.syslog.facility | Preserved Falco field | text |  |
| falco.output_fields.syslog.facility.str | Preserved Falco field | text |  |
| falco.output_fields.syslog.severity | Preserved Falco field | text |  |
| falco.output_fields.syslog.severity.str | Preserved Falco field | text |  |
| falco.output_fields.thread.cap_effective | Preserved Falco field | text |  |
| falco.output_fields.thread.cap_permitted | Preserved Falco field | text |  |
| falco.output_fields.thread.cgroups | Aggregated string of cgroups the thread belongs to. | flattened |  |
| falco.output_fields.thread.cpu | CPU consumed by the thread in the last second. | double |  |
| falco.output_fields.thread.cpu_system | The system CPU consumed by the thread in the last second. | double |  |
| falco.output_fields.thread.cpu_user | The user CPU consumed by the thread in the last second. | double |  |
| falco.output_fields.thread.exectime | CPU time spent by last scheduled thread. | long | nanos |
| falco.output_fields.thread.ismain | Denotes if the threat generating the event is the main one in the process. | boolean |  |
| falco.output_fields.thread.pfmajor | Number of major page faults since thread start. | unsigned_long |  |
| falco.output_fields.thread.pfminor | Number of minor page faults since thread start. | unsigned_long |  |
| falco.output_fields.thread.tid | Preserved Falco field | integer |  |
| falco.output_fields.thread.totalexectime | Total CPU time for the current thread since the beginning of the capture. | long | nanos |
| falco.output_fields.thread.vmrss | Resident non-swapped memory for the process' main thread. Non-main threads will appear as zero. | unsigned_long |  |
| falco.output_fields.thread.vmsize | Total virtual memory for the process' main thread. Non-main threads will appear as zero. | unsigned_long |  |
| falco.output_fields.thread.vtid | The ID of the thread generating the event as seen from its current PID namespace. | long |  |
| falco.output_fields.user.homedir | Home directory of the user. | text |  |
| falco.output_fields.user.loginname | Audit user name. | keyword |  |
| falco.output_fields.user.loginuid | Audit user ID. If an invalid UID is encountered, returns -1. | long |  |
| falco.output_fields.user.name | Preserved Falco field | text |  |
| falco.output_fields.user.shell | User's shell. | keyword |  |
| falco.output_fields.user.uid | Preserved Falco field | integer |  |
| falco.priority | Falco alert priority | keyword |  |
| falco.rule | Name of the Falco rule that triggered the alert | keyword |  |
| falco.source | Preserved Falco field | keyword |  |
| falco.tags | Preserved Falco field | keyword |  |
| falco.time | Preserved Falco field | date |  |
| falco.uuid | Preserved Falco field | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| input.type | Input type | keyword |  |
| log.offset | Log offset | long |  |
| log.source.address | Log source when collecting via TCP input | keyword |  |
| process.group.id | Preserved Falco field | text |  |
| process.group.name | Preserved Falco field | text |  |
| process.group_leader.vpid.exepath | Preserved Falco field | text |  |
| process.group_leader.vpid.name | Preserved Falco field | text |  |
| process.pid.ts | Preserved Falco field | text |  |
| process.session_leader.pid.exepath | Preserved Falco field | text |  |


An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2024-07-15T16:03:02.820Z",
    "agent": {
        "ephemeral_id": "c4fe7d78-3d16-43ec-8056-9d6fa3b45beb",
        "id": "1b52f58d-1b3f-49f6-be71-11d20f9918f8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "container": {
        "id": "a7d5e7bf5bec",
        "name": "elastic-package-service-falco-event-generator-1"
    },
    "data_stream": {
        "dataset": "falco.alerts",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "1b52f58d-1b3f-49f6-be71-11d20f9918f8",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "falco.alerts",
        "ingested": "2024-07-15T16:03:12Z",
        "kind": "alert",
        "original": "{\"uuid\":\"34c62001-dc25-4172-a66c-c8fa2d526880\",\"output\":\"2024-07-15T16:03:02.820333475+0000: Warning Sensitive file opened for reading by trusted program after startup (file=/etc/shadow pcmdline=event-generator run --loop gparent=containerd-shim ggparent=containerd-shim gggparent=init evt_type=openat user=root user_uid=0 user_loginuid=-1 process=httpd proc_exepath=/bin/event-generator parent=event-generator command=httpd --loglevel info run ^syscall.ReadSensitiveFileUntrusted$ --sleep 6s terminal=0 container_id=a7d5e7bf5bec container_name=elastic-package-service-falco-event-generator-1)\",\"priority\":\"Warning\",\"rule\":\"Read sensitive file trusted after startup\",\"time\":\"2024-07-15T16:03:02.820333475Z\",\"output_fields\":{\"container.id\":\"a7d5e7bf5bec\",\"container.name\":\"elastic-package-service-falco-event-generator-1\",\"evt.time.iso8601\":1721059382820333475,\"evt.type\":\"openat\",\"fd.name\":\"/etc/shadow\",\"proc.aname[2]\":\"containerd-shim\",\"proc.aname[3]\":\"containerd-shim\",\"proc.aname[4]\":\"init\",\"proc.cmdline\":\"httpd --loglevel info run ^syscall.ReadSensitiveFileUntrusted$ --sleep 6s\",\"proc.exepath\":\"/bin/event-generator\",\"proc.name\":\"httpd\",\"proc.pcmdline\":\"event-generator run --loop\",\"proc.pname\":\"event-generator\",\"proc.tty\":0,\"user.loginuid\":-1,\"user.name\":\"root\",\"user.uid\":0},\"source\":\"syscall\",\"tags\":[\"T1555\",\"container\",\"filesystem\",\"host\",\"maturity_stable\",\"mitre_credential_access\"],\"hostname\":\"c59de1a7ddbc\"}",
        "provider": "syscall",
        "start": 1721059382820333600,
        "timezone": "+00:00"
    },
    "event.category": [
        "process"
    ],
    "event.severity": 3,
    "event.type": [
        "access"
    ],
    "falco": {
        "hostname": "c59de1a7ddbc",
        "output": "2024-07-15T16:03:02.820333475+0000: Warning Sensitive file opened for reading by trusted program after startup (file=/etc/shadow pcmdline=event-generator run --loop gparent=containerd-shim ggparent=containerd-shim gggparent=init evt_type=openat user=root user_uid=0 user_loginuid=-1 process=httpd proc_exepath=/bin/event-generator parent=event-generator command=httpd --loglevel info run ^syscall.ReadSensitiveFileUntrusted$ --sleep 6s terminal=0 container_id=a7d5e7bf5bec container_name=elastic-package-service-falco-event-generator-1)",
        "output_fields": {
            "container": {
                "id": "a7d5e7bf5bec",
                "name": "elastic-package-service-falco-event-generator-1"
            },
            "evt": {
                "time": {
                    "iso8601": 1721059382820333600
                },
                "type": "openat"
            },
            "fd": {
                "name": "/etc/shadow"
            },
            "proc": {
                "cmdline": "httpd --loglevel info run ^syscall.ReadSensitiveFileUntrusted$ --sleep 6s",
                "exepath": "/bin/event-generator",
                "name": "httpd",
                "pcmdline": "event-generator run --loop",
                "pname": "event-generator",
                "tty": 0
            },
            "user": {
                "loginuid": -1,
                "name": "root",
                "uid": "0"
            }
        },
        "priority": "Warning",
        "rule": "Read sensitive file trusted after startup",
        "source": "syscall",
        "tags": [
            "T1555",
            "container",
            "filesystem",
            "host",
            "maturity_stable",
            "mitre_credential_access"
        ],
        "time": "2024-07-15T16:03:02.820333475Z",
        "uuid": "34c62001-dc25-4172-a66c-c8fa2d526880"
    },
    "falco.container.mounts": null,
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "29b44b57f32c4ff282841a8a4406ef95",
        "ip": [
            "172.30.0.7"
        ],
        "mac": [
            "02-42-AC-1E-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.6.12-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.30.0.4:50956"
        },
        "syslog": {
            "appname": "Falco",
            "facility": {
                "code": 0,
                "name": "kernel"
            },
            "hostname": "7f26c2bd9471",
            "priority": 4,
            "procid": "{\"uuid\":\"34c62001-dc25-4172-a66c-c8fa2d526880\",\"output\":\"2024-07-15T16:03:02.820333475+0000: Warning Sensitive file opened for reading by trusted program after startup (file=/etc/shadow pcmdline=event-generator run --loop gparent=containerd-shim ggparent=containerd-shim gggparent=init evt_type=openat user=root user_uid=0 user_loginuid=-1 process=httpd proc_exepath=/bin/event-generator parent=event-generator command=httpd --loglevel info run ^syscall.ReadSensitiveFileUntrusted$ --sleep 6s terminal=0 container_id=a7d5e7bf5bec container_name=elastic-package-service-falco-event-generator-1)\",\"priority\":\"Warning\",\"rule\":\"Read sensitive file trusted after startup\",\"time\":\"2024-07-15T16:03:02.820333475Z\",\"output_fields\":{\"container.id\":\"a7d5e7bf5bec\",\"container.name\":\"elastic-package-service-falco-event-generator-1\",\"evt.time.iso8601\":1721059382820333475,\"evt.type\":\"openat\",\"fd.name\":\"/etc/shadow\",\"proc.aname[2]\":\"containerd-shim\",\"proc.aname[3]\":\"containerd-shim\",\"proc.aname[4]\":\"init\",\"proc.cmdline\":\"httpd --loglevel info run ^syscall.ReadSensitiveFileUntrusted$ --sleep 6s\",\"proc.exepath\":\"/bin/event-generator\",\"proc.name\":\"httpd\",\"proc.pcmdline\":\"event-generator run --loop\",\"proc.pname\":\"event-generator\",\"proc.tty\":0,\"user.loginuid\":-1,\"user.name\":\"root\",\"user.uid\":0},\"source\":\"syscall\",\"tags\":[\"T1555\",\"container\",\"filesystem\",\"host\",\"maturity_stable\",\"mitre_credential_access\"",
            "severity": {
                "code": 4,
                "name": "Warning"
            }
        }
    },
    "observer": {
        "hostname": "c59de1a7ddbc"
    },
    "process": {
        "command_line": "httpd --loglevel info run ^syscall.ReadSensitiveFileUntrusted$ --sleep 6s",
        "executable": "/bin/event-generator",
        "name": "httpd",
        "parent": {
            "command_line": "event-generator run --loop",
            "name": "event-generator"
        },
        "user": {
            "id": "0",
            "name": "root"
        }
    },
    "related": {
        "hosts": [
            "c59de1a7ddbc"
        ]
    },
    "rule": {
        "name": "Read sensitive file trusted after startup"
    },
    "tags": [
        "preserve_original_event",
        "preserve_falco_fields"
    ],
    "threat.technique.id": [
        "T1555"
    ]
}
```
