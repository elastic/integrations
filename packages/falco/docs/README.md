# Falco Integration
This integration allows for the shipping of [Falco](https://falco.org/) alerts to Elastic for observability and organizational awareness.

## Data Streams
The Falco integration contains a data stream for two input sources: One for syslogs and another for logfiles.

### syslog
The syslog input collects data directly pertaining to Falco alerts on host machines, as shipped by the agent itself on the machine. 

### logfile
The logfile input operates in a similar manner to the syslog input, but pulls Falco events / alerts from a logfile generated and stored by the host machine in a volume.

### Event Structure
Falco events can contain a multitude of various fields pertaining to the type of activity on the host machine. An example of one such type of event is the following:
```json
{
	"container": {
		"id": "abcdef123456",
		"name": "nginx-container",
		"image": {
		"name": "nginx",
		"digest": "sha256:abcdef123456"
		},
		"type": "docker",
		"privileged": false,
		"ip": "192.168.1.10",
		"runtime": "docker",
		"mounts": "/var/log/nginx:/var/log/nginx:rw /etc/nginx:/etc/nginx:ro"
	},
	"proc": {
		"thread": {
		"cap_inheritable": "test string"
		},
		"env": "development",
		"name": "test process",
		"exepath": "/usr/sbin/nginx",
		"cmdnargs": 7456
	},
	"file": {
		"directory": "/var/log/nginx",
		"name": "access.log",
		"inode": "123456"
	},
	"client": {
		"ip": "192.168.1.20",
		"port": 54321,
		"domain": "client.example.com"
	},
	"server": {
		"ip": "192.168.1.10",
		"port": 80,
		"domain": "example.com"
	},
	"evt": {
		"category": "system",
		"type": "send",
		"pluginname": "nginx",
		"plugininfo": "Nginx access log",
		"latency": 0.123,
		"dir": "outbound",
		"args": "/index.html",
		"info": "GET request",
		"res": "SUCCESS"
	}
}
```

**Exported Fields - ECS**
| Field | Description | Type |
|-------|-------------|------|
| event.kind|The kind of alert, which in the case of Falco is "alert".|constant_keyword |
| event.category|The category of the event, based on the driver collecting data.|text |
| event.type|Name of the event.|keyword |
| event.outcome|How the event resolved.|keyword |
| event.created|Date / time the event was first read by an Agent.|date |
| event.ingested|Date / time the event first reached the datastore.|date |
| threat.technique.id|ID based on Mitre tags within Falco.|keyword |
| event.original|Raw output of the Falco rule.|text |
| event.severity|Priority of the event. Needs lowercase filter.|keyword |
| rule.name|Name of the Falco rule.|keyword |
| tags|Non-Mitre tags from Falco.|text |
| '@timestamp'|Event timestamp with nanos.|date |
| event.start|Event timestamp with nanos.|date |
| event.provider|Name of the source that produced the event.|keyword |
| process.executable|Full executable path of the process.|text |
| process.parent.executable|The process.exe path of the parent process.|text |
| process.name|Name of the process generating the event.|text |
| process.parent.name|Name of the parent of the process generating the event.|text |
| process.args|Arguments passed over the command line when starting the process which generated the event.|text |
| process.command_line|Concatenation of process.name and process.args.|text |
| process.parent.command_line|The process.command_line equivalent for the parent process.|text |
| process.args_count|The count of command line args.|long |
| process.env_vars|Concatenated string of encironment variables for the process generating the event.|text |
| process.working_directory|Current working directory of the event.|text |
| process.pid|ID of the process generating the event.|long |
| process.parent.pid|PID for the parent of the process generating the event.|long |
| process.vpid|ID of the process generating the event as seen from its current PID namespace.|long |
| process.parent.vpid|ID of the parent process generating the event as seen from its current PID namespace.|long |
| process.session_leader.vpid|Session ID of the process generating the event.|long |
| process.session_leader.name|Name of the current process's session leader.|text |
| process.session_leader.executable|Full executable path of the current process's session leader.|text |
| process.group_leader.vpid|Process group ID of the process generating the event, as seen from its current PID namespace.|long |
| process.group_leader.name|Name of the current process's group leader.|text |
| process.group_leader.executable|Full executable path of the current process's group leader.|text |
| process.uptime|Number of nanoseconds since the process started.|long |
| process.parent.uptime|Number of nanoseconds since the parent process started.|long |
| process.start|Start of process as epoch timestamp in nanos.|date_nanos |
| process.parent.start|Start of parent process as epoch timestamp in nanos.|date_nanos |
| process.session_leader.same_as_process|Denotes if this process is the leader of the process session.|boolean |
| process.group_leader.same_as_process|Denotes if this process is the leader of the virtual process group.|boolean |
| process.thread.capabilities.permitted|Set of permitted capabilities.|text |
| process.thread.capabilities.effective|Set of effective capabilities.|text |
| process.thread.id|ID of the thread generating the event.|long |
| process.user.id|User ID.|integer |
| process.user.name|User name.|keyword |
| process.group.id|Group ID.|keyword |
| process.group.name|Group name.|keyword |
| container.id|Truncated container ID from Linux cgroups by Falco within the kernel. Serves as a lookup key to retrieve other container information.|text |
| container.name|Container name.|text |
| container.image.name|Container image name.|text |
| container.runtime|Container type (docker, cri-o, containerd etc)|text |
| container.security_context.privileged|Denotes if containers are running as privileged.|boolean |
| container.image.tag|The container image tag.|text |
| container.image.hash.all|The container image registry digest.|text |
| host.ip|The container's primary IP address.|ip |
| file.directory|If the FD is a file, this lists the directory which contains it.|text |
| file.name|If the FD is a file, the filename without the path.|text |
| file.type|Type of FD, if fd.type is file or directory.|text |
| file.path|Path of file FD, if fd.type is file or directory.|text |
| client.ip|Matches the client IP address of the FD.|ip |
| client.address|Matches the client IP address of the FD.|ip |
| server.ip|Matches the server IP address of the FD.|ip |
| server.address|Matches the server IP address of the FD.|ip |
| source.ip|Matches the local IP address of the FD.|ip |
| source.address|Matches the local IP address of the FD.|ip |
| destination.ip|Matches the remote IP address of the FD.|ip |
| destination.address|Matches the remote IP address of the FD.|ip |
| client.port|For TCP/UDP FDs, the client port.|text |
| server.port|For TCP/UDP FDs, the server port.|text |
| source.port|For TCP/UDP FDs, the source port.|text |
| destination.port|For TCP/UDP FDs, the destination port.|text |
| client.domain|Domain name associated with the client IP address.|text |
| server.domain|Domain name associated with the server IP address.|text |
| local.domain|Domain name associated with the local IP address.|text |
| remote.domain|Domain name associated with the remote IP address.|text |
| file.inode|Inode number of the referenced file.|text |
| log.syslog.facility.name|Facility as a string.|text |
| log.syslog.facility.code|Facility as a number (0-23).|integer |
| log.syslog.severity.name|Severity as a string. Can have one of these values; emerg, alert, crit, err, warn, notice, info, debug.|text |
| log.syslog.severity.code|Severity as a number (0-7).|text |
| orchestrator.namespace|Kubernetes namespace name.|text |
| orchestrator.resource.name|Kubernetes pod name.|text |
| orchestrator.resource.id|Kubernetes pod UID, assigned upon pod creation within Kubernetes.|text |
| orchestrator.resource.label|Kubernetes pod key/value labels.|text |
| orchestrator.resource.ip|Kubernetes pod IP.|text |
| orchestrator.resource.type|Returns "pod" if other pod fields are present.|text |
| orchestrator.type|Returns "Kubernetes" if other pod fields are present.|text |


**Exported Fields - Custom**
| Field | Description | Type |
|-------|-------------|------|
| event.sequence|Event number.|long |
| observer.hostname|Host of the originating event.|text |
| related.hosts|Host of the originating event.|text |
| Falco|Namespace for Falco-specific fields without a direct ECS equivalent.|group |
|Falco.evt.pluginname|Name of the plugin that generated the event (if applicable).|keyword |
|Falco.evt.plugininfo|Summary of the event if it came from a plugin-defined event source.|text |
|Falco.evt.is_async|Denotes whether the event is async or not.|boolean |
|Falco.evt.asynctype|The type of event, if asyncronous.|keyword |
|Falco.evt.latency|Delta between an exit event and corresponding enter event.|long |
|Falco.evt.deltatime|Delta between current event and previous.|long |
|Falco.evt.dir|Either an enter event (>) or an exit event (<).|keyword |
|Falco.evt.cpu|Number of the CPU where the event occurred.|integer |
|Falco.evt.args|Aggregated string of all event arguments.|text |
|Falco.evt.info|Contains either the event arguments, or the data decoded from them.|text |
|Falco.evt.buffer|Binary buffer for events which have one.|binary |
|Falco.evt.buflen|Length of the binary buffer, if applicable.|unsigned_long |
|Falco.evt.res|Return value of the event.|text |
|Falco.evt.rawres|Return value of the event, as a number.|long |
|Falco.evt.failed|Denotes if the event returned an error status.|boolean |
|Falco.evt.is_io|Denotes events that read or write to FDs.|boolean |
|Falco.evt.is_io_read|Denotes events that read from FDs.|boolean |
|Falco.evt.is_io_write|Denotes events that write to FDs.|boolean |
|Falco.evt.io_dir|Type based on whether the event reads from or writes to FDs.|keyword |
|Falco.evt.is_wait|Denotes events that force the thread to wait.|boolean |
|Falco.evt.wait_latency|Time spent waiting for events to return, in cases where the thread is forced to wait.|long |
|Falco.evt.is_syslog|Denotes events that are written to /dev/log|boolean |
|Falco.evt.count.error|Returns 1 for events that returned with an error|integer |
|Falco.evt.count.error_file|Returns 1 for events that returned with an error and are related to file I/O|integer |
|Falco.evt.count.error_net|Returns 1 for events that returned with an error and are related to network I/O|integer |
|Falco.evt.count.error_memory|Returns 1 for events that returned with an error and are related to memory allocation.|integer |
|Falco.evt.count.error_other|Returns 1 for events that returned with an error and are related to none of the previous categories.|integer |
|Falco.evt.count.exit|Returns 1 for exit events.|integer |
|Falco.evt.abspath|Calculated absolute path.|text |
|Falco.evt.abspath_src|Source of the absolute path.|text |
|Falco.evt.abspath_dst|Destination of the absolute path.|text |
|Falco.evt.is_open_read|Denotes whether or not the path was opened for reading for open/openat/openat2/open_by_handle_at events.|boolean |
|Falco.evt.is_open_write|Denotes whether or not the path was opened for writing for open/openat/openat2/open_by_handle_at events.|boolean |
|Falco.evt.is_open_exec|Denotes whether or not a file was created with execute permissions for open/openat/openat2/open_by_handle_at or create events.|boolean |
|Falco.evt.is_open_create|Denotes whether or not a file was created for open/openat/openat2/open_by_handle_at events.|boolean |
|Falco.proc.exe|First command line argument, collected from args.|text |
|Falco.proc.pexe|First command line argument of the parent process.|text |
|Falco.proc.cmdlenargs|Total length of command line args, excluding whitespace.|long |
|Falco.proc.exeline|Full command line, with exe as first argument.|text |
|Falco.proc.loginshellid|PID of the oldest shell among the ancestors of the current process, if applicable.|long |
|Falco.proc.tty|Controlling terminal of the process.|long |
|Falco.proc.sid.exe|First command line argument of the current process's session leader.|text |
|Falco.proc.vpgid.exe|First command line argument of the current process's group leader.|text |
|Falco.proc.is_exe_writable|Denotes if this process' executable file is writable by the same user that spawned the process.|boolean |
|Falco.proc.is_exe_upper_layer|Denotes if this process' executable file is in upper layer in overlayfs.|boolean |
|Falco.proc.is_exe_from_memfd|Denotes if this process' executable file is in upper layer in overlayfs.|boolean |
|Falco.proc.exe_ino|The inode number of the executable file on disk.|long |
|Falco.proc.exe_ino_ctime|Last status change of executable file as epoch timestamp.|date_nanos |
|Falco.proc.exe_ino_mtime|Last modification time of executable file as epoch timestamp.|date_nanos |
|Falco.proc.exe_ino_ctime_duration_proc_start|Number of nanoseconds between modifying status of executable image and spawning a new process using the changed executable image.|long |
|Falco.proc.exe_ino_ctime_duration_pidns_start|Number of nanoseconds between PID namespace start ts and ctime exe file if PID namespace start predates ctime.|long |
|Falco.proc.pidns_init_start_ts|Start of PID namespace as epoch timestamp.|date_nanos |
|Falco.proc.thread.cap_inheritable|Set of inheritable capabilities set.|keyword |
|Falco.proc.is_container_healthcheck|Denotes if this process is running as a part of the container's health check.|boolean |
|Falco.proc.is_container_liveness_probe|Denotes if this process is running as a part of the container's liveness probe.|boolean |
|Falco.proc.is_container_readiness_probe|Denotes if this process is running as a part of the container's readiness probe.|boolean |
|Falco.proc.fdopencount|Number of open FDs for the process.|unsigned_long |
|Falco.proc.fdopenlimit|Maximum number of FDs the process can open.|long |
|Falco.proc.fdusage|Ratio between open FDs and maximum available FDs for the process.|double |
|Falco.proc.vmsize|Total virtual memory for the process.|unsigned_long |
|Falco.proc.vmrss|Resident nonswapped memory for the process.|unsigned_long |
|Falco.proc.vmswap|Swapped memory for the process.|unsigned_long |
|Falco.thread.pfmajor|Number of major page faults since thread start.|unsigned_long |
|Falco.thread.pfminor|Number of minor page faults since thread start.|unsigned_long |
|Falco.thread.ismain|Denotes if the threat generating the event is the main one in the process.|boolean |
|Falco.thread.vtid|The ID of the thread generating the event as seen from its current PID namespace.|long |
|Falco.thread.exectime|CPU time spent by last scheduled thread.|long |
|Falco.thread.totalexectime|Total CPU time for the current thread since the beginning of the capture.|long |
|Falco.thread.cgroups|Aggregated string of cgroups the thread belongs to.|flattened |
|Falco.proc.nthreads|Number of alive threads in the process generating the event currently has, including the leader thread.|unsigned_long |
|Falco.proc.nchilds|Number of alive (not leader) threads in the process generating the event currently has, excluding the leader thread.|unsigned_long |
|Falco.thread.cpu|CPU consumed by the thread in the last second.|double |
|Falco.thread.cpu_user|The user CPU consumed by the thread in the last second.|double |
|Falco.thread.cpu_system|The system CPU consumed by the thread in the last second.|double |
|Falco.thread.vmsize|Total virtual memory for the process' main thread. Nonmain threads will appear as zero.|unsigned_long |
|Falco.thread.vmrss|Resident nonswapped memory for the process' main thread. Nonmain threads will appear as zero.|unsigned_long |
|Falco.user.homedir|Home directory of the user.|text |
|Falco.user.shell|User's shell.|keyword |
|Falco.user.loginuid|Audit user ID. If an invalid UID is encountered, returns 1.|long |
|Falco.user.loginname|Audit user name.|keyword |
|Falco.container.image.full_id|Full container ID, enriched as part of the container engine enrichment.|keyword |
|Falco.container.image.id|Container image ID.|keyword |
|Falco.container.mounts|List of mount information.|nested |
|Falco.container.mounts.source|The container image repository.|keyword |
|Falco.container.mounts.dest|The container's health check. Will be N/A if no health check configured.|keyword |
|Falco.container.mounts.mode|The container's liveness probe. Will be N/A if no liveness probe configured.|keyword |
|Falco.container.mounts.rdrw|The container's readiness probe. Will be N/A if no readiness probe configured.|keyword |
|Falco.container.mounts.propogation|Container start as epoch timestamp.|keyword |
|Falco.container.image.repository|Number of nanoseconds since container.start_ts.|keyword |
|Falco.container.healthcheck|Container's CNI result field from the respective container status info.|text |
|Falco.container.liveness_probe|Unique number identifying the file descriptor.|text |
|Falco.container.readiness_probe|Type of FD. Can be 'file', 'directory', 'ipv4', 'ipv6', 'unix', 'pipe', 'event', 'signalfd', 'eventpoll', 'inotify' 'signalfd' or 'memfd'.|text |
|Falco.container.start_ts|Type of FD as a single character. Can be 'f' for file, 4 for IPv4 socket, 6 for IPv6 socket, 'u' for unix socket, p for pipe, 'e' for eventfd, 's' for signalfd, 'l' for eventpoll, 'i' for inotify, 'b' for bpf, 'u' for userfaultd, 'r' for io_uring, 'm' for memfd ,'o' for unknown.|date_nanos |
|Falco.container.duration|FD full name. If the fd is a file, this field contains the full path. If the FD is a socket, this field contain the connection tuple.|long |
|Falco.container.cni_json|The IP protocol of a socket. Can be 'tcp', 'udp', 'icmp' or 'raw'.|object |
|Falco.fd.num|The socket family for socket events. Can be 'ip' or 'unix'.| object_keyword |
|Falco.fd.type|Denotes if process owning the FD is the server endpoint in the connection.|long |
|Falco.fd.typechar|Unique identifier for the FD, created from the FD number and thread ID.|keyword |
|Falco.fd.name|Concatenation of the container ID and the FD name.|keyword |
|Falco.fd.I4proto|Concatenation of the container ID and the directory name.|text |
|Falco.fd.sockfamily|For TCP/UDP FDs, the client protocol.|keyword |
|Falco.fd.is_server|For TCP/UDP FDs, the server protocol.|keyword |
|Falco.fd.uid|For TCP/UDP FDs, the local protocol.|boolean |
|Falco.fd.containername|For TCP/UDP FDs, the remote protocol.|keyword |
|Falco.fd.containerdirectory|Denotes if the socket is connected for TCP/UDP FDs.|keyword |
|Falco.fd.cproto|Denotes if the name of an FD changes due to an event.|keyword |
|Falco.fd.sproto|Device number containing the referenced file.|keyword |
|Falco.fd.lproto|Major device number containing the referenced file.|keyword |
|Falco.fd.rproto|Minor device number containing the referenced file.|keyword |
|Falco.fd.connected|For any event type that deals with a filesystem path, the path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed.|keyword |
|Falco.fd.name_changed|For any event type that deals with a filesystem path, and specifically for a source and target like mv, cp, etc, the source path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed.|boolean |
|Falco.fd.dev|For any event type that deals with a filesystem path, and specifically for a target and target like mv, cp, etc, the target path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed.|boolean |
|Falco.fd.dev_major|For poll events, FD names in the fds argument.|integer |
|Falco.fd.dev_minor|For poll events, client IP addresses in the fds argument.|integer |
|Falco.fs.path.name|For poll events, server IP addresses in the fds argument.|integer |
|Falco.fs.path.source|For poll events / TCP/UDP FDs, client TCP/UDP ports in the fds argument.|keyword |
|Falco.fs.path.target|For poll events, server TCP/UDP ports in the fds argument.|keyword |
|Falco.fdlist.names|Truncated Kubernetes pod sandbox ID (first 12 characters).|keyword |
|Falco.fdlist.cips|Full, nontruncated Kubernetes pod sandbox ID.|keyword |
|Falco.fdlist.sips|Kubernetes CNI result field from the respective pod status info.|ip |
|Falco.fdlist.cports|Preserved Falco field for event.original.|ip |
|Falco.fdlist.sports|Preserved Falco field for event.severity.|ip |
|Falco.k8s.pod.sandbox_id|Preserved Falco field for rule.name.|ip |
|Falco.k8s.pod.full_sandbox_id|Preserved Falco field for event.sequence.|keyword |
|Falco.k8s.pod.cni_json|Preserved Falco field for @timestamp.|keyword |
| output|Preserved Falco field for event.original.|object |
| priority|Preserved Falco field for observer.hostname| object_keyword |
| rule|Preserved Falco field for process.executable|text |
| evt.num|Preserved Falco field for process.parent.executable|keyword |
| evt.time|Preserved Falco field for process.name|text |
| evt.source|Preserved Falco field for process.parent.name|integer |
| evt.hostname|Preserved Falco field for process.command_line|text |
| proc.exepath|Preserved Falco field for process.parent.command_line|text |
| proc.pexepath|Preserved Falco field for process.args_count|text |
| proc.name|Preserved Falco field for process.env_vars|text |
| proc.pname|Preserved Falco field for process.working_directory|text |
| proc.cmdline|Preserved Falco field for process.pid|text |
| proc.pcmdline|Preserved Falco field for process.parent.pid|text |
| proc.cmdnargs|Preserved Falco field for process.vpid|text |
| proc.env|Preserved Falco field for process.parent.vpid|text |
| proc.cwd|Preserved Falco field for process.session_leader|integer |
| proc.pid|Preserved Falco field for process.session_leader.name|text |
| proc.ppid|Preserved Falco field for process.session_leader.executable|text |
| proc.vpid|Preserved Falco field for process.group_leader.vpid|integer |
| proc.pvpid|Preserved Falco field for process.group_leader.name|integer |
| proc.sid|Preserved Falco field for process.group_leader.executable|integer |
| proc.sname|Preserved Falco field for process.uptime|integer |
| proc.sid.exepath|Preserved Falco field for process.parent.uptime|integer |
| proc.vpgid|Preserved Falco field for process.pid.start|text |
| proc.vpgid.name|Preserved Falco field for process.parent.start|text |
| proc.vpgid.exepath|Preserved Falco field for process.session_leader.same_as_process|integer |
| proc.duration|Preserved Falco field for process.group_leader.same_as_process|text |
| proct.ppid.duration|Preserved Falco field for process.thread.capabilities.permitted|text |
| proc.pid.ts|Preserved Falco field for process.thread.capabilities.effective|text |
| proc.ppid.ts|Preserved Falco field for process.thread.id|text |
| proc.is_sid_leader|Preserved Falco field for process.user.uid|text |
| proc.is_vpgid_leader|Preserved Falco field for process.user.name|text |
| thread.cap_permitted|Preserved Falco field for process.group.id|boolean |
| thread.cap_effective|Preserved Falco field for process.group.name|boolean |
| thread.tid|Preserved Falco field for container.image.name|text |
| user.uid|Preserved Falco field for container.runtime|text |
| user.name|Preserved Falco field for container.security_context.privileged|integer |
| group.gid|Preserved Falco field for container.image.hash.all|integer |
| group.name|Preserved Falco field for host.ip|text |
| container.image|Preserved Falco field for file.directory|integer |
| container.type|Preserved Falco field for file.name|text |
| container.privileged|Preserved Falco field for client.ip|text |
| container.image.digest|Preserved Falco field for server.ip|text |
| container.ip|Preserved Falco field for source.ip|boolean |
| fd.directory|Preserved Falco field for destination.ip|text |
| fd.filename|Preserved Falco field for client.port|text |
| fd.cip|Preserved Falco field for server.port|text |
| fd.sip|Preserved Falco field for source.port|text |
| fd.lip|Preserved Falco field for destination.port|ip |
| fd.rip|Preserved Falco field for client.domain|ip |
| fd.cport|Preserved Falco field for server.domain|ip |
| fd.sport|Preserved Falco field for source.domain|ip |
| fd.lport|Preserved Falco field for destination.domain|text |
| fd.rport|Preserved Falco field for file.inode|text |
| fd.cip.name|Preserved Falco field for log.syslog.facility.name|text |
| fd.sip.name|Preserved Falco field for log.syslog.facility.code|text |
| fd.lip.name|Preserved Falco field for log.syslog.severity.name|text |
| fd.rip.name|Preserved Falco field for log.syslog.severity.code|text |
| fd.ino|Preserved Falco field for orchestrator.namespace|text |
| syslog.facility.str|Preserved Falco field for orchestrator.resource.name|text |
| syslog.facility|Preserved Falco field for orchestrator.resource.id|text |
| syslog.severity.str|Preserved Falco field for orchestrator.resource.label|text |
| syslog.severity|Preserved Falco field for orchestrator.resource.ip|text |
| k8s.ns.name|Preserved Falco field for container.mounts|text |
| k8s.pod.name|Preserved Falco field for evt.args|text |
| k8s.pod.uid|Preserved Falco field for evt.category|text |
| k8s.pod.labels|Preserved Falco field for evt.dir|text |
| k8s.pod.ip|Preserved Falco field for evt.info|text |
| container.mounts|Preserved Falco field for evt.latency|text |
| evt.args|Preserved Falco field for evt.plugininfo|text |
| evt.category|Preserved Falco field for evt.pluginname|text |
| evt.dir|Preserved Falco field for evt.res|text |
| evt.info|Preserved Falco field for evt.type|text |
| evt.latency|Preserved Falco field for observer.product|text |
| evt.plugininfo|Preserved Falco field for observer.type|text |
| evt.pluginname|Preserved Falco field for observer.vendor|float |
| evt.res|Preserved Falco field for proc.thread.cap_inheritable|text |
| evt.type|Required field for integration|text |
| observer.product|Required field for integration|text |
| observer.type|Required field for integration|text |
| observer.vendor|Required field for integration|text |
| proc.thread.cap_inheritable|Required field for integration|text |
| hostname|Required field for integration|text |
| input.type|Required field for integration|text |
| log.source.address|Required field for integration|keyword |
| message|Required field for integration|keyword |
| process.program|Required field for integration|text |
| syslog.facility_label|Required field for integration|text |
| syslog.priority|Required field for integration|keyword |
| syslog.severity_label|Required field for integration|text |

## Requirements

This integration is compatible with Falco version 0.37 and above, and should not be expected to perform successfully in lower versions. The system will only receive fields output by Falco’s rules. If a rule does not include a desired field the rule must be edited in Falco to add the field.

## Setup
Use the Falco integration to connect to your Falco account and collect data from multiple machines / hosts. When you configure the integration, you can collect data from as many hosts or machines as you need.

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

