# Falco Integration
This integration allows for the shipping of [Falco](https://falco.org/) alerts to Elastic for observability and organizational awareness.

## Data Streams
The Falco integration contains a data stream for two input sources: One for tcp inputs and another for logfiles. These two input sources are used to collect data which can then be analyzed by using either the dashboard included with the integration or via the creation of a custom dashboard within Kibana. 

### tcp
The tcp input collects data directly pertaining to Falco alerts on host machines, as shipped by the agent itself on the machine. 

### logfile
The logfile input operates in a similar manner to the syslog input, but pulls Falco events / alerts from a logfile generated and stored by the host machine in a volume.

### Event Structure
Falco events can contain a multitude of various fields pertaining to the type of activity on the host machine. An example of one such type of event is the following:
```json
{
	"@timestamp": "2024-05-13T13:23:29.089Z",
	"Falco": {
		"hostname": "a2000de987ff",
		"output": "2024-05-13T13:23:36.089890892+0000: Warning Sensitive file opened for reading by non-trusted program (file=/etc/shadow gparent=runc ggparent=init gggparent=init evt_type=openat user=root user_uid=0 user_loginuid=-1 process=event-generator proc_exepath=/bin/event-generator parent=containerd-shim command=event-generator run --loop terminal=0 container_id=84c0b936c919 container_name=elastic-package-service-falco-event-generator-1)",
		"output_fields": {
			"client": {
				"ip": "216.160.83.56"
			},
			"container": {
				"id": "84c0b936c919",
				"name": "elastic-package-service-falco-event-generator-1"
			},
			"destination": {
				"ip": "67.43.156.0"
			},
			"evt": {
				"failed": true,
				"res": "ENOENT",
				"time": {
					"iso8601": 1715606609089890892
				},
				"type": "openat"
			},
			"fd": {
				"cport": 5400,
				"directory": "var/log/example",
				"filename": "example.tar.gz",
				"ino": "567874",
				"lport": 5689,
				"name": "/etc/shadow",
				"rport": 6789,
				"sport": 5700
			},
			"proc": {
				"cmdline": "event-generator run --loop",
				"exepath": "/bin/event-generator",
				"name": "event-generator",
				"pname": "containerd-shim",
				"tty": 0
			},
			"server": {
				"ip": "89.160.20.112"
			},
			"source": {
				"ip": "89.160.20.128"
			},
			"user": {
				"loginuid": -1,
				"name": "root",
				"uid": "0"
			}
		},
		"priority": "Warning",
		"rule": "Read sensitive file untrusted",
		"source": "syscall",
		"tags": [
			"T1555",
			"container",
			"filesystem",
			"host",
			"maturity_stable",
			"mitre_credential_access"
		],
		"time": "2024-05-13T13:23:36.089890892Z"
	},
	"Falco.container.mounts": null,
	"client": {
		"address": "216.160.83.56",
		"ip": "216.160.83.56",
		"port": 5400
	},
	"container": {
		"id": "84c0b936c919",
		"name": "elastic-package-service-falco-event-generator-1"
	},
	"destination": {
		"address": "67.43.156.0",
		"ip": "67.43.156.0",
		"port": 6789
	},
	"event": {
		"ingested": "2024-06-28T12:19:59.616584551Z",
		"kind": "alert",
		"original": "{\"hostname\":\"a2000de987ff\",\"output\":\"2024-05-13T13:23:36.089890892+0000: Warning Sensitive file opened for reading by non-trusted program (file=/etc/shadow gparent=runc ggparent=init gggparent=init evt_type=openat user=root user_uid=0 user_loginuid=-1 process=event-generator proc_exepath=/bin/event-generator parent=containerd-shim command=event-generator run --loop terminal=0 container_id=84c0b936c919 container_name=elastic-package-service-falco-event-generator-1)\",\"priority\":\"Warning\",\"rule\":\"Read sensitive file untrusted\",\"source\":\"syscall\",\"tags\":[\"T1555\",\"container\",\"filesystem\",\"host\",\"maturity_stable\",\"mitre_credential_access\"],\"time\":\"2024-05-13T13:23:36.089890892Z\", \"output_fields\": {\"container.id\":\"84c0b936c919\",\"container.name\":\"elastic-package-service-falco-event-generator-1\",\"evt.time.iso8601\":1715606609089890892,\"evt.type\":\"openat\",\"evt.res\": \"ENOENT\",\"evt.failed\":true,\"fd.name\":\"/etc/shadow\",\"fd.directory\":\"var/log/example\",\"fd.filename\":\"example.tar.gz\",\"fd.cip\":\"216.160.83.56\",\"fd.sip\":\"89.160.20.112\",\"fd.lip\":\"89.160.20.128\",\"fd.rip\":\"67.43.156.0\",\"fd.cport\":5400,\"fd.sport\":5700,\"fd.lport\":5689,\"fd.rport\":6789,\"fd.ino\":\"567874\",\"proc.aname[2]\":\"runc\",\"proc.aname[3]\":\"init\",\"proc.aname[4]\":\"init\",\"proc.cmdline\":\"event-generator run --loop\",\"proc.exepath\":\"/bin/event-generator\",\"proc.name\":\"event-generator\",\"proc.pname\":\"containerd-shim\",\"proc.tty\":0,\"user.loginuid\":-1,\"user.name\":\"root\",\"user.uid\":0}}",
		"outcome": "failure",
		"provider": "syscall",
		"start": 1715606609089890892
	},
	"event.category": [
		"process"
	],
	"event.severity": 3,
	"event.type": [
		"access"
	],
	"file": {
		"directory": "var/log/example",
		"inode": "567874",
		"name": "example.tar.gz"
	},
	"log": {
		"file": {
			"path": "/var/foo/events.log"
		}
	},
	"observer": {
		"hostname": "a2000de987ff"
	},
	"process": {
		"command_line": "event-generator run --loop",
		"executable": "/bin/event-generator",
		"name": "event-generator",
		"parent": {
			"name": "containerd-shim"
		},
		"user": {
			"id": "0",
			"name": "root"
		}
	},
	"related": {
		"hosts": [
			"a2000de987ff"
		]
	},
	"rule": {
		"name": "Read sensitive file untrusted"
	},
	"server": {
		"address": "89.160.20.112",
		"ip": "89.160.20.112",
		"port": 5700
	},
	"source": {
		"address": "89.160.20.128",
		"ip": "89.160.20.128",
		"port": 5689
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

**Exported Fields - ECS**
| Field | Description | Type |
|-------|-------------|------|
|event.kind|The kind of alert, which in the case of falco is "alert".|constant_keyword |
|event.category|The category of the event, based on the driver collecting data.|text |
|event.type|Name of the event.|keyword |
|event.outcome|How the event resolved.|keyword |
|event.created|Date / time the event was first read by an Agent.|date |
|event.ingested|Date / time the event first reached the datastore.|date |
|threat.technique.id|ID based on Mitre tags within falco.|keyword |
|event.original|Raw output of the falco rule.|text |
|event.severity|Priority of the event. Needs lowercase filter.|keyword |
|rule.name|Name of the falco rule.|keyword |
|tags|Non-Mitre tags from falco.|text |
|@timestamp|Event timestamp with nanos.|date |
|event.start|Event timestamp with nanos.|date |
|event.provider|Name of the source that produced the event.|keyword |
|process.executable|Full executable path of the process.|text |
|process.parent.executable|The process.exe path of the parent process.|text |
|process.name|Name of the process generating the event.|text |
|process.parent.name|Name of the parent of the process generating the event.|text |
|process.args|Arguments passed over the command line when starting the process which generated the event.|text |
|process.command_line|Concatenation of process.name and process.args.|text |
|process.parent.command_line|The process.command_line equivalent for the parent process.|text |
|process.args_count|The count of command line args.|long |
|process.env_vars|Concatenated string of encironment variables for the process generating the event.|text |
|process.working_directory|Current working directory of the event.|text |
|process.pid|ID of the process generating the event.|long |
|process.parent.pid|PID for the parent of the process generating the event.|long |
|process.vpid|ID of the process generating the event as seen from its current PID namespace.|long |
|process.parent.vpid|ID of the parent process generating the event as seen from its current PID namespace.|long |
|process.session_leader.vpid|Session ID of the process generating the event.|long |
|process.session_leader.name|Name of the current process's session leader.|text |
|process.session_leader.executable|Full executable path of the current process's session leader.|text |
|process.group_leader.vpid|Process group ID of the process generating the event, as seen from its current PID namespace.|long |
|process.group_leader.name|Name of the current process's group leader.|text |
|process.group_leader.executable|Full executable path of the current process's group leader.|text |
|process.uptime|Number of nanoseconds since the process started.|long |
|process.parent.uptime|Number of nanoseconds since the parent process started.|long |
|process.start|Start of process as epoch timestamp in nanos.|date_nanos |
|process.parent.start|Start of parent process as epoch timestamp in nanos.|date_nanos |
|process.session_leader.same_as_process|Denotes if this process is the leader of the process session.|boolean |
|process.group_leader.same_as_process|Denotes if this process is the leader of the virtual process group.|boolean |
|process.thread.capabilities.permitted|Set of permitted capabilities.|text |
|process.thread.capabilities.effective|Set of effective capabilities.|text |
|process.thread.id|ID of the thread generating the event.|long |
|process.user.id|User ID.|integer |
|process.user.name|User name.|keyword |
|process.group.id|Group ID.|keyword |
|process.group.name|Group name.|keyword |
|container.id|Truncated container ID from Linux cgroups by falco within the kernel. Serves as a lookup key to retrieve other container information.|text |
|container.name|Container name.|text |
|container.image.name|Container image name.|text |
|container.runtime|Container type (docker, cri-o, containerd etc)|text |
|container.security_context.privileged|Denotes if containers are running as privileged.|boolean |
|container.image.tag|The container image tag.|text |
|container.image.hash.all|The container image registry digest.|text |
|host.ip|The container's primary IP address.|ip |
|file.directory|If the FD is a file, this lists the directory which contains it.|text |
|file.name|If the FD is a file, the filename without the path.|text |
|file.type|Type of FD, if fd.type is file or directory.|text |
|file.path|Path of file FD, if fd.type is file or directory.|text |
|client.ip|Matches the client IP address of the FD.|ip |
|client.address|Matches the client IP address of the FD.|ip |
|server.ip|Matches the server IP address of the FD.|ip |
|server.address|Matches the server IP address of the FD.|ip |
|source.ip|Matches the local IP address of the FD.|ip |
|source.address|Matches the local IP address of the FD.|ip |
|destination.ip|Matches the remote IP address of the FD.|ip |
|destination.address|Matches the remote IP address of the FD.|ip |
|client.port|For TCP/UDP FDs, the client port.|text |
|server.port|For TCP/UDP FDs, the server port.|text |
|source.port|For TCP/UDP FDs, the source port.|text |
|destination.port|For TCP/UDP FDs, the destination port.|text |
|client.domain|Domain name associated with the client IP address.|text |
|server.domain|Domain name associated with the server IP address.|text |
|local.domain|Domain name associated with the local IP address.|text |
|remote.domain|Domain name associated with the remote IP address.|text |
|file.inode|Inode number of the referenced file.|text |
|log.syslog.facility.name|Facility as a string.|text |
|log.syslog.facility.code|Facility as a number (0-23).|integer |
|log.syslog.severity.name|Severity as a string. Can have one of these values; emerg, alert, crit, err, warn, notice, info, debug.|text |
|log.syslog.severity.code|Severity as a number (0-7).|text |
|orchestrator.namespace|Kubernetes namespace name.|text |
|orchestrator.resource.name|Kubernetes pod name.|text |
|orchestrator.resource.id|Kubernetes pod UID, assigned upon pod creation within Kubernetes.|text |
|orchestrator.resource.label|Kubernetes pod key/value labels.|text |
|orchestrator.resource.ip|Kubernetes pod IP.|text |
|orchestrator.resource.type|Returns "pod" if other pod fields are present.|text |
|orchestrator.type|Returns "Kubernetes" if other pod fields are present.|text |


**Exported Fields - Custom**
| Field | Description | Type |
|-------|-------------|------|
|event.sequence|Event number.|long |
|observer.hostname|Host of the originating event.|text |
|related.hosts|Host of the originating event.|text |
|falco|Namespace for falco-specific fields without a direct ECS equivalent.|group |
|falco.evt.pluginname|Name of the plugin that generated the event (if applicable).|keyword |
|falco.evt.plugininfo|Summary of the event if it came from a plugin-defined event source.|text |
|falco.evt.is_async|Denotes whether the event is async or not.|boolean |
|falco.evt.asynctype|The type of event, if asyncronous.|keyword |
|falco.evt.latency|Delta between an exit event and corresponding enter event.|long |
|falco.evt.deltatime|Delta between current event and previous.|long |
|falco.evt.dir|Either an enter event (>) or an exit event (<).|keyword |
|falco.evt.cpu|Number of the CPU where the event occurred.|integer |
|falco.evt.args|Aggregated string of all event arguments.|text |
|falco.evt.info|Contains either the event arguments, or the data decoded from them.|text |
|falco.evt.buffer|Binary buffer for events which have one.|binary |
|falco.evt.buflen|Length of the binary buffer, if applicable.|unsigned_long |
|falco.evt.res|Return value of the event.|text |
|falco.evt.rawres|Return value of the event, as a number.|long |
|falco.evt.failed|Denotes if the event returned an error status.|boolean |
|falco.evt.is_io|Denotes events that read or write to FDs.|boolean |
|falco.evt.is_io_read|Denotes events that read from FDs.|boolean |
|falco.evt.is_io_write|Denotes events that write to FDs.|boolean |
|falco.evt.io_dir|Type based on whether the event reads from or writes to FDs.|keyword |
|falco.evt.is_wait|Denotes events that force the thread to wait.|boolean |
|falco.evt.wait_latency|Time spent waiting for events to return, in cases where the thread is forced to wait.|long |
|falco.evt.is_syslog|Denotes events that are written to /dev/log|boolean |
|falco.evt.count.error|Returns 1 for events that returned with an error|integer |
|falco.evt.count.error_file|Returns 1 for events that returned with an error and are related to file I/O|integer |
|falco.evt.count.error_net|Returns 1 for events that returned with an error and are related to network I/O|integer |
|falco.evt.count.error_memory|Returns 1 for events that returned with an error and are related to memory allocation.|integer |
|falco.evt.count.error_other|Returns 1 for events that returned with an error and are related to none of the previous categories.|integer |
|falco.evt.count.exit|Returns 1 for exit events.|integer |
|falco.evt.abspath|Calculated absolute path.|text |
|falco.evt.abspath_src|Source of the absolute path.|text |
|falco.evt.abspath_dst|Destination of the absolute path.|text |
|falco.evt.is_open_read|Denotes whether or not the path was opened for reading for open/openat/openat2/open_by_handle_at events.|boolean |
|falco.evt.is_open_write|Denotes whether or not the path was opened for writing for open/openat/openat2/open_by_handle_at events.|boolean |
|falco.evt.is_open_exec|Denotes whether or not a file was created with execute permissions for open/openat/openat2/open_by_handle_at or create events.|boolean |
|falco.evt.is_open_create|Denotes whether or not a file was created for open/openat/openat2/open_by_handle_at events.|boolean |
|falco.proc.exe|First command line argument, collected from args.|text |
|falco.proc.pexe|First command line argument of the parent process.|text |
|falco.proc.cmdlenargs|Total length of command line args, excluding whitespace.|long |
|falco.proc.exeline|Full command line, with exe as first argument.|text |
|falco.proc.loginshellid|PID of the oldest shell among the ancestors of the current process, if applicable.|long |
|falco.proc.tty|Controlling terminal of the process.|long |
|falco.proc.sid.exe|First command line argument of the current process's session leader.|text |
|falco.proc.vpgid.exe|First command line argument of the current process's group leader.|text |
|falco.proc.is_exe_writable|Denotes if this process' executable file is writable by the same user that spawned the process.|boolean |
|falco.proc.is_exe_upper_layer|Denotes if this process' executable file is in upper layer in overlayfs.|boolean |
|falco.proc.is_exe_from_memfd|Denotes if this process' executable file is in upper layer in overlayfs.|boolean |
|falco.proc.exe_ino|The inode number of the executable file on disk.|long |
|falco.proc.exe_ino_ctime|Last status change of executable file as epoch timestamp.|date_nanos |
|falco.proc.exe_ino_mtime|Last modification time of executable file as epoch timestamp.|date_nanos |
|falco.proc.exe_ino_ctime_duration_proc_start|Number of nanoseconds between modifying status of executable image and spawning a new process using the changed executable image.|long |
|falco.proc.exe_ino_ctime_duration_pidns_start|Number of nanoseconds between PID namespace start ts and ctime exe file if PID namespace start predates ctime.|long |
|falco.proc.pidns_init_start_ts|Start of PID namespace as epoch timestamp.|date_nanos |
|falco.proc.thread.cap_inheritable|Set of inheritable capabilities set.|keyword |
|falco.proc.is_container_healthcheck|Denotes if this process is running as a part of the container's health check.|boolean |
|falco.proc.is_container_liveness_probe|Denotes if this process is running as a part of the container's liveness probe.|boolean |
|falco.proc.is_container_readiness_probe|Denotes if this process is running as a part of the container's readiness probe.|boolean |
|falco.proc.fdopencount|Number of open FDs for the process.|unsigned_long |
|falco.proc.fdopenlimit|Maximum number of FDs the process can open.|long |
|falco.proc.fdusage|Ratio between open FDs and maximum available FDs for the process.|double |
|falco.proc.vmsize|Total virtual memory for the process.|unsigned_long |
|falco.proc.vmrss|Resident nonswapped memory for the process.|unsigned_long |
|falco.proc.vmswap|Swapped memory for the process.|unsigned_long |
|falco.thread.pfmajor|Number of major page faults since thread start.|unsigned_long |
|falco.thread.pfminor|Number of minor page faults since thread start.|unsigned_long |
|falco.thread.ismain|Denotes if the threat generating the event is the main one in the process.|boolean |
|falco.thread.vtid|The ID of the thread generating the event as seen from its current PID namespace.|long |
|falco.thread.exectime|CPU time spent by last scheduled thread.|long |
|falco.thread.totalexectime|Total CPU time for the current thread since the beginning of the capture.|long |
|falco.thread.cgroups|Aggregated string of cgroups the thread belongs to.|flattened |
|falco.proc.nthreads|Number of alive threads in the process generating the event currently has, including the leader thread.|unsigned_long |
|falco.proc.nchilds|Number of alive (not leader) threads in the process generating the event currently has, excluding the leader thread.|unsigned_long |
|falco.thread.cpu|CPU consumed by the thread in the last second.|double |
|falco.thread.cpu_user|The user CPU consumed by the thread in the last second.|double |
|falco.thread.cpu_system|The system CPU consumed by the thread in the last second.|double |
|falco.thread.vmsize|Total virtual memory for the process' main thread. Nonmain threads will appear as zero.|unsigned_long |
|falco.thread.vmrss|Resident nonswapped memory for the process' main thread. Nonmain threads will appear as zero.|unsigned_long |
|falco.user.homedir|Home directory of the user.|text |
|falco.user.shell|User's shell.|keyword |
|falco.user.loginuid|Audit user ID. If an invalid UID is encountered, returns 1.|long |
|falco.user.loginname|Audit user name.|keyword |
|falco.container.image.full_id|Full container ID, enriched as part of the container engine enrichment.|keyword |
|falco.container.image.id|Container image ID.|keyword |
|falco.container.mounts|List of mount information.|nested |
|falco.container.mounts.source|Subfield of container.mounts|keyword |
|falco.container.mounts.dest|Subfield of container.mounts|keyword |
|falco.container.mounts.mode|Subfield of container.mounts|keyword |
|falco.container.mounts.rdrw|Subfield of container.mounts|keyword |
|falco.container.mounts.propogation|Subfield of container.mounts|keyword |
|falco.container.image.repository|The container image repository.|keyword |
|falco.container.healthcheck|The container's health check. Will be N/A if no health check configured.|text |
|falco.container.liveness_probe|The container's liveness probe. Will be N/A if no liveness probe configured.|text |
|falco.container.readiness_probe|The container's readiness probe. Will be N/A if no readiness probe configured.|text|
|falco.container.start_ts|Container start as epoch timestamp.|date_nanos|
|falco.container.duration|Number of nanoseconds since container.start_ts.|long|nanos|
|falco.container.cni_json|Container's CNI result field from the respective container status info.|object|keyword|
|falco.fd.num|Unique number identifying the file descriptor.|long|
|falco.fd.type|Type of FD. Can be 'file', 'directory', 'ipv4', 'ipv6', 'unix', 'pipe', 'event', 'signalfd', 'eventpoll', 'inotify' 'signalfd' or 'memfd'.|keyword|
|falco.fd.typechar|Type of FD as a single character. Can be 'f' for file, 4 for IPv4 socket, 6 for IPv6 socket, 'u' for unix socket, p for pipe, 'e' for eventfd, 's' for signalfd, 'l' for eventpoll, 'i' for inotify, 'b' for bpf, 'u' for userfaultd, 'r' for io_uring, 'm' for memfd ,'o' for unknown.|keyword|
|falco.fd.name|FD full name. If the fd is a file, this field contains the full path. If the FD is a socket, this field contain the connection tuple.|text|
|falco.fd.I4proto|The IP protocol of a socket. Can be 'tcp', 'udp', 'icmp' or 'raw'.|keyword|
|falco.fd.sockfamily|The socket family for socket events. Can be 'ip' or 'unix'.|keyword|
|falco.fd.is_server|Denotes if process owning the FD is the server endpoint in the connection.|boolean|
|falco.fd.uid|Unique identifier for the FD, created from the FD number and thread ID.|keyword|
|falco.fd.containername|Concatenation of the container ID and the FD name.|keyword|
|falco.fd.containerdirectory|Concatenation of the container ID and the directory name.|keyword|
|falco.fd.cproto|For TCP/UDP FDs, the client protocol.|keyword|
|falco.fd.sproto|For TCP/UDP FDs, the server protocol.|keyword|
|falco.fd.lproto|For TCP/UDP FDs, the local protocol.|keyword|
|falco.fd.rproto|For TCP/UDP FDs, the remote protocol.|keyword|
|falco.fd.connected|Denotes if the socket is connected for TCP/UDP FDs.|boolean|
|falco.fd.name_changed|Denotes if the name of an FD changes due to an event.|boolean|
|falco.fd.dev|Device number containing the referenced file.|integer|
|falco.fd.dev_major|Major device number containing the referenced file.|integer|
|falco.fd.dev_minor|Minor device number containing the referenced file.|integer|
|falco.fs.path.name|For any event type that deals with a filesystem path, the path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed.|keyword|
|falco.fs.path.source|For any event type that deals with a filesystem path, and specifically for a source and target like mv, cp, etc, the source path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed.|keyword|
|falco.fs.path.target|For any event type that deals with a filesystem path, and specifically for a target and target like mv, cp, etc, the target path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed.|keyword|
|falco.fdlist.names|For poll events, FD names in the fds argument.|keyword|
|falco.fdlist.cips|For poll events, client IP addresses in the fds argument.|ip|
|falco.fdlist.sips|For poll events, server IP addresses in the fds argument.|ip|
|falco.fdlist.cports|For poll events / TCP/UDP FDs, client TCP/UDP ports in the fds argument.|ip|
|falco.fdlist.sports|For poll events, server TCP/UDP ports in the fds argument.|ip|
|falco.k8s.pod.sandbox_id|Truncated Kubernetes pod sandbox ID (first 12 characters).|keyword|
|falco.k8s.pod.full_sandbox_id|Full, non-truncated Kubernetes pod sandbox ID.|keyword|
|falco.k8s.pod.cni_json|Kubernetes CNI result field from the respective pod status info.|object|keyword|
|falco.output|Preserved Falco field|text|
|falco.priority|Preserved falco field|keyword |
|falco.rule|Preserved falco field|text |
|falco.evt.num|Preserved falco field|keyword |
|falco.evt.time|Preserved falco field|text |
|falco.evt.source|Preserved falco field|integer |
|falco.evt.hostname|Preserved falco field|text |
|falco.proc.exepath|Preserved falco field|text |
|falco.proc.pexepath|Preserved falco field|text |
|falco.proc.name|Preserved falco field|text |
|falco.proc.pname|Preserved falco field|text |
|falco.proc.cmdline|Preserved falco field|text |
|falco.proc.pcmdline|Preserved falco field|text |
|falco.proc.cmdnargs|Preserved falco field|text |
|falco.proc.env|Preserved falco field|text |
|falco.proc.cwd|Preserved falco field |integer |
|falco.proc.pid|Preserved falco field|text |
|falco.proc.ppid|Preserved falco field|text |
|falco.proc.vpid|Preserved falco field|integer |
|falco.proc.pvpid|Preserved falco field|integer |
|falco.proc.sid|Preserved falco field|integer |
|falco.proc.sname|Preserved falco field|integer |
|falco.proc.sid.exepath|Preserved falco|integer |
|falco.proc.vpgid|Preserved falco field|text |
|falco.proc.vpgid.name|Preserved falco field|text |
|falco.proc.vpgid.exepath|Preserved falco field|integer |
|falco.proc.duration|Preserved falco field|text |
|falco.proct.ppid.duration|Preserved falco field|text |
|falco.proc.pid.ts|Preserved falco field|text |
|falco.proc.ppid.ts|Preserved falco field|text |
|falco.proc.is_sid_leader|Preserved falco field|text |
|falco.proc.is_vpgid_leader|Preserved falco field|text |
|falco.thread.cap_permitted|Preserved falco field|boolean |
|falco.thread.cap_effective|Preserved falco field|boolean |
|falco.thread.tid|Preserved falco field|text |
|falco.user.uid|Preserved falco field|text |
|falco.user.name|Preserved falco field|integer |
|falco.group.gid|Preserved falco field|integer |
|falco.group.name|Preserved falco field|text |
|falco.container.image|Preserved falco field|integer |
|falco.container.type|Preserved falco fielde|text |
|falco.container.privileged|Preserved falco field|text |
|falco.container.image.digest|Preserved falco field|text |
|falco.container.ip|Preserved falco field|boolean |
|falco.fd.directory|Preserved falco field|text |
|falco.fd.filename|Preserved falco field|text |
|falco.fd.cip|Preserved falco field|text |
|falco.fd.sip|Preserved falco field|text |
|falco.fd.lip|Preserved falco field|ip |
|falco.fd.rip|Preserved falco field|ip |
|falco.fd.cport|Preserved falco field|ip |
|falco.fd.sport|Preserved falco field|ip |
|falco.fd.lport|Preserved falco field|text |
|falco.fd.rport|Preserved falco field|text |
|falco.fd.cip.name|Preserved falco field|text |
|falco.fd.sip.name|Preserved falco field|text |
|falco.fd.lip.name|Preserved falco field|text |
|falco.fd.rip.name|Preserved falco field|text |
|falco.fd.ino|Preserved falco field|text |
|falco.syslog.facility.str|Preserved falco field|text |
|falco.syslog.facility|Preserved falco field|text |
|falco.syslog.severity.str|Preserved falco field|text |
|falco.syslog.severity|Preserved falco field|text |
|falco.k8s.ns.name|Preserved falco field|text |
|falco.k8s.pod.name|Preserved falco field|text |
|falco.k8s.pod.uid|Preserved falco field|text |
|falco.k8s.pod.labels|Preserved falco field|text |
|falco.k8s.pod.ip|Preserved falco field|text |
|falco.evt.args|Preserved falco field|text |
|falco.evt.category|Preserved falco field|text |
|falco.evt.dir|Preserved falco field|text |
|falco.evt.info|Preserved falco field|text |
|falco.evt.latency|Preserved falco field|text |
|falco.evt.plugininfo|Preserved falco field|text |
|falco.evt.pluginname|Preserved falco field|float |
|falco.evt.res|Preserved falco field|text |
|falco.evt.type|Required field for integration|text |
|falco.observer.product|Required field for integration|text |
|falco.observer.type|Required field for integration|text |
|falco.observer.vendor|Required field for integration|text |
|falco.hostname|Required field for integration|text |
|falco.input.type|Required field for integration|text |
|falco.log.source.address|Required field for integration|keyword |
|falco.message|Required field for integration|keyword |
|falco.process.program|Required field for integration|text |
|falco.syslog.facility_label|Required field for integration|text |
|falco.syslog.priority|Required field for integration|keyword |
|falco.syslog.severity_label|Required field for integration|text |

## Requirements

This integration is compatible with Falco version 0.37 and above, and should not be expected to perform successfully in lower versions. The system will only receive fields output by Falco's rules. If a rule does not include a desired field the rule must be edited in falco to add the field.

## Setup
Use the falco integration to connect to your Falco account and collect data from multiple machines / hosts. When you configure the integration, you can collect data from as many hosts or machines as you need.

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

