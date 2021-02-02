# Elastic Agent Integration

The Elastic Agent Integration allow you to monitor your Elastic Agents.

The default datasets are `elastic_agent`.

## Metrics

### Core

**Exported fields**

| Field                   | Description                                                                                                                                                                                                        | Type                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------- |
| @timestamp              | Event timestamp.                                                                                                                                                                                                   | date                                                    |
| cloud.account.id        | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier.                                 | keyword                                                 |
| cloud.availability_zone | Availability zone in which this host is running.                                                                                                                                                                   | keyword                                                 |
| cloud.image.id          | Image ID for the cloud instance.                                                                                                                                                                                   | keyword                                                 |
| cloud.instance.id       | Instance ID of the host machine.                                                                                                                                                                                   | keyword                                                 |
| cloud.instance.name     | Instance name of the host machine.                                                                                                                                                                                 | keyword                                                 |
| cloud.machine.type      | Machine type of the host machine.                                                                                                                                                                                  | keyword                                                 |
| cloud.project.id        | Name of the project in Google Cloud.                                                                                                                                                                               | keyword                                                 |
| cloud.provider          | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean.                                                                                                                                   | keyword                                                 |
| cloud.region            | Region in which this host is running.                                                                                                                                                                              | keyword                                                 |
| container.id            | Unique container id.                                                                                                                                                                                               | keyword                                                 |
| container.image.name    | Name of the image the container was built on.                                                                                                                                                                      | keyword                                                 |
| container.labels        | Image labels.                                                                                                                                                                                                      | object                                                  |
| container.name          | Container name.                                                                                                                                                                                                    | keyword                                                 |
| data_stream.dataset     | Data stream dataset.                                                                                                                                                                                               | constant_keyword                                        |
| data_stream.namespace   | Data stream namespace.                                                                                                                                                                                             | constant_keyword                                        |
| data_stream.type        | Data stream type.                                                                                                                                                                                                  | constant_keyword                                        |
| host.architecture       | Operating system architecture.                                                                                                                                                                                     | keyword                                                 |
| host.containerized      | If the host is a container.                                                                                                                                                                                        | boolean                                                 |
| host.domain             | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword                                                 |
| host.hostname           | Hostname of the host. It normally contains what the `hostname` command returns on the host machine.                                                                                                                | keyword                                                 |
| host.id                 | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`.                                                                   | keyword                                                 |
| host.ip                 | Host ip address.                                                                                                                                                                                                   | ip                                                      |
| host.mac                | Host mac address.                                                                                                                                                                                                  | keyword                                                 |
| host.name               | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use.                                 | keyword                                                 |
| host.os.build           | OS build information.                                                                                                                                                                                              | keyword                                                 |
| host.os.codename        | OS codename, if any.                                                                                                                                                                                               | keyword                                                 |
| host.os.family          | OS family (such as redhat, debian, freebsd, windows).                                                                                                                                                              | keyword                                                 |
| host.os.full            | Operating system name, including the version or code name.                                                                                                                                                         | keyword                                                 |
| host.os.kernel          | Operating system kernel version as a raw string.                                                                                                                                                                   | keyword                                                 |
| host.os.name            | Operating system name, without the version.                                                                                                                                                                        | keyword                                                 |
| host.os.platform        | Operating system platform (such centos, ubuntu, windows).                                                                                                                                                          | keyword                                                 |
| host.os.version         | Operating system version as a raw string.                                                                                                                                                                          | keyword                                                 |
| host.type               | Type of host.                                                                                                                                                                                                      | keyword                                                 |
| elastic_agent.id        |                                                                                                                                                                                                                    | Elastic agent id.                                       |
| elastic_agent.process   |                                                                                                                                                                                                                    | Elastic agent process (elastic-agent, metricbeat, ...). |
| elastic_agent.version   |                                                                                                                                                                                                                    | Elastic version as a raw string.                        |

### Process

The Elastic Agent `process` dataset provides process statistics about Elastic Agent processes. One document is
provided for each process.

| Field | Description | Type |
| ----- | ----------- | ---- |

| system.process.cpu.system.ticks | The amount of CPU time the process spent in kernel space. | long |
| system.process.cpu.system.time.me | The time when the process was started. | date |
| system.process.cpu.total.ticks | The total CPU time spent by the process. | long |
| system.process.cpu.total.value | The value of CPU usage since starting the process. | long |
| system.process.cpu.total.time.me | The time when the process was started. | date |
| system.process.cpu.user.ticks | The amount of CPU time the process spent in user space. | long |
| system.process.cpu.user.time.me | The time when the process was started. | date |
| system.process.env | The environment variables used to start the process. The data is available on FreeBSD, Linux, and OS X. | object |
| system.process.fd.limit.soft | The soft limit on the number of file descriptors opened by the process. The soft limit can be changed by the process at any time. | long |
| system.process.fd.open | The number of file descriptors open by the process. | long |
| system.process.memory.size | The total virtual memory the process has. On Windows this represents the Commit Charge (the total amount of memory that the memory manager has committed for a running process) value in bytes for this process. | long |
| system.process.cgroup.blkio.id | ID of the cgroup. | keyword |
| system.process.cgroup.blkio.path | Path to the cgroup relative to the cgroup subsystems mountpoint. | keyword |
| system.process.cgroup.blkio.total.bytes | Total number of bytes transferred to and from all block devices by processes in the cgroup. | long |
| system.process.cgroup.blkio.total.ios | Total number of I/O operations performed on all devices by processes in the cgroup as seen by the throttling policy. | long |
| system.process.cgroup.cpu.cfs.period.us | Period of time in microseconds for how regularly a cgroup's access to CPU resources should be reallocated. | long |
| system.process.cgroup.cpu.cfs.quota.us | Total amount of time in microseconds for which all tasks in a cgroup can run during one period (as defined by cfs.period.us). | long |
| system.process.cgroup.cpu.cfs.shares | An integer value that specifies a relative share of CPU time available to the tasks in a cgroup. The value specified in the cpu.shares file must be 2 or higher. | long |
| system.process.cgroup.cpu.id | ID of the cgroup. | keyword |
| system.process.cgroup.cpu.path | Path to the cgroup relative to the cgroup subsystem's mountpoint. | keyword |
| system.process.cgroup.cpu.rt.period.us | Period of time in microseconds for how regularly a cgroup's access to CPU resources is reallocated. | long |
| system.process.cgroup.cpu.rt.runtime.us | Period of time in microseconds for the longest continuous period in which the tasks in a cgroup have access to CPU resources. | long |
| system.process.cgroup.cpu.stats.periods | Number of period intervals (as specified in cpu.cfs.period.us) that have elapsed. | long |
| system.process.cgroup.cpu.stats.throttled.ns | The total time duration (in nanoseconds) for which tasks in a cgroup have been throttled. | long |
| system.process.cgroup.cpu.stats.throttled.periods | Number of times tasks in a cgroup have been throttled (that is, not allowed to run because they have exhausted all of the available time as specified by their quota). | long |
| system.process.cgroup.cpuacct.id | ID of the cgroup. | keyword |
| system.process.cgroup.cpuacct.path | Path to the cgroup relative to the cgroup subsystem's mountpoint. | keyword |
| system.process.cgroup.cpuacct.percpu | CPU time (in nanoseconds) consumed on each CPU by all tasks in this cgroup. | object |
| system.process.cgroup.cpuacct.stats.system.ns | CPU time consumed by tasks in user (kernel) mode. | long |
| system.process.cgroup.cpuacct.stats.user.ns | CPU time consumed by tasks in user mode. | long |
| system.process.cgroup.cpuacct.total.ns | Total CPU time in nanoseconds consumed by all tasks in the cgroup. | long |
| system.process.cgroup.id | The ID common to all cgroups associated with this task. If there isn't a common ID used by all cgroups this field will be absent. | keyword |
| system.process.cgroup.memory.id | ID of the cgroup. | keyword |
| system.process.cgroup.memory.kmem.failures | The number of times that the memory limit (kmem.limit.bytes) was reached. | long |
| system.process.cgroup.memory.kmem.limit.bytes | The maximum amount of kernel memory that tasks in the cgroup are allowed to use. | long |
| system.process.cgroup.memory.kmem.usage.bytes | Total kernel memory usage by processes in the cgroup (in bytes). | long |
| system.process.cgroup.memory.kmem.usage.max.bytes | The maximum kernel memory used by processes in the cgroup (in bytes). | long |
| system.process.cgroup.memory.kmem_tcp.failures | The number of times that the memory limit (kmem_tcp.limit.bytes) was reached. | long |
| system.process.cgroup.memory.kmem_tcp.limit.bytes | The maximum amount of memory for TCP buffers that tasks in the cgroup are allowed to use. | long |
| system.process.cgroup.memory.kmem_tcp.usage.bytes | Total memory usage for TCP buffers in bytes. | long |
| system.process.cgroup.memory.kmem_tcp.usage.max.bytes | The maximum memory used for TCP buffers by processes in the cgroup (in bytes). | long |
| system.process.cgroup.memory.mem.failures | The number of times that the memory limit (mem.limit.bytes) was reached. | long |
| system.process.cgroup.memory.mem.limit.bytes | The maximum amount of user memory in bytes (including file cache) that tasks in the cgroup are allowed to use. | long |
| system.process.cgroup.memory.mem.usage.bytes | Total memory usage by processes in the cgroup (in bytes). | long |
| system.process.cgroup.memory.mem.usage.max.bytes | The maximum memory used by processes in the cgroup (in bytes). | long |
| system.process.cgroup.memory.memsw.failures | The number of times that the memory plus swap space limit (memsw.limit.bytes) was reached. | long |
| system.process.cgroup.memory.memsw.limit.bytes | The maximum amount for the sum of memory and swap usage that tasks in the cgroup are allowed to use. | long |
| system.process.cgroup.memory.memsw.usage.bytes | The sum of current memory usage plus swap space used by processes in the cgroup (in bytes). | long |
| system.process.cgroup.memory.memsw.usage.max.bytes | The maximum amount of memory and swap space used by processes in the cgroup (in bytes). | long |
| system.process.cgroup.memory.path | Path to the cgroup relative to the cgroup subsystem's mountpoint. | keyword |
| system.process.cgroup.memory.stats.active_anon.bytes | Anonymous and swap cache on active least-recently-used (LRU) list, including tmpfs (shmem), in bytes. | long |
| system.process.cgroup.memory.stats.active_file.bytes | File-backed memory on active LRU list, in bytes. | long |
| system.process.cgroup.memory.stats.cache.bytes | Page cache, including tmpfs (shmem), in bytes. | long |
| system.process.cgroup.memory.stats.hierarchical_memory_limit.bytes | Memory limit for the hierarchy that contains the memory cgroup, in bytes. | long |
| system.process.cgroup.memory.stats.hierarchical_memsw_limit.bytes | Memory plus swap limit for the hierarchy that contains the memory cgroup, in bytes. | long |
| system.process.cgroup.memory.stats.inactive_anon.bytes | Anonymous and swap cache on inactive LRU list, including tmpfs (shmem), in bytes | long |
| system.process.cgroup.memory.stats.inactive_file.bytes | File-backed memory on inactive LRU list, in bytes. | long |
| system.process.cgroup.memory.stats.major_page_faults | Number of times that a process in the cgroup triggered a major fault. "Major" faults happen when the kernel actually has to read the data from disk. | long |
| system.process.cgroup.memory.stats.mapped_file.bytes | Size of memory-mapped mapped files, including tmpfs (shmem), in bytes. | long |
| system.process.cgroup.memory.stats.page_faults | Number of times that a process in the cgroup triggered a page fault. | long |
| system.process.cgroup.memory.stats.pages_in | Number of pages paged into memory. This is a counter. | long |
| system.process.cgroup.memory.stats.pages_out | Number of pages paged out of memory. This is a counter. | long |
| system.process.cgroup.memory.stats.rss.bytes | Anonymous and swap cache (includes transparent hugepages), not including tmpfs (shmem), in bytes. | long |
| system.process.cgroup.memory.stats.rss_huge.bytes | Number of bytes of anonymous transparent hugepages. | long |
| system.process.cgroup.memory.stats.swap.bytes | Swap usage, in bytes. | long |
| system.process.cgroup.memory.stats.unevictable.bytes | Memory that cannot be reclaimed, in bytes. | long |
| system.process.cgroup.path | The path to the cgroup relative to the cgroup subsystem's mountpoint. If there isn't a common path used by all cgroups this field will be absent. | keyword |
