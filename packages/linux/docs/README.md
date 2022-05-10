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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| system.entropy.available_bits | The available bits of entropy | long |
| system.entropy.pct | The percentage of available entropy, relative to the pool size of 4096 | scaled_float |


### Network summary

The linux `network_summary` data stream provides network IO metrics collected from the
operating system. These events are global and sorted by protocol.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| system.network_summary.icmp.\* | ICMP counters | object |
| system.network_summary.ip.\* | IP counters | object |
| system.network_summary.tcp.\* | TCP counters | object |
| system.network_summary.udp.\* | UDP counters | object |
| system.network_summary.udp_lite.\* | UDP Lite counters | object |


### RAID

This is the raid data stream of the module system. It collects stats about the raid.

This data stream is available on:

- Linux

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| system.raid.blocks.synced | Number of blocks on the device that are in sync, in 1024-byte blocks. | long |
| system.raid.blocks.total | Number of blocks the device holds, in 1024-byte blocks. | long |
| system.raid.disks.active | Number of active disks. | long |
| system.raid.disks.failed | Number of failed disks. | long |
| system.raid.disks.spare | Number of spared disks. | long |
| system.raid.disks.states.\* | map of raw disk states | object |
| system.raid.disks.total | Total number of disks the device consists of. | long |
| system.raid.level | The raid level of the device | keyword |
| system.raid.name | Name of the device. | keyword |
| system.raid.status | activity-state of the device. | keyword |
| system.raid.sync_action | Current sync action, if the RAID array is redundant | keyword |


### Service

The `service` data stream reports on the status of systemd services.

This data stream is available on:

- Linux

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.cpu.usage | Percent CPU used which is normalized by the number of CPU cores and it ranges from 0 to 1. Scaling factor: 1000. For example: For a two core host, this value should be the average of the two cores, between 0 and 1. | scaled_float |
| host.disk.read.bytes | The total number of bytes (gauge) read successfully (aggregated from all disks) since the last metric collection. | long |
| host.disk.write.bytes | The total number of bytes (gauge) written successfully (aggregated from all disks) since the last metric collection. | long |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.geo.city_name | City name. | keyword |
| host.geo.continent_code | Two-letter code representing continent's name. | keyword |
| host.geo.continent_name | Name of the continent. | keyword |
| host.geo.country_iso_code | Country ISO code. | keyword |
| host.geo.country_name | Country name. | keyword |
| host.geo.location | Longitude and latitude. | geo_point |
| host.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| host.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| host.geo.region_iso_code | Region ISO code. | keyword |
| host.geo.region_name | Region name. | keyword |
| host.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.network.egress.bytes | The number of bytes (gauge) sent out on all network interfaces by the host since the last metric collection. | long |
| host.network.egress.packets | The number of packets (gauge) sent out on all network interfaces by the host since the last metric collection. | long |
| host.network.ingress.bytes | The number of bytes received (gauge) on all network interfaces by the host since the last metric collection. | long |
| host.network.ingress.packets | The number of packets (gauge) received on all network interfaces by the host since the last metric collection. | long |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.full.text | Multi-field of `host.os.full`. | match_only_text |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. One of these following values should be used (lowercase): linux, macos, unix, windows. If the OS you're dealing with is not in the list, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| host.uptime | Seconds the host has been up. | long |
| host.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| host.user.email | User email address. | keyword |
| host.user.full_name | User's full name, if available. | keyword |
| host.user.full_name.text | Multi-field of `host.user.full_name`. | match_only_text |
| host.user.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| host.user.group.id | Unique identifier for the group on the system/platform. | keyword |
| host.user.group.name | Name of the group. | keyword |
| host.user.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| host.user.id | Unique identifier of the user. | keyword |
| host.user.name | Short name or login of the user. | keyword |
| host.user.name.text | Multi-field of `host.user.name`. | match_only_text |
| host.user.roles | Array of user roles at the time of the event. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.code_signature.digest_algorithm | The hashing algorithm used to sign the process. This value can distinguish signatures when a file is signed multiple times by the same signer but with a different digest algorithm. | keyword |
| process.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| process.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.code_signature.subject_name | Subject name of the code signer | keyword |
| process.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.code_signature.timestamp | Date and time when the code signature was generated and signed. | date |
| process.code_signature.trusted | Stores the trust status of the certificate chain. Validating the trust of the certificate chain may be complicated, and this field should only be populated by tools that actively check the status. | boolean |
| process.code_signature.valid | Boolean to capture if the digital signature is verified against the binary content. Leave unpopulated if a certificate was unchecked. | boolean |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.elf.architecture | Machine architecture of the ELF file. | keyword |
| process.elf.byte_order | Byte sequence of ELF file. | keyword |
| process.elf.cpu_type | CPU type of the ELF file. | keyword |
| process.elf.creation_date | Extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. | date |
| process.elf.exports | List of exported element names and types. | flattened |
| process.elf.header.abi_version | Version of the ELF Application Binary Interface (ABI). | keyword |
| process.elf.header.class | Header class of the ELF file. | keyword |
| process.elf.header.data | Data table of the ELF header. | keyword |
| process.elf.header.entrypoint | Header entrypoint of the ELF file. | long |
| process.elf.header.object_version | "0x1" for original ELF files. | keyword |
| process.elf.header.os_abi | Application Binary Interface (ABI) of the Linux OS. | keyword |
| process.elf.header.type | Header type of the ELF file. | keyword |
| process.elf.header.version | Version of the ELF header. | keyword |
| process.elf.imports | List of imported element names and types. | flattened |
| process.elf.sections | An array containing an object for each section of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.sections.\*`. | nested |
| process.elf.sections.chi2 | Chi-square probability distribution of the section. | long |
| process.elf.sections.entropy | Shannon entropy calculation from the section. | long |
| process.elf.sections.flags | ELF Section List flags. | keyword |
| process.elf.sections.name | ELF Section List name. | keyword |
| process.elf.sections.physical_offset | ELF Section List offset. | keyword |
| process.elf.sections.physical_size | ELF Section List physical size. | long |
| process.elf.sections.type | ELF Section List type. | keyword |
| process.elf.sections.virtual_address | ELF Section List virtual address. | long |
| process.elf.sections.virtual_size | ELF Section List virtual size. | long |
| process.elf.segments | An array containing an object for each segment of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.segments.\*`. | nested |
| process.elf.segments.sections | ELF object segment sections. | keyword |
| process.elf.segments.type | ELF object segment type. | keyword |
| process.elf.shared_libraries | List of shared libraries used by this ELF object. | keyword |
| process.elf.telfhash | telfhash symbol hash for ELF file. | keyword |
| process.end | The time the process ended. | date |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.hash.sha512 | SHA512 hash. | keyword |
| process.hash.ssdeep | SSDEEP hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.parent.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.parent.code_signature.digest_algorithm | The hashing algorithm used to sign the process. This value can distinguish signatures when a file is signed multiple times by the same signer but with a different digest algorithm. | keyword |
| process.parent.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| process.parent.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.parent.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.parent.code_signature.subject_name | Subject name of the code signer | keyword |
| process.parent.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.parent.code_signature.timestamp | Date and time when the code signature was generated and signed. | date |
| process.parent.code_signature.trusted | Stores the trust status of the certificate chain. Validating the trust of the certificate chain may be complicated, and this field should only be populated by tools that actively check the status. | boolean |
| process.parent.code_signature.valid | Boolean to capture if the digital signature is verified against the binary content. Leave unpopulated if a certificate was unchecked. | boolean |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.elf.architecture | Machine architecture of the ELF file. | keyword |
| process.parent.elf.byte_order | Byte sequence of ELF file. | keyword |
| process.parent.elf.cpu_type | CPU type of the ELF file. | keyword |
| process.parent.elf.creation_date | Extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. | date |
| process.parent.elf.exports | List of exported element names and types. | flattened |
| process.parent.elf.header.abi_version | Version of the ELF Application Binary Interface (ABI). | keyword |
| process.parent.elf.header.class | Header class of the ELF file. | keyword |
| process.parent.elf.header.data | Data table of the ELF header. | keyword |
| process.parent.elf.header.entrypoint | Header entrypoint of the ELF file. | long |
| process.parent.elf.header.object_version | "0x1" for original ELF files. | keyword |
| process.parent.elf.header.os_abi | Application Binary Interface (ABI) of the Linux OS. | keyword |
| process.parent.elf.header.type | Header type of the ELF file. | keyword |
| process.parent.elf.header.version | Version of the ELF header. | keyword |
| process.parent.elf.imports | List of imported element names and types. | flattened |
| process.parent.elf.sections | An array containing an object for each section of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.sections.\*`. | nested |
| process.parent.elf.sections.chi2 | Chi-square probability distribution of the section. | long |
| process.parent.elf.sections.entropy | Shannon entropy calculation from the section. | long |
| process.parent.elf.sections.flags | ELF Section List flags. | keyword |
| process.parent.elf.sections.name | ELF Section List name. | keyword |
| process.parent.elf.sections.physical_offset | ELF Section List offset. | keyword |
| process.parent.elf.sections.physical_size | ELF Section List physical size. | long |
| process.parent.elf.sections.type | ELF Section List type. | keyword |
| process.parent.elf.sections.virtual_address | ELF Section List virtual address. | long |
| process.parent.elf.sections.virtual_size | ELF Section List virtual size. | long |
| process.parent.elf.segments | An array containing an object for each segment of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.segments.\*`. | nested |
| process.parent.elf.segments.sections | ELF object segment sections. | keyword |
| process.parent.elf.segments.type | ELF object segment type. | keyword |
| process.parent.elf.shared_libraries | List of shared libraries used by this ELF object. | keyword |
| process.parent.elf.telfhash | telfhash symbol hash for ELF file. | keyword |
| process.parent.end | The time the process ended. | date |
| process.parent.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.parent.hash.md5 | MD5 hash. | keyword |
| process.parent.hash.sha1 | SHA1 hash. | keyword |
| process.parent.hash.sha256 | SHA256 hash. | keyword |
| process.parent.hash.sha512 | SHA512 hash. | keyword |
| process.parent.hash.ssdeep | SSDEEP hash. | keyword |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pe.architecture | CPU architecture target for the file. | keyword |
| process.parent.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| process.parent.pe.description | Internal description of the file, provided at compile-time. | keyword |
| process.parent.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| process.parent.pe.imphash | A hash of the imports in a PE file. An imphash -- or import hash -- can be used to fingerprint binaries even after recompilation or other code-level transformations have occurred, which would change more traditional hash values. Learn more at https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html. | keyword |
| process.parent.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| process.parent.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| process.parent.pgid | Identifier of the group of processes the process belongs to. | long |
| process.parent.pid | Process id. | long |
| process.parent.ppid | Parent process' pid. | long |
| process.parent.start | The time the process started. | date |
| process.parent.thread.id | Thread ID. | long |
| process.parent.thread.name | Thread name. | keyword |
| process.parent.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.parent.title.text | Multi-field of `process.parent.title`. | match_only_text |
| process.parent.uptime | Seconds the process has been up. | long |
| process.parent.working_directory | The working directory of the process. | keyword |
| process.parent.working_directory.text | Multi-field of `process.parent.working_directory`. | match_only_text |
| process.pe.architecture | CPU architecture target for the file. | keyword |
| process.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| process.pe.description | Internal description of the file, provided at compile-time. | keyword |
| process.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| process.pe.imphash | A hash of the imports in a PE file. An imphash -- or import hash -- can be used to fingerprint binaries even after recompilation or other code-level transformations have occurred, which would change more traditional hash values. Learn more at https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html. | keyword |
| process.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| process.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| process.pgid | Identifier of the group of processes the process belongs to. | long |
| process.pid | Process id. | long |
| process.ppid | Parent process' pid. | long |
| process.start | The time the process started. | date |
| process.thread.id | Thread ID. | long |
| process.thread.name | Thread name. | keyword |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| process.uptime | Seconds the process has been up. | long |
| process.working_directory | The working directory of the process. | keyword |
| process.working_directory.text | Multi-field of `process.working_directory`. | match_only_text |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
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
| systemd.fragment_path | Service file location | keyword |
| systemd.unit | Service unit name | keyword |
| user.changes.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.changes.email | User email address. | keyword |
| user.changes.full_name | User's full name, if available. | keyword |
| user.changes.full_name.text | Multi-field of `user.changes.full_name`. | match_only_text |
| user.changes.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.changes.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.changes.group.name | Name of the group. | keyword |
| user.changes.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| user.changes.id | Unique identifier of the user. | keyword |
| user.changes.name | Short name or login of the user. | keyword |
| user.changes.name.text | Multi-field of `user.changes.name`. | match_only_text |
| user.changes.roles | Array of user roles at the time of the event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.effective.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.effective.email | User email address. | keyword |
| user.effective.full_name | User's full name, if available. | keyword |
| user.effective.full_name.text | Multi-field of `user.effective.full_name`. | match_only_text |
| user.effective.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.effective.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.effective.group.name | Name of the group. | keyword |
| user.effective.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| user.effective.id | Unique identifier of the user. | keyword |
| user.effective.name | Short name or login of the user. | keyword |
| user.effective.name.text | Multi-field of `user.effective.name`. | match_only_text |
| user.effective.roles | Array of user roles at the time of the event. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.group.name | Name of the group. | keyword |
| user.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.roles | Array of user roles at the time of the event. | keyword |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.full_name | User's full name, if available. | keyword |
| user.target.full_name.text | Multi-field of `user.target.full_name`. | match_only_text |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |
| user.target.roles | Array of user roles at the time of the event. | keyword |


### Socket

This data stream requires kernel 2.6.14 or newer.

The Linux `socket` data stream reports an event for each new TCP socket that it
sees. It does this by polling the kernel periodically to get a dump of all
sockets. You set the polling interval by configuring the `period` option.
Specifying a short polling interval with this data stream is important to avoid
missing short-lived connections.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| network.application | A name given to an application level protocol. This can be arbitrarily assigned for things like microservices, but also apply to things like skype, icq, facebook, twitter. This would be used in situations where the vendor or service can be decoded such as from the source/dest IP owners, ports, or wire format. The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.inner | Network.inner fields are added in addition to network.vlan fields to describe the innermost VLAN when q-in-q VLAN tagging is present. Allowed fields include vlan.id and vlan.name. Inner vlan fields are typically used when sending traffic with multiple 802.1q encapsulations to a network sensor (e.g. Zeek, Wireshark.) | object |
| network.inner.vlan.id | VLAN ID as reported by the observer. | keyword |
| network.inner.vlan.name | Optional VLAN name as reported by the observer. | keyword |
| network.name | Name given by operators to sections of their network. | keyword |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.protocol | L7 Network protocol name. ex. http, lumberjack, transport protocol. The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.vlan.id | VLAN ID as reported by the observer. | keyword |
| network.vlan.name | Optional VLAN name as reported by the observer. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.code_signature.digest_algorithm | The hashing algorithm used to sign the process. This value can distinguish signatures when a file is signed multiple times by the same signer but with a different digest algorithm. | keyword |
| process.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| process.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.code_signature.subject_name | Subject name of the code signer | keyword |
| process.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.code_signature.timestamp | Date and time when the code signature was generated and signed. | date |
| process.code_signature.trusted | Stores the trust status of the certificate chain. Validating the trust of the certificate chain may be complicated, and this field should only be populated by tools that actively check the status. | boolean |
| process.code_signature.valid | Boolean to capture if the digital signature is verified against the binary content. Leave unpopulated if a certificate was unchecked. | boolean |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.elf.architecture | Machine architecture of the ELF file. | keyword |
| process.elf.byte_order | Byte sequence of ELF file. | keyword |
| process.elf.cpu_type | CPU type of the ELF file. | keyword |
| process.elf.creation_date | Extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. | date |
| process.elf.exports | List of exported element names and types. | flattened |
| process.elf.header.abi_version | Version of the ELF Application Binary Interface (ABI). | keyword |
| process.elf.header.class | Header class of the ELF file. | keyword |
| process.elf.header.data | Data table of the ELF header. | keyword |
| process.elf.header.entrypoint | Header entrypoint of the ELF file. | long |
| process.elf.header.object_version | "0x1" for original ELF files. | keyword |
| process.elf.header.os_abi | Application Binary Interface (ABI) of the Linux OS. | keyword |
| process.elf.header.type | Header type of the ELF file. | keyword |
| process.elf.header.version | Version of the ELF header. | keyword |
| process.elf.imports | List of imported element names and types. | flattened |
| process.elf.sections | An array containing an object for each section of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.sections.\*`. | nested |
| process.elf.sections.chi2 | Chi-square probability distribution of the section. | long |
| process.elf.sections.entropy | Shannon entropy calculation from the section. | long |
| process.elf.sections.flags | ELF Section List flags. | keyword |
| process.elf.sections.name | ELF Section List name. | keyword |
| process.elf.sections.physical_offset | ELF Section List offset. | keyword |
| process.elf.sections.physical_size | ELF Section List physical size. | long |
| process.elf.sections.type | ELF Section List type. | keyword |
| process.elf.sections.virtual_address | ELF Section List virtual address. | long |
| process.elf.sections.virtual_size | ELF Section List virtual size. | long |
| process.elf.segments | An array containing an object for each segment of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.segments.\*`. | nested |
| process.elf.segments.sections | ELF object segment sections. | keyword |
| process.elf.segments.type | ELF object segment type. | keyword |
| process.elf.shared_libraries | List of shared libraries used by this ELF object. | keyword |
| process.elf.telfhash | telfhash symbol hash for ELF file. | keyword |
| process.end | The time the process ended. | date |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.hash.sha512 | SHA512 hash. | keyword |
| process.hash.ssdeep | SSDEEP hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.parent.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.parent.code_signature.digest_algorithm | The hashing algorithm used to sign the process. This value can distinguish signatures when a file is signed multiple times by the same signer but with a different digest algorithm. | keyword |
| process.parent.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| process.parent.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.parent.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.parent.code_signature.subject_name | Subject name of the code signer | keyword |
| process.parent.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.parent.code_signature.timestamp | Date and time when the code signature was generated and signed. | date |
| process.parent.code_signature.trusted | Stores the trust status of the certificate chain. Validating the trust of the certificate chain may be complicated, and this field should only be populated by tools that actively check the status. | boolean |
| process.parent.code_signature.valid | Boolean to capture if the digital signature is verified against the binary content. Leave unpopulated if a certificate was unchecked. | boolean |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.elf.architecture | Machine architecture of the ELF file. | keyword |
| process.parent.elf.byte_order | Byte sequence of ELF file. | keyword |
| process.parent.elf.cpu_type | CPU type of the ELF file. | keyword |
| process.parent.elf.creation_date | Extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. | date |
| process.parent.elf.exports | List of exported element names and types. | flattened |
| process.parent.elf.header.abi_version | Version of the ELF Application Binary Interface (ABI). | keyword |
| process.parent.elf.header.class | Header class of the ELF file. | keyword |
| process.parent.elf.header.data | Data table of the ELF header. | keyword |
| process.parent.elf.header.entrypoint | Header entrypoint of the ELF file. | long |
| process.parent.elf.header.object_version | "0x1" for original ELF files. | keyword |
| process.parent.elf.header.os_abi | Application Binary Interface (ABI) of the Linux OS. | keyword |
| process.parent.elf.header.type | Header type of the ELF file. | keyword |
| process.parent.elf.header.version | Version of the ELF header. | keyword |
| process.parent.elf.imports | List of imported element names and types. | flattened |
| process.parent.elf.sections | An array containing an object for each section of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.sections.\*`. | nested |
| process.parent.elf.sections.chi2 | Chi-square probability distribution of the section. | long |
| process.parent.elf.sections.entropy | Shannon entropy calculation from the section. | long |
| process.parent.elf.sections.flags | ELF Section List flags. | keyword |
| process.parent.elf.sections.name | ELF Section List name. | keyword |
| process.parent.elf.sections.physical_offset | ELF Section List offset. | keyword |
| process.parent.elf.sections.physical_size | ELF Section List physical size. | long |
| process.parent.elf.sections.type | ELF Section List type. | keyword |
| process.parent.elf.sections.virtual_address | ELF Section List virtual address. | long |
| process.parent.elf.sections.virtual_size | ELF Section List virtual size. | long |
| process.parent.elf.segments | An array containing an object for each segment of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.segments.\*`. | nested |
| process.parent.elf.segments.sections | ELF object segment sections. | keyword |
| process.parent.elf.segments.type | ELF object segment type. | keyword |
| process.parent.elf.shared_libraries | List of shared libraries used by this ELF object. | keyword |
| process.parent.elf.telfhash | telfhash symbol hash for ELF file. | keyword |
| process.parent.end | The time the process ended. | date |
| process.parent.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.parent.hash.md5 | MD5 hash. | keyword |
| process.parent.hash.sha1 | SHA1 hash. | keyword |
| process.parent.hash.sha256 | SHA256 hash. | keyword |
| process.parent.hash.sha512 | SHA512 hash. | keyword |
| process.parent.hash.ssdeep | SSDEEP hash. | keyword |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pe.architecture | CPU architecture target for the file. | keyword |
| process.parent.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| process.parent.pe.description | Internal description of the file, provided at compile-time. | keyword |
| process.parent.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| process.parent.pe.imphash | A hash of the imports in a PE file. An imphash -- or import hash -- can be used to fingerprint binaries even after recompilation or other code-level transformations have occurred, which would change more traditional hash values. Learn more at https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html. | keyword |
| process.parent.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| process.parent.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| process.parent.pgid | Identifier of the group of processes the process belongs to. | long |
| process.parent.pid | Process id. | long |
| process.parent.ppid | Parent process' pid. | long |
| process.parent.start | The time the process started. | date |
| process.parent.thread.id | Thread ID. | long |
| process.parent.thread.name | Thread name. | keyword |
| process.parent.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.parent.title.text | Multi-field of `process.parent.title`. | match_only_text |
| process.parent.uptime | Seconds the process has been up. | long |
| process.parent.working_directory | The working directory of the process. | keyword |
| process.parent.working_directory.text | Multi-field of `process.parent.working_directory`. | match_only_text |
| process.pe.architecture | CPU architecture target for the file. | keyword |
| process.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| process.pe.description | Internal description of the file, provided at compile-time. | keyword |
| process.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| process.pe.imphash | A hash of the imports in a PE file. An imphash -- or import hash -- can be used to fingerprint binaries even after recompilation or other code-level transformations have occurred, which would change more traditional hash values. Learn more at https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html. | keyword |
| process.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| process.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| process.pgid | Identifier of the group of processes the process belongs to. | long |
| process.pid | Process id. | long |
| process.ppid | Parent process' pid. | long |
| process.start | The time the process started. | date |
| process.thread.id | Thread ID. | long |
| process.thread.name | Thread name. | keyword |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| process.uptime | Seconds the process has been up. | long |
| process.working_directory | The working directory of the process. | keyword |
| process.working_directory.text | Multi-field of `process.working_directory`. | match_only_text |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| system.socket.local.ip | Local IP address. This can be an IPv4 or IPv6 address. | ip |
| system.socket.local.port | Local port. | long |
| system.socket.process.cmdline | Full command line | keyword |
| system.socket.remote.etld_plus_one | The effective top-level domain (eTLD) of the remote host plus one more label. For example, the eTLD+1 for "foo.bar.golang.org." is "golang.org.". The data for determining the eTLD comes from an embedded copy of the data from http://publicsuffix.org. | keyword |
| system.socket.remote.host | PTR record associated with the remote IP. It is obtained via reverse IP lookup. | keyword |
| system.socket.remote.host_error | Error describing the cause of the reverse lookup failure. | keyword |
| system.socket.remote.ip | Remote IP address. This can be an IPv4 or IPv6 address. | ip |
| system.socket.remote.port | Remote port. | long |
| user.changes.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.changes.email | User email address. | keyword |
| user.changes.full_name | User's full name, if available. | keyword |
| user.changes.full_name.text | Multi-field of `user.changes.full_name`. | match_only_text |
| user.changes.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.changes.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.changes.group.name | Name of the group. | keyword |
| user.changes.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| user.changes.id | Unique identifier of the user. | keyword |
| user.changes.name | Short name or login of the user. | keyword |
| user.changes.name.text | Multi-field of `user.changes.name`. | match_only_text |
| user.changes.roles | Array of user roles at the time of the event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.effective.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.effective.email | User email address. | keyword |
| user.effective.full_name | User's full name, if available. | keyword |
| user.effective.full_name.text | Multi-field of `user.effective.full_name`. | match_only_text |
| user.effective.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.effective.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.effective.group.name | Name of the group. | keyword |
| user.effective.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| user.effective.id | Unique identifier of the user. | keyword |
| user.effective.name | Short name or login of the user. | keyword |
| user.effective.name.text | Multi-field of `user.effective.name`. | match_only_text |
| user.effective.roles | Array of user roles at the time of the event. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.group.name | Name of the group. | keyword |
| user.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.roles | Array of user roles at the time of the event. | keyword |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.email | User email address. | keyword |
| user.target.full_name | User's full name, if available. | keyword |
| user.target.full_name.text | Multi-field of `user.target.full_name`. | match_only_text |
| user.target.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.target.group.name | Name of the group. | keyword |
| user.target.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |
| user.target.roles | Array of user roles at the time of the event. | keyword |


### Users

The linux/users data stream reports logged in users and associated sessions via dbus and logind, which is a systemd component. By default, the data stream will look in `/var/run/dbus/` for a system socket, although a new path can be selected with `DBUS_SYSTEM_BUS_ADDRESS`.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | Source domain. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_code | Two-letter code representing continent's name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| source.registered_domain | The highest registered source domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| source.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| source.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.email | User email address. | keyword |
| source.user.full_name | User's full name, if available. | keyword |
| source.user.full_name.text | Multi-field of `source.user.full_name`. | match_only_text |
| source.user.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.group.id | Unique identifier for the group on the system/platform. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| source.user.roles | Array of user roles at the time of the event. | keyword |
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

