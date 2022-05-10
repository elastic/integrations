# Redis Integration

This integration periodically fetches logs and metrics from [Redis](https://redis.io/) servers.

## Compatibility

The `log` and `slowlog` datasets were tested with logs from Redis versions 1.2.6, 2.4.6, and 3.0.2, so we expect
compatibility with any version 1.x, 2.x, or 3.x.

The `info`, `key` and `keyspace` datasets were tested with Redis 3.2.12, 4.0.11 and 5.0-rc4, and are expected to work
with all versions `>= 3.0`.

## Logs

### log

The `log` dataset collects the Redis standard logs.

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
| error.message | Error message. | match_only_text |
| event.created | Date/time when the event was first read by an agent, or by your pipeline. | date |
| event.dataset | Event dataset | constant_keyword |
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
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.pid | Process id. | long |
| redis.log.role | The role of the Redis instance. Can be one of `master`, `slave`, `child` (for RDF/AOF writing child), or `sentinel`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### slowlog

The `slowlog` dataset collects the Redis slow logs.

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
| error.message | Error message. | match_only_text |
| event.created | Date/time when the event was first read by an agent, or by your pipeline. | date |
| event.dataset | Event dataset | constant_keyword |
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
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.pid | Process id. | long |
| redis.log.role | The role of the Redis instance. Can be one of `master`, `slave`, `child` (for RDF/AOF writing child), or `sentinel`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

### info

The `info` dataset collects information and statistics from Redis by running the `INFO` command and parsing the returned
result.

An example event for `info` looks as following:

```json
{
    "@timestamp": "2020-06-25T10:16:10.138Z",
    "redis": {
        "info": {
            "clients": {
                "biggest_input_buf": 0,
                "blocked": 0,
                "connected": 5,
                "longest_output_list": 0,
                "max_input_buffer": 0,
                "max_output_buffer": 0
            },
            "cluster": {
                "enabled": false
            },
            "cpu": {
                "used": {
                    "sys": 1.66,
                    "sys_children": 0,
                    "user": 0.39,
                    "user_children": 0.01
                }
            },
            "memory": {
                "active_defrag": {},
                "allocator": "jemalloc-4.0.3",
                "allocator_stats": {
                    "fragmentation": {},
                    "rss": {}
                },
                "fragmentation": {
                    "ratio": 2.71
                },
                "max": {
                    "policy": "noeviction",
                    "value": 0
                },
                "used": {
                    "lua": 37888,
                    "peak": 945016,
                    "rss": 2453504,
                    "value": 904992
                }
            },
            "persistence": {
                "aof": {
                    "bgrewrite": {
                        "last_status": "ok"
                    },
                    "buffer": {},
                    "copy_on_write": {},
                    "enabled": false,
                    "fsync": {},
                    "rewrite": {
                        "buffer": {},
                        "current_time": {
                            "sec": -1
                        },
                        "in_progress": false,
                        "last_time": {
                            "sec": -1
                        },
                        "scheduled": false
                    },
                    "size": {},
                    "write": {
                        "last_status": "ok"
                    }
                },
                "loading": false,
                "rdb": {
                    "bgsave": {
                        "current_time": {
                            "sec": -1
                        },
                        "in_progress": false,
                        "last_status": "ok",
                        "last_time": {
                            "sec": -1
                        }
                    },
                    "copy_on_write": {},
                    "last_save": {
                        "changes_since": 35,
                        "time": 1548663522
                    }
                }
            },
            "replication": {
                "backlog": {
                    "active": 0,
                    "first_byte_offset": 0,
                    "histlen": 0,
                    "size": 1048576
                },
                "connected_slaves": 0,
                "master": {
                    "offset": 0,
                    "sync": {}
                },
                "master_offset": 0,
                "role": "master",
                "slave": {}
            },
            "server": {
                "arch_bits": "64",
                "build_id": "b9a4cd86ce8027d3",
                "config_file": "",
                "gcc_version": "6.4.0",
                "git_dirty": "0",
                "git_sha1": "00000000",
                "hz": 10,
                "lru_clock": 5159690,
                "mode": "standalone",
                "multiplexing_api": "epoll",
                "run_id": "0f681cb959aa47413ec40ff383715c923f9cbefd",
                "tcp_port": 6379,
                "uptime": 707
            },
            "slowlog": {
                "count": 0
            },
            "stats": {
                "active_defrag": {},
                "commands_processed": 265,
                "connections": {
                    "received": 848,
                    "rejected": 0
                },
                "instantaneous": {
                    "input_kbps": 0.18,
                    "ops_per_sec": 6,
                    "output_kbps": 1.39
                },
                "keys": {
                    "evicted": 0,
                    "expired": 0
                },
                "keyspace": {
                    "hits": 15,
                    "misses": 0
                },
                "latest_fork_usec": 0,
                "migrate_cached_sockets": 0,
                "net": {
                    "input": {
                        "bytes": 7300
                    },
                    "output": {
                        "bytes": 219632
                    }
                },
                "pubsub": {
                    "channels": 0,
                    "patterns": 0
                },
                "sync": {
                    "full": 0,
                    "partial": {
                        "err": 0,
                        "ok": 0
                    }
                }
            }
        }
    },
    "event": {
        "duration": 374411,
        "dataset": "redis.info",
        "module": "redis"
    },
    "metricset": {
        "name": "info",
        "period": 10000
    },
    "service": {
        "address": "localhost:6379",
        "type": "redis"
    },
    "ecs": {
        "version": "1.5.0"
    }
}
```

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
| os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| os.full | Operating system name, including the version or code name. | keyword |
| os.full.text | Multi-field of `os.full`. | match_only_text |
| os.kernel | Operating system kernel version as a raw string. | keyword |
| os.name | Operating system name, without the version. | keyword |
| os.name.text | Multi-field of `os.name`. | match_only_text |
| os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. One of these following values should be used (lowercase): linux, macos, unix, windows. If the OS you're dealing with is not in the list, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| os.version | Operating system version as a raw string. | keyword |
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
| process.start | The time the process started. | date |
| process.thread.id | Thread ID. | long |
| process.thread.name | Thread name. | keyword |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| process.uptime | Seconds the process has been up. | long |
| process.working_directory | The working directory of the process. | keyword |
| process.working_directory.text | Multi-field of `process.working_directory`. | match_only_text |
| redis.info.clients.biggest_input_buf | Biggest input buffer among current client connections (replaced by max_input_buffer). | long |
| redis.info.clients.blocked | Number of clients pending on a blocking call (BLPOP, BRPOP, BRPOPLPUSH). | long |
| redis.info.clients.connected | Number of client connections (excluding connections from slaves). | long |
| redis.info.clients.longest_output_list | Longest output list among current client connections (replaced by max_output_buffer). | long |
| redis.info.clients.max_input_buffer | Biggest input buffer among current client connections (on redis 5.0). | long |
| redis.info.clients.max_output_buffer | Longest output list among current client connections. | long |
| redis.info.cluster.enabled | Indicates that the Redis cluster is enabled. | boolean |
| redis.info.cpu.used.sys | System CPU consumed by the Redis server. | scaled_float |
| redis.info.cpu.used.sys_children | User CPU consumed by the Redis server. | scaled_float |
| redis.info.cpu.used.user | System CPU consumed by the background processes. | scaled_float |
| redis.info.cpu.used.user_children | User CPU consumed by the background processes. | scaled_float |
| redis.info.memory.active_defrag.is_running | Flag indicating if active defragmentation is active | boolean |
| redis.info.memory.allocator | Memory allocator. | keyword |
| redis.info.memory.allocator_stats.active | Active memeory | long |
| redis.info.memory.allocator_stats.allocated | Allocated memory | long |
| redis.info.memory.allocator_stats.fragmentation.bytes | Fragmented bytes | long |
| redis.info.memory.allocator_stats.fragmentation.ratio | Fragmentation ratio | float |
| redis.info.memory.allocator_stats.resident | Resident memory | long |
| redis.info.memory.allocator_stats.rss.bytes | Resident bytes | long |
| redis.info.memory.allocator_stats.rss.ratio | Resident ratio | float |
| redis.info.memory.fragmentation.bytes | Bytes between used_memory_rss and used_memory | long |
| redis.info.memory.fragmentation.ratio | Ratio between used_memory_rss and used_memory | float |
| redis.info.memory.max.policy | Eviction policy to use when memory limit is reached. | keyword |
| redis.info.memory.max.value | Memory limit. | long |
| redis.info.memory.used.dataset | The size in bytes of the dataset | long |
| redis.info.memory.used.lua | Used memory by the Lua engine. | long |
| redis.info.memory.used.peak | Peak memory consumed by Redis. | long |
| redis.info.memory.used.rss | Number of bytes that Redis allocated as seen by the operating system (a.k.a resident set size). | long |
| redis.info.memory.used.value | Total number of bytes allocated by Redis. | long |
| redis.info.persistence.aof.bgrewrite.last_status | Status of the last AOF rewrite operatio | keyword |
| redis.info.persistence.aof.buffer.size | Size of the AOF buffer | long |
| redis.info.persistence.aof.copy_on_write.last_size | The size in bytes of copy-on-write allocations during the last RBD save operation | long |
| redis.info.persistence.aof.enabled | Flag indicating AOF logging is activated | boolean |
| redis.info.persistence.aof.fsync.delayed | Delayed fsync counter | long |
| redis.info.persistence.aof.fsync.pending | Number of fsync pending jobs in background I/O queue | long |
| redis.info.persistence.aof.rewrite.buffer.size | Size of the AOF rewrite buffer | long |
| redis.info.persistence.aof.rewrite.current_time.sec | Duration of the on-going AOF rewrite operation if any | long |
| redis.info.persistence.aof.rewrite.in_progress | Flag indicating a AOF rewrite operation is on-going | boolean |
| redis.info.persistence.aof.rewrite.last_time.sec | Duration of the last AOF rewrite operation in seconds | long |
| redis.info.persistence.aof.rewrite.scheduled | Flag indicating an AOF rewrite operation will be scheduled once the on-going RDB save is complete. | boolean |
| redis.info.persistence.aof.size.base | AOF file size on latest startup or rewrite | long |
| redis.info.persistence.aof.size.current | AOF current file size | long |
| redis.info.persistence.aof.write.last_status | Status of the last write operation to the AOF | keyword |
| redis.info.persistence.loading | Flag indicating if the load of a dump file is on-going | boolean |
| redis.info.persistence.rdb.bgsave.current_time.sec | Duration of the on-going RDB save operation if any | long |
| redis.info.persistence.rdb.bgsave.in_progress | Flag indicating a RDB save is on-going | boolean |
| redis.info.persistence.rdb.bgsave.last_status | Status of the last RDB save operation | keyword |
| redis.info.persistence.rdb.bgsave.last_time.sec | Duration of the last RDB save operation in seconds | long |
| redis.info.persistence.rdb.copy_on_write.last_size | The size in bytes of copy-on-write allocations during the last RBD save operation | long |
| redis.info.persistence.rdb.last_save.changes_since | Number of changes since the last dump | long |
| redis.info.persistence.rdb.last_save.time | Epoch-based timestamp of last successful RDB save | long |
| redis.info.replication.backlog.active | Flag indicating replication backlog is active | long |
| redis.info.replication.backlog.first_byte_offset | The master offset of the replication backlog buffer | long |
| redis.info.replication.backlog.histlen | Size in bytes of the data in the replication backlog buffer | long |
| redis.info.replication.backlog.size | Total size in bytes of the replication backlog buffer | long |
| redis.info.replication.connected_slaves | Number of connected slaves | long |
| redis.info.replication.master.last_io_seconds_ago | Number of seconds since the last interaction with master | long |
| redis.info.replication.master.link_status | Status of the link (up/down) | keyword |
| redis.info.replication.master.offset | The server's current replication offset | long |
| redis.info.replication.master.second_offset | The offset up to which replication IDs are accepted | long |
| redis.info.replication.master.sync.in_progress | Indicate the master is syncing to the slave | boolean |
| redis.info.replication.master.sync.last_io_seconds_ago | Number of seconds since last transfer I/O during a SYNC operation | long |
| redis.info.replication.master.sync.left_bytes | Number of bytes left before syncing is complete | long |
| redis.info.replication.master_offset | The server's current replication offset | long |
| redis.info.replication.role | Role of the instance (can be "master", or "slave"). | keyword |
| redis.info.replication.slave.is_readonly | Flag indicating if the slave is read-only | boolean |
| redis.info.replication.slave.offset | The replication offset of the slave instance | long |
| redis.info.replication.slave.priority | The priority of the instance as a candidate for failover | long |
| redis.info.server.arch_bits |  | keyword |
| redis.info.server.build_id |  | keyword |
| redis.info.server.config_file |  | keyword |
| redis.info.server.gcc_version |  | keyword |
| redis.info.server.git_dirty |  | keyword |
| redis.info.server.git_sha1 |  | keyword |
| redis.info.server.hz |  | long |
| redis.info.server.lru_clock |  | long |
| redis.info.server.mode |  | keyword |
| redis.info.server.multiplexing_api |  | keyword |
| redis.info.server.run_id |  | keyword |
| redis.info.server.tcp_port |  | long |
| redis.info.server.uptime |  | long |
| redis.info.slowlog.count | Count of slow operations | long |
| redis.info.stats.active_defrag.hits | Number of value reallocations performed by active the defragmentation process | long |
| redis.info.stats.active_defrag.key_hits | Number of keys that were actively defragmented | long |
| redis.info.stats.active_defrag.key_misses | Number of keys that were skipped by the active defragmentation process | long |
| redis.info.stats.active_defrag.misses | Number of aborted value reallocations started by the active defragmentation process | long |
| redis.info.stats.commands_processed | Total number of commands processed. | long |
| redis.info.stats.connections.received | Total number of connections received. | long |
| redis.info.stats.connections.rejected | Total number of connections rejected. | long |
| redis.info.stats.instantaneous.input_kbps | The network's read rate per second in KB/sec | scaled_float |
| redis.info.stats.instantaneous.ops_per_sec | Number of commands processed per second | long |
| redis.info.stats.instantaneous.output_kbps | The network's write rate per second in KB/sec | scaled_float |
| redis.info.stats.keys.evicted | Number of evicted keys due to maxmemory limit | long |
| redis.info.stats.keys.expired | Total number of key expiration events | long |
| redis.info.stats.keyspace.hits | Number of successful lookup of keys in the main dictionary | long |
| redis.info.stats.keyspace.misses | Number of failed lookup of keys in the main dictionary | long |
| redis.info.stats.latest_fork_usec | Duration of the latest fork operation in microseconds | long |
| redis.info.stats.migrate_cached_sockets | The number of sockets open for MIGRATE purposes | long |
| redis.info.stats.net.input.bytes | Total network input in bytes. | long |
| redis.info.stats.net.output.bytes | Total network output in bytes. | long |
| redis.info.stats.pubsub.channels | Global number of pub/sub channels with client subscriptions | long |
| redis.info.stats.pubsub.patterns | Global number of pub/sub pattern with client subscriptions | long |
| redis.info.stats.slave_expires_tracked_keys | The number of keys tracked for expiry purposes (applicable only to writable slaves) | long |
| redis.info.stats.sync.full | The number of full resyncs with slaves | long |
| redis.info.stats.sync.partial.err | The number of denied partial resync requests | long |
| redis.info.stats.sync.partial.ok | The number of accepted partial resync requests | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |


### key

The `key` dataset collects information about Redis keys.

For each key matching one of the configured patterns, an event is sent to Elasticsearch with information about this key,
what includes the type, its length when available, and its TTL.

Patterns are configured as a list containing these fields:

* `pattern` (required): pattern for key names, as accepted by the Redis KEYS or SCAN commands.
* `limit` (optional): safeguard when using patterns with wildcards to avoid collecting too many keys (Default: 0, no limit)
* `keyspace` (optional): Identifier of the database to use to look for the keys (Default: 0)

An example event for `key` looks as following:

```json
{
    "@timestamp": "2020-06-25T10:16:10.138Z",
    "redis": {
        "key": {
            "expire": {
                "ttl": 360
            },
            "id": "0:foo",
            "length": 3,
            "name": "foo",
            "type": "string"
        }
    },
    "event": {
        "duration": 374411,
        "dataset": "redis.key",
        "module": "redis"
    },
    "metricset": {
        "name": "key",
        "period": 10000
    },
    "service": {
        "address": "localhost:6379",
        "type": "redis"
    },
    "ecs": {
        "version": "1.5.0"
    }
}
```

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
| redis.key.expire.ttl | Seconds to expire. | long |
| redis.key.id | Unique id for this key (With the form `\<keyspace\>:\<name\>`). | keyword |
| redis.key.length | Length of the key (Number of elements for lists, length for strings, cardinality for sets). | long |
| redis.key.name | Key name. | keyword |
| redis.key.type | Key type as shown by `TYPE` command. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### keyspace

The `keyspace` dataset collects information about the Redis keyspaces. For each keyspace, an event is sent to
Elasticsearch. The keyspace information is fetched from the `INFO` command.

An example event for `keyspace` looks as following:

```json
{
    "@timestamp": "2020-06-25T10:16:10.138Z",
    "redis": {
        "keyspace": {
            "avg_ttl": 359459,
            "expires": 0,
            "id": "db0",
            "keys": 1
        }
    },
    "event": {
        "duration": 374411,
        "dataset": "redis.keyspace",
        "module": "redis"
    },
    "metricset": {
        "name": "keyspace",
        "period": 10000
    },
    "service": {
        "address": "localhost:6379",
        "type": "redis"
    },
    "ecs": {
        "version": "1.5.0"
    }
}
```

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
| redis.keyspace.avg_ttl | Average ttl. | long |
| redis.keyspace.expires |  | long |
| redis.keyspace.id | Keyspace identifier. | keyword |
| redis.keyspace.keys | Number of keys in the keyspace. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
