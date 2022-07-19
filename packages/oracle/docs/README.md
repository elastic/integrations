# Oracle Integration

This integration is for ingesting Audit Trail logs and fetching performance, tablespace and sysmetric metrics from Oracle Databases.

The integration expects an *.aud audit file that is generated from Oracle Databases by default. If this has been disabled then please see the [Oracle Database Audit Trail Documentation](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/introduction-to-auditing.html#GUID-8D96829C-9151-4FA4-BED9-831D088F12FF).

## Compatibility

This integration has been tested with Oracle Database 19c, and should work for 18c as well though it has not been tested.

### Database Audit Log

The `database_audit` dataset collects Oracle Audit logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.address | Some event client addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| client.domain | The domain name of the client system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.user.name | Short name or login of the user. | keyword |
| client.user.name.text | Multi-field of `client.user.name`. | match_only_text |
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
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | related log flags |  |
| log.offset | Log offset | long |
| message | human-readable summary of the event | text |
| oracle.database_audit.action | The action performed during the audit event. This could for example be the raw query. | keyword |
| oracle.database_audit.action_number | Action is a numeric value representing the action the user performed. The corresponding name of the action type is in the AUDIT_ACTIONS table. For example, action 100 refers to LOGON. | keyword |
| oracle.database_audit.client.address | The IP Address or Domain used by the client. | keyword |
| oracle.database_audit.client.terminal | If available, the client terminal type, for example "pty". | keyword |
| oracle.database_audit.client.user | The user running the client or connection to the database. | keyword |
| oracle.database_audit.database.host | Client host machine name. | keyword |
| oracle.database_audit.database.id | Database identifier calculated when the database is created. It corresponds to the DBID column of the V$DATABASE data dictionary view. | keyword |
| oracle.database_audit.database.user | The database user used to authenticate. | keyword |
| oracle.database_audit.entry.id | Indicates the current audit entry number, assigned to each audit trail record. The audit entry.id sequence number is shared between fine-grained audit records and regular audit records. | keyword |
| oracle.database_audit.length | Refers to the total number of bytes used in this audit record. This number includes the trailing newline bytes (\n), if any, at the end of the audit record. | long |
| oracle.database_audit.privilege | The privilege group related to the database user. | keyword |
| oracle.database_audit.session_id | Indicates the audit session ID number. | keyword |
| oracle.database_audit.status | Database Audit Status. | keyword |
| process.pid | Process id. | long |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.user.name | Short name or login of the user. | keyword |
| server.user.name.text | Multi-field of `server.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.roles | Array of user roles at the time of the event. | keyword |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


An example event for `database_audit` looks as following:

```json
{
    "@timestamp": "2020-10-07T14:57:51.000Z",
    "agent": {
        "ephemeral_id": "021be4f6-f6ea-47c5-aa38-62ba8c3f0f3c",
        "id": "5940e9e3-013b-43c0-a459-261d69b08862",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "client": {
        "user": {
            "name": "oracle"
        }
    },
    "data_stream": {
        "dataset": "oracle.database_audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "5940e9e3-013b-43c0-a459-261d69b08862",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "action": "database_audit",
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "oracle.database_audit",
        "ingested": "2022-02-24T08:25:06Z",
        "kind": "event",
        "outcome": "success",
        "timezone": "-04:00",
        "type": "access"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.240.7"
        ],
        "mac": [
            "02:42:c0:a8:f0:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.60.1-microsoft-standard-WSL2",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/ORCLCDB_ora_13765_20201007105751904399925443.aud.log"
        },
        "flags": [
            "multiline"
        ],
        "offset": 882
    },
    "oracle": {
        "database_audit": {
            "action": "CONNECT",
            "action_number": "100",
            "client": {
                "terminal": "pts/0"
            },
            "length": 253,
            "session_id": "4294967295",
            "status": "0"
        }
    },
    "process": {
        "pid": 13765
    },
    "related": {
        "hosts": [
            "testlab.local"
        ],
        "user": [
            "/",
            "oracle"
        ]
    },
    "server": {
        "address": "testlab.local",
        "domain": "testlab.local",
        "user": {
            "name": "/"
        }
    },
    "tags": [
        "oracle-database_audit"
    ],
    "user": {
        "roles": "SYSDBA"
    }
}
```

### Database Performance Metrics

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.dataset | Event module | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.ip | Host ip addresses. | ip |  |
| oracle.performance.buffer_pool | Name of the buffer pool in the instance | keyword |  |
| oracle.performance.cache.buffer.hit.pct | The cache hit ratio of the specified buffer pool. | double | gauge |
| oracle.performance.cache.get.consistent | DB block gets. It is a count of blocks read in CURRENT mode. | long | gauge |
| oracle.performance.cache.get.db_blocks | DB block gets. It is a count of blocks read in CURRENT mode. | long | gauge |
| oracle.performance.cache.physical_reads | Physical reads. This metric represents the number of data blocks read from disk per second during a time period | long | gauge |
| oracle.performance.cursors.avg | Average cursors opened by username and machine | double | gauge |
| oracle.performance.cursors.cache_hit.pct | Ratio of session cursor cache hits from total number of cursors | double | gauge |
| oracle.performance.cursors.max | Max cursors opened by username and machine | double | gauge |
| oracle.performance.cursors.opened.current | Total number of current open cursors | long | gauge |
| oracle.performance.cursors.opened.total | Total number of cursors opened since the instance started | long | gauge |
| oracle.performance.cursors.parse.real | Real number of parses that occurred: session cursor cache hits - parse count (total) | double | gauge |
| oracle.performance.cursors.parse.total | Total number of parse calls (hard and soft). A soft parse is a check on an object already in the shared pool, to verify that the permissions on the underlying object have not changed | long | gauge |
| oracle.performance.cursors.session.cache_hits | Number of hits in the session cursor cache. A hit means that the SQL statement did not have to be reparsed. | double | gauge |
| oracle.performance.cursors.total | Total opened cursors by username and machine | double | gauge |
| oracle.performance.io_reloads | Reloads by Pins ratio. A Reload is any PIN of an object that is not the first PIN performed since the object handle was created, and which requires loading the object from disk. Pins are the number of times a PIN was requested for objects of this namespace. | long | gauge |
| oracle.performance.lock_requests | Average of the ratio between gethits and gets being Gethits the number of times an object’s handle was found in memory and gets the number of times a lock was requested for objects of this namespace. | long | gauge |
| oracle.performance.machine | Operating system machine name | keyword |  |
| oracle.performance.pin_requests | Average of all pinhits/pins ratios being PinHits the number of times all of the metadata pieces of the library object were found in memory and pins the number of times a PIN was requested for objects of this namespace. | long | gauge |
| oracle.performance.username | Oracle username | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


An example event for `performance` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "event": {
        "dataset": "oracle.performance",
        "duration": 115000,
        "module": "sql"
    },
    "metricset": {
        "name": "query",
        "period": 60000
    },
    "oracle": {
        "performance": {
            "cursors": {
                "opened": {
                    "current": 7,
                    "total": 6225
                },
                "parse": {
                    "real": 1336,
                    "total": 3684
                },
                "session": {
                    "cache_hits": 5020
                },
                "cache_hit": {
                    "pct": 0.8064257028112449
                }
            },
            "io_reloads": 0.0013963503027202182,
            "lock_requests": 0.5725039956419224,
            "pin_requests": 0.7780581056654354
        }
    },
    "service": {
        "address": "oracle://localhost:1521/ORCLCDB.localdomain",
        "type": "sql"
    }
}
```

### Database Tablespace Metrics

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.dataset | Event module | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.ip | Host ip addresses. | ip |  |
| oracle.tablespace.data_file.id | Tablespace unique identifier. | long | gauge |
| oracle.tablespace.data_file.name | Filename of the data file | keyword |  |
| oracle.tablespace.data_file.online_status | Last known online status of the data file. One of SYSOFF, SYSTEM, OFFLINE, ONLINE or RECOVER. | keyword |  |
| oracle.tablespace.data_file.size.bytes | Size of the file in bytes | long | gauge |
| oracle.tablespace.data_file.size.free.bytes | The size of the file available for user data. The actual size of the file minus this value is used to store file related metadata. | long | gauge |
| oracle.tablespace.data_file.size.max.bytes | Maximum file size in bytes | long | gauge |
| oracle.tablespace.data_file.status | 'File status: AVAILABLE or INVALID (INVALID means that the file number is not in use, for example, a file in a tablespace that was dropped)' | keyword |  |
| oracle.tablespace.name | Tablespace name | keyword |  |
| oracle.tablespace.space.free.bytes | Tablespace total free space available, in bytes. | long | gauge |
| oracle.tablespace.space.total.bytes | Tablespace total size, in bytes. | long | gauge |
| oracle.tablespace.space.used.bytes | Tablespace used space, in bytes. | long | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


An example event for `tablespace` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "event": {
        "dataset": "oracle.tablespace",
        "duration": 115000,
        "module": "sql"
    },
    "metricset": {
        "name": "query",
        "period": 60000
    },
    "oracle": {
        "tablespace": {
            "data_file": {
                "size": {
                    "max": {
                        "bytes": 34359721984
                    },
                    "bytes": 1310720000,
                    "free": {
                        "bytes": 1309671424
                    }
                },
                "online_status": "ONLINE",
                "name": "/u02/app/oracle/oradata/ORCL/sysaux01.dbf",
                "id": 3,
                "status": "AVAILABLE"
            },
            "name": "SYSAUX",
            "space": {
                "total": {
                    "bytes": 2355101696
                },
                "used": {
                    "bytes": 1310720000
                },
                "free": {
                    "bytes": 70713344
                }
            }
        }
    },
    "service": {
        "address": "oracle://localhost:1521/ORCLCDB.localdomain",
        "type": "sql"
    }
}
```

### Database Sysmetrics 

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.dataset | Event module | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.ip | Host ip addresses. | ip |  |
| oracle.sysmetric.average_active_sessions | Average Active Sessions. | double | gauge |
| oracle.sysmetric.cpu_usage_per_sec | CPU Usage Per Second. | double | gauge |
| oracle.sysmetric.current_os_load | Current OS Load. | double | gauge |
| oracle.sysmetric.db_block_changes_per_sec | DB Block Changes Per Second. | double | gauge |
| oracle.sysmetric.host_cpu_utilization_pct | Host CPU Utilization (%). | double | gauge |
| oracle.sysmetric.network_traffic_volume_per_sec | Network Traffic Volume Per Second. | double | gauge |
| oracle.sysmetric.physical_read_total_bytes_per_sec | Physical Read Total Bytes Per Second. | double | gauge |
| oracle.sysmetric.physical_reads_per_sec | Physical Reads Per Second. | double | gauge |
| oracle.sysmetric.physical_writes_per_sec | Physical Writes Per Second. | double | gauge |
| oracle.sysmetric.response_time_per_txn | Response Time Per Transaction. | double | gauge |
| oracle.sysmetric.session_count | Session Count. | long | gauge |
| oracle.sysmetric.total_index_scans_per_txn | Total Index Scans Per Transaction. | double | gauge |
| oracle.sysmetric.total_table_scans_per_txn | Total Table Scans Per Transaction. | double | gauge |
| oracle.sysmetric.user_rollbacks_per_sec | User Rollbacks Per Second. | long | gauge |
| oracle.sysmetric.user_transaction_per_sec | User Transaction Per Second. | double | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


An example event for `sysmetric` looks as following:

```json
{
    "@timestamp": "2022-05-27T02:18:55.112Z",
    "event": {
        "dataset": "oracle.sysmetric",
        "module": "sql",
        "duration": 408974115
    },
    "metricset": {
        "name": "query",
        "period": 60000
    },
    "oracle": {
        "sysmetric": {
            "response_time_per_txn": 27.7113,
            "current_os_load": 1.0693359375,
            "session_count": 52,
            "db_block_changes_per_sec": 0.0505135544704496,
            "user_transaction_per_sec": 0,
            "average_active_sessions": 0.0046659875399899,
            "physical_read_total_bytes_per_sec": 57131.2342145142,
            "user_rollbacks_per_sec": 0,
            "physical_writes_per_sec": 0,
            "total_table_scans_per_txn": 17,
            "host_cpu_utilization_pct": 11.5422822480079,
            "physical_reads_per_sec": 0,
            "network_traffic_volume_per_sec": 521.990234046136,
            "total_index_scans_per_txn": 211
        }
    },
    "service": {
        "address": "oracle://localhost:1521/ORCLCDB.localdomain",
        "type": "sql"
    }
}
```
