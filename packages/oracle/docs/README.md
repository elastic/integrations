# Oracle Integration

This integration is for ingesting Audit Trail logs and fetching performance, tablespace and sysmetric metrics from Oracle Databases.

The integration expects an *.aud audit file that is generated from Oracle Databases by default. If this has been disabled then please see the [Oracle Database Audit Trail Documentation](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/introduction-to-auditing.html#GUID-8D96829C-9151-4FA4-BED9-831D088F12FF).

### Requirements

Connectivity to Oracle can be facilitated in two ways either by using official Oracle libraries or by using a JDBC driver. Facilitation of the connectivity using JDBC is not supported currently with Metricbeat. Connectivity can be facilitated using Oracle libraries and the detailed steps to do the same are mentioned below.

#### Oracle Database Connection Pre-requisites

To get connected with the Oracle Database ORACLE_SID, ORACLE_BASE, ORACLE_HOME environment variables should be set.

For example: Let’s consider Oracle Database 21c installation using RPM manually by following the [Oracle Installation instructions](https://docs.oracle.com/en/database/oracle/oracle-database/21/ladbi/running-rpm-packages-to-install-oracle-database.html). Environment variables should be set as follows:
    `ORACLE_SID=ORCLCDB`
    `ORACLE_BASE=/opt/oracle/oradata`
    `ORACLE_HOME=/opt/oracle/product/21c/dbhome_1`
Also, add `$ORACLE_HOME/bin` to the `PATH` environment variable.

#### Oracle Instant Client

Oracle Instant Client enables development and deployment of applications that connect to Oracle Database. The Instant Client libraries provide the necessary network connectivity and advanced data features to make full use of Oracle Database. If you have OCI Oracle server which comes with these libraries pre-installed, you don't need a separate client installation.

The OCI library install few Client Shared Libraries that must be referenced on the machine where Metricbeat is installed. Please follow the [Oracle Client Installation link](https://docs.oracle.com/en/database/oracle/oracle-database/21/lacli/install-instant-client-using-zip.html#GUID-D3DCB4FB-D3CA-4C25-BE48-3A1FB5A22E84) link for OCI Instant Client set up. The OCI Instant Client is available with the Oracle Universal Installer, RPM file or ZIP file. Download links can be found at the [Oracle Instant Client Download page](https://www.oracle.com/database/technologies/instant-client/downloads.html).

####  Enable Listener

The Oracle listener is a service that runs on the database host and receives requests from Oracle clients. Make sure that [Listener](https://docs.oracle.com/cd/B19306_01/network.102/b14213/lsnrctl.htm) is be running. 
To check if the listener is running or not, run: 

`lsnrctl STATUS`

If the listener is not running, use the command to start:

`lsnrctl START`

Then, Metricbeat can be launched.

*Host Configuration*

The following two types of host configurations are supported:

1. Old style host configuration for backwards compatibility:
    - `hosts: ["user/pass@0.0.0.0:1521/ORCLPDB1.localdomain"]`
    - `hosts: ["user/password@0.0.0.0:1521/ORCLPDB1.localdomain as sysdba"]`

2. DSN host configuration:
    - `hosts: ['user="user" password="pass" connectString="0.0.0.0:1521/ORCLPDB1.localdomain"']`
    - `hosts: ['user="user" password="password" connectString="host:port/service_name" sysdba=true']`


Note: If the password contains the backslash (`\`) character, it must be escaped with a backslash. For example, if the password is `my\_password`, it should be written as `my\\_password`.


## Compatibility

This integration has been tested with Oracle Database 19c, and should work for 18c as well though it has not been tested.

### Audit Log

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
        "version": "8.3.0"
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

### Performance Metrics

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| event.dataset | Event module | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| oracle.performance.buffer_pool | Name of the buffer pool in the instance. | keyword |  |  |
| oracle.performance.cache.buffer.hit.pct | The cache hit ratio of the specified buffer pool. | double | percent | gauge |
| oracle.performance.cache.get.consistent | Consistent gets statistic. | long |  | gauge |
| oracle.performance.cache.get.db_blocks | Database blocks gotten. | long |  | gauge |
| oracle.performance.cache.physical_reads | Physical reads. This metric represents the number of data blocks read from disk per second during a time period. | long |  | gauge |
| oracle.performance.cursors.avg | Average cursors opened by username and machine. | double |  | gauge |
| oracle.performance.cursors.cache_hit.pct | Ratio of session cursor cache hits from total number of cursors. | double | percent | gauge |
| oracle.performance.cursors.max | Max cursors opened by username and machine. | double |  | gauge |
| oracle.performance.cursors.opened.current | Total number of current open cursors. | long |  | gauge |
| oracle.performance.cursors.opened.total | Total number of cursors opened since the instance started. | long |  | counter |
| oracle.performance.cursors.parse.real | "Real number of parses that occurred: session cursor cache hits - parse count (total)." | double |  | gauge |
| oracle.performance.cursors.parse.total | Total number of parse calls (hard and soft). A soft parse is a check on an object already in the shared pool, to verify that the permissions on the underlying object have not changed. | long |  | gauge |
| oracle.performance.cursors.session.cache_hits | Number of hits in the session cursor cache. A hit means that the SQL statement did not have to be reparsed. | double |  | gauge |
| oracle.performance.cursors.total | Total opened cursors by username and machine. | double |  | gauge |
| oracle.performance.io_reloads | Reloads by Pins ratio. A Reload is any PIN of an object that is not the first PIN performed since the object handle was created, and which requires loading the object from disk. Pins are the number of times a PIN was requested for objects of this namespace. | double |  | gauge |
| oracle.performance.lock_requests | Average of the ratio between 'gethits' and 'gets', where 'gethits' the number of times an object's handle was found in memory and 'gets' is the number of times a lock was requested for objects of this namespace. | double |  | gauge |
| oracle.performance.machine | Operating system machine name. | keyword |  |  |
| oracle.performance.pin_requests | Average of all pinhits/pins ratios, where 'PinHits' is the number of times all of the metadata pieces of the library object were found in memory and 'pins' is the number of times a PIN was requested for objects of this namespace. | double |  | gauge |
| oracle.performance.username | Oracle username | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


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

### Tablespace Metrics

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| event.dataset | Event module | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| oracle.tablespace.data_file.id | Tablespace unique identifier. | long |  |  |
| oracle.tablespace.data_file.name | Filename of the data file | keyword |  |  |
| oracle.tablespace.data_file.online_status | Last known online status of the data file. One of SYSOFF, SYSTEM, OFFLINE, ONLINE or RECOVER. | keyword |  |  |
| oracle.tablespace.data_file.size.bytes | Size of the file in bytes | long | byte | gauge |
| oracle.tablespace.data_file.size.free.bytes | The size of the file available for user data. The actual size of the file minus this value is used to store file related metadata. | long | byte | gauge |
| oracle.tablespace.data_file.size.max.bytes | Maximum file size in bytes | long | byte | gauge |
| oracle.tablespace.data_file.status | File status: AVAILABLE or INVALID (INVALID means that the file number is not in use, for example, a file in a tablespace that was dropped) | keyword |  |  |
| oracle.tablespace.name | Tablespace name | keyword |  |  |
| oracle.tablespace.space.free.bytes | Tablespace total free space available, in bytes. | long | byte | gauge |
| oracle.tablespace.space.total.bytes | Tablespace total size, in bytes. | long | byte | gauge |
| oracle.tablespace.space.used.bytes | Tablespace used space, in bytes. | long | byte | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


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

### Sysmetrics 

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| event.dataset | Event module | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| oracle.sysmetric.active_parallel_sessions | Active parallel sessions | double |  | gauge |
| oracle.sysmetric.active_serial_sessions | Active serial sessions. | double |  | gauge |
| oracle.sysmetric.average_active_sessions | Average active sessions. | double |  | gauge |
| oracle.sysmetric.average_synchronous_single-block_read_latency | Average synchronous single-block read latency. | double |  | gauge |
| oracle.sysmetric.background_checkpoints_per_sec | Background checkpoints per second. | double |  | gauge |
| oracle.sysmetric.background_cpu_usage_per_sec | Background CPU usage per sec | double |  | gauge |
| oracle.sysmetric.background_time_per_sec | Background time per second. | double |  | gauge |
| oracle.sysmetric.branch_node_splits_per_sec | Branch node splits per second. | double |  | gauge |
| oracle.sysmetric.branch_node_splits_per_txn | Branch node splits per transaction. | double |  | gauge |
| oracle.sysmetric.buffer_cache_hit_ratio | Buffer cache hit ratio | double |  | gauge |
| oracle.sysmetric.captured_user_calls | Captured user calls. | double |  | gauge |
| oracle.sysmetric.cell_physical_io_interconnect_bytes | Cell physical io interconnect bytes. | double |  | gauge |
| oracle.sysmetric.consistent_read_changes_per_sec | Consistent read changes per second. | double |  | gauge |
| oracle.sysmetric.consistent_read_changes_per_txn | Consistent read changes per transaction. | double |  | gauge |
| oracle.sysmetric.consistent_read_gets_per_sec | Consistent read gets per second. | double |  | gauge |
| oracle.sysmetric.consistent_read_gets_per_txn | Consistent read gets per transaction. | double |  | gauge |
| oracle.sysmetric.cpu_usage_per_sec | CPU usage per second. | double |  | gauge |
| oracle.sysmetric.cpu_usage_per_txn | CPU usage per transaction. | double |  | gauge |
| oracle.sysmetric.cr_blocks_created_per_sec | Cr blocks created per second. | double |  | gauge |
| oracle.sysmetric.cr_blocks_created_per_txn | Cr blocks created per transaction. | double |  | gauge |
| oracle.sysmetric.cr_undo_records_applied_per_sec | Cr undo records applied per second. | double |  | gauge |
| oracle.sysmetric.cr_undo_records_applied_per_txn | Cr undo records applied per transaction. | double |  | gauge |
| oracle.sysmetric.current_logons_count | Current logons count. | double |  | gauge |
| oracle.sysmetric.current_open_cursors_count | Current open cursors count | double |  | gauge |
| oracle.sysmetric.current_os_load | Current os load | double |  | gauge |
| oracle.sysmetric.cursor_cache_hit_ratio | Cursor cache hit ratio. | double |  | gauge |
| oracle.sysmetric.database_cpu_time_ratio | Database CPU time ratio | double |  | gauge |
| oracle.sysmetric.database_time_per_sec | Database time per second. | double |  | gauge |
| oracle.sysmetric.database_wait_time_ratio | Database wait time ratio. | double |  | gauge |
| oracle.sysmetric.db_block_changes_per_sec | Db block changes per second. | double |  | gauge |
| oracle.sysmetric.db_block_changes_per_txn | Db block changes per transaction. | double |  | gauge |
| oracle.sysmetric.db_block_changes_per_user_call | Db block changes per user call. | double |  | gauge |
| oracle.sysmetric.db_block_gets_per_sec | Db block gets per sec | double |  | gauge |
| oracle.sysmetric.db_block_gets_per_txn | Db block gets per transaction | double |  | gauge |
| oracle.sysmetric.db_block_gets_per_user_call | Db block gets per user call. | double |  | gauge |
| oracle.sysmetric.dbwr_checkpoints_per_sec | Dbwr checkpoints per sec. | double |  | gauge |
| oracle.sysmetric.ddl_statements_parallelized_per_sec | Ddl statements parallelized per sec | double |  | gauge |
| oracle.sysmetric.disk_sort_per_sec | Disk sort per second. | double |  | gauge |
| oracle.sysmetric.disk_sort_per_txn | Disk sort per transaction. | double |  | gauge |
| oracle.sysmetric.dml_statements_parallelized_per_sec | Dml statements parallelized per sec | double |  | gauge |
| oracle.sysmetric.enqueue_deadlocks_per_sec | Enqueue deadlocks per sec | double |  | gauge |
| oracle.sysmetric.enqueue_deadlocks_per_txn | Enqueue deadlocks per transaction. | double |  | gauge |
| oracle.sysmetric.enqueue_requests_per_sec | Enqueue requests per second. | double |  | gauge |
| oracle.sysmetric.enqueue_requests_per_txn | Enqueue requests per transaction | double |  | gauge |
| oracle.sysmetric.enqueue_timeouts_per_sec | Enqueue timeouts per second. | double |  | gauge |
| oracle.sysmetric.enqueue_timeouts_per_txn | Enqueue timeouts per transaction. | double |  | gauge |
| oracle.sysmetric.enqueue_waits_per_sec | Enqueue waits per second. | double |  | gauge |
| oracle.sysmetric.enqueue_waits_per_txn | Enqueue waits per transaction. | double |  | gauge |
| oracle.sysmetric.execute_without_parse_ratio | Execute without parse ratio | double |  | gauge |
| oracle.sysmetric.executions_per_sec | Executions per second. | double |  | gauge |
| oracle.sysmetric.executions_per_txn | Executions per transaction. | double |  | gauge |
| oracle.sysmetric.executions_per_user_call | Executions per user call | double |  | gauge |
| oracle.sysmetric.full_index_scans_per_sec | Full index scans per second. | double |  | gauge |
| oracle.sysmetric.full_index_scans_per_txn | Full index scans per transaction. | double |  | gauge |
| oracle.sysmetric.gc_cr_block_received_per_second | Gc cr block received per second. | double |  | gauge |
| oracle.sysmetric.gc_cr_block_received_per_txn | Gc cr block received per transaction. | double |  | gauge |
| oracle.sysmetric.gc_current_block_received_per_second | Gc current block received per second. | double |  | gauge |
| oracle.sysmetric.gc_current_block_received_per_txn | Gc current block received per transaction | double |  | gauge |
| oracle.sysmetric.global_cache_average_cr_get_time | Global cache average cr get time. | double |  | gauge |
| oracle.sysmetric.global_cache_average_current_get_time | Global cache average current get time | double |  | gauge |
| oracle.sysmetric.global_cache_blocks_corrupted | Global cache blocks corrupted. | double |  | gauge |
| oracle.sysmetric.global_cache_blocks_lost | Global cache blocks lost. | double |  | gauge |
| oracle.sysmetric.hard_parse_count_per_sec | Hard parse count per sec | double |  | gauge |
| oracle.sysmetric.hard_parse_count_per_txn | Hard parse count per transaction. | double |  | gauge |
| oracle.sysmetric.host_cpu_usage_per_sec | Host CPU usage per sec. | double |  | gauge |
| oracle.sysmetric.host_cpu_utilization_pct | Host CPU utilization percentage. | double | percent | gauge |
| oracle.sysmetric.io_megabytes_per_second | IO megabytes per second | double |  | gauge |
| oracle.sysmetric.io_requests_per_second | IO requests per second | double |  | gauge |
| oracle.sysmetric.leaf_node_splits_per_sec | Leaf node splits per second. | double |  | gauge |
| oracle.sysmetric.leaf_node_splits_per_txn | Leaf node splits per transaction. | double |  | gauge |
| oracle.sysmetric.library_cache_hit_ratio | Library cache hit ratio. | double |  | gauge |
| oracle.sysmetric.library_cache_miss_ratio | Library cache miss ratio. | double |  | gauge |
| oracle.sysmetric.logical_reads_per_sec | Logical reads per sec. | double |  | gauge |
| oracle.sysmetric.logical_reads_per_txn | Logical reads per transaction. | double |  | gauge |
| oracle.sysmetric.logical_reads_per_user_call | Logical reads per user call. | double |  | gauge |
| oracle.sysmetric.logons_per_sec | Logons per sec | double |  | gauge |
| oracle.sysmetric.logons_per_txn | Logons per transaction. | double |  | gauge |
| oracle.sysmetric.long_table_scans_per_sec | Long table scans per second. | double |  | gauge |
| oracle.sysmetric.long_table_scans_per_txn | Long table scans per transaction. | double |  | gauge |
| oracle.sysmetric.memory_sorts_ratio | Memory sorts ratio. | double |  | gauge |
| oracle.sysmetric.network_traffic_volume_per_sec | Network traffic volume per second. | double |  | gauge |
| oracle.sysmetric.open_cursors_per_sec | Open cursors per sec | double |  | gauge |
| oracle.sysmetric.open_cursors_per_txn | Open cursors per transaction | double |  | gauge |
| oracle.sysmetric.parse_failure_count_per_sec | Parse failure count per sec | double |  | gauge |
| oracle.sysmetric.parse_failure_count_per_txn | Parse failure count per transaction. | double |  | gauge |
| oracle.sysmetric.pga_cache_hit_pct | Pga cache hit percentage. | double | percent | gauge |
| oracle.sysmetric.physical_read_bytes_per_sec | Physical read bytes per second. | double |  | gauge |
| oracle.sysmetric.physical_read_io_requests_per_sec | Physical read io requests per second. | double |  | gauge |
| oracle.sysmetric.physical_read_total_bytes_per_sec | Physical read total bytes per second. | double |  | gauge |
| oracle.sysmetric.physical_read_total_io_requests_per_sec | Physical read total io requests per sec | double |  | gauge |
| oracle.sysmetric.physical_reads_direct_lobs_per_sec | Physical reads direct lobs per second. | double |  | gauge |
| oracle.sysmetric.physical_reads_direct_lobs_per_txn | Physical reads direct lobs per transaction. | double |  | gauge |
| oracle.sysmetric.physical_reads_direct_per_sec | Physical reads direct per second. | double |  | gauge |
| oracle.sysmetric.physical_reads_direct_per_txn | Physical reads direct per transaction. | double |  | gauge |
| oracle.sysmetric.physical_reads_per_sec | Physical reads per second. | double |  | gauge |
| oracle.sysmetric.physical_reads_per_txn | Physical reads per transaction. | double |  | gauge |
| oracle.sysmetric.physical_write_bytes_per_sec | Physical write bytes per second. | double |  | gauge |
| oracle.sysmetric.physical_write_io_requests_per_sec | Physical write io requests per second. | double |  | gauge |
| oracle.sysmetric.physical_write_total_bytes_per_sec | Physical write total bytes per second. | double |  | gauge |
| oracle.sysmetric.physical_write_total_io_requests_per_sec | Physical write total io requests per second. | double |  | gauge |
| oracle.sysmetric.physical_writes_direct_lobs__per_txn | Physical writes direct lobs per transaction | double |  | gauge |
| oracle.sysmetric.physical_writes_direct_lobs_per_sec | Physical writes direct lobs per sec | double |  | gauge |
| oracle.sysmetric.physical_writes_direct_per_sec | Physical writes direct per second. | double |  | gauge |
| oracle.sysmetric.physical_writes_direct_per_txn | Physical writes direct per transaction. | double |  | gauge |
| oracle.sysmetric.physical_writes_per_sec | Physical writes per second. | double |  | gauge |
| oracle.sysmetric.physical_writes_per_txn | Physical writes per transaction. | double |  | gauge |
| oracle.sysmetric.pq_qc_session_count | Pq qc session count. | double |  | gauge |
| oracle.sysmetric.pq_slave_session_count | Pq slave session count. | double |  | gauge |
| oracle.sysmetric.process_limit_pct | Process limit percentage. | double | percent | gauge |
| oracle.sysmetric.px_downgraded_1_to_25pct_per_sec | Px downgraded 1 to 25 percentage per second. | double | percent | gauge |
| oracle.sysmetric.px_downgraded_25_to_50pct_per_sec | Px downgraded 25 to 50 percentage per sec | double | percent | gauge |
| oracle.sysmetric.px_downgraded_50_to_75pct_per_sec | Px downgraded 50 to 75 percentage per second. | double | percent | gauge |
| oracle.sysmetric.px_downgraded_75_to_99pct_per_sec | Px downgraded 75 to 99 percentage per second. | double | percent | gauge |
| oracle.sysmetric.px_downgraded_to_serial_per_sec | Px downgraded to serial per sec. | double |  | gauge |
| oracle.sysmetric.px_operations_not_downgraded_per_sec | Px operations not downgraded per second. | double |  | gauge |
| oracle.sysmetric.queries_parallelized_per_sec | Queries parallelized per second. | double |  | gauge |
| oracle.sysmetric.recursive_calls_per_sec | Recursive calls per second. | double |  | gauge |
| oracle.sysmetric.recursive_calls_per_txn | Recursive calls per transaction. | double |  | gauge |
| oracle.sysmetric.redo_allocation_hit_ratio | Redo allocation hit ratio. | double |  | gauge |
| oracle.sysmetric.redo_generated_per_sec | Redo generated per second. | double |  | gauge |
| oracle.sysmetric.redo_generated_per_txn | Redo generated per transaction | double |  | gauge |
| oracle.sysmetric.redo_writes_per_sec | Redo writes per second. | double |  | gauge |
| oracle.sysmetric.redo_writes_per_txn | Redo writes per transaction. | double |  | gauge |
| oracle.sysmetric.replayed_user_calls | Replayed user calls | double |  | gauge |
| oracle.sysmetric.response_time_per_txn | Response time per transaction. | double |  | gauge |
| oracle.sysmetric.row_cache_hit_ratio | Row cache hit ratio. | double |  | gauge |
| oracle.sysmetric.row_cache_miss_ratio | Row cache miss ratio. | double |  | gauge |
| oracle.sysmetric.rows_per_sort | Rows per sort. | double |  | gauge |
| oracle.sysmetric.run_queue_per_sec | Run queue per second. | double |  | gauge |
| oracle.sysmetric.session_count | Session count. | double |  | gauge |
| oracle.sysmetric.session_limit_pct | "Session limit percentage." | double | percent | gauge |
| oracle.sysmetric.shared_pool_free_pct | Shared pool free percentage. | double | percent | gauge |
| oracle.sysmetric.soft_parse_ratio | Soft parse ratio. | double |  | gauge |
| oracle.sysmetric.sql_service_response_time | Sql service response time | double |  | gauge |
| oracle.sysmetric.streams_pool_usage_percentage | Streams pool usage percentage. | double |  | gauge |
| oracle.sysmetric.temp_space_used | Temp space used | double |  | gauge |
| oracle.sysmetric.total_index_scans_per_sec | Total index scans per second. | double |  | gauge |
| oracle.sysmetric.total_index_scans_per_txn | Total index scans per transaction. | double |  | gauge |
| oracle.sysmetric.total_parse_count_per_sec | Total parse count per sec | double |  | gauge |
| oracle.sysmetric.total_parse_count_per_txn | Total parse count per transaction. | double |  | gauge |
| oracle.sysmetric.total_pga_allocated | Total pga allocated. | double |  | gauge |
| oracle.sysmetric.total_pga_used_by_sql_workareas | Total pga used by sql workareas | double |  | gauge |
| oracle.sysmetric.total_sorts_per_user_call | Total sorts per user call. | double |  | gauge |
| oracle.sysmetric.total_table_scans_per_sec | Total table scans per second. | double |  | gauge |
| oracle.sysmetric.total_table_scans_per_txn | Total table scans per transaction. | double |  | gauge |
| oracle.sysmetric.total_table_scans_per_user_call | Total table scans per user call. | double |  | gauge |
| oracle.sysmetric.txns_per_logon | transactions per logon. | double |  | gauge |
| oracle.sysmetric.user_calls_per_sec | User calls per second. | double |  | gauge |
| oracle.sysmetric.user_calls_per_txn | User calls per transaction | double |  | gauge |
| oracle.sysmetric.user_calls_ratio | User calls ratio | double |  | gauge |
| oracle.sysmetric.user_commits_per_sec | User commits per sec | double |  | gauge |
| oracle.sysmetric.user_commits_percentage | User commits percentage. | double |  | gauge |
| oracle.sysmetric.user_limit_pct | User limit percentage. | double | percent | gauge |
| oracle.sysmetric.user_rollback_undo_records_applied_per_txn | User rollback undo records applied per transaction. | double |  | gauge |
| oracle.sysmetric.user_rollback_undorec_applied_per_sec | User rollback undorec applied per second. | double |  | gauge |
| oracle.sysmetric.user_rollbacks_per_sec | User rollbacks per second. | double |  | gauge |
| oracle.sysmetric.user_rollbacks_percentage | User rollbacks percentage. | double |  | gauge |
| oracle.sysmetric.user_transaction_per_sec | User transaction per second. | double |  | gauge |
| oracle.sysmetric.vm_in_bytes_per_sec | Vm in bytes per sec | double |  | gauge |
| oracle.sysmetric.vm_out_bytes_per_sec | Vm out bytes per second. | double |  | gauge |
| oracle.sysmetric.workload_capture_and_replay_status | Workload capture and replay status. | double |  | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


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
            "row_cache_hit_ratio": 100,
            "current_open_cursors_count": 28,
            "total_pga_allocated": 194334720,
            "px_downgraded_75_to_99pct_per_sec": 0,
            "enqueue_deadlocks_per_txn": 0,
            "db_block_gets_per_sec": 1.83501683501684,
            "cr_blocks_created_per_txn": 0,
            "logical_reads_per_user_call": 5.44347826086956,
            "response_time_per_txn": 20.0772,
            "recursive_calls_per_sec": 21.9191919191919,
            "db_block_gets_per_txn": 54.5,
            "long_table_scans_per_txn": 0,
            "total_parse_count_per_txn": 54,
            "db_block_changes_per_user_call": 0.947826086956522,
            "px_downgraded_to_serial_per_sec": 0,
            "cell_physical_io_interconnect_bytes": 4483072,
            "physical_writes_direct_per_sec": 0,
            "current_os_load": 1.6591796875,
            "user_rollback_undo_records_applied_per_txn": 0,
            "db_block_changes_per_txn": 54.5,
            "disk_sort_per_sec": 0,
            "cr_undo_records_applied_per_txn": 0,
            "process_limit_pct": 27.3333333333333,
            "cpu_usage_per_sec": 0.77420202020202,
            "active_parallel_sessions": 0,
            "long_table_scans_per_sec": 0,
            "database_time_per_sec": 0.676,
            "physical_read_total_io_requests_per_sec": 3.75420875420875,
            "cr_undo_records_applied_per_sec": 0,
            "gc_cr_block_received_per_txn": 0,
            "active_serial_sessions": 1,
            "pq_slave_session_count": 0,
            "physical_writes_direct_per_txn": 0,
            "session_count": 66,
            "dbwr_checkpoints_per_sec": 0,
            "db_block_changes_per_sec": 1.83501683501684,
            "cpu_usage_per_txn": 22.9938,
            "vm_out_bytes_per_sec": 0,
            "parse_failure_count_per_sec": 0,
            "gc_cr_block_received_per_second": 0,
            "rows_per_sort": 2.27027027027027,
            "physical_read_bytes_per_sec": 0,
            "physical_writes_direct_lobs_per_sec": 0,
            "consistent_read_changes_per_txn": 2,
            "global_cache_blocks_lost": 0,
            "average_synchronous_single-block_read_latency": 0.0280373831775701,
            "physical_read_io_requests_per_sec": 0,
            "background_checkpoints_per_sec": 0,
            "enqueue_requests_per_txn": 6353.5,
            "global_cache_blocks_corrupted": 0,
            "user_transaction_per_sec": 0.0336700336700337,
            "logical_reads_per_sec": 10.5387205387205,
            "background_time_per_sec": 0.0137291582491582,
            "total_pga_used_by_sql_workareas": 0,
            "branch_node_splits_per_sec": 0,
            "px_downgraded_50_to_75pct_per_sec": 0,
            "user_rollback_undorec_applied_per_sec": 0,
            "consistent_read_gets_per_sec": 8.7037037037037,
            "consistent_read_changes_per_sec": 0.0673400673400673,
            "leaf_node_splits_per_txn": 0,
            "total_sorts_per_user_call": 0.321739130434783,
            "enqueue_requests_per_sec": 213.922558922559,
            "gc_current_block_received_per_txn": 0,
            "physical_reads_direct_per_sec": 0,
            "px_downgraded_1_to_25pct_per_sec": 0,
            "redo_allocation_hit_ratio": 100,
            "enqueue_deadlocks_per_sec": 0,
            "shared_pool_free_pct": 11.3199416627275,
            "row_cache_miss_ratio": 0,
            "database_cpu_time_ratio": 114.526926065388,
            "physical_write_io_requests_per_sec": 0.336700336700337,
            "redo_generated_per_txn": 11194,
            "enqueue_timeouts_per_sec": 0,
            "logical_reads_per_txn": 313,
            "average_active_sessions": 0.00676,
            "leaf_node_splits_per_sec": 0,
            "cursor_cache_hit_ratio": 153.703703703704,
            "physical_reads_direct_per_txn": 0,
            "branch_node_splits_per_txn": 0,
            "executions_per_user_call": 2.22608695652174,
            "px_operations_not_downgraded_per_sec": 0.0673400673400673,
            "workload_capture_and_replay_status": 0,
            "user_calls_per_sec": 1.93602693602694,
            "physical_read_total_bytes_per_sec": 57121.6161616162,
            "run_queue_per_sec": 0,
            "open_cursors_per_txn": 126,
            "physical_writes_per_txn": 10,
            "global_cache_average_cr_get_time": 0,
            "global_cache_average_current_get_time": 0,
            "gc_current_block_received_per_second": 0,
            "px_downgraded_25_to_50pct_per_sec": 0,
            "user_limit_pct": 0.00000109430402542797,
            "user_calls_ratio": 8.11573747353564,
            "current_logons_count": 47,
            "library_cache_miss_ratio": 0,
            "physical_writes_direct_lobs__per_txn": 0,
            "queries_parallelized_per_sec": 0,
            "total_table_scans_per_sec": 0.303030303030303,
            "physical_write_total_bytes_per_sec": 18350.9764309764,
            "io_megabytes_per_second": 0.0841750841750842,
            "execute_without_parse_ratio": 57.8125,
            "hard_parse_count_per_sec": 0,
            "user_commits_percentage": 100,
            "redo_generated_per_sec": 376.902356902357,
            "enqueue_timeouts_per_txn": 0,
            "captured_user_calls": 0,
            "physical_reads_direct_lobs_per_txn": 0,
            "session_limit_pct": 13.9830508474576,
            "pq_qc_session_count": 0,
            "host_cpu_usage_per_sec": 92.3905723905724,
            "physical_reads_direct_lobs_per_sec": 0,
            "parse_failure_count_per_txn": 0,
            "open_cursors_per_sec": 4.24242424242424,
            "user_rollbacks_per_sec": 0,
            "full_index_scans_per_sec": 0,
            "physical_writes_per_sec": 0.336700336700337,
            "physical_write_bytes_per_sec": 2758.24915824916,
            "memory_sorts_ratio": 100,
            "streams_pool_usage_percentage": 0,
            "user_rollbacks_percentage": 0,
            "consistent_read_gets_per_txn": 258.5,
            "user_commits_per_sec": 0.0336700336700337,
            "background_cpu_usage_per_sec": 0.626880471380471,
            "database_wait_time_ratio": 0,
            "user_calls_per_txn": 57.5,
            "hard_parse_count_per_txn": 0,
            "total_table_scans_per_txn": 9,
            "ddl_statements_parallelized_per_sec": 0,
            "temp_space_used": 0,
            "enqueue_waits_per_txn": 2,
            "io_requests_per_second": 5.23569023569024,
            "library_cache_hit_ratio": 100,
            "logons_per_sec": 0.420875420875421,
            "full_index_scans_per_txn": 0,
            "txns_per_logon": 0.08,
            "pga_cache_hit_pct": 100,
            "physical_reads_per_txn": 0,
            "host_cpu_utilization_pct": 11.6182572614108,
            "sql_service_response_time": 0.0283376146788991,
            "db_block_gets_per_user_call": 0.947826086956522,
            "physical_reads_per_sec": 0,
            "soft_parse_ratio": 100,
            "total_index_scans_per_sec": 3.06397306397306,
            "executions_per_txn": 128,
            "disk_sort_per_txn": 0,
            "logons_per_txn": 12.5,
            "enqueue_waits_per_sec": 0.0673400673400673,
            "physical_write_total_io_requests_per_sec": 1.48148148148148,
            "replayed_user_calls": 0,
            "dml_statements_parallelized_per_sec": 0,
            "cr_blocks_created_per_sec": 0,
            "total_table_scans_per_user_call": 0.156521739130435,
            "buffer_cache_hit_ratio": 100,
            "vm_in_bytes_per_sec": 0,
            "redo_writes_per_txn": 5.5,
            "network_traffic_volume_per_sec": 522.289562289562,
            "executions_per_sec": 4.30976430976431,
            "total_index_scans_per_txn": 91,
            "redo_writes_per_sec": 0.185185185185185,
            "recursive_calls_per_txn": 651,
            "total_parse_count_per_sec": 1.81818181818182
        }
    },
    "service": {
        "address": "oracle://localhost:1521/ORCLCDB.localdomain",
        "type": "sql"
    }
}
```
