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
| client.user.id | Unique identifier of the user. | keyword |
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
| oracle.database_audit.comment_text | Additional comments about the related audit record. | text |
| oracle.database_audit.database.host | Client host machine name. | keyword |
| oracle.database_audit.database.id | Database identifier calculated when the database is created. It corresponds to the DBID column of the V$DATABASE data dictionary view. | keyword |
| oracle.database_audit.database.user | The database user used to authenticate. | keyword |
| oracle.database_audit.entry.id | Indicates the current audit entry number, assigned to each audit trail record. The audit entry.id sequence number is shared between fine-grained audit records and regular audit records. | long |
| oracle.database_audit.length | Refers to the total number of bytes used in this audit record. This number includes the trailing newline bytes (\n), if any, at the end of the audit record. | long |
| oracle.database_audit.obj_creator | The owner of the object, equivalent field in DBA_AUDIT_Trail is OWNER. | keyword |
| oracle.database_audit.obj_name | The name of the object. | keyword |
| oracle.database_audit.os_userid | The related OS user. | keyword |
| oracle.database_audit.privilege | The privilege group related to the database user. | keyword |
| oracle.database_audit.returncode | Indicates if the audited action was successful. 0 indicates success. If the action fails, the return code lists the Oracle Database error number. | keyword |
| oracle.database_audit.ses_actions | Defines the type of action performed using 12 characters, each position indicates the result of an action. They are: ALTER, AUDIT, COMMENT, DELETE, GRANT, INDEX, INSERT, LOCK, RENAME, SELECT, UPDATE, and FLASHBACK. | keyword |
| oracle.database_audit.ses_tid | The ID of the object related to the audit event. | keyword |
| oracle.database_audit.session_id | Indicates the audit session ID number. | keyword |
| oracle.database_audit.statement | The statement ID related to the audit event. | keyword |
| oracle.database_audit.status | Database Audit Status. | keyword |
| oracle.database_audit.terminal | The terminal identifier. | keyword |
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
        "ephemeral_id": "9c0dd437-0b44-4ca7-a9ed-58fd8f291bf0",
        "id": "e9035b3c-b485-47ea-a7a7-f092698110a8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.0"
    },
    "client": {
        "user": {
            "name": "oracle"
        }
    },
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev"
        },
        "availability_zone": "asia-south1-c",
        "instance": {
            "id": "3010911784348669868",
            "name": "service-integration-dev-idc-01"
        },
        "machine": {
            "type": "n1-standard-8"
        },
        "project": {
            "id": "elastic-obs-integrations-dev"
        },
        "provider": "gcp",
        "service": {
            "name": "GCE"
        }
    },
    "data_stream": {
        "dataset": "oracle.database_audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "e9035b3c-b485-47ea-a7a7-f092698110a8",
        "snapshot": false,
        "version": "8.4.0"
    },
    "event": {
        "action": "database_audit",
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "oracle.database_audit",
        "ingested": "2022-10-07T13:36:38Z",
        "kind": "event",
        "outcome": "success",
        "timezone": "-04:00",
        "type": "access"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "5016511f0829451ea244f458eebf2212",
        "ip": [
            "172.23.0.7"
        ],
        "mac": [
            "02:42:ac:17:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-1078-gcp",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
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
        "offset": 858
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

### Tablespace Metrics

Tablespace metrics describes the tablespace usage metrics of all types of tablespaces in the oracle database.

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
    "@timestamp": "2022-10-07T13:51:10.988Z",
    "agent": {
        "ephemeral_id": "5eeec183-d06e-46b6-ad26-780a187b483a",
        "id": "fe56f067-831a-4cbf-8dfd-7eefe61e2884",
        "name": "docker-custom-agent",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev"
        },
        "availability_zone": "asia-south1-c",
        "instance": {
            "id": "3010911784348669868",
            "name": "service-integration-dev-idc-01"
        },
        "machine": {
            "type": "n1-standard-8"
        },
        "project": {
            "id": "elastic-obs-integrations-dev"
        },
        "provider": "gcp",
        "service": {
            "name": "GCE"
        }
    },
    "data_stream": {
        "dataset": "oracle.tablespace",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "fe56f067-831a-4cbf-8dfd-7eefe61e2884",
        "snapshot": false,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "oracle.tablespace",
        "duration": 251725096,
        "ingested": "2022-10-07T13:51:12Z",
        "module": "sql"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-custom-agent",
        "id": "5016511f0829451ea244f458eebf2212",
        "ip": [
            "172.29.0.2",
            "172.23.0.5"
        ],
        "mac": [
            "02:42:ac:17:00:05",
            "02:42:ac:1d:00:02"
        ],
        "name": "docker-custom-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-1078-gcp",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "query",
        "period": 60000
    },
    "oracle": {
        "tablespace": {
            "data_file": {
                "id": 3,
                "name": "/u02/app/oracle/oradata/ORCL/sysaux01.dbf",
                "online_status": "ONLINE",
                "size": {
                    "bytes": 723517440,
                    "free": {
                        "bytes": 722468864
                    },
                    "max": {
                        "bytes": 34359721984
                    }
                },
                "status": "AVAILABLE"
            },
            "name": "SYSAUX",
            "space": {
                "free": {
                    "bytes": 23920640
                },
                "total": {
                    "bytes": 1712324608
                },
                "used": {
                    "bytes": 723517440
                }
            }
        }
    },
    "service": {
        "address": "elastic-package-service_oracle_1:1521",
        "type": "sql"
    }
}
```

### Sysmetrics 

The system metrics value captured for the most current time interval for the long duration (60-seconds) are mentioned below

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
    "@timestamp": "2022-10-07T13:55:00.546Z",
    "agent": {
        "ephemeral_id": "1c413238-5639-4144-866e-0a5dc002b3ae",
        "id": "ab8270b9-d8eb-4966-b23b-3f60acf81fc5",
        "name": "docker-custom-agent",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev"
        },
        "availability_zone": "asia-south1-c",
        "instance": {
            "id": "3010911784348669868",
            "name": "service-integration-dev-idc-01"
        },
        "machine": {
            "type": "n1-standard-8"
        },
        "project": {
            "id": "elastic-obs-integrations-dev"
        },
        "provider": "gcp",
        "service": {
            "name": "GCE"
        }
    },
    "data_stream": {
        "dataset": "oracle.sysmetric",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "ab8270b9-d8eb-4966-b23b-3f60acf81fc5",
        "snapshot": false,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "oracle.sysmetric",
        "duration": 70105824,
        "ingested": "2022-10-07T13:55:01Z",
        "module": "sql"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-custom-agent",
        "id": "5016511f0829451ea244f458eebf2212",
        "ip": [
            "172.30.0.2",
            "172.23.0.5"
        ],
        "mac": [
            "02:42:ac:17:00:05",
            "02:42:ac:1e:00:02"
        ],
        "name": "docker-custom-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-1078-gcp",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "query",
        "period": 60000
    },
    "oracle": {
        "sysmetric": {
            "active_parallel_sessions": 0,
            "active_serial_sessions": 1,
            "average_active_sessions": 0.763702261472433,
            "average_synchronous_single-block_read_latency": 1.85720397903519,
            "background_checkpoints_per_sec": 0,
            "background_cpu_usage_per_sec": 8.80918124793661,
            "background_time_per_sec": 0.504249933971608,
            "branch_node_splits_per_sec": 0,
            "branch_node_splits_per_txn": 0,
            "buffer_cache_hit_ratio": 95.8323015411497,
            "captured_user_calls": 0,
            "cell_physical_io_interconnect_bytes": 2318690121,
            "consistent_read_changes_per_sec": 198.349290194784,
            "consistent_read_changes_per_txn": 187.75,
            "consistent_read_gets_per_sec": 5465.48365797293,
            "consistent_read_gets_per_txn": 5173.421875,
            "cpu_usage_per_sec": 16.9158385605811,
            "cpu_usage_per_txn": 16.0118984375,
            "cr_blocks_created_per_sec": 5.41432816110928,
            "cr_blocks_created_per_txn": 5.125,
            "cr_undo_records_applied_per_sec": 187.4050841862,
            "cr_undo_records_applied_per_txn": 177.390625,
            "current_logons_count": 58,
            "current_open_cursors_count": 23,
            "current_os_load": 3.0693359375,
            "cursor_cache_hit_ratio": 288.034240670033,
            "database_cpu_time_ratio": 22.149781942464,
            "database_time_per_sec": 76.3702261472433,
            "database_wait_time_ratio": 77.850218057536,
            "db_block_changes_per_sec": 532.023770221195,
            "db_block_changes_per_txn": 503.59375,
            "db_block_changes_per_user_call": 80.1741293532338,
            "db_block_gets_per_sec": 467.315945856718,
            "db_block_gets_per_txn": 442.34375,
            "db_block_gets_per_user_call": 70.4228855721393,
            "dbwr_checkpoints_per_sec": 0.0495212941564873,
            "ddl_statements_parallelized_per_sec": 0,
            "disk_sort_per_sec": 0,
            "disk_sort_per_txn": 0,
            "dml_statements_parallelized_per_sec": 0,
            "enqueue_deadlocks_per_sec": 0,
            "enqueue_deadlocks_per_txn": 0,
            "enqueue_requests_per_sec": 337.867282931661,
            "enqueue_requests_per_txn": 319.8125,
            "enqueue_timeouts_per_sec": 0.0660283922086497,
            "enqueue_timeouts_per_txn": 0.0625,
            "enqueue_waits_per_sec": 0.709805216242984,
            "enqueue_waits_per_txn": 0.671875,
            "execute_without_parse_ratio": 58.783430566882,
            "executions_per_sec": 789.418950148564,
            "executions_per_txn": 747.234375,
            "executions_per_user_call": 118.962686567164,
            "full_index_scans_per_sec": 15.8468141300759,
            "full_index_scans_per_txn": 15,
            "gc_cr_block_received_per_second": 0,
            "gc_cr_block_received_per_txn": 0,
            "gc_current_block_received_per_second": 0,
            "gc_current_block_received_per_txn": 0,
            "global_cache_average_cr_get_time": 0,
            "global_cache_average_current_get_time": 0,
            "global_cache_blocks_corrupted": 0,
            "global_cache_blocks_lost": 0,
            "hard_parse_count_per_sec": 57.3291515351601,
            "hard_parse_count_per_txn": 54.265625,
            "host_cpu_usage_per_sec": 147.457906899967,
            "host_cpu_utilization_pct": 18.5347331728774,
            "io_megabytes_per_second": 36.5137008913833,
            "io_requests_per_second": 194.569164740839,
            "leaf_node_splits_per_sec": 0.0825354902608121,
            "leaf_node_splits_per_txn": 0.078125,
            "library_cache_hit_ratio": 86.2607519496164,
            "library_cache_miss_ratio": 13.7392480503836,
            "logical_reads_per_sec": 5933.01419610432,
            "logical_reads_per_txn": 5615.96875,
            "logical_reads_per_user_call": 894.084577114428,
            "logons_per_sec": 2.12941564872895,
            "logons_per_txn": 2.015625,
            "long_table_scans_per_sec": 0,
            "long_table_scans_per_txn": 0,
            "memory_sorts_ratio": 100,
            "network_traffic_volume_per_sec": 272.499174645097,
            "open_cursors_per_sec": 676.758005942555,
            "open_cursors_per_txn": 640.59375,
            "parse_failure_count_per_sec": 0.445691647408386,
            "parse_failure_count_per_txn": 0.421875,
            "pga_cache_hit_pct": 100,
            "physical_read_bytes_per_sec": 2027310.39947177,
            "physical_read_io_requests_per_sec": 145.757675800594,
            "physical_read_total_bytes_per_sec": 20257138.8577088,
            "physical_read_total_io_requests_per_sec": 181.247936612743,
            "physical_reads_direct_lobs_per_sec": 0.0165070980521624,
            "physical_reads_direct_lobs_per_txn": 0.015625,
            "physical_reads_direct_per_sec": 0.214592274678112,
            "physical_reads_direct_per_txn": 0.203125,
            "physical_reads_per_sec": 247.474413998019,
            "physical_reads_per_txn": 234.25,
            "physical_write_bytes_per_sec": 2569.29679762298,
            "physical_write_io_requests_per_sec": 0.313634862991086,
            "physical_write_total_bytes_per_sec": 18017706.3222186,
            "physical_write_total_io_requests_per_sec": 31.9247276328821,
            "physical_writes_direct_lobs__per_txn": 0.015625,
            "physical_writes_direct_lobs_per_sec": 0.0165070980521624,
            "physical_writes_direct_per_sec": 0.165070980521624,
            "physical_writes_direct_per_txn": 0.15625,
            "physical_writes_per_sec": 0.313634862991086,
            "physical_writes_per_txn": 0.296875,
            "pq_qc_session_count": 0,
            "pq_slave_session_count": 0,
            "process_limit_pct": 32,
            "px_downgraded_1_to_25pct_per_sec": 0,
            "px_downgraded_25_to_50pct_per_sec": 0,
            "px_downgraded_50_to_75pct_per_sec": 0,
            "px_downgraded_75_to_99pct_per_sec": 0,
            "px_downgraded_to_serial_per_sec": 0,
            "px_operations_not_downgraded_per_sec": 0.0990425883129746,
            "queries_parallelized_per_sec": 0.0330141961043249,
            "recursive_calls_per_sec": 3343.26510399472,
            "recursive_calls_per_txn": 3164.609375,
            "redo_allocation_hit_ratio": 99.9522388059702,
            "redo_generated_per_sec": 76213.2717068339,
            "redo_generated_per_txn": 72140.625,
            "redo_writes_per_sec": 7.03202377022119,
            "redo_writes_per_txn": 6.65625,
            "replayed_user_calls": 0,
            "response_time_per_txn": 72.2891921875,
            "row_cache_hit_ratio": 92.3379204207569,
            "row_cache_miss_ratio": 7.66207957924306,
            "rows_per_sort": 14.9770789502824,
            "run_queue_per_sec": 0,
            "session_count": 70,
            "session_limit_pct": 14.8305084745763,
            "shared_pool_free_pct": 9.46832958020662,
            "soft_parse_ratio": 82.3803967327888,
            "sql_service_response_time": 0.0227977564465819,
            "streams_pool_usage_percentage": 0,
            "temp_space_used": 0,
            "total_index_scans_per_sec": 731.693628260152,
            "total_index_scans_per_txn": 692.59375,
            "total_parse_count_per_sec": 325.371409706174,
            "total_parse_count_per_txn": 307.984375,
            "total_pga_allocated": 298474496,
            "total_pga_used_by_sql_workareas": 0,
            "total_sorts_per_user_call": 22.4651741293532,
            "total_table_scans_per_sec": 42.3407065037966,
            "total_table_scans_per_txn": 40.078125,
            "total_table_scans_per_user_call": 6.38059701492537,
            "txns_per_logon": 0.496124031007752,
            "user_calls_per_sec": 6.6358534169693,
            "user_calls_per_txn": 6.28125,
            "user_calls_ratio": 0.198091033177784,
            "user_commits_per_sec": 1.03994717728623,
            "user_commits_percentage": 98.4375,
            "user_limit_pct": 0.00000135041773350686,
            "user_rollback_undo_records_applied_per_txn": 0.1875,
            "user_rollback_undorec_applied_per_sec": 0.198085176625949,
            "user_rollbacks_per_sec": 0.0165070980521624,
            "user_rollbacks_percentage": 1.5625,
            "user_transaction_per_sec": 1.0564542753384,
            "vm_in_bytes_per_sec": 0,
            "vm_out_bytes_per_sec": 0,
            "workload_capture_and_replay_status": 0
        }
    },
    "service": {
        "address": "elastic-package-service_oracle_1:1521",
        "type": "sql"
    }
}
```

### Memory Metrics 

A Program Global Area (PGA) is a memory region that contains data and control information for a server process. It is nonshared memory created by Oracle Database when a server process is started. Access to the PGA is exclusive to the server process. Metrics concerning Program Global Area (PGA) memory are mentioned below.

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
| oracle.memory.pga.aggregate_auto_target | Amount of PGA memory the Oracle Database can use for work areas running in automatic mode. | double | byte | gauge |
| oracle.memory.pga.aggregate_target_parameter | Current value of the PGA_AGGREGATE_TARGET initialization parameter. If this parameter is not set, then its value is 0 and automatic management of PGA memory is disabled. | double | byte | gauge |
| oracle.memory.pga.cache_hit_pct | A metric computed by the Oracle Database to reflect the performance of the PGA memory component, cumulative since instance startup. | double | percent | gauge |
| oracle.memory.pga.global_memory_bound | Maximum size of a work area executed in automatic mode. | double | byte | gauge |
| oracle.memory.pga.maximum_allocated | Maximum number of bytes of PGA memory allocated at one time since instance startup. | double | byte | gauge |
| oracle.memory.pga.total_allocated | Current amount of PGA memory allocated by the instance. | double | byte | gauge |
| oracle.memory.pga.total_freeable_memory | Number of bytes of PGA memory in all processes that could be freed back to the operating system. | double | byte | gauge |
| oracle.memory.pga.total_inuse | Indicates how much PGA memory is currently consumed by work areas. This number can be used to determine how much memory is consumed by other consumers of the PGA memory (for example, PL/SQL or Java). | double | byte | gauge |
| oracle.memory.pga.total_used_for_auto_workareas | Indicates how much PGA memory is currently consumed by work areas running under the automatic memory management mode. This number can be used to determine how much memory is consumed by other consumers of the PGA memory (for example, PL/SQL or Java). | double | byte | gauge |
| oracle.memory.sga.free_memory | Amount of free memory in the Shared pool. | double | byte | gauge |
| oracle.memory.sga.total_memory | Amount of total memory in the Shared pool. | double | byte | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


An example event for `memory` looks as following:

```json
{
    "@timestamp": "2022-10-07T13:39:29.922Z",
    "agent": {
        "ephemeral_id": "8dd84084-f02d-40df-8642-ad22035bbf78",
        "id": "f5f65ff4-151c-4b09-876d-a46acf38f06d",
        "name": "docker-custom-agent",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev"
        },
        "availability_zone": "asia-south1-c",
        "instance": {
            "id": "3010911784348669868",
            "name": "service-integration-dev-idc-01"
        },
        "machine": {
            "type": "n1-standard-8"
        },
        "project": {
            "id": "elastic-obs-integrations-dev"
        },
        "provider": "gcp",
        "service": {
            "name": "GCE"
        }
    },
    "data_stream": {
        "dataset": "oracle.memory",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f5f65ff4-151c-4b09-876d-a46acf38f06d",
        "snapshot": false,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "oracle.memory",
        "duration": 103851536,
        "ingested": "2022-10-07T13:39:31Z",
        "module": "sql"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-custom-agent",
        "id": "5016511f0829451ea244f458eebf2212",
        "ip": [
            "172.25.0.2",
            "172.23.0.5"
        ],
        "mac": [
            "02:42:ac:17:00:05",
            "02:42:ac:19:00:02"
        ],
        "name": "docker-custom-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-1078-gcp",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "query",
        "period": 60000
    },
    "oracle": {
        "memory": {
            "pga": {
                "aggregate_auto_target": 569124864,
                "aggregate_target_parameter": 805306368,
                "cache_hit_pct": 100,
                "global_memory_bound": 104857600,
                "maximum_allocated": 334553088,
                "total_allocated": 200572928,
                "total_freeable_memory": 34930688,
                "total_inuse": 147128320,
                "total_used_for_auto_workareas": 0
            },
            "sga": {
                "free_memory": 30123968,
                "total_memory": 335544320
            }
        }
    },
    "service": {
        "address": "elastic-package-service_oracle_1:1521",
        "type": "sql"
    }
}
```

### System Statistics Metrics 

The System Global Area (SGA) is a group of shared memory structures that contain data and control information for one Oracle Database instance. Metrics concerning System Global Area (SGA) memory are mentioned below.

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
| oracle.system_statistics.bytes_received_via_sqlnet_from_client | Total number of bytes received from the client over Oracle Net Services. | double | byte | counter |
| oracle.system_statistics.bytes_received_via_sqlnet_from_dblink | Total number of bytes received from a database link over Oracle Net Services | double | byte | counter |
| oracle.system_statistics.bytes_sent_via_sqlnet_to_client | Total number of bytes sent to the client from the foreground processes. | double | byte | counter |
| oracle.system_statistics.bytes_sent_via_sqlnet_to_dblink | Total number of bytes sent over a database link. | double | byte | counter |
| oracle.system_statistics.cpu_used_by_this_session | Amount of CPU time (in 10s of milliseconds) used by a session from the time a user call starts until it ends. | double | ms | counter |
| oracle.system_statistics.db_block_changes | This statistic counts the total number of changes that were part of an update or delete operation that were made to all blocks in the SGA. | double |  | counter |
| oracle.system_statistics.db_block_gets_from_cache | The number of times a CURRENT block was requested from the buffer cache. | double |  | counter |
| oracle.system_statistics.db_time | The sum of CPU consumption of all the Oracle process and the sum of non-idle wait time. | double |  | counter |
| oracle.system_statistics.dbwr_checkpoint_buffers_written | The number of buffers that were written for checkpoints. | double |  | counter |
| oracle.system_statistics.dbwr_checkpoints | The number of times the DBWR was asked to scan the cache and write all blocks marked for a checkpoint or the end of recovery. | double |  | counter |
| oracle.system_statistics.dml_statements_parallelized | The number of DML statements that were executed in parallel. | double |  | counter |
| oracle.system_statistics.enqueue_conversions | Total number of conversions of the state of table or row lock. | double |  | counter |
| oracle.system_statistics.enqueue_deadlocks | Total number of deadlocks between table or row locks in different sessions. | double |  | counter |
| oracle.system_statistics.enqueue_releases | Total number of table or row locks released. | double |  | counter |
| oracle.system_statistics.enqueue_requests | Total number of table or row locks acquired | double |  | counter |
| oracle.system_statistics.enqueue_timeouts | Total number of table and row locks (acquired and converted) that timed out before they could complete. | double |  | counter |
| oracle.system_statistics.enqueue_waits | Total number of waits that occurred during an enqueue convert or get because the enqueue get was deferred. | double |  | counter |
| oracle.system_statistics.exchange_deadlocks | Number of times that a process detected a potential deadlock when exchanging two buffers and raised an internal, restartable error. Index scans are the only operations that perform exchanges. | double |  | counter |
| oracle.system_statistics.execute_count | Total number of calls (user and recursive) that executed SQL statements. | double |  | counter |
| oracle.system_statistics.gc_current_block_receive_time | The total time required for consistent read requests to complete. It records the round-trip time for all requests for consistent read blocks. | double |  | counter |
| oracle.system_statistics.index_fast_full_scans_direct_read | The number of fast full scans initiated using direct read. | double |  | counter |
| oracle.system_statistics.index_fast_full_scans_full | The number of fast full scans initiated using direct read. | double |  | counter |
| oracle.system_statistics.index_fast_full_scans_rowid_ranges | The number of fast full scans initiated with rowid endpoints specified. | double |  | counter |
| oracle.system_statistics.java_call_heap_live_size | The Java call heap live size. | double |  | counter |
| oracle.system_statistics.java_call_heap_total_size | The total Java call heap size. | double | byte | counter |
| oracle.system_statistics.java_call_heap_used_size | The Java call heap used size. | double |  | counter |
| oracle.system_statistics.lob_reads | The number of LOB API read operations performed in the session/system. | double |  | counter |
| oracle.system_statistics.lob_writes | The number of LOB API write operations performed in the session/system. | double |  | counter |
| oracle.system_statistics.logons_current | Total number of current logons. | double |  | counter |
| oracle.system_statistics.opened_cursors_current | Total number of current open cursors. | double |  | counter |
| oracle.system_statistics.os_system_time_used | The  total CPU time used for system calls. | double |  | counter |
| oracle.system_statistics.os_user_time_used | The total CPU time used for user calls. | double |  | counter |
| oracle.system_statistics.parallel_operations_not_downgraded | Number of times parallel execution was executed at the requested degree of parallelism | double |  | counter |
| oracle.system_statistics.parse_count_hard | Total number of parse calls (real parses). | double |  | counter |
| oracle.system_statistics.parse_count_total | Total number of parse calls (hard, soft, and describe). | double |  | counter |
| oracle.system_statistics.parse_time_cpu | Total CPU time used for parsing (hard and soft) in 10s of milliseconds | double | ms | counter |
| oracle.system_statistics.parse_time_elapsed | Total elapsed time for parsing, in 10s of milliseconds. | double | ms | counter |
| oracle.system_statistics.physical_read_bytes | Total size in bytes of all disk reads by application activity (and not other instance activity) only. | double | byte | counter |
| oracle.system_statistics.physical_read_io_requests | Number of read requests for application activity (mainly buffer cache and direct load operation) which read one or more database blocks per request. | double |  | counter |
| oracle.system_statistics.physical_read_total_bytes | Total size in bytes of disk reads by all database instance activity including application reads, backup and recovery, and other utilities. | double | byte | counter |
| oracle.system_statistics.physical_read_total_io_requests | The number of read requests which read one or more database blocks for all instance activity including application, backup and recovery, and other utilities. | double |  | counter |
| oracle.system_statistics.physical_reads | Total number of data blocks read from disk. | double |  | counter |
| oracle.system_statistics.physical_write_bytes | Total size in bytes of all disk writes from the database application activity (and not other kinds of instance activity). | double | byte | counter |
| oracle.system_statistics.physical_write_io_requests | Number of write requests for application activity (mainly buffer cache and direct load operation) which wrote one or more database blocks per request. | double |  | counter |
| oracle.system_statistics.physical_write_total_bytes | Total size in bytes of all disk writes for the database instance including application activity, backup and recovery, and other utilities. | double | byte | counter |
| oracle.system_statistics.physical_write_total_io_requests | The number of write requests which wrote one or more database blocks from all instance activity including application activity, backup and recovery, and other utilities. | double |  | counter |
| oracle.system_statistics.physical_writes | Total number of data blocks written to disk. This statistics value equals the sum of physical writes direct and physical writes from cache values. | double |  | counter |
| oracle.system_statistics.physical_writes_direct | Number of writes directly to disk, bypassing the buffer cache (as in a direct load operation). | double |  | counter |
| oracle.system_statistics.physical_writes_from_cache | Total number of data blocks written to disk from the buffer cache. This is a subset of "physical writes" statistic. | double |  | counter |
| oracle.system_statistics.process_last_non_idle_time | The last time this process executed. | double |  | counter |
| oracle.system_statistics.queries_parallelized | Number of SELECT statements executed in parallel. | double |  | counter |
| oracle.system_statistics.recovery_blocks_read | The number of blocks read during recovery. | double |  | counter |
| oracle.system_statistics.recursive_calls | The number of recursive calls generated at both the user and system level. | double |  | counter |
| oracle.system_statistics.recursive_cpu_usage | Total CPU time used by non-user calls (recursive calls). | double |  | counter |
| oracle.system_statistics.redo_blocks_written | Total number of redo blocks written. | double |  | counter |
| oracle.system_statistics.redo_buffer_allocation_retries | Total number of retries necessary to allocate space in the redo buffer. | double |  | counter |
| oracle.system_statistics.redo_log_space_requests | The number of times the active log file is full and Oracle must wait for disk space to be allocated for the redo log entries. | double |  | counter |
| oracle.system_statistics.redo_log_space_wait_time | Total time waited in centiseconds for available space in the redo log buffer. | double |  | counter |
| oracle.system_statistics.redo_size | Total amount of redo generated in bytes. | double | byte | counter |
| oracle.system_statistics.redo_synch_time | Elapsed time of all redo synch writes calls in 10s of milliseconds. | double | ms | counter |
| oracle.system_statistics.redo_write_time | Total elapsed time of the write from the redo log buffer to the current redo log file in microseconds. | double | micros | counter |
| oracle.system_statistics.redo_writes | Total number of writes by LGWR to the redo log files. | double |  | counter |
| oracle.system_statistics.session_cursor_cache_count | Total number of cursors cached. | double |  | counter |
| oracle.system_statistics.session_cursor_cache_hits | Total number of cursors cached. | double |  | counter |
| oracle.system_statistics.session_logical_reads | The sum of db block gets plus consistent gets. This includes logical reads of database blocks from either the buffer cache or process private memory. | double |  | counter |
| oracle.system_statistics.session_stored_procedure_space | Amount of memory this session is using for stored procedures. | double |  | counter |
| oracle.system_statistics.smon_posted_for_instance_recovery | The total count or number of times SMON posted for instance recovery. | double |  | counter |
| oracle.system_statistics.smon_posted_for_txn_recovery_for_other_instances | The total count or number of times SMON posted for instance recovery | double |  | counter |
| oracle.system_statistics.sorts_disk | The number of sort operations that required at least one disk write. | double |  | counter |
| oracle.system_statistics.sorts_memory | The number of sort operations that were performed completely in memory and did not require any disk writes. | double |  | counter |
| oracle.system_statistics.sorts_rows | Total number of rows sorted. | double |  | counter |
| oracle.system_statistics.table_scan_rows_gotten | Number of rows that are processed during scanning operations. | double |  | counter |
| oracle.system_statistics.table_scans_direct_read | The number of table scans performed with direct read (bypassing the buffer cache). | double |  | counter |
| oracle.system_statistics.table_scans_long_tables | Long (or conversely short) tables can be defined as tables that do not meet the short table criteria. | double |  | counter |
| oracle.system_statistics.table_scans_rowid_ranges | During parallel query, the number of table scans conducted with specified ROWID ranges. | double |  | counter |
| oracle.system_statistics.transaction_rollbacks | Number of transactions being successfully rolled back. | double |  | counter |
| oracle.system_statistics.user_calls | Number of user calls such as login, parse, fetch, or execute. | double |  | counter |
| oracle.system_statistics.user_commits | Number of user commits. When a user commits a transaction, the redo generated that reflects the changes made to database blocks must be written to disk. | double |  | counter |
| oracle.system_statistics.user_rollbacks | Number of times users manually issue the ROLLBACK statement or an error occurs during a user's transactions. | double |  | counter |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


An example event for `system_statistics` looks as following:

```json
{
    "@timestamp": "2022-10-07T13:48:15.201Z",
    "agent": {
        "ephemeral_id": "f2d450a8-4b36-4312-a7d3-d40e9dd497de",
        "id": "86617af8-bc78-468e-974e-f1f6c2f4252a",
        "name": "docker-custom-agent",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev"
        },
        "availability_zone": "asia-south1-c",
        "instance": {
            "id": "3010911784348669868",
            "name": "service-integration-dev-idc-01"
        },
        "machine": {
            "type": "n1-standard-8"
        },
        "project": {
            "id": "elastic-obs-integrations-dev"
        },
        "provider": "gcp",
        "service": {
            "name": "GCE"
        }
    },
    "data_stream": {
        "dataset": "oracle.system_statistics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "86617af8-bc78-468e-974e-f1f6c2f4252a",
        "snapshot": false,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "oracle.system_statistics",
        "duration": 78582802,
        "ingested": "2022-10-07T13:48:16Z",
        "module": "sql"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-custom-agent",
        "id": "5016511f0829451ea244f458eebf2212",
        "ip": [
            "172.28.0.2",
            "172.23.0.5"
        ],
        "mac": [
            "02:42:ac:17:00:05",
            "02:42:ac:1c:00:02"
        ],
        "name": "docker-custom-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-1078-gcp",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "query",
        "period": 60000
    },
    "oracle": {
        "system_statistics": {
            "bytes_received_via_sqlnet_from_client": 14721,
            "bytes_received_via_sqlnet_from_dblink": 0,
            "bytes_sent_via_sqlnet_to_client": 25089,
            "bytes_sent_via_sqlnet_to_dblink": 0,
            "cpu_used_by_this_session": 1757,
            "db_block_changes": 31452,
            "db_block_gets_from_cache": 26812,
            "db_time": 64663,
            "dbwr_checkpoint_buffers_written": 0,
            "dbwr_checkpoints": 3,
            "dml_statements_parallelized": 0,
            "enqueue_conversions": 474,
            "enqueue_deadlocks": 0,
            "enqueue_releases": 23216,
            "enqueue_requests": 23256,
            "enqueue_timeouts": 9,
            "enqueue_waits": 48,
            "exchange_deadlocks": 0,
            "execute_count": 53816,
            "gc_current_block_receive_time": 0,
            "index_fast_full_scans_direct_read": 0,
            "index_fast_full_scans_full": 825,
            "index_fast_full_scans_rowid_ranges": 0,
            "java_call_heap_live_size": 0,
            "java_call_heap_total_size": 0,
            "java_call_heap_used_size": 0,
            "lob_reads": 46,
            "lob_writes": 126,
            "logons_current": 41,
            "opened_cursors_current": 25,
            "os_system_time_used": 0,
            "os_user_time_used": 0,
            "parallel_operations_not_downgraded": 8,
            "parse_count_hard": 4172,
            "parse_count_total": 20567,
            "parse_time_cpu": 565,
            "parse_time_elapsed": 1151,
            "physical_read_bytes": 143777792,
            "physical_read_io_requests": 10867,
            "physical_read_total_bytes": 1262504960,
            "physical_read_total_io_requests": 13544,
            "physical_reads": 17551,
            "physical_write_bytes": 188416,
            "physical_write_io_requests": 23,
            "physical_write_total_bytes": 1093925193,
            "physical_write_total_io_requests": 2109,
            "physical_writes": 23,
            "physical_writes_direct": 14,
            "physical_writes_from_cache": 9,
            "process_last_non_idle_time": 1665150494,
            "queries_parallelized": 2,
            "recovery_blocks_read": 0,
            "recursive_calls": 222360,
            "recursive_cpu_usage": 1431,
            "redo_blocks_written": 9450,
            "redo_buffer_allocation_retries": 4,
            "redo_log_space_requests": 32,
            "redo_log_space_wait_time": 309,
            "redo_size": 4575392,
            "redo_synch_time": 556,
            "redo_write_time": 287,
            "redo_writes": 392,
            "session_cursor_cache_count": 4016,
            "session_cursor_cache_hits": 53035,
            "session_logical_reads": 369510,
            "session_stored_procedure_space": 0,
            "smon_posted_for_instance_recovery": 0,
            "smon_posted_for_txn_recovery_for_other_instances": 0,
            "sorts_disk": 0,
            "sorts_memory": 12253,
            "sorts_rows": 155361,
            "table_scan_rows_gotten": 3034247,
            "table_scans_direct_read": 0,
            "table_scans_long_tables": 0,
            "table_scans_rowid_ranges": 0,
            "transaction_rollbacks": 6,
            "user_calls": 559,
            "user_commits": 60,
            "user_rollbacks": 1
        }
    },
    "service": {
        "address": "elastic-package-service_oracle_1:1521",
        "type": "sql"
    }
}
```

### Performance Metrics

Performance metrics give an overview of where time is spent in the system and enable comparisons of wait times across the system.

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
| oracle.performance.failed_db_jobs | This metric checks for failed DBMS jobs. | double |  | gauge |
| oracle.performance.io_reloads | Reloads by Pins ratio. A Reload is any PIN of an object that is not the first PIN performed since the object handle was created, and which requires loading the object from disk. Pins are the number of times a PIN was requested for objects of this namespace. | double |  | gauge |
| oracle.performance.lock_requests | Average of the ratio between 'gethits' and 'gets', where 'gethits' the number of times an object's handle was found in memory and 'gets' is the number of times a lock was requested for objects of this namespace. | double |  | gauge |
| oracle.performance.machine | Operating system machine name. | keyword |  |  |
| oracle.performance.pin_requests | Average of all pinhits/pins ratios, where 'PinHits' is the number of times all of the metadata pieces of the library object were found in memory and 'pins' is the number of times a PIN was requested for objects of this namespace. | double |  | gauge |
| oracle.performance.session_count.active | Total count of sessions. | double |  | gauge |
| oracle.performance.session_count.inactive | Total count of Inactive sessions. | double |  | gauge |
| oracle.performance.session_count.inactive_morethan_onehr | Total inactive sessions more than one hour. | double |  | gauge |
| oracle.performance.username | Oracle username | keyword |  |  |
| oracle.performance.wait.pct_time | Percentage of time waits that are not Idle wait class. | double | percent | gauge |
| oracle.performance.wait.pct_waits | Percentage of number of pct time waits that are not of Idle wait class. | double | percent | gauge |
| oracle.performance.wait.time_waited_secs | Amount of time spent in the wait class by the session. | double | s | gauge |
| oracle.performance.wait.total_waits | Number of times waits of the class occurred for the session. | double |  | counter |
| oracle.performance.wait.wait_class | Every wait event belongs to a class of wait event. Wait classes can be one of the following - Administrative, Application, Cluster, Commit, Concurrency, Configuration, Idle, Network, Other, Scheduler, System IO, User IO | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


An example event for `performance` looks as following:

```json
{
    "@timestamp": "2022-10-07T13:42:25.922Z",
    "agent": {
        "ephemeral_id": "cfd75b5a-ee3e-4747-867d-26066b5f2fa2",
        "id": "c7fd3bdf-1cef-4832-a28a-dfba467cec42",
        "name": "docker-custom-agent",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev"
        },
        "availability_zone": "asia-south1-c",
        "instance": {
            "id": "3010911784348669868",
            "name": "service-integration-dev-idc-01"
        },
        "machine": {
            "type": "n1-standard-8"
        },
        "project": {
            "id": "elastic-obs-integrations-dev"
        },
        "provider": "gcp",
        "service": {
            "name": "GCE"
        }
    },
    "data_stream": {
        "dataset": "oracle.performance",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "c7fd3bdf-1cef-4832-a28a-dfba467cec42",
        "snapshot": false,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "oracle.performance",
        "duration": 86829497,
        "ingested": "2022-10-07T13:42:27Z",
        "module": "sql"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-custom-agent",
        "id": "5016511f0829451ea244f458eebf2212",
        "ip": [
            "172.26.0.2",
            "172.23.0.5"
        ],
        "mac": [
            "02:42:ac:17:00:05",
            "02:42:ac:1a:00:02"
        ],
        "name": "docker-custom-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-1078-gcp",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "query",
        "period": 60000
    },
    "oracle": {
        "performance": {
            "buffer_pool": "DEFAULT",
            "cache": {
                "buffer": {
                    "hit": {
                        "pct": 0.9500370839435895
                    }
                },
                "get": {
                    "consistent": 345751,
                    "db_blocks": 27726
                },
                "physical_reads": 18660
            }
        }
    },
    "service": {
        "address": "elastic-package-service_oracle_1:1521",
        "type": "sql"
    }
}
```
