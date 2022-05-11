# MySQL Enterprise Integration

This integration is for different types of MySQL logs. Currently focusing on data from the MySQL Enterprise Audit Plugin in JSON format.

To configure the the Enterprise Audit Plugin to output in JSON format please follow the directions in the [MySQL Documentation](https://dev.mysql.com/doc/refman/8.0/en/audit-log-file-formats.html).

## Compatibility

This integration has been tested against MySQL Enterprise 5.7.x and 8.0.x

### Audit Log

The `audit` dataset collects MySQL Enterprise Audit logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.full.text | Multi-field of `host.os.full`. | match_only_text |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| message | human-readable summary of the event | text |
| mysqlenterprise.audit.account.host | A string representing the client host name. | keyword |
| mysqlenterprise.audit.account.user | A string representing the user that the server authenticated the client as. This is the user name that the server uses for privilege checking. | keyword |
| mysqlenterprise.audit.class | A string representing the event class. The class defines the type of event, when taken together with the event item that specifies the event subclass. | keyword |
| mysqlenterprise.audit.connection_data.connection_attributes | Connection attributes that might be passed by different MySQL Clients. | flattened |
| mysqlenterprise.audit.connection_data.connection_type | The security state of the connection to the server. Permitted values are tcp/ip (TCP/IP connection established without encryption), ssl (TCP/IP connection established with encryption), socket (Unix socket file connection), named_pipe (Windows named pipe connection), and shared_memory (Windows shared memory connection). | keyword |
| mysqlenterprise.audit.connection_data.db | A string representing a database name. For connection_data, it is the default database. For table_access_data, it is the table database. | keyword |
| mysqlenterprise.audit.connection_data.status | An integer representing the command status: 0 for success, nonzero if an error occurred. | long |
| mysqlenterprise.audit.connection_id | An integer representing the client connection identifier. This is the same as the value returned by the CONNECTION_ID() function within the session. | keyword |
| mysqlenterprise.audit.general_data.command | A string representing the type of instruction that generated the audit event, such as a command that the server received from a client. | keyword |
| mysqlenterprise.audit.general_data.query | A string representing the text of an SQL statement. The value can be empty. Long values may be truncated. The string, like the audit log file itself, is written using UTF-8 (up to 4 bytes per character), so the value may be the result of conversion. | keyword |
| mysqlenterprise.audit.general_data.sql_command | A string that indicates the SQL statement type. | keyword |
| mysqlenterprise.audit.general_data.status | An integer representing the command status: 0 for success, nonzero if an error occurred. This is the same as the value of the mysql_errno() C API function. | long |
| mysqlenterprise.audit.id | An unsigned integer representing an event ID. | keyword |
| mysqlenterprise.audit.login.os | A string representing the external user name used during the authentication process, as set by the plugin used to authenticate the client. | keyword |
| mysqlenterprise.audit.login.proxy | A string representing the proxy user. The value is empty if user proxying is not in effect. | keyword |
| mysqlenterprise.audit.login.user | A string representing the information indicating how a client connected to the server. | keyword |
| mysqlenterprise.audit.shutdown_data.server_id | An integer representing the server ID. This is the same as the value of the server_id system variable. | keyword |
| mysqlenterprise.audit.startup_data.mysql_version | An integer representing the server ID. This is the same as the value of the server_id system variable. | keyword |
| mysqlenterprise.audit.startup_data.server_id | An integer representing the server ID. This is the same as the value of the server_id system variable. | keyword |
| mysqlenterprise.audit.table_access_data.db | A string representing a database name. For connection_data, it is the default database. For table_access_data, it is the table database. | keyword |
| mysqlenterprise.audit.table_access_data.query | A string representing the text of an SQL statement. The value can be empty. Long values may be truncated. The string, like the audit log file itself, is written using UTF-8 (up to 4 bytes per character), so the value may be the result of conversion. | keyword |
| mysqlenterprise.audit.table_access_data.sql_command | A string that indicates the SQL statement type. | keyword |
| mysqlenterprise.audit.table_access_data.table | A string representing a table name. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| server.user.name | Short name or login of the user. | keyword |
| server.user.name.text | Multi-field of `server.user.name`. | match_only_text |
| service.id | Unique identifier of the running service. If the service is comprised of many nodes, the `service.id` should be the same for all nodes. This id should uniquely identify the service. This makes it possible to correlate logs and metrics for one specific service, no matter which particular node emitted the event. Note that if you need to see the events from one specific host of the service, you should filter on that `host.name` or `host.id` instead. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2020-10-19T19:21:33.000Z",
    "agent": {
        "ephemeral_id": "d192381e-e559-464a-876d-058ff4104145",
        "id": "1202ee7c-96a3-47b6-8ddf-4fd17e23f288",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "mysql_enterprise.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "1202ee7c-96a3-47b6-8ddf-4fd17e23f288",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "action": "mysql-startup",
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "mysql_enterprise.audit",
        "ingested": "2022-02-24T08:19:02Z",
        "kind": "event",
        "outcome": "unknown",
        "timezone": "+00:00"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.192.4"
        ],
        "mac": [
            "02:42:c0:a8:c0:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "full": "x86_64-Linux",
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
            "path": "/tmp/service_logs/mysql_audit.log"
        },
        "offset": 462
    },
    "mysqlenterprise": {
        "audit": {
            "account": {},
            "class": "audit",
            "connection_id": "0",
            "id": "0",
            "login": {},
            "startup_data": {}
        }
    },
    "process": {
        "args": [
            "/usr/local/mysql/bin/mysqld",
            "--loose-audit-log-format=JSON",
            "--log-error=log.err",
            "--pid-file=mysqld.pid",
            "--port=3306"
        ],
        "args_count": 5,
        "command_line": "/usr/local/mysql/bin/mysqld --loose-audit-log-format=JSON --log-error=log.err --pid-file=mysqld.pid --port=3306",
        "executable": "/usr/local/mysql/bin/mysqld",
        "name": "mysqld"
    },
    "related": {
        "user": [
            "skip-grants user"
        ]
    },
    "server": {
        "user": {
            "name": "skip-grants user"
        }
    },
    "service": {
        "id": "1",
        "version": "8.0.22-commercial"
    },
    "tags": [
        "mysql_enterprise-audit"
    ]
}
```