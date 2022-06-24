# Microsoft SQL Server Integration

The Microsoft SQL Server integration package allows you to search, observe and visualize the SQL Server audit logs and metrics through Elasticsearch. 

Auditing an instance of the SQL Server Database Engine or an individual database involves tracking and logging events that occur on the Database Engine. 
SQL Server audit lets you create server audits, which can contain server audit specifications for server level events, and database audit specifications for database level events. 
See: [SQL Server Audit page](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver15) for more information on SQL Server auditing.

`performance` metrics gathers the list of performance objects available on that server. Each server will have a different list of performance objects depending on the installed software.
`transaction_log` metrics collects all usage stats and the total space usage.

## Named Instance

Microsoft SQL Server has a feature that allows running multiple databases on the same host (or clustered hosts) with separate settings. Edit the instance port and provide the named instance port to connect to the named instance and collect metrics.
See: [Instruction on how to configure server to listen Named Instance port](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-server-to-listen-on-a-specific-tcp-port?view=sql-server-ver15)

## Compatibility

The package collects `performance` and `transaction_log` metrics, and `audit` events from the event log. Other log sources such as file are not supported.

## Configuration

### audit

There are several levels of auditing for SQL Server, depending on government or standards requirements for your installation. The SQL Server Audit feature enables you to audit server-level and database-level groups of events and individual events. 

See: [SQL Server Audit Action Groups and Actions](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions?view=sql-server-ver15) for more information on the different audit levels.

See: [Instructions on how to enable auditing for SQL Server](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/create-a-server-audit-and-server-audit-specification?view=sql-server-ver15).

>Note: For the integration package to be able to read and send audit events the event target must be configured to be Windows event log.

### audit events

Enable to collect SQL Server audit events from the specified windows event log channel.

### performance metrics

Collects the `performance` counter metrics. Dynamic counter feature provides flexibility to collect metrics by providing the counter name as an input.

See: [Instructions about each performance counter metrics](https://docs.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-os-performance-counters-transact-sql?view=sql-server-ver15
)

### transaction_log metrics

Collects system level `transaction_log` metrics information for SQL Server instance.

See: [Instructions and the operations supported by transaction log](https://docs.microsoft.com/en-us/sql/relational-databases/logs/the-transaction-log-sql-server?view=sql-server-ver15)

## Logs

### audit

The SQL Server audit dataset provides events from the configured Windows event log channel. All SQL Server audit specific fields are available in the `sqlserver.audit` field group.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| sqlserver.audit.action_id | ID of the action | keyword |
| sqlserver.audit.additional_information | Any additional information about the event stored as XML. | text |
| sqlserver.audit.affected_rows | Number of rows affected by the operation. | long |
| sqlserver.audit.application_name | Name of the application that caused the audit event. | keyword |
| sqlserver.audit.audit_schema_version | Audit event schema version. | keyword |
| sqlserver.audit.class_type | Type of auditable entity that the audit occurs on. | keyword |
| sqlserver.audit.client_ip | "Name or IP address of the machine running the application that caused the audit event." | keyword |
| sqlserver.audit.connection_id | Connection ID (unique UUID for the connection) | keyword |
| sqlserver.audit.data_sensitivity_information | Sensitivity information about the operation. | keyword |
| sqlserver.audit.database_name | The database context in which the action occurred. | keyword |
| sqlserver.audit.database_principal_id | ID of the database user context that the action is performed in. | keyword |
| sqlserver.audit.database_principal_name | Current user. | keyword |
| sqlserver.audit.duration_milliseconds | Duration of the operation in milliseconds. | long |
| sqlserver.audit.event_time | Date/time when the auditable action is fired. | date |
| sqlserver.audit.host_name | SQL Server host name. | keyword |
| sqlserver.audit.is_column_permission | Flag indicating a column level permission | boolean |
| sqlserver.audit.object_id | "The primary ID of the entity on which the audit occurred. This ID can be one of server objects, databases, database objects or schema objects." | keyword |
| sqlserver.audit.object_name | "The name of the entity on which the audit occurred. This can be server objects, databases, database objects, schema objects or TSQL statement (if any)." | keyword |
| sqlserver.audit.permission_bitmask | When applicable shows the permissions that were granted, denied or revoked. | keyword |
| sqlserver.audit.response_rows | Number of rows returned. | long |
| sqlserver.audit.schema_name | The schema context in which the action occurred. | keyword |
| sqlserver.audit.sequence_group_id | Sequence group ID (unique UUID). | keyword |
| sqlserver.audit.sequence_number | Tracks the sequence of records within a single audit record  that was too large to fit in the write buffer for audits. | integer |
| sqlserver.audit.server_instance_name | "Name of the server instance where the audit occurred. Uses the standard machine\\instance format." | keyword |
| sqlserver.audit.server_principal_id | ID of the login context that the action is performed in. | keyword |
| sqlserver.audit.server_principal_name | Current login. | keyword |
| sqlserver.audit.server_principal_sid | Current login SID. | keyword |
| sqlserver.audit.session_id | ID of the session on which the event occurred. | integer |
| sqlserver.audit.session_server_principal_name | Server principal for the session. | keyword |
| sqlserver.audit.statement | TSQL statement (if any) | text |
| sqlserver.audit.succeeded | Indicates whether or not the permission check of the action triggering the audit event succeeded or failed. | boolean |
| sqlserver.audit.target_database_principal_id | Database principal that the auditable action applies to. | keyword |
| sqlserver.audit.target_database_principal_name | Target user of the action. | keyword |
| sqlserver.audit.target_server_principal_id | Server principal that the auditable action applies to. | keyword |
| sqlserver.audit.target_server_principal_name | Target login of the action. | keyword |
| sqlserver.audit.target_server_principal_sid | SID of the target login. | keyword |
| sqlserver.audit.transaction_id | Transaction ID | keyword |
| sqlserver.audit.user_defined_event_id | User defined event ID. | integer |
| sqlserver.audit.user_defined_information | User defined information | text |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |
| winlog.activity_id | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. | keyword |
| winlog.api | The event log API type used to read the record. The possible values are "wineventlog" for the Windows Event Log API or "eventlogging" for the Event Logging API. The Event Logging API was designed for Windows Server 2003 or Windows 2000 operating systems. In Windows Vista, the event logging infrastructure was redesigned. On Windows Vista or later operating systems, the Windows Event Log API is used. Winlogbeat automatically detects which API to use for reading event logs. | keyword |
| winlog.channel | The name of the channel from which this record was read. This value is one of the names from the `event_logs` collection in the configuration. | keyword |
| winlog.computer_name | The name of the computer that generated the record. When using Windows event forwarding, this name can differ from `agent.hostname`. | keyword |
| winlog.event_data | The event-specific data. This field is mutually exclusive with `user_data`. If you are capturing event data on versions prior to Windows Vista, the parameters in `event_data` are named `param1`, `param2`, and so on, because event log parameters are unnamed in earlier versions of Windows. | object |
| winlog.event_data.param1 |  | keyword |
| winlog.event_data.param2 |  | keyword |
| winlog.event_data.param3 |  | keyword |
| winlog.event_data.param4 |  | keyword |
| winlog.event_data.param5 |  | keyword |
| winlog.event_data.param6 |  | keyword |
| winlog.event_data.param7 |  | keyword |
| winlog.event_data.param8 |  | keyword |
| winlog.event_id | The event identifier. The value is specific to the source of the event. | keyword |
| winlog.keywords | The keywords are used to classify an event. | keyword |
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.process.pid | The process_id of the Client Server Runtime Process. | long |
| winlog.process.thread.id |  | long |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field. | keyword |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | The Windows security identifier (SID) of the account associated with this event. If Winlogbeat cannot resolve the SID to a name, then the `user.name`, `user.domain`, and `user.type` fields will be omitted from the event. If you discover Winlogbeat not resolving SIDs, review the log for clues as to what the problem may be. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.user_data | The event specific data. This field is mutually exclusive with `event_data`. | object |
| winlog.version | The version number of the event's definition. | long |


## Metrics

### performance

The Microsoft SQL Server `performance` dataset provides metrics from the performance counter table. All `performance` metrics will be available in `sqlserver.metrics` field group.

An example event for `performance` looks as following:

```json
{
    "@timestamp": "2022-06-08T13:35:05.558Z",
    "agent": {
        "ephemeral_id": "16ad2de8-8ba3-496f-98d1-cbe19441c168",
        "id": "848cea0e-c052-49b3-983d-64e13d3b9a6f",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.3.0"
    },
    "cloud": {
        "account": {},
        "instance": {
            "id": "b30e45e6-7900-4900-8d67-e37cb13374bc",
            "name": "obs-int-windows-dev"
        },
        "machine": {
            "type": "Standard_D16ds_v5"
        },
        "provider": "azure",
        "region": "CentralIndia",
        "service": {
            "name": "Virtual Machines"
        }
    },
    "data_stream": {
        "dataset": "microsoft_sqlserver.performance",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "848cea0e-c052-49b3-983d-64e13d3b9a6f",
        "snapshot": true,
        "version": "8.3.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "microsoft_sqlserver.performance",
        "duration": 7151724,
        "ingested": "2022-06-08T13:35:06Z",
        "module": "sql"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.18.0.4"
        ],
        "mac": [
            "02:42:ac:12:00:04"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.16.3-microsoft-standard-WSL2",
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
    "mssql": {
        "metrics": {
            "user_connections": 1
        }
    },
    "service": {
        "address": "elastic-package-service-microsoft_sqlserver-1:1433",
        "type": "sql"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| mssql.metrics.active_temp_tables | Number of temporary tables/table variables in use. | long |  |
| mssql.metrics.batch_requests_per_sec | Number of Transact-SQL command batches received per second. This statistic is affected by all constraints (such as I/O, number of users, cache size, complexity of requests, and so on). High batch requests mean good throughput. | float | gauge |
| mssql.metrics.buffer_cache_hit_ratio | The ratio is the total number of cache hits divided by the total number of cache lookups over the last few thousand page accesses. After a long period of time, the ratio moves very little. Because reading from the cache is much less expensive than reading from disk, you want this ratio to be high. | double |  |
| mssql.metrics.buffer_checkpoint_pages_per_sec | Indicates the number of pages flushed to disk per second by a checkpoint or other operation that require all dirty pages to be flushed. | float | gauge |
| mssql.metrics.buffer_database_pages | Indicates the number of pages in the buffer pool with database content. | long |  |
| mssql.metrics.buffer_page_life_expectancy | Indicates the number of seconds a page will stay in the buffer pool without references (in seconds). | long |  |
| mssql.metrics.buffer_target_pages | Ideal number of pages in the buffer pool. | long |  |
| mssql.metrics.compilations_per_sec | Number of SQL compilations per second. Indicates the number of times the compile code path is entered. Includes compiles caused by statement-level recompilations in SQL Server. After SQL Server user activity is stable, this value reaches a steady state. | float | gauge |
| mssql.metrics.connection_reset_per_sec | Total number of logins started per second from the connection pool. | float | gauge |
| mssql.metrics.dynamic_counter.name | Dynamic counter name is given by user. | keyword |  |
| mssql.metrics.dynamic_counter.value | Dynamic counter value is fetched from performance table for the dynamic counter name which is provided by user. | long |  |
| mssql.metrics.lock_waits_per_sec | Number of lock requests per second that required the caller to wait. | float | gauge |
| mssql.metrics.logins_per_sec | Total number of logins started per second. This does not include pooled connections. | float | gauge |
| mssql.metrics.logouts_per_sec | Total number of logout operations started per second. | float | gauge |
| mssql.metrics.page_splits_per_sec | Number of page splits per second that occur as the result of overflowing index pages. | float | gauge |
| mssql.metrics.re_compilations_per_sec | Number of statement recompiles per second. Counts the number of times statement recompiles are triggered. Generally, you want the recompiles to be low. | float | gauge |
| mssql.metrics.transactions | Total number of transactions | long |  |
| mssql.metrics.user_connections | Total number of user connections. | long |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


### transaction_log

The Microsoft SQL Server `transaction_log` dataset provides metrics from the log space usage and log stats tables of the system databases. All `transaction_log` metrics will be available in `sqlserver.metrics` field group.

An example event for `transaction_log` looks as following:

```json
{
    "@timestamp": "2022-06-08T10:20:14.787809Z",
    "mssql": {
        "metrics": {
            "database_name": "msdb",
            "database_id": 1,
            "used_log_space_bytes": 41.17647171020508,
            "log_space_in_bytes_since_last_backup": 397312,
            "total_log_size_bytes": 2088960,
            "used_log_space_pct": 860160
        }
    },
    "metricset": {
        "period": 10000,
        "name": "query"
    },
    "agent": {
        "id": "e7b17c22-4223-46c3-b982-ff0d570b5fa6",
        "ephemeral_id": "d1a76cf4-2463-478a-a474-36e771218467",
        "type": "metricbeat",
        "version": "8.3.0"
    },
    "service": {
        "address": "54.90.251.237:1433",
        "type": "sql"
    },
    "elastic_agent": {
        "id": "e7b17c22-4223-46c3-b982-ff0d570b5fa6",
        "version": "8.3.0",
        "snapshot": true
    },
    "event": {
        "duration": 5595352584,
        "agent_id_status": "verified",
        "ingested": "2022-05-23T10:20:21Z",
        "module": "sql",
        "dataset": "microsoft_sqlserver.transaction_log"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "microsoft_sqlserver.transaction_log"
    },
    "ecs": {
        "version": "8.0.0"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| mssql.metrics.active_log_size | Total active transaction log size in bytes. | long | byte | counter |
| mssql.metrics.database_id | Unique ID of the database inside MSSQL. | long |  |  |
| mssql.metrics.database_name | Name of the database. | keyword |  |  |
| mssql.metrics.log_backup_time | Last transaction log backup time. | date |  |  |
| mssql.metrics.log_recovery_size | Log size in bytes since log recovery log sequence number (LSN). | long | byte | gauge |
| mssql.metrics.log_since_last_checkpoint | Log size in bytes since last checkpoint log sequence number (LSN). | long | byte | gauge |
| mssql.metrics.log_since_last_log_backup | Log file size since last backup in bytes. | long | byte | gauge |
| mssql.metrics.log_space_in_bytes_since_last_backup | The amount of space used since the last log backup in bytes. | long | byte | gauge |
| mssql.metrics.total_log_size | Total log size. | long | byte | counter |
| mssql.metrics.total_log_size_bytes | Total transaction log size in bytes. | long | byte | counter |
| mssql.metrics.used_log_space_bytes | The occupied size of the log in bytes. | long | byte | gauge |
| mssql.metrics.used_log_space_pct | A percentage of the occupied size of the log as a percent of the total log size. | float | percent | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
