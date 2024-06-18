# Microsoft SQL Server Integration

The Microsoft SQL Server integration package allows you to search, observe, and visualize the SQL Server audit logs, as well as performance and transaction log metrics, through Elasticsearch.

## Data streams

The Microsoft SQL Server integration collects two types of data streams: logs and metrics.

**Logs** help you keep a record of events happening in Microsoft SQL Server.
Log data streams collected by the integration include:

* `audit` provides events from the configured Windows event log channel. For more information on SQL Server auditing, refer to [SQL Server Audit](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver15).
* `logs` parses error logs created by the Microsoft SQL server.

Other log sources, such as files, are not supported.

Find more details in [Logs](#logs).

**Metrics** give you insight into the state of Microsoft SQL Server.
Metric data streams collected by the integration include:

* `performance` metrics gather the list of performance objects available on that server. Each server will have a different list of performance objects depending on the installed software.
* `transaction_log` metrics collect all usage stats and the total space usage.

Find more details in [Metrics](#metrics).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

### Microsoft SQL Server permissions

Before you can start sending data to Elastic, make sure you have the necessary Microsoft SQL Server permissions.

If you browse Microsoft Developer Network (MSDN) for the following tables, you will find a "Permissions" section that defines the permission needed for each table (for example, [the "Permissions" section on the `sys.dm_db_log_space_usage`](https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-db-log-space-usage-transact-sql?view=sql-server-ver15#permissions) page).

1. `transaction_log`:
    - [sys.databases](https://learn.microsoft.com/en-us/sql/relational-databases/system-compatibility-views/sys-sysdatabases-transact-sql?view=sql-server-ver16)
    - [sys.dm_db_log_space_usage](https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-db-log-space-usage-transact-sql?view=sql-server-ver16)
    - [sys.dm_db_log_stats (DB_ID)](https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-db-log-stats-transact-sql?view=sql-server-ver16) (Available on SQL Server (MSSQL) 2016 (13.x) SP 2 and later)
2. `performance`:
    - [sys.dm_os_performance_counters](https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-os-performance-counters-transact-sql?view=sql-server-ver16)


## Setup

For step-by-step instructions on how to set up any integration, refer to the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

Below you'll find more specific details on setting up the Microsoft SQL Server integration.

### Named Instance

Microsoft SQL Server has a feature that allows running multiple databases on the same host (or clustered hosts) with separate settings. Establish a named instance connection by using the instance name along with the hostname (e.g. `host/instance_name` or `host:named_instance_port`) to collect metrics. Details of the host configuration are provided below.

#### Query by Instance Name or Server Name in Kibana

The data can be visualized in Kibana by filtering based on the instance name and server name. The instance name can be filtered by `mssql.metrics.instance_name` and the server name by `mssql.metrics.server_name` fields.

### Host Configuration

As part of the input configuration, you need to provide the user name, password and host details. The host configuration supports both named instances or default (no-name) instances, using the syntax below.

>Note: This integration supports collecting metrics from a single host. For multi-host metrics, each host can be run as a new integration.

**Connecting to Default Instance (host)**:

* `host`        (e.g. `localhost` (Instance name is not needed when connecting to default instance))
* `host:port`   (e.g. `localhost:1433`)

**Connecting to Named Instance (host)**:

* `host/instance_name`          (e.g. `localhost/namedinstance_01`)
* `host:named_instance_port`    (e.g. `localhost:60873`)



### Configuration

#### Audit

There are several levels of auditing for SQL Server, depending on government or standards requirements for your installation. The SQL Server Audit feature enables you to audit server-level and database-level groups of events and individual events.

For more information on the different audit levels, refer to [SQL Server Audit Action Groups and Actions](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions?view=sql-server-ver15).
Then to enable auditing for SQL Server, refer to these [instructions](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/create-a-server-audit-and-server-audit-specification?view=sql-server-ver15).

>Note: For the integration package to be able to read and send audit events the event target must be configured to be Windows event log.

#### Audit events

Collects SQL Server audit events from the specified windows event log channel.

#### Log

The SQL Server `log` contains user-defined events and certain system events you can use for troubleshooting.

Read more in [View the SQL Server error log in SQL Server Management Studio](https://docs.microsoft.com/en-us/sql/relational-databases/performance/view-the-sql-server-error-log-sql-server-management-studio?view=sql-server-ver16).

#### Performance metrics

Collects the `performance` counter metrics. The dynamic counter feature provides flexibility to collect metrics by providing the counter as an input.
This input can be a regular expression which will filter results based on pattern.
For example, if %grant% is given as input, it will enable metrics collection for all of the counters with names like 'Memory Grants Pending', 'Active memory grants count' etc.
MSSQL supports a limited set of regular expressions. For more details, refer to [Pattern Matching in Search Conditions](https://learn.microsoft.com/en-us/previous-versions/sql/sql-server-2008-r2/ms187489(v=sql.105)?redirectedfrom=MSDN).

> Note: Dynamic counters will go through some basic ingest pipeline post-processing to make counter names in lowercase and remove special characters and these fields will not have any static field mappings.

The feature `merge_results` has been introduced in 8.4 beats which creates a single event by combining the metrics in a single event. For more details, refer to [SQL module](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-module-sql.html#_example_merge_multiple_queries_to_single_event).

Read more in [instructions about each performance counter metrics](https://docs.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-os-performance-counters-transact-sql?view=sql-server-ver15).

#### Transaction log metrics

Collects system level `transaction_log` metrics information for SQL Server instance.
Metrics for user-level databases can be collected by providing a list of user databases for which metrics are to be collected.

Read more in [instructions and the operations supported by transaction log](https://docs.microsoft.com/en-us/sql/relational-databases/logs/the-transaction-log-sql-server?view=sql-server-ver15).

#### Fetch from all databases

To simplify the process of fetching metrics from all databases on the server, you can enable the `Fetch from all databases` toggle when configuring the integration. This field overrides manually entered database names in the `Databases` input and instead fetches the required `transaction_log` metrics from all databases, including system and user-defined databases.

Keep in mind that this feature is disabled by default and needs to be manually enabled to be activated.

#### Password URL encoding

When the password contains special characters, pass these special characters using URL encoding.

## Logs

### audit

The SQL Server audit dataset provides events from the configured Windows event log channel. All SQL Server audit-specific fields are available in the `sqlserver.audit` field group.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
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


### log

The Microsoft SQL Server `log` dataset parses error logs created by the Microsoft SQL server.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-07-14T07:12:49.210Z",
    "agent": {
        "ephemeral_id": "688f9c4d-2ac0-43b6-9421-bf465d5c92f0",
        "id": "42a4484f-4eb2-4802-bd76-1f1118713d64",
        "name": "docker-fleet-agent",
        "type": "filebeat",
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
        "dataset": "microsoft_sqlserver.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "42a4484f-4eb2-4802-bd76-1f1118713d64",
        "snapshot": false,
        "version": "8.3.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "database"
        ],
        "dataset": "microsoft_sqlserver.log",
        "ingested": "2022-07-14T07:13:12Z",
        "kind": "event",
        "original": "2022-07-14 07:12:49.21 Server      Microsoft SQL Server 2019 (RTM-CU16-GDR) (KB5014353) - 15.0.4236.7 (X64) \n\tMay 29 2022 15:55:47 \n\tCopyright (C) 2019 Microsoft Corporation\n\tDeveloper Edition (64-bit) on Linux (Ubuntu 20.04.4 LTS) <X64>",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/errorlog"
        },
        "flags": [
            "multiline"
        ],
        "offset": 0
    },
    "message": "Microsoft SQL Server 2019 (RTM-CU16-GDR) (KB5014353) - 15.0.4236.7 (X64) \n\tMay 29 2022 15:55:47 \n\tCopyright (C) 2019 Microsoft Corporation\n\tDeveloper Edition (64-bit) on Linux (Ubuntu 20.04.4 LTS) <X64>",
    "microsoft_sqlserver": {
        "log": {
            "origin": "Server"
        }
    },
    "tags": [
        "mssql-logs"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | This field contains the flags of the event. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| microsoft_sqlserver.log.origin | Origin of the message usually the server but it can also be a recovery process | keyword |


## Metrics

### performance

The Microsoft SQL Server `performance` dataset provides metrics from the performance counter table. All `performance` metrics will be available in the `sqlserver.metrics` field group.

An example event for `performance` looks as following:

```json
{
    "@timestamp": "2022-11-23T05:03:28.987Z",
    "agent": {
        "ephemeral_id": "70f5c0c1-37b1-486b-9806-8105b2cdcd20",
        "id": "6d444a4a-2158-445e-8953-dc6eef720a34",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
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
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "6d444a4a-2158-445e-8953-dc6eef720a34",
        "snapshot": false,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "microsoft_sqlserver.performance",
        "duration": 41134100,
        "ingested": "2022-11-23T05:03:30Z",
        "module": "sql"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "66392b0697b84641af8006d87aeb89f1",
        "ip": [
            "172.18.0.5"
        ],
        "mac": [
            "02-42-AC-12-00-05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "query",
        "period": 60000
    },
    "mssql": {
        "metrics": {
            "active_temp_tables": 0,
            "batch_requests_per_sec": 54,
            "buffer_cache_hit_ratio": 24,
            "buffer_checkpoint_pages_per_sec": 105,
            "buffer_database_pages": 2215,
            "buffer_page_life_expectancy": 16,
            "buffer_target_pages": 2408448,
            "compilations_per_sec": 80,
            "connection_reset_per_sec": 13,
            "instance_name": "MSSQLSERVER",
            "lock_waits_per_sec": 4,
            "logins_per_sec": 16,
            "logouts_per_sec": 15,
            "memory_grants_pending": 0,
            "page_splits_per_sec": 9,
            "re_compilations_per_sec": 0,
            "server_name": "d10aad520431",
            "transactions": 0,
            "user_connections": 1
        }
    },
    "service": {
        "address": "elastic-package-service_microsoft_sqlserver_1",
        "type": "sql"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| mssql.metrics.active_temp_tables | Number of temporary tables/table variables in use. | long | gauge |
| mssql.metrics.batch_requests_per_sec | Number of Transact-SQL command batches received per second. This statistic is affected by all constraints (such as I/O, number of users, cache size, complexity of requests, and so on). High batch requests mean good throughput. | float | gauge |
| mssql.metrics.buffer_cache_hit_ratio | The ratio is the total number of cache hits divided by the total number of cache lookups over the last few thousand page accesses. After a long period of time, the ratio moves very little. Because reading from the cache is much less expensive than reading from disk, you want this ratio to be high. | double | gauge |
| mssql.metrics.buffer_checkpoint_pages_per_sec | Indicates the number of pages flushed to disk per second by a checkpoint or other operation that require all dirty pages to be flushed. | float | gauge |
| mssql.metrics.buffer_database_pages | Indicates the number of pages in the buffer pool with database content. | long | gauge |
| mssql.metrics.buffer_page_life_expectancy | Indicates the number of seconds a page will stay in the buffer pool without references (in seconds). | long | gauge |
| mssql.metrics.buffer_target_pages | Ideal number of pages in the buffer pool. | long | gauge |
| mssql.metrics.compilations_per_sec | Number of SQL compilations per second. Indicates the number of times the compile code path is entered. Includes compiles caused by statement-level recompilations in SQL Server. After SQL Server user activity is stable, this value reaches a steady state. | float | gauge |
| mssql.metrics.connection_reset_per_sec | Total number of logins started per second from the connection pool. | float | gauge |
| mssql.metrics.instance_name | Name of the mssql connected instance. | keyword |  |
| mssql.metrics.lock_waits_per_sec | Number of lock requests per second that required the caller to wait. | float | gauge |
| mssql.metrics.logins_per_sec | Total number of logins started per second. This does not include pooled connections. | float | gauge |
| mssql.metrics.logouts_per_sec | Total number of logout operations started per second. | float | gauge |
| mssql.metrics.memory_grants_pending | This is generated from the default pattern given for Dynamic Counter Name variable. This counter tells us how many processes are waiting for the memory to be assigned to them so they can get started. | long |  |
| mssql.metrics.page_splits_per_sec | Number of page splits per second that occur as the result of overflowing index pages. | float | gauge |
| mssql.metrics.re_compilations_per_sec | Number of statement recompiles per second. Counts the number of times statement recompiles are triggered. Generally, you want the recompiles to be low. | float | gauge |
| mssql.metrics.server_name | Name of the mssql server. | keyword |  |
| mssql.metrics.transactions | Total number of transactions | long | gauge |
| mssql.metrics.user_connections | Total number of user connections. | long | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### transaction_log

The Microsoft SQL Server `transaction_log` dataset provides metrics from the log space usage and log stats tables of the system databases. All `transaction_log` metrics will be available in the `sqlserver.metrics` field group.

An example event for `transaction_log` looks as following:

```json
{
    "@timestamp": "2022-12-20T07:34:29.687Z",
    "agent": {
        "ephemeral_id": "8d528ff8-5e90-4572-89f6-61fb3a6c96f1",
        "id": "d44a1c4a-95bf-47e9-afb0-453a2ef43c00",
        "name": "192.168.1.2",
        "type": "metricbeat",
        "version": "8.5.3"
    },
    "data_stream": {
        "dataset": "microsoft_sqlserver.transaction_log",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d44a1c4a-95bf-47e9-afb0-453a2ef43c00",
        "snapshot": false,
        "version": "8.5.3"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "microsoft_sqlserver.transaction_log",
        "duration": 2147044750,
        "ingested": "2022-12-20T07:34:32Z",
        "module": "sql"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "192.168.1.2",
        "id": "627E8AE5-E918-5073-A58E-8A2D9ED96875",
        "ip": [
            "192.168.1.2"
        ],
        "mac": [
            "36-F7-DC-28-23-80"
        ],
        "name": "192.168.1.2",
        "os": {
            "build": "21D62",
            "family": "darwin",
            "kernel": "21.3.0",
            "name": "macOS",
            "platform": "darwin",
            "type": "macos",
            "version": "12.2.1"
        }
    },
    "metricset": {
        "name": "query",
        "period": 60000
    },
    "mssql": {
        "metrics": {
            "database_id": 1,
            "database_name": "master",
            "instance_name": "MSSQLSERVER",
            "log_space_in_bytes_since_last_backup": 602112,
            "server_name": "obs-int-mssql20",
            "total_log_size_bytes": 2088960,
            "used_log_space_bytes": 1024000,
            "used_log_space_pct": 49.01960754394531
        }
    },
    "service": {
        "address": "20.228.135.242",
        "type": "sql"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| mssql.metrics.active_log_size | Total active transaction log size in bytes. | long | byte | counter |
| mssql.metrics.database_id | Unique ID of the database inside MSSQL. | long |  |  |
| mssql.metrics.database_name | Name of the database. | keyword |  |  |
| mssql.metrics.instance_name | Name of the mssql connected instance. | keyword |  |  |
| mssql.metrics.log_backup_time | Last transaction log backup time. | date |  |  |
| mssql.metrics.log_recovery_size | Log size in bytes since log recovery log sequence number (LSN). | long | byte | gauge |
| mssql.metrics.log_since_last_checkpoint | Log size in bytes since last checkpoint log sequence number (LSN). | long | byte | gauge |
| mssql.metrics.log_since_last_log_backup | Log file size since last backup in bytes. | long | byte | gauge |
| mssql.metrics.log_space_in_bytes_since_last_backup | The amount of space used since the last log backup in bytes. | long | byte | gauge |
| mssql.metrics.query_id | Autogenerated ID representing the mssql query that is executed to fetch the results. | keyword |  |  |
| mssql.metrics.server_name | Name of the mssql server. | keyword |  |  |
| mssql.metrics.total_log_size | Total log size. | long | byte | counter |
| mssql.metrics.total_log_size_bytes | Total transaction log size in bytes. | long | byte | counter |
| mssql.metrics.used_log_space_bytes | The occupied size of the log in bytes. | long | byte | gauge |
| mssql.metrics.used_log_space_pct | A percentage of the occupied size of the log as a percent of the total log size. | float | percent | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |

