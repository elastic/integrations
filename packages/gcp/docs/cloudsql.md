# CloudSQL

The `cloudsql` dataset fetches metrics from [CloudSQL](https://cloud.google.com/sql) in Google Cloud Platform. It contains all metrics exported from the [GCP CloudSQL Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-cloudsql).

`gcp.labels.cloudsql.name` label is utilized to identify the type of Google Cloud SQL database that generated the metrics. In the pipelines, this label is crucial for distinguishing between various Cloud SQL database types and directing the metrics to their respective destinations. Current valid values are `mysql`, `postgres` and `sqlserver`. Other values will be dropped.

## MySQL Metrics

CloudSQL MySQL metrics.

An example event for `cloudsql_mysql` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev",
            "name": "elastic-obs-integrations-dev"
        },
        "instance": {
            "id": "4751091017865185079",
            "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
        },
        "machine": {
            "type": "e2-medium"
        },
        "provider": "gcp",
        "availability_zone": "us-central1-c",
        "region": "us-central1"
    },
    "event": {
        "dataset": "gcp.cloudsql_mysql",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "cloudsql_mysql": {
            "database": {
                "up": 1
            }
        },
        "labels": {
            "user": {
                "goog-gke-node": ""
            }
        }
    },
    "host": {
        "id": "4751091017865185079",
        "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
    },
    "metricset": {
        "name": "metrics",
        "period": 10000
    },
    "service": {
        "type": "gcp"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| gcp.cloudsql_mysql.database.active_directory.domain_reachable | Indicates whether the instance is able to ping a domain controller from the connected Managed Active Directory domain. | long |  | gauge |
| gcp.cloudsql_mysql.database.active_directory.instance_available | Indicates whether the instance is currently available using Windows Authentication. | long |  | gauge |
| gcp.cloudsql_mysql.database.auto_failover_request.count | Delta of number of instance auto-failover requests. | long |  | counter |
| gcp.cloudsql_mysql.database.available_for_failover | This is \> 0 if the failover operation is available on the instance. | long |  | gauge |
| gcp.cloudsql_mysql.database.cpu.reserved_cores.count | Number of cores reserved for the database. | double |  | gauge |
| gcp.cloudsql_mysql.database.cpu.usage_time.sec | Cumulative CPU usage time in seconds. | double | s |  |
| gcp.cloudsql_mysql.database.cpu.utilization.pct | Current CPU utilization represented as a percentage of the reserved CPU that is currently in use. | double |  | gauge |
| gcp.cloudsql_mysql.database.disk.bytes_used.bytes | Data utilization in bytes. | long | byte | gauge |
| gcp.cloudsql_mysql.database.disk.bytes_used_by_data_type.bytes | Data utilization in bytes. | long | byte | gauge |
| gcp.cloudsql_mysql.database.disk.quota.bytes | Maximum data disk size in bytes. | long | byte | gauge |
| gcp.cloudsql_mysql.database.disk.read_ops.count | Delta count of data disk read IO operations. | long |  | counter |
| gcp.cloudsql_mysql.database.disk.utilization.pct | The fraction of the disk quota that is currently in use. | double |  | gauge |
| gcp.cloudsql_mysql.database.disk.write_ops.count | Delta count of data disk write IO operations. | long |  | counter |
| gcp.cloudsql_mysql.database.innodb_buffer_pool_pages_dirty.count | Number of unflushed pages in the InnoDB buffer pool. | long |  | gauge |
| gcp.cloudsql_mysql.database.innodb_buffer_pool_pages_free.count | Number of unused pages in the InnoDB buffer pool. | long |  | gauge |
| gcp.cloudsql_mysql.database.innodb_buffer_pool_pages_total.count | Total number of pages in the InnoDB buffer pool. | long |  | gauge |
| gcp.cloudsql_mysql.database.innodb_data_fsyncs.count | Delta count of InnoDB fsync() calls. | long |  | counter |
| gcp.cloudsql_mysql.database.innodb_os_log_fsyncs.count | Delta count of InnoDB fsync() calls to the log file. | long |  | counter |
| gcp.cloudsql_mysql.database.innodb_pages_read.count | Delta count of InnoDB pages read. | long |  | counter |
| gcp.cloudsql_mysql.database.innodb_pages_written.count | Delta count of InnoDB pages written. | long |  | counter |
| gcp.cloudsql_mysql.database.instance_state | The current serving state of the Cloud SQL instance. | long |  | gauge |
| gcp.cloudsql_mysql.database.memory.quota.bytes | Maximum RAM size in bytes. | long | byte | gauge |
| gcp.cloudsql_mysql.database.memory.total_usage.bytes | Total RAM usage in bytes. This metric reports the RAM usage of the database process, including the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_mysql.database.memory.usage.bytes | RAM usage in bytes. This metric reports the RAM usage of the server, excluding the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_mysql.database.memory.utilization.pct | The fraction of the memory quota that is currently in use. | double | percent | gauge |
| gcp.cloudsql_mysql.database.network.connections.count | Number of connections to databases on the Cloud SQL instance. Only applicable to MySQL and SQL Server. | long |  | gauge |
| gcp.cloudsql_mysql.database.network.received_bytes.count | Delta count of bytes received through the network. | long |  | counter |
| gcp.cloudsql_mysql.database.network.sent_bytes.count | Delta count of bytes sent through the network. | long |  | counter |
| gcp.cloudsql_mysql.database.queries.count | Delta count of statements executed by the server. | long |  | counter |
| gcp.cloudsql_mysql.database.questions.count | Delta count of statements executed by the server sent by the client. | long |  | counter |
| gcp.cloudsql_mysql.database.received_bytes.count | Delta count of bytes received by MySQL process. | long |  | counter |
| gcp.cloudsql_mysql.database.replication.last_io_errno | The error number of the most recent error that caused the I/O thread to stop. | long |  | gauge |
| gcp.cloudsql_mysql.database.replication.last_sql_errno | The error number of the most recent error that caused the SQL thread to stop. | long |  | gauge |
| gcp.cloudsql_mysql.database.replication.log_archive_failure.count | Number of failed attempts for archiving replication log files. | long |  | counter |
| gcp.cloudsql_mysql.database.replication.log_archive_success.count | Number of successful attempts for archiving replication log files. | long |  | counter |
| gcp.cloudsql_mysql.database.replication.network_lag.sec | Indicates time taken from primary binary log to IO thread on replica. Only applicable to replicas. | long | s | gauge |
| gcp.cloudsql_mysql.database.replication.replica_lag.sec | Number of seconds the read replica is behind its primary (approximation). | double | s | gauge |
| gcp.cloudsql_mysql.database.replication.seconds_behind_master.sec | Number of seconds the read replica is behind its primary (approximation). | long | s | gauge |
| gcp.cloudsql_mysql.database.replication.slave_io_running | Indicates whether the I/O thread for reading the primary's binary log is running. Possible values are Yes, No and Connecting. | keyword |  |  |
| gcp.cloudsql_mysql.database.replication.slave_io_running_state | Indicates whether the I/O thread for reading the primary's binary log is running. Possible values are Yes, No and Connecting, and the values are exposed through the 'state' field. | long |  | gauge |
| gcp.cloudsql_mysql.database.replication.slave_sql_running | Indicates whether the SQL thread for executing events in the relay log is running. | keyword |  |  |
| gcp.cloudsql_mysql.database.replication.slave_sql_running_state | Indicates whether the SQL thread for executing events in the relay log is running. Possible values are Yes / No, and the values are exposed through the 'state' field. | long |  | gauge |
| gcp.cloudsql_mysql.database.replication.state | The current serving state of replication. | long |  | gauge |
| gcp.cloudsql_mysql.database.sent_bytes.count | Delta count of bytes sent by MySQL process. | long |  | counter |
| gcp.cloudsql_mysql.database.state | The current serving state of the Cloud SQL instance. | keyword |  |  |
| gcp.cloudsql_mysql.database.up | Indicates if the server is up or not. | long |  | gauge |
| gcp.cloudsql_mysql.database.uptime.sec | Delta count of the time in seconds the instance has been running. | long | s |  |
| gcp.labels.metadata.\* |  | object |  |  |
| gcp.labels.metrics.\* |  | object |  |  |
| gcp.labels.resource.\* |  | object |  |  |
| gcp.labels.system.\* |  | object |  |  |
| gcp.labels.user.\* |  | object |  |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


## PostgreSQL Metrics

CloudSQL PostgreSQL metrics.

An example event for `cloudsql_postgresql` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev",
            "name": "elastic-obs-integrations-dev"
        },
        "instance": {
            "id": "4751091017865185079",
            "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
        },
        "machine": {
            "type": "e2-medium"
        },
        "provider": "gcp",
        "availability_zone": "us-central1-c",
        "region": "us-central1"
    },
    "event": {
        "dataset": "gcp.cloudsql_postgresql",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "cloudsql_postgresql": {
            "database": {
                "up": 1
            }
        },
        "labels": {
            "user": {
                "goog-gke-node": ""
            }
        }
    },
    "host": {
        "id": "4751091017865185079",
        "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
    },
    "metricset": {
        "name": "metrics",
        "period": 10000
    },
    "service": {
        "type": "gcp"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| gcp.cloudsql_postgresql.database.active_directory.domain_reachable | Indicates whether the instance is able to ping a domain controller from the connected Managed Active Directory domain. | long |  | gauge |
| gcp.cloudsql_postgresql.database.active_directory.instance_available | Indicates whether the instance is currently available using Windows Authentication. | long |  | gauge |
| gcp.cloudsql_postgresql.database.auto_failover_request.count | Delta of number of instance auto-failover requests. | long |  | counter |
| gcp.cloudsql_postgresql.database.available_for_failover | This is \> 0 if the failover operation is available on the instance. | long |  | gauge |
| gcp.cloudsql_postgresql.database.blocks_read.count | Number of disk blocks read by this database. The source field distingushes actual reads from disk versus reads from buffer cache. | long |  | counter |
| gcp.cloudsql_postgresql.database.cpu.reserved_cores.count | Number of cores reserved for the database. | double |  | gauge |
| gcp.cloudsql_postgresql.database.cpu.usage_time.sec | Cumulative CPU usage time in seconds. | double | s |  |
| gcp.cloudsql_postgresql.database.cpu.utilization.pct | Current CPU utilization represented as a percentage of the reserved CPU that is currently in use. | double | percent | gauge |
| gcp.cloudsql_postgresql.database.deadlock.count | Number of deadlocks detected for this database. | long |  | counter |
| gcp.cloudsql_postgresql.database.disk.bytes_used.bytes | Data utilization in bytes. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.disk.bytes_used_by_data_type.bytes | Data utilization in bytes. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.disk.quota.bytes | Maximum data disk size in bytes. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.disk.read_ops.count | Delta count of data disk read IO operations. | long |  | counter |
| gcp.cloudsql_postgresql.database.disk.utilization.pct | The fraction of the disk quota that is currently in use. | double | percent | gauge |
| gcp.cloudsql_postgresql.database.disk.write_ops.count | Delta count of data disk write IO operations. | long |  | counter |
| gcp.cloudsql_postgresql.database.external_sync.initial_sync_complete | Whether all databases on the Postgres External Server (ES) replica have completed the initial sync and are replicating changes from the source. | long |  | gauge |
| gcp.cloudsql_postgresql.database.external_sync.max_replica_byte_lag.bytes | Replication lag in bytes for Postgres External Server (ES) replicas. Aggregated across all DBs on the replica. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.insights.aggregate.execution_time | Accumulated query execution time per user per database. This is the sum of cpu time, io wait time, lock wait time, process context switch, and scheduling for all the processes involved in the query execution. | long |  |  |
| gcp.cloudsql_postgresql.database.insights.aggregate.io_time | Accumulated IO time per user per database. | long |  |  |
| gcp.cloudsql_postgresql.database.insights.aggregate.latencies | Query latency distribution per user per database. | long |  |  |
| gcp.cloudsql_postgresql.database.insights.aggregate.lock_time | Accumulated lock wait time per user per database. | long |  |  |
| gcp.cloudsql_postgresql.database.insights.aggregate.row.count | Total number of rows affected during query execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.aggregate.shared_blk_access.count | Shared blocks (regular tables & indexed) accessed by statement execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.perquery.execution_time | Accumulated execution times per user per database per query.This is the sum of cpu time, io wait time, lock wait time, process context switch, and scheduling for all the processes involved in the query execution. | long |  |  |
| gcp.cloudsql_postgresql.database.insights.perquery.io_time | Accumulated IO time per user per database per query. | long |  |  |
| gcp.cloudsql_postgresql.database.insights.perquery.latencies | Query latency distribution per user per database per query. | histogram |  |  |
| gcp.cloudsql_postgresql.database.insights.perquery.lock_time | Accumulated lock wait time per user per database per query. | long |  |  |
| gcp.cloudsql_postgresql.database.insights.perquery.row.count | Total number of rows affected during query execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.perquery.shared_blk_access.count | Shared blocks (regular tables & indexed) accesssed by statement execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.pertag.execution_time | Accumulated execution times per user per database per tag.This is the sum of cpu time, io wait time, lock wait time, process context switch, and scheduling for all the processes involved in the query execution. | long |  |  |
| gcp.cloudsql_postgresql.database.insights.pertag.io_time | Accumulated IO write time per user per database per tag. | long |  |  |
| gcp.cloudsql_postgresql.database.insights.pertag.latencies | Query latency distribution per user per database per tag. | histogram |  |  |
| gcp.cloudsql_postgresql.database.insights.pertag.lock_time | Accumulated lock wait time per user per database per tag. | long |  |  |
| gcp.cloudsql_postgresql.database.insights.pertag.row.count | Total number of rows affected during query execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.pertag.shared_blk_access.count | Shared blocks (regular tables & indexed) accessed by statement execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.instance_state | The current serving state of the Cloud SQL instance. | long |  | gauge |
| gcp.cloudsql_postgresql.database.memory.quota.bytes | Maximum RAM size in bytes. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.memory.total_usage.bytes | Total RAM usage in bytes. This metric reports the RAM usage of the database process, including the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.memory.usage.bytes | RAM usage in bytes. This metric reports the RAM usage of the server, excluding the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.memory.utilization.pct | The fraction of the memory quota that is currently in use. | double | percent | gauge |
| gcp.cloudsql_postgresql.database.network.connections.count | Number of connections to databases on the Cloud SQL instance. Only applicable to MySQL and SQL Server. | long |  | gauge |
| gcp.cloudsql_postgresql.database.network.received_bytes.count | Delta count of bytes received through the network. | long |  | counter |
| gcp.cloudsql_postgresql.database.network.sent_bytes.count | Delta count of bytes sent through the network. | long |  | counter |
| gcp.cloudsql_postgresql.database.num_backends.count | Number of connections to the Cloud SQL PostgreSQL instance. | long |  | gauge |
| gcp.cloudsql_postgresql.database.num_backends_by_state.count | Number of connections to the Cloud SQL PostgreSQL instance, grouped by its state. | long |  | gauge |
| gcp.cloudsql_postgresql.database.replication.log_archive_failure.count | Number of failed attempts for archiving replication log files. | long |  | counter |
| gcp.cloudsql_postgresql.database.replication.log_archive_success.count | Number of successful attempts for archiving replication log files. | long |  | counter |
| gcp.cloudsql_postgresql.database.replication.network_lag.sec | Indicates time taken from primary binary log to IO thread on replica. Only applicable to replicas. | long | s | gauge |
| gcp.cloudsql_postgresql.database.replication.replica_byte_lag.bytes | Replication lag in bytes. Reported from the master per replica. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.replication.replica_lag.sec | Number of seconds the read replica is behind its primary (approximation). | double | s | gauge |
| gcp.cloudsql_postgresql.database.replication.state | The current serving state of replication. | long |  | gauge |
| gcp.cloudsql_postgresql.database.state | The current serving state of the Cloud SQL instance. | keyword |  |  |
| gcp.cloudsql_postgresql.database.transaction.count | Delta count of number of transactions. | long |  | counter |
| gcp.cloudsql_postgresql.database.transaction_id.count | Delta count of transaction ID. | long |  | counter |
| gcp.cloudsql_postgresql.database.transaction_id_utilization.pct | Current utilization represented as a percentage of transaction IDs consumed by the Cloud SQL PostgreSQL instance. Values are typically numbers between 0.0 and 1.0. Charts display the values as a percentage between 0% and 100%. | double | percent | gauge |
| gcp.cloudsql_postgresql.database.tuple_size.count | Number of tuples (rows) in the database. | long |  | gauge |
| gcp.cloudsql_postgresql.database.tuples_processed.count | Number of tuples(rows) processed for a given database for operations like insert, update or delete. | long |  | counter |
| gcp.cloudsql_postgresql.database.up | Indicates if the server is up or not. | long |  | gauge |
| gcp.cloudsql_postgresql.database.uptime.sec | Delta count of the time in seconds the instance has been running. | long | s |  |
| gcp.cloudsql_postgresql.database.vacuum.oldest_transaction_age | Age of the oldest transaction yet to be vacuumed in the Cloud SQL PostgreSQL instance, measured in number of transactions that have happened since the oldest transaction. | long |  | gauge |
| gcp.labels.metadata.\* |  | object |  |  |
| gcp.labels.metrics.\* |  | object |  |  |
| gcp.labels.resource.\* |  | object |  |  |
| gcp.labels.system.\* |  | object |  |  |
| gcp.labels.user.\* |  | object |  |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |



## SQL Server Metrics

CloudSQL SQL Server metrics.

An example event for `cloudsql_sqlserver` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev",
            "name": "elastic-obs-integrations-dev"
        },
        "instance": {
            "id": "4751091017865185079",
            "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
        },
        "machine": {
            "type": "e2-medium"
        },
        "provider": "gcp",
        "availability_zone": "us-central1-c",
        "region": "us-central1"
    },
    "event": {
        "dataset": "gcp.cloudsql_sqlserver",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "cloudsql_sqlserver": {
            "database": {
                "up": 1
            }
        },
        "labels": {
            "user": {
                "goog-gke-node": ""
            }
        }
    },
    "host": {
        "id": "4751091017865185079",
        "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
    },
    "metricset": {
        "name": "metrics",
        "period": 10000
    },
    "service": {
        "type": "gcp"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| gcp.cloudsql_sqlserver.database.active_directory.domain_reachable | Indicates whether the instance is able to ping a domain controller from the connected Managed Active Directory domain. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.active_directory.instance_available | Indicates whether the instance is currently available using Windows Authentication. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.audits_size.bytes | Tracks the size in bytes of stored SQLServer audit files on an instance. | long | byte | counter |
| gcp.cloudsql_sqlserver.database.audits_upload.count | Counts total number of SQLServer audit file uploads to a GCS bucket and whether or not an upload was successful. | long |  | counter |
| gcp.cloudsql_sqlserver.database.auto_failover_request.count | Delta of number of instance auto-failover requests. | long |  | counter |
| gcp.cloudsql_sqlserver.database.available_for_failover | This is \> 0 if the failover operation is available on the instance. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.cpu.reserved_cores.count | Number of cores reserved for the database. | double |  | gauge |
| gcp.cloudsql_sqlserver.database.cpu.usage_time.sec | Cumulative CPU usage time in seconds. | double | s |  |
| gcp.cloudsql_sqlserver.database.cpu.utilization.pct | Current CPU utilization represented as a percentage of the reserved CPU that is currently in use. | double | percent | gauge |
| gcp.cloudsql_sqlserver.database.disk.bytes_used.bytes | Data utilization in bytes. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.disk.bytes_used_by_data_type.bytes | Data utilization in bytes. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.disk.quota.bytes | Maximum data disk size in bytes. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.disk.read_ops.count | Delta count of data disk read IO operations. | long |  | counter |
| gcp.cloudsql_sqlserver.database.disk.utilization.pct | The fraction of the disk quota that is currently in use. | double | percent | gauge |
| gcp.cloudsql_sqlserver.database.disk.write_ops.count | Delta count of data disk write IO operations. | long |  | counter |
| gcp.cloudsql_sqlserver.database.external_sync.primary_to_replica_connection_health | Indicates whether there is connectivity from Primary to the Replica to push replication updates. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.instance_state | The current serving state of the Cloud SQL instance. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.memory.quota.bytes | Maximum RAM size in bytes. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.memory.total_usage.bytes | Total RAM usage in bytes. This metric reports the RAM usage of the database process, including the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.memory.usage.bytes | RAM usage in bytes. This metric reports the RAM usage of the server, excluding the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.memory.utilization.pct | The fraction of the memory quota that is currently in use. | double | percent | gauge |
| gcp.cloudsql_sqlserver.database.network.connections.count | Number of connections to databases on the Cloud SQL instance. Only applicable to MySQL and SQL Server. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.network.received_bytes.count | Delta count of bytes received through the network. | long |  | counter |
| gcp.cloudsql_sqlserver.database.network.sent_bytes.count | Delta count of bytes sent through the network. | long |  | counter |
| gcp.cloudsql_sqlserver.database.replication.log_archive_failure.count | Number of failed attempts for archiving replication log files. | long |  | counter |
| gcp.cloudsql_sqlserver.database.replication.log_archive_success.count | Number of successful attempts for archiving replication log files. | long |  | counter |
| gcp.cloudsql_sqlserver.database.replication.network_lag.sec | Indicates time taken from primary binary log to IO thread on replica. Only applicable to replicas. | long | s | gauge |
| gcp.cloudsql_sqlserver.database.replication.replica_lag.sec | Number of seconds the read replica is behind its primary (approximation). | double | s | gauge |
| gcp.cloudsql_sqlserver.database.replication.state | The current serving state of replication. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.state | The current serving state of the Cloud SQL instance. | keyword |  |  |
| gcp.cloudsql_sqlserver.database.up | Indicates if the server is up or not. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.uptime.sec | Delta count of the time in seconds the instance has been running. | long | s |  |
| gcp.labels.metadata.\* |  | object |  |  |
| gcp.labels.metrics.\* |  | object |  |  |
| gcp.labels.resource.\* |  | object |  |  |
| gcp.labels.system.\* |  | object |  |  |
| gcp.labels.user.\* |  | object |  |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |

