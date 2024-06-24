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
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| gcp.cloudsql_mysql.database.auto_failover_request.count | Delta of number of instance auto-failover requests. | long |  | gauge |
| gcp.cloudsql_mysql.database.available_for_failover | This is \> 0 if the failover operation is available on the instance. | long |  | gauge |
| gcp.cloudsql_mysql.database.cpu.reserved_cores.count | Number of cores reserved for the database. | double |  | gauge |
| gcp.cloudsql_mysql.database.cpu.usage_time.sec | Delta CPU usage time in seconds. | double | s | gauge |
| gcp.cloudsql_mysql.database.cpu.utilization.pct | Current CPU utilization represented as a percentage of the reserved CPU that is currently in use. | double | percent | gauge |
| gcp.cloudsql_mysql.database.disk.bytes_used.bytes | Data utilization in bytes. | long | byte | gauge |
| gcp.cloudsql_mysql.database.disk.quota.bytes | Maximum data disk size in bytes. | long | byte | gauge |
| gcp.cloudsql_mysql.database.disk.read_ops.count | Delta count of data disk read IO operations. | long |  | gauge |
| gcp.cloudsql_mysql.database.disk.utilization.pct | The fraction of the disk quota that is currently in use. | double | percent | gauge |
| gcp.cloudsql_mysql.database.disk.write_ops.count | Delta count of data disk write IO operations. | long |  | gauge |
| gcp.cloudsql_mysql.database.innodb_buffer_pool_pages_dirty.count | Number of unflushed pages in the InnoDB buffer pool. | long |  | gauge |
| gcp.cloudsql_mysql.database.innodb_buffer_pool_pages_free.count | Number of unused pages in the InnoDB buffer pool. | long |  | gauge |
| gcp.cloudsql_mysql.database.innodb_buffer_pool_pages_total.count | Total number of pages in the InnoDB buffer pool. | long |  | gauge |
| gcp.cloudsql_mysql.database.innodb_data_fsyncs.count | Delta count of InnoDB fsync() calls. | long |  | gauge |
| gcp.cloudsql_mysql.database.innodb_os_log_fsyncs.count | Delta count of InnoDB fsync() calls to the log file. | long |  | gauge |
| gcp.cloudsql_mysql.database.innodb_pages_read.count | Delta count of InnoDB pages read. | long |  | gauge |
| gcp.cloudsql_mysql.database.innodb_pages_written.count | Delta count of InnoDB pages written. | long |  | gauge |
| gcp.cloudsql_mysql.database.instance_state | The current serving state of the Cloud SQL instance. | boolean |  |  |
| gcp.cloudsql_mysql.database.memory.quota.bytes | Maximum RAM size in bytes. | long | byte | gauge |
| gcp.cloudsql_mysql.database.memory.total_usage.bytes | Total RAM usage in bytes. This metric reports the RAM usage of the database process, including the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_mysql.database.memory.usage.bytes | RAM usage in bytes. This metric reports the RAM usage of the server, excluding the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_mysql.database.memory.utilization.pct | The fraction of the memory quota that is currently in use. | double | percent | gauge |
| gcp.cloudsql_mysql.database.network.connections.count | Number of connections to databases on the Cloud SQL instance. Only applicable to MySQL and SQL Server. | long |  | gauge |
| gcp.cloudsql_mysql.database.network.received_bytes.count | Delta count of bytes received through the network. | long |  | gauge |
| gcp.cloudsql_mysql.database.network.sent_bytes.count | Delta count of bytes sent through the network. | long |  | gauge |
| gcp.cloudsql_mysql.database.queries.count | Delta count of statements executed by the server. | long |  | gauge |
| gcp.cloudsql_mysql.database.questions.count | Delta count of statements executed by the server sent by the client. | long |  | gauge |
| gcp.cloudsql_mysql.database.received_bytes.count | Delta count of bytes received by MySQL process. | long |  | gauge |
| gcp.cloudsql_mysql.database.replication.last_io_errno | The error number of the most recent error that caused the I/O thread to stop. | long |  | gauge |
| gcp.cloudsql_mysql.database.replication.last_sql_errno | The error number of the most recent error that caused the SQL thread to stop. | long |  | gauge |
| gcp.cloudsql_mysql.database.replication.network_lag.sec | Indicates time taken from primary binary log to IO thread on replica. Only applicable to replicas. | long | s | gauge |
| gcp.cloudsql_mysql.database.replication.replica_lag.sec | Number of seconds the read replica is behind its primary (approximation). | double | s | gauge |
| gcp.cloudsql_mysql.database.replication.seconds_behind_master.sec | Number of seconds the read replica is behind its primary (approximation). | long | s | gauge |
| gcp.cloudsql_mysql.database.replication.slave_io_running | Indicates whether the I/O thread for reading the primary's binary log is running. Possible values are Yes, No and Connecting. | keyword |  |  |
| gcp.cloudsql_mysql.database.replication.slave_io_running_state | Indicates whether the I/O thread for reading the primary's binary log is running. Possible values are Yes, No and Connecting, and the values are exposed through the 'state' field. | boolean |  |  |
| gcp.cloudsql_mysql.database.replication.slave_sql_running | Indicates whether the SQL thread for executing events in the relay log is running. | keyword |  |  |
| gcp.cloudsql_mysql.database.replication.slave_sql_running_state | Indicates whether the SQL thread for executing events in the relay log is running. Possible values are Yes / No, and the values are exposed through the 'state' field. | boolean |  |  |
| gcp.cloudsql_mysql.database.sent_bytes.count | Delta count of bytes sent by MySQL process. | long |  | gauge |
| gcp.cloudsql_mysql.database.up | Indicates if the server is up or not. | long |  | gauge |
| gcp.cloudsql_mysql.database.uptime.sec | Delta count of the time in seconds the instance has been running. | long | s | gauge |
| gcp.labels.metadata.\* |  | object |  |  |
| gcp.labels.metrics.\* |  | object |  |  |
| gcp.labels.resource.\* |  | object |  |  |
| gcp.labels.system.\* |  | object |  |  |
| gcp.labels.user.\* |  | object |  |  |
| gcp.labels_fingerprint | Hashed value of the labels field. | keyword |  |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |


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
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| gcp.cloudsql_postgresql.database.auto_failover_request.count | Delta of number of instance auto-failover requests. | long |  | gauge |
| gcp.cloudsql_postgresql.database.available_for_failover | This is \> 0 if the failover operation is available on the instance. | long |  | gauge |
| gcp.cloudsql_postgresql.database.cpu.reserved_cores.count | Number of cores reserved for the database. | double |  | gauge |
| gcp.cloudsql_postgresql.database.cpu.usage_time.sec | Delta CPU usage time in seconds. | double | s | gauge |
| gcp.cloudsql_postgresql.database.cpu.utilization.pct | Current CPU utilization represented as a percentage of the reserved CPU that is currently in use. | double | percent | gauge |
| gcp.cloudsql_postgresql.database.disk.bytes_used.bytes | Data utilization in bytes. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.disk.quota.bytes | Maximum data disk size in bytes. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.disk.read_ops.count | Delta count of data disk read IO operations. | long |  | gauge |
| gcp.cloudsql_postgresql.database.disk.utilization.pct | The fraction of the disk quota that is currently in use. | double | percent | gauge |
| gcp.cloudsql_postgresql.database.disk.write_ops.count | Delta count of data disk write IO operations. | long |  | gauge |
| gcp.cloudsql_postgresql.database.insights.aggregate.execution_time | Accumulated query execution time per user per database. This is the sum of cpu time, io wait time, lock wait time, process context switch, and scheduling for all the processes involved in the query execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.aggregate.io_time | Accumulated IO time per user per database. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.aggregate.latencies | Query latency distribution per user per database. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.aggregate.lock_time | Accumulated lock wait time per user per database. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.aggregate.row.count | Total number of rows affected during query execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.aggregate.shared_blk_access.count | Shared blocks (regular tables & indexed) accessed by statement execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.perquery.execution_time | Accumulated execution times per user per database per query.This is the sum of cpu time, io wait time, lock wait time, process context switch, and scheduling for all the processes involved in the query execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.perquery.io_time | Accumulated IO time per user per database per query. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.perquery.latencies | Query latency distribution per user per database per query. | histogram |  |  |
| gcp.cloudsql_postgresql.database.insights.perquery.lock_time | Accumulated lock wait time per user per database per query. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.perquery.row.count | Total number of rows affected during query execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.perquery.shared_blk_access.count | Shared blocks (regular tables & indexed) accesssed by statement execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.pertag.execution_time | Accumulated execution times per user per database per tag.This is the sum of cpu time, io wait time, lock wait time, process context switch, and scheduling for all the processes involved in the query execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.pertag.io_time | Accumulated IO write time per user per database per tag. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.pertag.latencies | Query latency distribution per user per database per tag. | histogram |  |  |
| gcp.cloudsql_postgresql.database.insights.pertag.lock_time | Accumulated lock wait time per user per database per tag. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.pertag.row.count | Total number of rows affected during query execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.insights.pertag.shared_blk_access.count | Shared blocks (regular tables & indexed) accessed by statement execution. | long |  | counter |
| gcp.cloudsql_postgresql.database.instance_state | The current serving state of the Cloud SQL instance. | boolean |  |  |
| gcp.cloudsql_postgresql.database.memory.quota.bytes | Maximum RAM size in bytes. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.memory.total_usage.bytes | Total RAM usage in bytes. This metric reports the RAM usage of the database process, including the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.memory.usage.bytes | RAM usage in bytes. This metric reports the RAM usage of the server, excluding the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.memory.utilization.pct | The fraction of the memory quota that is currently in use. | double | percent | gauge |
| gcp.cloudsql_postgresql.database.network.connections.count | Number of connections to databases on the Cloud SQL instance. Only applicable to MySQL and SQL Server. | long |  | gauge |
| gcp.cloudsql_postgresql.database.network.received_bytes.count | Delta count of bytes received through the network. | long |  | gauge |
| gcp.cloudsql_postgresql.database.network.sent_bytes.count | Delta count of bytes sent through the network. | long |  | gauge |
| gcp.cloudsql_postgresql.database.num_backends.count | Number of connections to the Cloud SQL PostgreSQL instance. | long |  | gauge |
| gcp.cloudsql_postgresql.database.replication.network_lag.sec | Indicates time taken from primary binary log to IO thread on replica. Only applicable to replicas. | long | s | gauge |
| gcp.cloudsql_postgresql.database.replication.replica_byte_lag.bytes | Replication lag in bytes. Reported from the master per replica. | long | byte | gauge |
| gcp.cloudsql_postgresql.database.replication.replica_lag.sec | Number of seconds the read replica is behind its primary (approximation). | double | s | gauge |
| gcp.cloudsql_postgresql.database.transaction.count | Delta count of number of transactions. | long |  | gauge |
| gcp.cloudsql_postgresql.database.transaction_id.count | Delta count of transaction ID. | long |  | gauge |
| gcp.cloudsql_postgresql.database.transaction_id_utilization.pct | Current utilization represented as a percentage of transaction IDs consumed by the Cloud SQL PostgreSQL instance. Values are typically numbers between 0.0 and 1.0. Charts display the values as a percentage between 0% and 100%. | double | percent | gauge |
| gcp.cloudsql_postgresql.database.up | Indicates if the server is up or not. | long |  | gauge |
| gcp.cloudsql_postgresql.database.uptime.sec | Delta count of the time in seconds the instance has been running. | long | s | gauge |
| gcp.cloudsql_postgresql.database.vacuum.oldest_transaction_age | Age of the oldest transaction yet to be vacuumed in the Cloud SQL PostgreSQL instance, measured in number of transactions that have happened since the oldest transaction. | long |  | gauge |
| gcp.labels.metadata.\* |  | object |  |  |
| gcp.labels.metrics.\* |  | object |  |  |
| gcp.labels.resource.\* |  | object |  |  |
| gcp.labels.system.\* |  | object |  |  |
| gcp.labels.user.\* |  | object |  |  |
| gcp.labels_fingerprint | Hashed value of the labels field. | keyword |  |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |



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
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| gcp.cloudsql_sqlserver.database.audits_size.bytes | Tracks the size in bytes of stored SQLServer audit files on an instance. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.audits_upload.count | Delta count of total number of SQLServer audit file uploads to a GCS bucket and whether or not an upload was successful. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.auto_failover_request.count | Delta of number of instance auto-failover requests. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.available_for_failover | This is \> 0 if the failover operation is available on the instance. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.cpu.reserved_cores.count | Number of cores reserved for the database. | double |  | gauge |
| gcp.cloudsql_sqlserver.database.cpu.usage_time.sec | Delta CPU usage time in seconds. | double | s | gauge |
| gcp.cloudsql_sqlserver.database.cpu.utilization.pct | Current CPU utilization represented as a percentage of the reserved CPU that is currently in use. | double | percent | gauge |
| gcp.cloudsql_sqlserver.database.disk.bytes_used.bytes | Data utilization in bytes. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.disk.quota.bytes | Maximum data disk size in bytes. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.disk.read_ops.count | Delta count of data disk read IO operations. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.disk.utilization.pct | The fraction of the disk quota that is currently in use. | double | percent | gauge |
| gcp.cloudsql_sqlserver.database.disk.write_ops.count | Delta count of data disk write IO operations. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.instance_state | The current serving state of the Cloud SQL instance. | boolean |  |  |
| gcp.cloudsql_sqlserver.database.memory.quota.bytes | Maximum RAM size in bytes. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.memory.total_usage.bytes | Total RAM usage in bytes. This metric reports the RAM usage of the database process, including the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.memory.usage.bytes | RAM usage in bytes. This metric reports the RAM usage of the server, excluding the buffer/cache. | long | byte | gauge |
| gcp.cloudsql_sqlserver.database.memory.utilization.pct | The fraction of the memory quota that is currently in use. | double | percent | gauge |
| gcp.cloudsql_sqlserver.database.network.connections.count | Number of connections to databases on the Cloud SQL instance. Only applicable to MySQL and SQL Server. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.network.received_bytes.count | Delta count of bytes received through the network. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.network.sent_bytes.count | Delta count of bytes sent through the network. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.replication.network_lag.sec | Indicates time taken from primary binary log to IO thread on replica. Only applicable to replicas. | long | s | gauge |
| gcp.cloudsql_sqlserver.database.replication.replica_lag.sec | Number of seconds the read replica is behind its primary (approximation). | double | s | gauge |
| gcp.cloudsql_sqlserver.database.up | Indicates if the server is up or not. | long |  | gauge |
| gcp.cloudsql_sqlserver.database.uptime.sec | Delta count of the time in seconds the instance has been running. | long | s | gauge |
| gcp.labels.metadata.\* |  | object |  |  |
| gcp.labels.metrics.\* |  | object |  |  |
| gcp.labels.resource.\* |  | object |  |  |
| gcp.labels.system.\* |  | object |  |  |
| gcp.labels.user.\* |  | object |  |  |
| gcp.labels_fingerprint | Hashed value of the labels field. | keyword |  |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |

