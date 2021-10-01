# rds

## Metrics

An example event for `rds` looks as following:

```json
{
    "@timestamp": "2020-05-28T17:58:34.537Z",
    "ecs": {
        "version": "1.5.0"
    },
    "service": {
        "type": "aws"
    },
    "aws": {
        "rds": {
            "latency": {
                "dml": 0,
                "insert": 0,
                "update": 0,
                "commit": 0,
                "ddl": 0,
                "delete": 0,
                "select": 0.21927814569536422
            },
            "queries": 6.197934021992669,
            "aurora_bin_log_replica_lag": 0,
            "transactions": {
                "blocked": 0,
                "active": 0
            },
            "deadlocks": 0,
            "login_failures": 0,
            "throughput": {
                "network": 1.399813358218904,
                "insert": 0,
                "ddl": 0,
                "select": 2.5165408396246853,
                "delete": 0,
                "commit": 0,
                "network_transmit": 0.699906679109452,
                "update": 0,
                "dml": 0,
                "network_receive": 0.699906679109452
            },
            "cpu": {
                "total": {
                    "pct": 0.03
                }
            },
            "db_instance": {
                "arn": "arn:aws:rds:eu-west-1:428152502467:db:database-1-instance-1-eu-west-1a",
                "class": "db.r5.large",
                "identifier": "database-1-instance-1-eu-west-1a",
                "status": "available"
            },
            "cache_hit_ratio.result_set": 0,
            "aurora_replica.lag.ms": 19.576,
            "free_local_storage.bytes": 32431271936,
            "cache_hit_ratio.buffer": 100,
            "disk_usage": {
                "bin_log.bytes": 0
            },
            "db_instance.identifier": "database-1-instance-1-eu-west-1a",
            "freeable_memory.bytes": 4436537344,
            "engine_uptime.sec": 10463030,
            "database_connections": 0
        }
    },
    "cloud": {
        "provider": "aws",
        "region": "eu-west-1",
        "account": {
            "id": "428152502467",
            "name": "elastic-beats"
        },
        "availability_zone": "eu-west-1a"
    },
    "event": {
        "dataset": "aws.rds",
        "module": "aws",
        "duration": 10777919184
    },
    "metricset": {
        "name": "rds",
        "period": 60000
    },
    "agent": {
        "name": "MacBook-Elastic.local",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
        "id": "12f376ef-5186-4e8b-a175-70f1140a8f30"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.\*.metrics.\*.\* | Metrics that returned from Cloudwatch API query. | object |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.\* | Metric dimensions. | object |
| aws.dimensions.DBClusterIdentifier | This dimension filters the data that you request for a specific Amazon Aurora DB cluster. | keyword |
| aws.dimensions.DBClusterIdentifier,Role | This dimension filters the data that you request for a specific Aurora DB cluster, aggregating the metric by instance role (WRITER/READER). | keyword |
| aws.dimensions.DBInstanceIdentifier | This dimension filters the data that you request for a specific DB instance. | keyword |
| aws.dimensions.DatabaseClass | This dimension filters the data that you request for all instances in a database class. | keyword |
| aws.dimensions.DbClusterIdentifier, EngineName | This dimension filters the data that you request for a specific Aurora DB cluster, aggregating the metric by engine name. | keyword |
| aws.dimensions.EngineName | This dimension filters the data that you request for the identified engine name only. | keyword |
| aws.dimensions.SourceRegion | This dimension filters the data that you request for the specified region only. | keyword |
| aws.rds.aurora_bin_log_replica_lag | The amount of time a replica DB cluster running on Aurora with MySQL compatibility lags behind the source DB cluster. | long |
| aws.rds.aurora_global_db.data_transfer.bytes | In an Aurora Global Database, the amount of redo log data transferred from the master AWS Region to a secondary AWS Region. | long |
| aws.rds.aurora_global_db.replicated_write_io.bytes | In an Aurora Global Database, the number of write I/O operations replicated from the primary AWS Region to the cluster volume in a secondary AWS Region. | long |
| aws.rds.aurora_global_db.replication_lag.ms | For an Aurora Global Database, the amount of lag when replicating updates from the primary AWS Region, in milliseconds. | long |
| aws.rds.aurora_replica.lag.ms | For an Aurora Replica, the amount of lag when replicating updates from the primary instance, in milliseconds. | long |
| aws.rds.aurora_replica.lag_max.ms | The maximum amount of lag between the primary instance and each Aurora DB instance in the DB cluster, in milliseconds. | long |
| aws.rds.aurora_replica.lag_min.ms | The minimum amount of lag between the primary instance and each Aurora DB instance in the DB cluster, in milliseconds. | long |
| aws.rds.aurora_volume_left_total.bytes | The remaining available space for the cluster volume, measured in bytes. | long |
| aws.rds.backtrack_change_records.creation_rate | The number of backtrack change records created over five minutes for your DB cluster. | long |
| aws.rds.backtrack_change_records.stored | The actual number of backtrack change records used by your DB cluster. | long |
| aws.rds.backtrack_window.actual | The difference between the target backtrack window and the actual backtrack window. | long |
| aws.rds.backtrack_window.alert | The number of times that the actual backtrack window is smaller than the target backtrack window for a given period of time. | long |
| aws.rds.backup_storage_billed_total.bytes | The total amount of backup storage in bytes for which you are billed for a given Aurora DB cluster. | long |
| aws.rds.cache_hit_ratio.buffer | The percentage of requests that are served by the buffer cache. | long |
| aws.rds.cache_hit_ratio.result_set | The percentage of requests that are served by the Resultset cache. | long |
| aws.rds.cpu.credit_balance | The number of earned CPU credits that an instance has accrued since it was launched or started. | long |
| aws.rds.cpu.credit_usage | The number of CPU credits spent by the instance for CPU utilization. | long |
| aws.rds.cpu.total.pct | The percentage of CPU utilization. | scaled_float |
| aws.rds.database_connections | The number of database connections in use. | long |
| aws.rds.db_instance.arn | Amazon Resource Name(ARN) for each rds. | keyword |
| aws.rds.db_instance.class | Contains the name of the compute and memory capacity class of the DB instance. | keyword |
| aws.rds.db_instance.db_cluster_identifier | This identifier is the unique key that identifies a DB cluster specifically for Amazon Aurora DB cluster. | keyword |
| aws.rds.db_instance.engine_name | Each DB instance runs a DB engine, like MySQL, MariaDB, PostgreSQL and etc. | keyword |
| aws.rds.db_instance.identifier | Contains a user-supplied database identifier. This identifier is the unique key that identifies a DB instance. | keyword |
| aws.rds.db_instance.role | DB roles like WRITER or READER, specifically for Amazon Aurora DB cluster. | keyword |
| aws.rds.db_instance.status | Specifies the current state of this database. | keyword |
| aws.rds.deadlocks | The average number of deadlocks in the database per second. | long |
| aws.rds.disk_queue_depth | The number of outstanding IOs (read/write requests) waiting to access the disk. | float |
| aws.rds.disk_usage.bin_log.bytes | The amount of disk space occupied by binary logs on the master. Applies to MySQL read replicas. | long |
| aws.rds.disk_usage.replication_slot.mb | The disk space used by replication slot files. Applies to PostgreSQL. | long |
| aws.rds.disk_usage.transaction_logs.mb | The disk space used by transaction logs. Applies to PostgreSQL. | long |
| aws.rds.engine_uptime.sec | The amount of time that the instance has been running, in seconds. | long |
| aws.rds.failed_sql_server_agent_jobs | The number of failed SQL Server Agent jobs during the last minute. | long |
| aws.rds.free_local_storage.bytes | The amount of storage available for temporary tables and logs, in bytes. | long |
| aws.rds.free_storage.bytes | The amount of available storage space. | long |
| aws.rds.freeable_memory.bytes | The amount of available random access memory. | long |
| aws.rds.latency.commit | The amount of latency for commit operations, in milliseconds. | float |
| aws.rds.latency.ddl | The amount of latency for data definition language (DDL) requests, in milliseconds. | float |
| aws.rds.latency.delete | The amount of latency for delete queries, in milliseconds. | float |
| aws.rds.latency.dml | The amount of latency for inserts, updates, and deletes, in milliseconds. | float |
| aws.rds.latency.insert | The amount of latency for insert queries, in milliseconds. | float |
| aws.rds.latency.read | The average amount of time taken per disk I/O operation. | float |
| aws.rds.latency.select | The amount of latency for select queries, in milliseconds. | float |
| aws.rds.latency.update | The amount of latency for update queries, in milliseconds. | float |
| aws.rds.latency.write | The average amount of time taken per disk I/O operation. | float |
| aws.rds.login_failures | The average number of failed login attempts per second. | long |
| aws.rds.maximum_used_transaction_ids | The maximum transaction ID that has been used. Applies to PostgreSQL. | long |
| aws.rds.oldest_replication_slot_lag.mb | The lagging size of the replica lagging the most in terms of WAL data received. Applies to PostgreSQL. | long |
| aws.rds.queries | The average number of queries executed per second. | long |
| aws.rds.rds_to_aurora_postgresql_replica_lag.sec | The amount of lag in seconds when replicating updates from the primary RDS PostgreSQL instance to other nodes in the cluster. | long |
| aws.rds.read_io.ops_per_sec | The average number of disk read I/O operations per second. | float |
| aws.rds.replica_lag.sec | The amount of time a Read Replica DB instance lags behind the source DB instance. Applies to MySQL, MariaDB, and PostgreSQL Read Replicas. | long |
| aws.rds.storage_used.backup_retention_period.bytes | The total amount of backup storage in bytes used to support the point-in-time restore feature within the Aurora DB cluster's backup retention window. | long |
| aws.rds.storage_used.snapshot.bytes | The total amount of backup storage in bytes consumed by all Aurora snapshots for an Aurora DB cluster outside its backup retention window. | long |
| aws.rds.swap_usage.bytes | The amount of swap space used on the DB instance. This metric is not available for SQL Server. | long |
| aws.rds.throughput.commit | The average number of commit operations per second. | float |
| aws.rds.throughput.ddl | The average number of DDL requests per second. | float |
| aws.rds.throughput.delete | The average number of delete queries per second. | float |
| aws.rds.throughput.dml | The average number of inserts, updates, and deletes per second. | float |
| aws.rds.throughput.insert | The average number of insert queries per second. | float |
| aws.rds.throughput.network | The amount of network throughput both received from and transmitted to clients by each instance in the Aurora MySQL DB cluster, in bytes per second. | float |
| aws.rds.throughput.network_receive | The incoming (Receive) network traffic on the DB instance, including both customer database traffic and Amazon RDS traffic used for monitoring and replication. | float |
| aws.rds.throughput.network_transmit | The outgoing (Transmit) network traffic on the DB instance, including both customer database traffic and Amazon RDS traffic used for monitoring and replication. | float |
| aws.rds.throughput.read | The average amount of time taken per disk I/O operation. | float |
| aws.rds.throughput.select | The average number of select queries per second. | float |
| aws.rds.throughput.update | The average number of update queries per second. | float |
| aws.rds.throughput.write | The average number of bytes written to disk per second. | float |
| aws.rds.transaction_logs_generation | The disk space used by transaction logs. Applies to PostgreSQL. | long |
| aws.rds.transactions.active | The average number of current transactions executing on an Aurora database instance per second. | long |
| aws.rds.transactions.blocked | The average number of transactions in the database that are blocked per second. | long |
| aws.rds.volume.read.iops | The number of billed read I/O operations from a cluster volume, reported at 5-minute intervals. | long |
| aws.rds.volume.write.iops | The number of write disk I/O operations to the cluster volume, reported at 5-minute intervals. | long |
| aws.rds.volume_used.bytes | The amount of storage used by your Aurora DB instance, in bytes. | long |
| aws.rds.write_io.ops_per_sec | The average number of disk write I/O operations per second. | float |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.\* | Tag key value pairs from aws resources. | object |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
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
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |
| error.message | Error message. | match_only_text |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
