# MySQL Integration

## Overview

[MySQL](https://www.mysql.com/) is an open-source Relational Database Management System (RDBMS) that enables users to store, manage, and retrieve structured data efficiently.

Use the MySQL integration to:

- Collect error and slow query logs, as well as status, galera status, and replication status metrics, to provide insights into database operations, query performance and replication health.
- Create informative visualizations to track usage trends, measure key metrics, and derive actionable business insights.
- Set up alerts to minimize Mean Time to Detect (MTTD) and Mean Time to Resolve (MTTR) by quickly referencing relevant logs during troubleshooting.

## Data streams

The MySQL integration collects logs and metrics data, providing comprehensive insights into database operations and performance.

Logs provide insights into the operations and events within the MySQL environment. The MySQL integration collects `error` logs helping users to track errors and warnings, understand their causes, and address database-related issues efficiently. This includes monitoring for slow-performing queries through the `slowlog` data stream, which is critical for identifying and resolving queries that negatively affect database performance. 

Metrics offer statistics that reflect the performance and health of MySQL. The `status` data stream, for instance, gathers a variety of performance metrics, including connection errors, cache efficiency, and InnoDB storage engine details. The `galera_status` data stream offers a view into the health and performance of Galera Clusters, which is vital for the maintenance of distributed database systems. For replication health, the `replica_status` data stream provides metrics that shed light on the state of replication between the source and replica servers, ensuring the replication process is functioning correctly. 

Data streams:

- `error`: Collect error logs from the MySQL server, helping to detect and troubleshoot issues that may affect database functionality. This data stream includes information such as error messages, severities, and error codes.
- `slowlog`: Collect slow-performing queries that exceed a defined time threshold. This data stream includes details such as query execution time, lock time, rows affected, and the actual query text, which are crucial for pinpointing and optimizing slow queries.
- `status`: Collect various status and performance indicators, including connection errors, cache performance, binary log usage, network I/O, thread activity, and detailed InnoDB metrics, allowing for a thorough analysis of the MySQL server's health and efficiency.
- `galera_status`: Collect various status and performance metrics, which provide insights into cluster performance, including replication health and node status, to maintain the robustness and fault tolerance of the distributed database system.
- `replica_status`:  Collect metrics related to status and performance of the replication process, including details from source and replica servers.

Note:
- Users can monitor MySQL logs by using the logs-* index pattern in the Discover feature, while metrics can be viewed using the metrics-* index pattern.

## Compatibility

The `error` and `slowlog` datasets were tested with logs from MySQL `5.5`, `5.7` and `8.0`, MariaDB `10.1`, `10.2` and `10.3`, and Percona `5.7` and `8.0`.

The `galera_status` and `status` datasets were tested with MySQL and Percona `5.7` and `8.0` and are expected to work with all versions >= `5.7.0`. It is also tested with MariaDB `10.2`, `10.3` and `10.4`.

The `replica_status` was tested with MySQL `5.7` and `8.0.22`,  MariaDB `10.4` and `10.5.1`, Percona `5.7` and `8.0.22`.

Note:

Information about which query is used to fetch replica status in Mysql, MariaDB and Percona:
- MySQL versions `8.0.22` and newer support both [`SHOW REPLICA STATUS;`](https://dev.mysql.com/doc/refman/8.0/en/show-replica-status.html) and [`SHOW SLAVE STATUS;`](https://dev.mysql.com/doc/refman/8.0/en/show-slave-status.html) queries. However, versions older than `8.0.22` only support the `SHOW SLAVE STATUS;` query.
- MariaDB versions `10.5.1` and newer support both [`SHOW REPLICA STATUS;`](https://mariadb.com/kb/en/show-replica-status/) and `SHOW SLAVE STATUS;` queries. However, versions older than `10.5.1` only support the `SHOW SLAVE STATUS;` query. Also, the output of both commands are identical, with the Replica Status metrics names remaining consistent across versions in MariaDB.
- Percona versions `8.0.22` and newer support both [`SHOW REPLICA STATUS;`](https://docs.percona.com/percona-server/8.0/release-notes/Percona-Server-8.0.22-13.html) and `SHOW SLAVE STATUS;` queries. However, versions older than `8.0.22` only support the `SHOW SLAVE STATUS;` query.

## Prerequisites

Users require Elasticsearch for storing and searching their data, and Kibana for visualizing and managing it. They can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on their own hardware.

In order to ingest data from MySQL:

- Users should specify the hostname, username, and password to connect to the MySQL database. Additionally, there is query parameter in replica_status data stream(default query is `SHOW REPLICA STATUS;` user can change it to `SHOW SLAVE STATUS`).
- Users should specify the paths of MySQL error logs and slow logs. (default paths are:- Error logs: `/var/log/mysql/error.log*` and `/var/log/mysqld.log*`, Slow logs: `/var/log/mysql/*-slow.log*` and `/var/lib/mysql/*-slow.log*`)

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the MySQL Integration should display a list of available dashboards. Click on the dashboard available for the user's configured data stream. It should be populated with the required data.

## Troubleshooting

For MySQL, MariaDB and Percona the query to check replica status varies depending on the version of the database. Users should adjust the query in the integration configuration accordingly. 

## Logs reference

### Error

The `error` dataset collects the MySQL error logs.

{{fields "error"}}

### Slow Log

The `slowlog` dataset collects the MySQL slow logs.

{{fields "slowlog"}}

## Metrics reference

### Galera Status

The `galera_status` dataset periodically fetches metrics from [Galera](http://galeracluster.com/)-MySQL cluster servers.

{{event "galera_status"}}

{{fields "galera_status"}}

### Replica Status

The `replica_status` dataset collects data from MySQL by running a `SHOW REPLICA STATUS;` or `SHOW SLAVE STATUS;` query. This data stream provides information about the configuration and status of the connection between the replica server and the source server.

{{event "replica_status"}}

{{fields "replica_status"}}

### Status

The `status` dataset collects data from MySQL by running a `SHOW GLOBAL STATUS;` SQL query. This query returns a large number of metrics.

{{event "status"}}

{{fields "status"}}