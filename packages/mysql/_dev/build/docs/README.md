# MySQL Integration

## Overview

[MySQL](https://www.mysql.com/) is an open-source Relational Database Management System (RDBMS) that enables users to store, manage, and retrieve structured data efficiently.

### Compatibility

Databases version compatibility across data streams.

|Data Stream      | MySQL Version   | MariaDB Version    |Percona Version | 
| ----------------|-----------------|--------------------|----------------|
|error and slowlog|`5.5`,`5.7`,`8.0`|`10.1`,`10.2`,`10.3`|`5.7`,`5.8`     |
|galera_status and status|`5.7`,`8.0`|`10.2`,`10.3`,`10.4`|`5.7`,`8.0`    |
|replica_status|`5.7`,`8.0.22`|`10.4`,`10.5.1`|`5.7`,`8.0.22`|
         

MySQL and Percona from version `8.0.22` onwards and MariaDB from version `10.5.1` onwards support the `SHOW REPLICA STATUS;` query. Versions prior to these use the `SHOW SLAVE STATUS;` query.
The `replica_status` data stream supports master-slave or master-replica replication configurations as specified in the [MySQL Replication Configuration](https://dev.mysql.com/doc/refman/8.4/en/replication-configuration.html) documentation.

## What data does this integration collect?

Use the MySQL integration to:

- Collect error and slow query logs, as well as status, galera status, and replication status metrics, to provide insights into database operations, query performance and replication health.
- Create informative visualizations to track usage trends, measure key metrics, and derive actionable business insights.
- Set up alerts to minimize Mean Time to Detect (MTTD) and Mean Time to Resolve (MTTR) by quickly referencing relevant logs during troubleshooting.

### Data streams

The MySQL integration collects logs and metrics data, providing comprehensive insights into database operations and performance.

**Logs** provide insights into the operations and events within the MySQL environment. The MySQL integration collects `error` logs helping users to track errors and warnings, understand their causes, and address database-related issues efficiently. This includes monitoring for slow-performing queries through the `slowlog` data stream, which is critical for identifying and resolving queries that negatively affect database performance. 

**Metrics** offer statistics that reflect the performance and health of MySQL. The `status` data stream, for instance, gathers a variety of performance metrics, including connection errors, cache efficiency, and InnoDB storage engine details. The `galera_status` data stream offers a view into the health and performance of Galera Clusters, which is vital for the maintenance of distributed database systems. For replication health, the `replica_status` data stream provides metrics that shed light on the state of replication between the source and replica servers, ensuring the replication process is functioning correctly. 

Data streams:

- `error`: Collects error logs from the MySQL server, helping to detect and troubleshoot issues that may affect database functionality. This data stream includes information such as error messages, severities, and error codes.
- `slowlog`: Collects slow-performing queries that exceed a defined time threshold. This data stream includes details such as query execution time, lock time, rows affected, and the actual query text, which are crucial for pinpointing and optimizing slow queries.
- `status`: Collects various status and performance indicators, including connection errors, cache performance, binary log usage, network I/O, thread activity, and detailed InnoDB metrics, allowing for a thorough analysis of the MySQL server's health and efficiency.
- `galera_status`: Collects various status and performance metrics, which provide insights into cluster performance, including replication health and node status, to maintain the robustness and fault tolerance of the distributed database system.
- `replica_status`: Collects metrics related to status and performance of the replication process, including details from source and replica servers.
- `performance`:  Monitors MySQL database performance by collecting metrics that help identify slow queries and track how database indexes are being used. This helps database administrators optimize their databases and troubleshoot performance issues.

**NOTE**: You can monitor MySQL logs by using the logs-* index pattern in the Discover feature, while metrics can be viewed using the metrics-* index pattern.

## What do I need to use this integration?

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

To ingest data from MySQL, you have to:

- Specify the hostname, username, and password to connect to the MySQL database. Additionally, there is query parameter in replica_status data stream(default query is `SHOW REPLICA STATUS;` user can change it to `SHOW SLAVE STATUS`).
- Specify the paths of MySQL error logs and slow logs. (default paths are:- Error logs: `/var/log/mysql/error.log*` and `/var/log/mysqld.log*`, Slow logs: `/var/log/mysql/*-slow.log*` and `/var/lib/mysql/*-slow.log*`)

Before you can start sending data to Elastic, make sure you have the necessary MySQL user permissions configured appropriately. It's important to create a user password that does not include special characters to ensure compatibility with the integration.

To create a MySQL user with the correct permissions and configure this user account within the Elastic Agent integration for metric collection follow these steps:

1. Create a dedicated user for Elastic monitoring.

   Connect to your MySQL server using a MySQL client with administrative privileges.

   `CREATE USER 'elastic_monitor'@'localhost' IDENTIFIED BY 'YourPasswordHere';`

    **NOTE**: Replace `YourPasswordHere` with a secure password that does not contain special characters. For example, a password like `p@$$w0rd!` will fail.

2. Grant the necessary permissions.

    The `elastic_monitor` user needs specific permissions to retrieve metrics. Run the following commands to grant these permissions:

    `GRANT PROCESS, SHOW DATABASES, REPLICATION CLIENT ON *.* TO` `'elastic_monitor'@'localhost';`
    `GRANT SELECT ON `mysql`.* TO 'elastic_monitor'@'localhost';`
    `GRANT SELECT ON `sys`.* TO 'elastic_monitor'@'localhost';`
    `GRANT SELECT ON `performance_schema`.* TO 'elastic_monitor'@'localhost';`

    For any specific databases you want to monitor, grant SELECT permission for each:

    `GRANT SELECT ON `example_db`.* TO 'elastic_monitor'@'localhost';`

    Replace `example_db` with the actual name of the database you intend to monitor.
   
3. Apply the permissions, run this command:

    `FLUSH PRIVILEGES;`

## How do I deploy this integration?

For step-by-step instructions on how to set up an integration, check the [Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

### Validation

After the integration is successfully configured, click the Assets tab of the MySQL Integration to display a list of the available dashboards. The dashboard should be populated with your configured data stream.

## Troubleshooting

For MySQL, MariaDB and Percona, the query used to check replica status changes depending on the version of the database. You can adjust the query in the integration configuration accordingly. 

## Logs reference

### Error

The `error` dataset collects the MySQL error logs.

{{event "error"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "error"}}

### Slow Log

The `slowlog` dataset collects the MySQL slow logs.

{{event "slowlog"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "slowlog"}}

## Metrics reference

### Galera Status

The `galera_status` dataset periodically fetches metrics from [Galera](http://galeracluster.com/)-MySQL cluster servers.

{{event "galera_status"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "galera_status"}}

### Replica Status

The `replica_status` dataset collects data from MySQL by running a `SHOW REPLICA STATUS;` or `SHOW SLAVE STATUS;` query. This data stream provides information about the configuration and status of the connection between the replica server and the source server.

{{event "replica_status"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "replica_status"}}

### Status

The MySQL `status` dataset collects data from MySQL by running a `SHOW GLOBAL STATUS;` SQL query. This query returns a large number of metrics.

{{event "status"}}

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "status"}}
