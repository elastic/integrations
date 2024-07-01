# MySQL Integration

This integration periodically fetches logs and metrics from [MySQL](https://www.mysql.com/) servers.

## Compatibility

The `error` and `slowlog` datasets were tested with logs from MySQL 5.5, 5.7 and 8.0, MariaDB 10.1, 10.2 and 10.3, and Percona 5.7 and 8.0.

The `galera_status` and `status` datasets were tested with MySQL and Percona 5.7 and 8.0 and are expected to work with all
versions >= 5.7.0. It is also tested with MariaDB 10.2, 10.3 and 10.4.

## Logs

### error

The `error` dataset collects the MySQL error logs.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "error"}}

### slowlog

The `slowlog` dataset collects the MySQL slow logs.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "slowlog"}}

## Metrics

### galera_status

The `galera_status` dataset periodically fetches metrics from [Galera](http://galeracluster.com/)-MySQL cluster servers.

{{event "galera_status"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "galera_status"}}

### status

The MySQL `status` dataset collects data from MySQL by running a `SHOW GLOBAL STATUS;` SQL query. This query returns a large number of metrics.

{{event "status"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "status"}}
