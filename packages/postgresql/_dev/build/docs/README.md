# PostgreSQL Integration

This integration periodically fetches logs and metrics from [PostgreSQL](https://www.postgresql.org/) servers.

## Compatibility

The `log` integration was tested with logs from versions 9.5 on Ubuntu, 9.6 on Debian, and finally 10.11, 11.4 and 12.2 on Arch Linux 9.3. CSV format was tested using versions 11 and 13 (distro is not relevant here).

The `activity`, `bgwriter`, `database` and `statement` integrations were tested with PostgreSQL 9.5.3 and is expected to work with all versions `>= 9`.

## Logs

### log

The `log` integration collects the PostgreSQL logs in plain text format or CSV.
AWS RDS PostgresSQL standard logs can also be collected by this integration.

#### Using CSV logs

Since the PostgreSQL CSV log file is a well-defined format,
there is almost no configuration to be done in Fleet, just the filepath.

On the other hand, it's necessary to configure PostgreSQL to emit `.csv` logs.

The recommended parameters are:
```
logging_collector = 'on';
log_destination = 'csvlog';
log_statement = 'none';
log_checkpoints = on;
log_connections = on;
log_disconnections = on;
log_lock_waits = on;
log_min_duration_statement = 0;
```

In busy servers, `log_min_duration_statement` can cause contention, so you can assign
a value greater than 0.

Both `log_connections` and `log_disconnections` can cause a lot of events if you don't have
persistent connections, so enable with care.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "log"}}

## Metrics access permission

Assigning `pg_monitor` or `pg_read_all_stats` rights to the database user might not be enough for fetching the metric data from PostgreSQL servers. 
Apart from `CONNECT` permission, the database user must be granted `SELECT` accesss on underlying tables / views `pg_stat_bgwriter`, `pg_stat_activity`, `pg_stat_database`, `pg_stat_statements`. 


```
   grant select on table pg_stat_bgwriter to user;
   grant select on table pg_stat_activity to user;
   grant select on table pg_stat_database to user;
   grant select on table pg_stat_statements to user; 
```
Run the below command if the `pg_stat_statements` view is unavailable 
```
CREATE EXTENSION pg_stat_statements;
``` 

## Metrics

### activity

The `activity` dataset periodically fetches metrics from PostgreSQL servers.

{{event "activity"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "activity"}}

### bgwriter

The PostgreSQL `bgwriter` dataset collects data from PostgreSQL by running a `SELECT * FROM pg_stat_bgwriter;` SQL query.

{{event "bgwriter"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "bgwriter"}}

### database

The `database` dataset periodically fetches metrics from PostgreSQL servers.

{{event "database"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "database"}}

### statement

The `statement` dataset periodically fetches metrics from PostgreSQL servers.

{{event "statement"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "statement"}}

## SLOs

SLOs are usually defined in terms of metrics such as availability, response time, and throughput, and they are used to ensure that the service meets the needs of its users.
You can use the Nginx integration to measure the availability of the Nginx service. The SLOs gets created automatically during the installation of the integration. The user can view the created SLOs in the Observability -> SLOs page.
>Note: To create and manage SLOs you need an appropriate [license](https://www.elastic.co/subscriptions).

### PostgreSQL transaction error rate
| Events      | Query                             |
|-------------|-----------------------------------|
| Good Query  | `NOT postgresql.activity.state : idle in transaction (aborted)` |
| Total Query | `postgresql.activity.state : *`   |
### PostgreSQL error logs rate
| Events      | Query                             |
|-------------|-----------------------------------|
| Query Filter | `data_stream.dataset : postgresql.log` |
| Good Query  | `NOT log.level : ERROR or NOT log.level : FATAL` |
| Total Query | `log.level : *`   |
### PostgreSQL database deadlocks rate
| Events      | Query                             |
|-------------|-----------------------------------|
| Good Query  | `postgresql.database.deadlocks < 100` |
| Total Query | `postgresql.database.deadlocks : *`   |
### PostgreSQL query cancellation rate
| Events      | Query                             |
|-------------|-----------------------------------|
| Good Query  | `postgresql.database.rows.deleted < 100` |
| Total Query | `postgresql.database.rows.deleted : *`   |
### PostgreSQL deleted row rate
| Events      | Query                             |
|-------------|-----------------------------------|
| Good Query  | `postgresql.database.conflicts :  0` |
| Total Query | `postgresql.database.conflicts : *`   |