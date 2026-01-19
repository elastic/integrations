# PostgreSQL Integration

This integration periodically fetches logs and metrics from [PostgreSQL](https://www.postgresql.org/) servers.

## Compatibility

### Logs

- **Plain text logs**: tested with PostgreSQL **9.5** (Ubuntu), **9.6** (Debian), and **10.11 / 11.4 / 12.2** (Arch Linux 9.3).
- **CSV logs**: tested with PostgreSQL **11** and **13**.

### Metrics

- **activity / bgwriter / database / statement**: tested with PostgreSQL **9.5.3** and expected to work with **PostgreSQL >= 9**.
- **checkpointer**: introduced in PostgreSQL **17** and requires **PostgreSQL >= 17**.

### PostgreSQL 17+ note (bgwriter vs checkpointer)

Starting with PostgreSQL **17**, some **checkpoint-related** fields that were previously available via `pg_stat_bgwriter` (and reported in the `bgwriter` dataset) were moved into the `checkpointer` dataset.

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

#### Timezone for logs (Optional)

User can specify a timezone when logging messages by using the `tz_map` parameter. This feature is particularly useful for ensuring logs are recorded in the specified timezone, making it easier to troubleshoot issues based on the time of occurrence in different time zones.

Note: If the tz_map parameter is not specified, it will be default to the timezone of the logs and map it with timestamp accordingly.

#### Supported Timezones
User can set the `tz_map` to any valid timezone identifier. Here are a few examples of supported timezones:

- `tz_short: 'EDT'`
- `tz_long: 'America/New_York'`
- `tz_short: 'IST'`
- `tz_long: 'Asia/Kolkata'`

#### Example Usage

When logging an event, user can pass the `timezone` parameter to ensure the time is recorded in the desired timezone. Here's an example of how you can use this parameter:

```yaml
tz_map:
  - tz_short: 'IST'
  - tz_long: 'Asia/Kolkata'
```

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

Note (PostgreSQL 17+): checkpoint-related fields are no longer surfaced in `pg_stat_bgwriter`. Starting with PostgreSQL 17, these checkpoint metrics are exposed separately and are collected by the `checkpointer` dataset in this integration.

{{event "bgwriter"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "bgwriter"}}

### checkpointer

The PostgreSQL `checkpointer` dataset collects checkpoint metrics introduced in PostgreSQL 17 to keep checkpoint-related fields supported going forward.

{{event "checkpointer"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "checkpointer"}}

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

## Alerting Rule Template
{{alertRuleTemplates}}