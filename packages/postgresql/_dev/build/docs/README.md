# PostgreSQL Integration

This integration periodically fetches logs and metrics from [PostgreSQL](https://www.postgresql.org/) servers.

## Compatibility

The `log` dataset was tested with logs from versions 9.5 on Ubuntu, 9.6 on Debian, and finally 10.11, 11.4 and 12.2 on Arch Linux 9.3. CSV format was tested using versions 11 and 13 (distro is not relevant here).

The `activity`, `bgwriter`, `database` and `statement` datasets were tested with PostgreSQL 9.5.3 and is expected to work with all versions >= 9.

## Logs

### log

The `log` dataset collects the PostgreSQL logs in plain text format or CSV.

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

{{fields "log"}}

## Metrics

### activity

The `activity` dataset periodically fetches metrics from PostgreSQL servers.

{{event "activity"}}

{{fields "activity"}}

### bgwriter

The PostgreSQL `bgwriter` dataset collects data from PostgreSQL by running a `SELECT * FROM pg_stat_bgwriter;` SQL query.

{{event "bgwriter"}}

{{fields "bgwriter"}}

### database

The `database` dataset periodically fetches metrics from PostgreSQL servers.

{{event "database"}}

{{fields "database"}}

### statement

The `statement` dataset periodically fetches metrics from PostgreSQL servers.

{{event "statement"}}

{{fields "statement"}}
