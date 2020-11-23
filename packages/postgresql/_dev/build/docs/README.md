# PostgreSQL Integration

This integration periodically fetches logs and metrics from [PostgreSQL](https://www.postgresql.org/) servers.

## Compatibility

The `log` dataset was tested with logs from versions 9.5 on Ubuntu, 9.6 on Debian, and finally 10.11, 11.4 and 12.2 on Arch Linux 9.3.

The `activity`, `bgwriter`, `database` and `statement` datasets were tested with PostgreSQL 9.5.3 and is expected to work with all versions >= 9.

## Logs

### log

The `log` dataset collects the PostgreSQL logs.

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