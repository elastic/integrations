# Microsoft SQL Server

This integration periodically fetches logs and metrics from [MSSQL](https://www.microsoft.com/en-us/sql-server) servers.

## Compatibility

The module is being tested with [2017 GA](https://hub.docker.com/r/microsoft/mssql-server-linux/) version under Linux

## Logs

### log

The `log` dataset collects the MySQL logs.

{{fields "log"}}

The following example shows how to set paths in the +modules.d/{modulename}.yml+
file to override the default paths for MSSQL logs:

```yaml
- module: mssql
  log:
    enabled: true
    var.paths: ["/var/opt/mssql/log/error*"]
```

## Metrics

### transaction_log

`transaction_log` Metricset fetches information about the operation and transaction log of each MSSQL database in the monitored instance. All data is extracted from the [Database Dynamic Management Views](https://docs.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/database-related-dynamic-management-views-transact-sql?view=sql-server-2017)

{{event "transaction_log"}}

{{fields "transaction_log"}}

### performance

`performance` Metricset fetches information from what's commonly known as [Performance Counters](https://docs.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-os-performance-counters-transact-sql?view=sql-server-2017) in MSSQL.

{{event "performance"}}

{{fields "performance"}}

### Configuration notes

When configuring the `hosts` option, you can specify native user credentials
as part of the host string with the following format:

```yaml
hosts: ["sqlserver://sa@localhost"]
```

To use Active Directory domain credentials, you can separately specify the username and password
using the respective configuration options to allow the domain to be included in the username:

```yaml
metricbeat.modules:
- module: mssql
  metricsets:
    - "transaction_log"
    - "performance"
  hosts: ["sqlserver://localhost"]
  username: domain\username
  password: verysecurepassword
  period: 10
```