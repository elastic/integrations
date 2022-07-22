# Microsoft SQL Server Integration

The Microsoft SQL Server integration package allows you to search, observe and visualize the SQL Server audit logs and metrics through Elasticsearch. 

Auditing an instance of the SQL Server Database Engine or an individual database involves tracking and logging events that occur on the Database Engine. 
SQL Server audit lets you create server audits, which can contain server audit specifications for server level events, and database audit specifications for database level events. 
See: [SQL Server Audit page](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver15) for more information on SQL Server auditing.

`performance` metrics gathers the list of performance objects available on that server. Each server will have a different list of performance objects depending on the installed software.
`transaction_log` metrics collects all usage stats and the total space usage.

## Named Instance

Microsoft SQL Server has a feature that allows running multiple databases on the same host (or clustered hosts) with separate settings. Edit the instance port and provide the named instance port to connect to the named instance and collect metrics.
See: [Instruction on how to configure server to listen Named Instance port](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-server-to-listen-on-a-specific-tcp-port?view=sql-server-ver15)

## Compatibility

The package collects `performance` and `transaction_log` metrics, and `audit` events from the event log. Other log sources such as file are not supported.

## Configuration

### audit

There are several levels of auditing for SQL Server, depending on government or standards requirements for your installation. The SQL Server Audit feature enables you to audit server-level and database-level groups of events and individual events. 

See: [SQL Server Audit Action Groups and Actions](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions?view=sql-server-ver15) for more information on the different audit levels.

See: [Instructions on how to enable auditing for SQL Server](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/create-a-server-audit-and-server-audit-specification?view=sql-server-ver15).

>Note: For the integration package to be able to read and send audit events the event target must be configured to be Windows event log.

### audit events

Enable to collect SQL Server audit events from the specified windows event log channel.

### log

The SQL Server `log` contains user-defined events and certain system events you can use for troubleshooting.

See: [View the SQL Server error log in SQL Server Management Studio](https://docs.microsoft.com/en-us/sql/relational-databases/performance/view-the-sql-server-error-log-sql-server-management-studio?view=sql-server-ver16)

### performance metrics

Collects the `performance` counter metrics. Dynamic counter feature provides flexibility to collect metrics by providing the counter name as an input.

See: [Instructions about each performance counter metrics](https://docs.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-os-performance-counters-transact-sql?view=sql-server-ver15)

### transaction_log metrics

Collects system level `transaction_log` metrics information for SQL Server instance.

See: [Instructions and the operations supported by transaction log](https://docs.microsoft.com/en-us/sql/relational-databases/logs/the-transaction-log-sql-server?view=sql-server-ver15)

## Logs

### audit

The SQL Server audit dataset provides events from the configured Windows event log channel. All SQL Server audit specific fields are available in the `sqlserver.audit` field group.

{{fields "audit"}}

### log

The Microsoft SQL Server `log` dataset parses error logs created by Microsoft SQL server.

{{event "log"}}

{{fields "log"}}

## Metrics

### performance

The Microsoft SQL Server `performance` dataset provides metrics from the performance counter table. All `performance` metrics will be available in `sqlserver.metrics` field group.

{{event "performance"}}

{{fields "performance"}}

### transaction_log

The Microsoft SQL Server `transaction_log` dataset provides metrics from the log space usage and log stats tables of the system databases. All `transaction_log` metrics will be available in `sqlserver.metrics` field group.

{{event "transaction_log"}}

{{fields "transaction_log"}}