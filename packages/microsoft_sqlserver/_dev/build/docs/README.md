# Microsoft SQL Server Integration

The Microsoft SQL Server integration package allows you to search, observe and visualize the SQL Server audit events through Elasticsearch. 
Auditing an instance of the SQL Server Database Engine or an individual database involves tracking and logging events that occur on the Database Engine. 
SQL Server audit lets you create server audits, which can contain server audit specifications for server level events, and database audit specifications for database level events. 
See: [SQL Server Audit page](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver15) for more information on SQL Server auditing.

## Compatibility

The package collects audit events from the event log. Other log sources such as file are not supported.

## Configuration

There are several levels of auditing for SQL Server, depending on government or standards requirements for your installation. The SQL Server Audit feature enables you to audit server-level and database-level groups of events and individual events. 

See: [SQL Server Audit Action Groups and Actions](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions?view=sql-server-ver15) for more information on the different audit levels.

See: [Instructions on how to enable auditing for SQL Server](https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/create-a-server-audit-and-server-audit-specification?view=sql-server-ver15).

>Note: For the integration package to be able to read and send audit events the event target must be configured to be Windows event log.

### Audit Events

Enable to collect SQL Server audit events from the specified windows event log channel.

## Logs

### Audit

The SQL Server audit dataset provides events from the configured Windows event log channel. All SQL Server audit specific fields are available in the `sqlserver.audit` field group.

{{fields "audit"}}
