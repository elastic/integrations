# Microsoft SQL Server Integration

The Microsoft SQL Server integration package allows you to monitor the SQL Server audit events.

## Compatibility

The package collects audit events from the event log. Other log sources such as file is not supported.

## Configuration

### Audit Events

Enable to collect SQL Server audit events from the specified windows event log channel.

## Logs

### Audit

The SQL Server `audit` dataset provides events from the Windows event log. The fields common to windows event are available in the `winlog` fields. SQL Server audit specific fields are available in the `sqlserver.audit` field group.

{{fields "audit"}}
