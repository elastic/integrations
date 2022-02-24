# MySQL Enterprise Integration

This integration is for different types of MySQL logs. Currently focusing on data from the MySQL Enterprise Audit Plugin in JSON format.

To configure the the Enterprise Audit Plugin to output in JSON format please follow the directions in the [MySQL Documentation](https://dev.mysql.com/doc/refman/8.0/en/audit-log-file-formats.html).

## Compatibility

This integration has been tested against MySQL Enterprise 5.7.x and 8.0.x

### Audit Log

The `audit` dataset collects MySQL Enterprise Audit logs.

{{fields "audit"}}

{{event "audit"}}