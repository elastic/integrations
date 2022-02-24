# Oracle Integration

This integration is for ingesting Audit Trail logs from Oracle Databases.

The integration expects an *.aud audit file that is generated from Oracle Databases by default. If this has been disabled then please see the [Oracle Database Audit Trail Documentation](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/introduction-to-auditing.html#GUID-8D96829C-9151-4FA4-BED9-831D088F12FF).

## Compatibility

This integration has been tested with Oracle Database 19c, and should work for 18c as well though it has not been tested.

### Database Audit Log

The `database_audit` dataset collects Oracle Audit logs.

{{fields "database_audit"}}

{{event "database_audit"}}