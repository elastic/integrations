# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Logs

This integration is for Oracle Weblogic Managed Server logs. It includes the following datasets for receiving logs from a file:

### Managed Server Logs

The `managed_server` dataset collects Managed Server logs from ManagedServer.log.

{{event "managed_server"}}

{{fields "managed_server"}}
