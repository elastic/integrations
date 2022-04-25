# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Logs

This integration is for Oracle Weblogic Access logs . It includes the following datasets for receiving logs from a file:

### Access logs

The `access` data stream collects Access logs form access.log.

{{event "access"}}

{{fields "access"}}
