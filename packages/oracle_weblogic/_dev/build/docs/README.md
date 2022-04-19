# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Requirements

In order to ingest data from Oracle WebLogic:
- You must know the host for Oracle WebLogic application, add that host while configuring the integration package.
- Add default path for jolokia.
- Configuring Jolokia for Weblogic

    User need to [download](https://jolokia.org/download.html) and add jar file and set env variables for jolokia

    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=<Port>,host=<hostname>
    ```

## Metrics

### Deployed Application Metrics

This `deployed_application` data stream gives metrics of Deployed Application.

{{event "deployed_application"}}

{{fields "deployed_application"}}
