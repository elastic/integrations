# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Requirements

In order to ingest data from Oracle WebLogic:
- You must know the host for Oracle WebLogic application, add that host while configuring the integration package.
- Add default path for jolokia.
- Configuring Jolokia for Weblogic

    User needs to [download](https://jolokia.org/download.html) and add the JAR file and set environment
     variables for jolokia.

    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=<Port>,host=<hostname>
    ``` 

    (Optional) User can run Jolokia on https by configuring following [paramters](https://jolokia.org/reference/html/agents.html#:~:text=Table%C2%A03.6.-,JVM%20agent%20configuration%20options,-Parameter).

    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=<Port>,host=<hostname>,protocol=<http/https>,keystore=<path-to-keystore>,keystorePassword=<kestore-password>,keyStoreType=<keystore-type>
    ```

## Metrics

### ThreadPool metrics

This `threadpool` data stream gives metrics of ThreadPool.

{{event "threadpool"}}

{{fields "threadpool"}}
