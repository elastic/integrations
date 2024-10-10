# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Requirements

In order to ingest data from Oracle WebLogic:
- User must add the path where the Jolokia agent is downloaded (For example, `/home/oracle/jolokia-jvm-1.6.0-agent.jar`).
- Configuring Jolokia for WebLogic

    User needs to [download](https://jolokia.org/download.html) and add the JAR file and set environment variables for Jolokia.

    ```
     -javaagent:<path-to-jolokia-agent>=port=<port>,host=<hostname>
    ``` 
    Example configuration:
    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=8005,host=localhost
    ```

    (Optional) User can run Jolokia on https by configuring following [parameters](https://jolokia.org/reference/html/agents.html#:~:text=Table%C2%A03.6.-,JVM%20agent%20configuration%20options,-Parameter).

    ```
     -javaagent:<path-to-jolokia-agent>=port=<port>,host=<hostname>,protocol=<http/https>,keystore=<path-to-keystore>,keystorePassword=<kestore-password>,keyStoreType=<keystore-type>
    ```

    Example configuration:
    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=8005,host=localhost,protocol=https,keystore=/u01/oracle/weblogic.jks,keystorePassword=host@123,keyStoreType=JKS
    ```
### Troubleshooting

- If `host.ip` appears conflicted under the ``logs-*`` data view, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Admin Server`` data stream. 
- If `host.ip` appears conflicted under the ``metrics-*`` data view, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds-reindex.html) the ``Deployed Application`` and ``Threadpool`` data streams.

## Logs

This integration collects Oracle WebLogic Admin Server, Managed Server, Domain and Access logs. It includes the following datasets for receiving logs from a file:

### Access logs

The `access` data stream collects Access logs form `Access.log`.

{{event "access"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "access"}}

### Admin Server logs

The `admin_server` data stream collects Admin Server logs from `Adminserver.log`.

{{event "admin_server"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "admin_server"}}

### Domain logs

The `domain` data stream collects Domain logs from `Domain.log`.

{{event "domain"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "domain"}}

### Managed Server Logs

The `managed_server` data stream collects Managed Server logs from `Managedserver.log`.

{{event "managed_server"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "managed_server"}}

## Metrics

### Deployed Application Metrics

The `deployed_application` data stream collects metrics of Deployed Application.

{{event "deployed_application"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "deployed_application"}}

### ThreadPool metrics

This `threadpool` data stream collects metrics of ThreadPool.

{{event "threadpool"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "threadpool"}}
