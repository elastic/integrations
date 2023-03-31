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

    (Optional) User can run Jolokia on https by configuring following [paramters](https://jolokia.org/reference/html/agents.html#:~:text=Table%C2%A03.6.-,JVM%20agent%20configuration%20options,-Parameter).

    ```
     -javaagent:<path-to-jolokia-agent>=port=<port>,host=<hostname>,protocol=<http/https>,keystore=<path-to-keystore>,keystorePassword=<kestore-password>,keyStoreType=<keystore-type>
    ```

    Example configuration:
    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=8005,host=localhost,protocol=https,keystore=/u01/oracle/weblogic.jks,keystorePassword=host@123,keyStoreType=JKS
    ```
### Troubleshooting

Conflicts in any field in any data stream can be solved by reindexing the data. 
If host.ip is shown conflicted under `logs-*` data view, then this issue can be solved by reindexing the `Admin Server` data stream's indices. 
If host.ip is shown conflicted under `metrics-*` data view, then this issue can be solved by reindexing the `Deployed Application` data stream's indices.
To reindex the data, the following steps must be performed.

1. Stop the data stream by going to `Integrations -> Oracle WebLogic -> Integration policies` and open the configuration of Oracle WebLogic and disable the `Collect Oracle WebLogic metrics` toggle to reindex metrics data stream and disable the `Collect Oracle WebLogic logs` toggle to reindex logs data stream and save the integration.

2. Perform the following steps in the Dev tools

```
PUT temp_index/
{
  "mappings": {
    "properties": {
      "<conflicting_field_name>": {
        "type": "<type>"
      }
    }
  }
}
```
Example:
```
PUT temp_index/
{
  "mappings": {
    "properties": {
      "host.ip": {
        "type": "ip"
      }
    }
  }
}
```

```
POST _reindex
{
  "source": {
    "index": "<index_name>"
  },
  "dest": {
    "index": "temp_index"
  }
}  
```
Example:
```
POST _reindex
{
  "source": {
    "index": "logs-oracle_weblogic.admin_server-default"
  },
  "dest": {
    "index": "temp_index"
  }
}
```

```
DELETE /_data_stream/<data_stream>
```
Example:
```
DELETE /_data_stream/logs-oracle_weblogic.admin_server-default
```

```
DELETE _index_template/<index_template>
```
Example:
```
DELETE _index_template/logs-oracle_weblogic.admin_server
```

```
POST _reindex
{
  "conflicts": "proceed",
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "<index_name>",
    "op_type": "create"

  }
}
```
Example:
```
POST _reindex
{
  "conflicts": "proceed",
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "logs-oracle_weblogic.admin_server-default",
    "op_type": "create"

  }
}
```

3. Verify data is reindexed completely.

4. Start the data stream by going to the `Integrations -> Oracle WebLogic -> Integration policies` and open configuration of Oracle WebLogic and enable the `Collect Oracle WebLogic metrics` toggle and enable the `Collect Oracle WebLogic logs` toggle and save the integration.

5. Perform the following step in the Dev tools

```
DELETE temp_index
```

More details about reindexing can be found [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html).

## Logs

This integration collects Oracle WebLogic Admin Server, Managed Server, Domain and Access logs. It includes the following datasets for receiving logs from a file:

### Access logs

The `access` data stream collects Access logs form `Access.log`.

{{event "access"}}

{{fields "access"}}

### Admin Server logs

The `admin_server` data stream collects Admin Server logs from `Adminserver.log`.

{{event "admin_server"}}

{{fields "admin_server"}}

### Domain logs

The `domain` data stream collects Domain logs from `Domain.log`.

{{event "domain"}}

{{fields "domain"}}

### Managed Server Logs

The `managed_server` data stream collects Managed Server logs from `Managedserver.log`.

{{event "managed_server"}}

{{fields "managed_server"}}

## Metrics

### Deployed Application Metrics

The `deployed_application` data stream collects metrics of Deployed Application.

{{event "deployed_application"}}

{{fields "deployed_application"}}

### ThreadPool metrics

This `threadpool` data stream collects metrics of ThreadPool.

{{event "threadpool"}}

{{fields "threadpool"}}
