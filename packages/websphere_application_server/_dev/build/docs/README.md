# WebSphere Application Server

This Elastic integration is used to collect the following metrics from [IBM WebSphere Application Server](https://www.ibm.com/cloud/websphere-application-server):

   - JDBC metrics
   - Servlet metrics
   - Session Manager metrics
   - ThreadPool metrics

This integration uses Prometheus to collect above metrics.

To open Prometheus endpoint read following [instructions](https://www.ibm.com/docs/en/was/9.0.5?topic=mosh-displaying-pmi-metrics-in-prometheus-format-metrics-app).

### Troubleshooting

If host.ip is shown conflicted under ``metrics-*`` data view, then this issue can be solved by reindexing the ``JDBC``, ``Servlet``, ``Session Manager`` and ``ThreadPool`` data stream's indices.

To reindex the data for a particular data stream, the following steps must be performed.

1. Stop the data stream by going to `Integrations -> WebSphere Application Server -> Integration policies` open the configuration of WebSphere Application Server and disable the `Collect WebSphere Application Server metrics` toggle to reindex metrics data stream and save the integration.

2. Copy data into the temporary index and delete the existing data stream and index template by performing the following steps in the Dev tools.

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
    "index": "metrics-websphere_application_server.jdbc-default"
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
DELETE /_data_stream/metrics-websphere_application_server.jdbc-default
```

```
DELETE _index_template/<index_template>
```

Example:
```
DELETE _index_template/metrics-websphere_application_server.jdbc
```

3. Go to `Integrations -> WebSphere Application Server -> Settings` and click on `Reinstall WebSphere Application Server`.

4. Copy data from temporary index to new index by performing the following steps in the Dev tools.

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
    "index": "metrics-websphere_application_server.jdbc-default",
    "op_type": "create"
  }
}
```

5. Verify data is reindexed completely.

6. Start the data stream by going to the `Integrations -> WebSphere Application Server -> Integration policies`, open configuration of integration, enable the `Collect WebSphere Application Server metrics` toggle and save the integration.

7. Delete temporary index by performing the following step in the Dev tools.

```
DELETE temp_index
```

More details about reindexing can be found [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html).

## JDBC

This data stream collects JDBC (Java Database Connectivity) related metrics.

{{event "jdbc"}}

{{fields "jdbc"}}

## Servlet

This data stream collects Servlet related metrics.

{{event "servlet"}}

{{fields "servlet"}}

### Session Manager

This data stream collects metrics related to Sessions.

{{event "session_manager"}}

{{fields "session_manager"}}

## ThreadPool

This data stream collects Thread related metrics.

{{event "threadpool"}}

{{fields "threadpool"}}
