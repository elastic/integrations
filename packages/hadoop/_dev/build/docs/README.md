# Hadoop

This integration is used to collect [Hadoop](https://hadoop.apache.org/) metrics as follows:

   - Application Metrics
   - Cluster Metrics
   - DataNode Metrics
   - NameNode Metrics
   - NodeManager Metrics   

This integration uses Resource Manager API and JMX API to collect above metrics.

## Compatibility

This integration has been tested against Hadoop versions `3.3.1`.

### Troubleshooting

If host.ip is shown conflicted under ``logs-*`` data view, then this issue can be solved by reindexing the ``Application`` data stream's indices.
If host.ip is shown conflicted under ``metrics-*`` data view, then this issue can be solved by reindexing the ``Cluster``, ``Datanode``, ``Namenode`` and ``Node Manager`` data stream's indices.
To reindex the data, the following steps must be performed.

1. Stop the data stream by going to `Integrations -> Hadoop -> Integration policies` open the configuration of Hadoop and disable the `Collect Hadoop metrics` toggle to reindex metrics data stream and save the integration.

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
    "index": "metrics-hadoop.cluster-default"
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
DELETE /_data_stream/metrics-hadoop.cluster-default
```

```
DELETE _index_template/<index_template>
```
Example:
```
DELETE _index_template/metrics-hadoop.cluster
```
3. Go to `Integrations -> Hadoop -> Settings` and click on `Reinstall Hadoop`.

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
    "index": "metrics-hadoop.cluster-default",
    "op_type": "create"

  }
}
```

5. Verify data is reindexed completely.

6. Start the data stream by going to the `Integrations -> Hadoop -> Integration policies` and open configuration of integration and enable the `Collect Hadoop metrics` toggle and save the integration.

7. Delete temporary index by performing the following step in the Dev tools.

```
DELETE temp_index
```

More details about reindexing can be found [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html).


## application

This data stream collects Application metrics.

{{event "application"}}

{{fields "application"}}

## cluster

This data stream collects Cluster metrics.

{{event "cluster"}}

{{fields "cluster"}}

## datanode

This data stream collects Datanode metrics.

{{event "datanode"}}

{{fields "datanode"}}

## namenode

This data stream collects Namenode metrics.

{{event "namenode"}}

{{fields "namenode"}}
## node_manager

This data stream collects Node Manager metrics.

{{event "node_manager"}}

{{fields "node_manager"}}
