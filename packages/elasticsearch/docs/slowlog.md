# Slowlog

## Logs

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.cluster.name | Name of the cluster | keyword |
| elasticsearch.cluster.uuid | UUID of the cluster | keyword |
| elasticsearch.component | Elasticsearch component from where the log event originated | keyword |
| elasticsearch.index.id | Index id | keyword |
| elasticsearch.index.name | Index name | keyword |
| elasticsearch.node.id | ID of the node | keyword |
| elasticsearch.node.name | Name of the node | keyword |
| elasticsearch.shard.id | Id of the shard | keyword |
| elasticsearch.slowlog.extra_source | Extra source information | keyword |
| elasticsearch.slowlog.id | Id | keyword |
| elasticsearch.slowlog.logger | Logger name | keyword |
| elasticsearch.slowlog.routing | Routing | keyword |
| elasticsearch.slowlog.search_type | Search type | keyword |
| elasticsearch.slowlog.source | Source of document that was indexed | keyword |
| elasticsearch.slowlog.source_query | Slow query | keyword |
| elasticsearch.slowlog.stats | Stats groups | keyword |
| elasticsearch.slowlog.took | Time it took to execute the query | keyword |
| elasticsearch.slowlog.total_hits | Total hits | keyword |
| elasticsearch.slowlog.total_shards | Total queried shards | keyword |
| elasticsearch.slowlog.type | Type | keyword |
| elasticsearch.slowlog.types | Types | keyword |

