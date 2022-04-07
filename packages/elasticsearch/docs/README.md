# Elasticsearch

The `elasticsearch` package collects metrics and logs of Elasticsearch.

## Compatibility

The `elasticsearch` package can monitor Elasticsearch 6.7.0 and later.

## Logs

NOTE: If you're running against Elasticsearch >= 7.0.0, configure the
`var.paths` setting to point to JSON logs. Otherwise, configure it
to point to plain text logs.

### Compatibility

The Elasticsearch package is compatible with logs from Elasticsearch 6.2 and newer.

### Audit

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.audit.action | The name of the action that was executed | keyword |
| elasticsearch.audit.component |  | keyword |
| elasticsearch.audit.event_type | The type of event that occurred: anonymous_access_denied, authentication_failed, access_denied, access_granted, connection_granted, connection_denied, tampered_request, run_as_granted, run_as_denied | keyword |
| elasticsearch.audit.indices | Indices accessed by action | keyword |
| elasticsearch.audit.invalidate.apikeys.owned_by_authenticated_user |  | boolean |
| elasticsearch.audit.layer | The layer from which this event originated: rest, transport or ip_filter | keyword |
| elasticsearch.audit.message |  | text |
| elasticsearch.audit.origin.type | Where the request originated: rest (request originated from a REST API request), transport (request was received on the transport channel), local_node (the local node issued the request) | keyword |
| elasticsearch.audit.realm | The authentication realm the authentication was validated against | keyword |
| elasticsearch.audit.request.id | Unique ID of request | keyword |
| elasticsearch.audit.request.name | The type of request that was executed | keyword |
| elasticsearch.audit.url.params | REST URI parameters | keyword |
| elasticsearch.audit.user.realm | The user's authentication realm, if authenticated | keyword |
| elasticsearch.audit.user.roles | Roles to which the principal belongs | keyword |
| elasticsearch.audit.user.run_as.name |  | keyword |
| elasticsearch.audit.user.run_as.realm |  | keyword |
| elasticsearch.cluster.name | Name of the cluster | keyword |
| elasticsearch.cluster.uuid | UUID of the cluster | keyword |
| elasticsearch.component | Elasticsearch component from where the log event originated | keyword |
| elasticsearch.index.id | Index id | keyword |
| elasticsearch.index.name | Index name | keyword |
| elasticsearch.node.id | ID of the node | keyword |
| elasticsearch.node.name | Name of the node | keyword |
| elasticsearch.shard.id | Id of the shard | keyword |
| http | Fields related to HTTP activity. Use the `url` field set to store the url of the request. | group |
| http.request.body.content | The full HTTP request body. | wildcard |
| http.request.body.content.text | Multi-field of `http.request.body.content`. | match_only_text |
| source | Source fields capture details about the sender of a network exchange/packet. These fields are populated from a network event, packet, or other event containing details of a network transaction. Source fields are usually populated in conjunction with destination fields. The source and destination fields are considered the baseline and should always be filled if an event contains source and destination details from a network transaction. If the event also contains identification of the client and server roles, then the client and server fields should also be populated. | group |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| url | URL fields provide support for complete or partial URLs, and supports the breaking down into scheme, domain, path, and so on. | group |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| user | The user fields describe information about the user that is relevant to the event. Fields can have one entry or multiple entries. If a user has more than one id, provide an array that includes all of them. | group |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


### Deprecation

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


### Garbage collection

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
| elasticsearch.gc.heap.size_kb | Total heap size in kilobytes. | integer |
| elasticsearch.gc.heap.used_kb | Used heap in kilobytes. | integer |
| elasticsearch.gc.jvm_runtime_sec | The time from JVM start up in seconds, as a floating point number. | float |
| elasticsearch.gc.old_gen.size_kb | Total size of old generation in kilobytes. | integer |
| elasticsearch.gc.old_gen.used_kb | Old generation occupancy in kilobytes. | integer |
| elasticsearch.gc.phase.class_unload_time_sec | Time spent unloading unused classes in seconds. | float |
| elasticsearch.gc.phase.cpu_time.real_sec | Total elapsed CPU time spent to complete the collection from start to finish. | float |
| elasticsearch.gc.phase.cpu_time.sys_sec | CPU time spent inside the kernel. | float |
| elasticsearch.gc.phase.cpu_time.user_sec | CPU time spent outside the kernel. | float |
| elasticsearch.gc.phase.duration_sec | Collection phase duration according to the Java virtual machine. | float |
| elasticsearch.gc.phase.name | Name of the GC collection phase. | keyword |
| elasticsearch.gc.phase.parallel_rescan_time_sec | Time spent in seconds marking live objects while application is stopped. | float |
| elasticsearch.gc.phase.scrub_string_table_time_sec | Pause time in seconds cleaning up string tables. | float |
| elasticsearch.gc.phase.scrub_symbol_table_time_sec | Pause time in seconds cleaning up symbol tables. | float |
| elasticsearch.gc.phase.weak_refs_processing_time_sec | Time spent processing weak references in seconds. | float |
| elasticsearch.gc.stopping_threads_time_sec | Time took to stop threads seconds. | float |
| elasticsearch.gc.tags | GC logging tags. | keyword |
| elasticsearch.gc.threads_total_stop_time_sec | Garbage collection threads total stop time seconds. | float |
| elasticsearch.gc.young_gen.size_kb | Total size of young generation in kilobytes. | integer |
| elasticsearch.gc.young_gen.used_kb | Young generation occupancy in kilobytes. | integer |
| elasticsearch.index.id | Index id | keyword |
| elasticsearch.index.name | Index name | keyword |
| elasticsearch.node.id | ID of the node | keyword |
| elasticsearch.node.name | Name of the node | keyword |
| elasticsearch.shard.id | Id of the shard | keyword |


### Server

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
| elasticsearch.server.gc.collection_duration.ms | Time spent in GC, in milliseconds | float |
| elasticsearch.server.gc.observation_duration.ms | Total time over which collection was observed, in milliseconds | float |
| elasticsearch.server.gc.overhead_seq | Sequence number | long |
| elasticsearch.server.gc.young.one |  | long |
| elasticsearch.server.gc.young.two |  | long |
| elasticsearch.server.stacktrace |  | keyword |
| elasticsearch.shard.id | Id of the shard | keyword |


### Slowlog

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


## Metrics

### Usage for Stack Monitoring

The `elasticsearch` package can be used to collect logs and metrics shown in our Stack Monitoring
UI in Kibana.

### Metric-specific configuration notes

Like other package, `elasticsearch` metrics collection accepts a `hosts` configuration setting.
This setting can contain a list of entries. The related `scope` setting determines how each entry in
the `hosts` list is interpreted by the module.

* If `scope` is set to `node` (default), each entry in the `hosts` list indicates a distinct node in an
  Elasticsearch cluster.
* If `scope` is set to `cluster`, each entry in the `hosts` list indicates a single endpoint for a distinct
  Elasticsearch cluster (for example, a load-balancing proxy fronting the cluster).

### Cross Cluster Replication

CCR It uses the Cross-Cluster Replication Stats API endpoint to fetch metrics about cross-cluster
replication from the Elasticsearch clusters that are participating in cross-cluster
replication.

If the Elasticsearch cluster does not have cross-cluster replication enabled, this package
will not collect metrics. A DEBUG log message about this will be emitted in the log.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.ccr.auto_follow.failed.follow_indices.count |  | long |
| elasticsearch.ccr.auto_follow.failed.remote_cluster_state_requests.count |  | long |
| elasticsearch.ccr.auto_follow.success.follow_indices.count |  | long |
| elasticsearch.ccr.bytes_read |  | long |
| elasticsearch.ccr.follower.aliases_version |  | long |
| elasticsearch.ccr.follower.global_checkpoint | Global checkpoint value on follower shard | long |
| elasticsearch.ccr.follower.index | Name of follower index | keyword |
| elasticsearch.ccr.follower.mapping_version |  | long |
| elasticsearch.ccr.follower.max_seq_no | Maximum sequence number of operation on the follower shard | long |
| elasticsearch.ccr.follower.operations.read.count |  | long |
| elasticsearch.ccr.follower.operations_written | Number of operations indexed (replicated) into the follower shard from the leader shard | long |
| elasticsearch.ccr.follower.settings_version |  | long |
| elasticsearch.ccr.follower.shard.number | Number of the shard within the index | long |
| elasticsearch.ccr.follower.time_since_last_read.ms | Time, in ms, since the follower last fetched from the leader | long |
| elasticsearch.ccr.last_requested_seq_no |  | long |
| elasticsearch.ccr.leader.global_checkpoint |  | long |
| elasticsearch.ccr.leader.index | Name of leader index | keyword |
| elasticsearch.ccr.leader.max_seq_no | Maximum sequence number of operation on the leader shard | long |
| elasticsearch.ccr.read_exceptions |  | nested |
| elasticsearch.ccr.remote_cluster |  | keyword |
| elasticsearch.ccr.requests.failed.read.count |  | long |
| elasticsearch.ccr.requests.failed.write.count |  | long |
| elasticsearch.ccr.requests.outstanding.read.count |  | long |
| elasticsearch.ccr.requests.outstanding.write.count |  | long |
| elasticsearch.ccr.requests.successful.read.count |  | long |
| elasticsearch.ccr.requests.successful.write.count |  | long |
| elasticsearch.ccr.shard_id |  | integer |
| elasticsearch.ccr.total_time.read.ms |  | long |
| elasticsearch.ccr.total_time.read.remote_exec.ms |  | long |
| elasticsearch.ccr.total_time.write.ms |  | long |
| elasticsearch.ccr.write_buffer.operation.count |  | long |
| elasticsearch.ccr.write_buffer.size.bytes |  | long |
| elasticsearch.cluster.id | Elasticsearch cluster id. | keyword |
| elasticsearch.cluster.name | Elasticsearch cluster name. | keyword |
| elasticsearch.cluster.state.id | Elasticsearch state id. | keyword |
| elasticsearch.node.id | Node ID | keyword |
| elasticsearch.node.master | Is the node the master node? | boolean |
| elasticsearch.node.mlockall | Is mlockall enabled on the node? | boolean |
| elasticsearch.node.name | Node name. | keyword |

### Cluster Stats

`cluster_stats` interrogates the 
[Cluster Stats API endpoint](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-stats.html)
to fetch information about the Elasticsearch cluster.

An example event for `cluster_stats` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "ephemeral_id": "2b6da727-313f-41fc-84af-3cd928f265c1",
        "type": "metricbeat",
        "version": "7.14.0"
    },
    "elastic_agent": {
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "version": "7.14.0",
        "snapshot": true
    },
    "@timestamp": "2021-07-30T14:47:15.382Z",
    "elasticsearch": {
        "cluster": {
            "stats": {
                "indices": {
                    "shards": {
                        "primaries": 39,
                        "count": 39
                    },
                    "total": 39,
                    "fielddata": {
                        "memory": {
                            "bytes": 288
                        }
                    }
                },
                "nodes": {
                    "data": 1,
                    "count": 1,
                    "master": 1
                },
                "status": "yellow"
            },
            "name": "docker-cluster",
            "id": "bvF4SoDLQU-sdM3YY8JI8Q"
        }
    },
    "ecs": {
        "version": "1.10.0"
    },
    "service": {
        "address": "http://elasticsearch:9200",
        "name": "elasticsearch",
        "type": "elasticsearch"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "elasticsearch.cluster_stats"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.11.10-arch1-1",
            "codename": "Core",
            "name": "CentOS Linux",
            "type": "linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "8979eb4aa312c3dccea3823dd92f92f5",
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "cluster_stats"
    },
    "event": {
        "duration": 10597401,
        "agent_id_status": "verified",
        "ingested": "2021-07-30T14:47:16.373264357Z",
        "module": "elasticsearch",
        "dataset": "elasticsearch.cluster_stats"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.cluster.id | Elasticsearch cluster id. | keyword |
| elasticsearch.cluster.name | Elasticsearch cluster name. | keyword |
| elasticsearch.cluster.state.id | Elasticsearch state id. | keyword |
| elasticsearch.cluster.stats.indices.docs.total | Total number of indices in cluster. | long |
| elasticsearch.cluster.stats.indices.fielddata.memory.bytes | Memory used for fielddata. | long |
| elasticsearch.cluster.stats.indices.shards.count | Total number of shards in cluster. | long |
| elasticsearch.cluster.stats.indices.shards.primaries | Total number of primary shards in cluster. | long |
| elasticsearch.cluster.stats.indices.store.size.bytes |  | long |
| elasticsearch.cluster.stats.indices.total |  | long |
| elasticsearch.cluster.stats.license.expiry_date_in_millis |  | long |
| elasticsearch.cluster.stats.license.status |  | keyword |
| elasticsearch.cluster.stats.license.type |  | keyword |
| elasticsearch.cluster.stats.nodes.count | Total number of nodes in cluster. | long |
| elasticsearch.cluster.stats.nodes.data |  | long |
| elasticsearch.cluster.stats.nodes.fs.available.bytes |  | long |
| elasticsearch.cluster.stats.nodes.fs.total.bytes |  | long |
| elasticsearch.cluster.stats.nodes.jvm.max_uptime.ms |  | long |
| elasticsearch.cluster.stats.nodes.jvm.memory.heap.max.bytes |  | long |
| elasticsearch.cluster.stats.nodes.jvm.memory.heap.used.bytes |  | long |
| elasticsearch.cluster.stats.nodes.master | Number of master-eligible nodes in cluster. | long |
| elasticsearch.cluster.stats.nodes.stats.data | Number of data nodes in cluster. | long |
| elasticsearch.cluster.stats.stack.apm.found |  | boolean |
| elasticsearch.cluster.stats.stack.xpack.ccr.available |  | boolean |
| elasticsearch.cluster.stats.stack.xpack.ccr.enabled |  | boolean |
| elasticsearch.cluster.stats.state.master_node |  | keyword |
| elasticsearch.cluster.stats.state.nodes_hash |  | keyword |
| elasticsearch.cluster.stats.state.state_uuid |  | keyword |
| elasticsearch.cluster.stats.state.version |  | keyword |
| elasticsearch.cluster.stats.status | Cluster status (green, yellow, red). | keyword |
| elasticsearch.cluster.stats.version |  | keyword |
| elasticsearch.node.id | Node ID | keyword |
| elasticsearch.node.master | Is the node the master node? | boolean |
| elasticsearch.node.mlockall | Is mlockall enabled on the node? | boolean |
| elasticsearch.node.name | Node name. | keyword |
| elasticsearch.version |  | keyword |

### Enrich

Enrch interrogates the [Enrich Stats API](https://www.elastic.co/guide/en/elasticsearch/reference/current/enrich-apis.html) 
endpoint to fetch information about Enrich coordinator nodesin the Elasticsearch cluster that are participating in 
ingest-time enrichment.

An example event for `enrich` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "type": "metricbeat",
        "ephemeral_id": "2b6da727-313f-41fc-84af-3cd928f265c1",
        "version": "7.14.0"
    },
    "elastic_agent": {
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "version": "7.14.0",
        "snapshot": true
    },
    "@timestamp": "2021-07-30T14:47:15.376Z",
    "elasticsearch": {
        "node": {
            "id": "6XuAxHXaRbeX6LUrxIfAxg"
        },
        "cluster": {
            "name": "docker-cluster",
            "id": "bvF4SoDLQU-sdM3YY8JI8Q"
        },
        "enrich": {
            "executed_searches": {
                "total": 0
            },
            "remote_requests": {
                "current": 0,
                "total": 0
            },
            "queue": {
                "size": 0
            }
        }
    },
    "ecs": {
        "version": "1.10.0"
    },
    "service": {
        "address": "http://elasticsearch:9200",
        "name": "elasticsearch",
        "type": "elasticsearch"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "elasticsearch.enrich"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.11.10-arch1-1",
            "codename": "Core",
            "name": "CentOS Linux",
            "type": "linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "8979eb4aa312c3dccea3823dd92f92f5",
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "enrich"
    },
    "event": {
        "duration": 2804362,
        "agent_id_status": "verified",
        "ingested": "2021-07-30T14:47:16.373180707Z",
        "module": "elasticsearch",
        "dataset": "elasticsearch.enrich"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.cluster.id | Elasticsearch cluster id. | keyword |
| elasticsearch.cluster.name | Elasticsearch cluster name. | keyword |
| elasticsearch.cluster.state.id | Elasticsearch state id. | keyword |
| elasticsearch.enrich.executed_searches.total | Number of search requests that enrich processors have executed since node startup. | long |
| elasticsearch.enrich.executing_policy.name |  | keyword |
| elasticsearch.enrich.executing_policy.task.action |  | keyword |
| elasticsearch.enrich.executing_policy.task.cancellable |  | boolean |
| elasticsearch.enrich.executing_policy.task.id |  | long |
| elasticsearch.enrich.executing_policy.task.parent_task_id |  | keyword |
| elasticsearch.enrich.executing_policy.task.task |  | keyword |
| elasticsearch.enrich.executing_policy.task.time.running.nano |  | long |
| elasticsearch.enrich.executing_policy.task.time.start.ms |  | long |
| elasticsearch.enrich.queue.size | Number of search requests in the queue. | long |
| elasticsearch.enrich.remote_requests.current | Current number of outstanding remote requests. | long |
| elasticsearch.enrich.remote_requests.total | Number of outstanding remote requests executed since node startup. | long |
| elasticsearch.node.id | Node ID | keyword |
| elasticsearch.node.master | Is the node the master node? | boolean |
| elasticsearch.node.mlockall | Is mlockall enabled on the node? | boolean |
| elasticsearch.node.name | Node name. | keyword |

### Index

An example event for `index` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "type": "metricbeat",
        "ephemeral_id": "2b6da727-313f-41fc-84af-3cd928f265c1",
        "version": "7.14.0"
    },
    "elastic_agent": {
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "version": "7.14.0",
        "snapshot": true
    },
    "@timestamp": "2021-07-30T14:46:47.831Z",
    "ecs": {
        "version": "1.10.0"
    },
    "elasticsearch": {
        "cluster": {
            "name": "docker-cluster",
            "id": "bvF4SoDLQU-sdM3YY8JI8Q"
        },
        "index": {
            "total": {
                "docs": {
                    "deleted": 0,
                    "count": 13267
                },
                "store": {
                    "size": {
                        "bytes": 1490775
                    }
                },
                "segments": {
                    "memory": {
                        "bytes": 50388
                    },
                    "count": 5
                }
            },
            "name": ".ds-metrics-elasticsearch.shard-default-2021.07.30-000001"
        }
    },
    "service": {
        "address": "http://elasticsearch:9200",
        "name": "elasticsearch",
        "type": "elasticsearch"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "elasticsearch.index"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.11.10-arch1-1",
            "codename": "Core",
            "name": "CentOS Linux",
            "type": "linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "8979eb4aa312c3dccea3823dd92f92f5",
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "index"
    },
    "event": {
        "duration": 14394992,
        "agent_id_status": "verified",
        "ingested": "2021-07-30T14:46:48.854674866Z",
        "module": "elasticsearch",
        "dataset": "elasticsearch.index"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.cluster.id | Elasticsearch cluster id. | keyword |
| elasticsearch.cluster.name | Elasticsearch cluster name. | keyword |
| elasticsearch.cluster.state.id | Elasticsearch state id. | keyword |
| elasticsearch.index.created |  | long |
| elasticsearch.index.hidden |  | boolean |
| elasticsearch.index.name | Index name. | keyword |
| elasticsearch.index.primaries.docs.count |  | long |
| elasticsearch.index.primaries.docs.deleted |  | long |
| elasticsearch.index.primaries.indexing.index_time_in_millis |  | long |
| elasticsearch.index.primaries.indexing.index_total |  | long |
| elasticsearch.index.primaries.indexing.throttle_time_in_millis |  | long |
| elasticsearch.index.primaries.merges.total_size_in_bytes |  | long |
| elasticsearch.index.primaries.query_cache.hit_count |  | long |
| elasticsearch.index.primaries.query_cache.memory_size_in_bytes |  | long |
| elasticsearch.index.primaries.query_cache.miss_count |  | long |
| elasticsearch.index.primaries.refresh.external_total_time_in_millis |  | long |
| elasticsearch.index.primaries.refresh.total_time_in_millis |  | long |
| elasticsearch.index.primaries.request_cache.evictions |  | long |
| elasticsearch.index.primaries.request_cache.hit_count |  | long |
| elasticsearch.index.primaries.request_cache.memory_size_in_bytes |  | long |
| elasticsearch.index.primaries.request_cache.miss_count |  | long |
| elasticsearch.index.primaries.search.query_time_in_millis |  | long |
| elasticsearch.index.primaries.search.query_total |  | long |
| elasticsearch.index.primaries.segments.count |  | long |
| elasticsearch.index.primaries.segments.doc_values_memory_in_bytes |  | long |
| elasticsearch.index.primaries.segments.fixed_bit_set_memory_in_bytes |  | long |
| elasticsearch.index.primaries.segments.index_writer_memory_in_bytes |  | long |
| elasticsearch.index.primaries.segments.memory_in_bytes |  | long |
| elasticsearch.index.primaries.segments.norms_memory_in_bytes |  | long |
| elasticsearch.index.primaries.segments.points_memory_in_bytes |  | long |
| elasticsearch.index.primaries.segments.stored_fields_memory_in_bytes |  | long |
| elasticsearch.index.primaries.segments.term_vectors_memory_in_bytes |  | long |
| elasticsearch.index.primaries.segments.terms_memory_in_bytes |  | long |
| elasticsearch.index.primaries.segments.version_map_memory_in_bytes |  | long |
| elasticsearch.index.primaries.store.size_in_bytes |  | long |
| elasticsearch.index.shards.total |  | long |
| elasticsearch.index.status |  | keyword |
| elasticsearch.index.total.docs.count | Total number of documents in the index. | long |
| elasticsearch.index.total.docs.deleted | Total number of deleted documents in the index. | long |
| elasticsearch.index.total.fielddata.evictions |  | long |
| elasticsearch.index.total.fielddata.memory_size_in_bytes |  | long |
| elasticsearch.index.total.indexing.index_time_in_millis |  | long |
| elasticsearch.index.total.indexing.index_total |  | long |
| elasticsearch.index.total.indexing.throttle_time_in_millis |  | long |
| elasticsearch.index.total.merges.total_size_in_bytes |  | long |
| elasticsearch.index.total.query_cache.evictions |  | long |
| elasticsearch.index.total.query_cache.hit_count |  | long |
| elasticsearch.index.total.query_cache.memory_size_in_bytes |  | long |
| elasticsearch.index.total.query_cache.miss_count |  | long |
| elasticsearch.index.total.refresh.external_total_time_in_millis |  | long |
| elasticsearch.index.total.refresh.total_time_in_millis |  | long |
| elasticsearch.index.total.request_cache.evictions |  | long |
| elasticsearch.index.total.request_cache.hit_count |  | long |
| elasticsearch.index.total.request_cache.memory_size_in_bytes |  | long |
| elasticsearch.index.total.request_cache.miss_count |  | long |
| elasticsearch.index.total.search.query_time_in_millis |  | long |
| elasticsearch.index.total.search.query_total |  | long |
| elasticsearch.index.total.segments.count | Total number of index segments. | long |
| elasticsearch.index.total.segments.doc_values_memory_in_bytes |  | long |
| elasticsearch.index.total.segments.fixed_bit_set_memory_in_bytes |  | long |
| elasticsearch.index.total.segments.index_writer_memory_in_bytes |  | long |
| elasticsearch.index.total.segments.memory_in_bytes | Total number of memory used by the segments in bytes. | long |
| elasticsearch.index.total.segments.norms_memory_in_bytes |  | long |
| elasticsearch.index.total.segments.points_memory_in_bytes |  | long |
| elasticsearch.index.total.segments.stored_fields_memory_in_bytes |  | long |
| elasticsearch.index.total.segments.term_vectors_memory_in_bytes |  | long |
| elasticsearch.index.total.segments.terms_memory_in_bytes |  | long |
| elasticsearch.index.total.segments.version_map_memory_in_bytes |  | long |
| elasticsearch.index.total.store.size_in_bytes | Total size of the index in bytes. | long |
| elasticsearch.index.uuid |  | keyword |
| elasticsearch.node.id | Node ID | keyword |
| elasticsearch.node.master | Is the node the master node? | boolean |
| elasticsearch.node.mlockall | Is mlockall enabled on the node? | boolean |
| elasticsearch.node.name | Node name. | keyword |

### Index recovery

By default only data about indices which are under active recovery are fetched.
To gather data about all indices set `active_only: false`.

An example event for `index_recovery` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "type": "metricbeat",
        "ephemeral_id": "2b6da727-313f-41fc-84af-3cd928f265c1",
        "version": "7.14.0"
    },
    "elastic_agent": {
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "version": "7.14.0",
        "snapshot": true
    },
    "@timestamp": "2021-07-30T14:41:17.832Z",
    "ecs": {
        "version": "1.10.0"
    },
    "elasticsearch": {
        "cluster": {
            "id": "8l_zoGznQRmtoX9iSC-goA",
            "name": "docker-cluster"
        },
        "index": {
            "name": ".kibana-event-log-8.0.0-000001",
            "recovery": {
                "id": 0,
                "index": {
                    "files": {
                        "percent": "0.0%",
                        "recovered": 0,
                        "reused": 0,
                        "total": 0
                    },
                    "size": {
                        "recovered_in_bytes": 0,
                        "reused_in_bytes": 0,
                        "total_in_bytes": 0
                    }
                },
                "primary": true,
                "source": {},
                "stage": "DONE",
                "start_time": {
                    "ms": 1605819056123
                },
                "stop_time": {
                    "ms": 1605819058696
                },
                "target": {
                    "host": "127.0.0.1",
                    "id": "Fkj12lAFQOex0DwK0HMwHw",
                    "name": "082618b4bb36",
                    "transport_address": "127.0.0.1:9300"
                },
                "translog": {
                    "percent": "100.0%",
                    "total": 0,
                    "total_on_start": 0
                },
                "type": "EMPTY_STORE"
            }
        }
    },
    "service": {
        "address": "http://elasticsearch:9200",
        "name": "elasticsearch",
        "type": "elasticsearch"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "elasticsearch.index_recovery"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.11.10-arch1-1",
            "codename": "Core",
            "name": "CentOS Linux",
            "family": "redhat",
            "type": "linux",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "8979eb4aa312c3dccea3823dd92f92f5",
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "index_recovery"
    },
    "event": {
        "duration": 4139652,
        "agent_id_status": "verified",
        "ingested": "2021-07-30T14:41:18.844042490Z",
        "module": "elasticsearch",
        "dataset": "elasticsearch.index_recovery"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.cluster.id | Elasticsearch cluster id. | keyword |
| elasticsearch.cluster.name | Elasticsearch cluster name. | keyword |
| elasticsearch.cluster.state.id | Elasticsearch state id. | keyword |
| elasticsearch.index.name |  | keyword |
| elasticsearch.index.recovery.id | Shard recovery id. | long |
| elasticsearch.index.recovery.index.files.percent |  | keyword |
| elasticsearch.index.recovery.index.files.recovered |  | long |
| elasticsearch.index.recovery.index.files.reused |  | long |
| elasticsearch.index.recovery.index.files.total |  | long |
| elasticsearch.index.recovery.index.size.recovered_in_bytes |  | long |
| elasticsearch.index.recovery.index.size.reused_in_bytes |  | long |
| elasticsearch.index.recovery.index.size.total_in_bytes |  | long |
| elasticsearch.index.recovery.name |  | keyword |
| elasticsearch.index.recovery.primary | True if primary shard. | boolean |
| elasticsearch.index.recovery.source.host | Source node host address (could be IP address or hostname). | keyword |
| elasticsearch.index.recovery.source.id | Source node id. | keyword |
| elasticsearch.index.recovery.source.name | Source node name. | keyword |
| elasticsearch.index.recovery.source.transport_address |  | keyword |
| elasticsearch.index.recovery.stage | Recovery stage. | keyword |
| elasticsearch.index.recovery.start_time.ms |  | long |
| elasticsearch.index.recovery.stop_time.ms |  | long |
| elasticsearch.index.recovery.target.host | Target node host address (could be IP address or hostname). | keyword |
| elasticsearch.index.recovery.target.id | Target node id. | keyword |
| elasticsearch.index.recovery.target.name | Target node name. | keyword |
| elasticsearch.index.recovery.target.transport_address |  | keyword |
| elasticsearch.index.recovery.total_time.ms |  | long |
| elasticsearch.index.recovery.translog.percent |  | keyword |
| elasticsearch.index.recovery.translog.total |  | long |
| elasticsearch.index.recovery.translog.total_on_start |  | long |
| elasticsearch.index.recovery.type | Shard recovery type. | keyword |
| elasticsearch.index.recovery.verify_index.check_index_time.ms |  | long |
| elasticsearch.index.recovery.verify_index.total_time.ms |  | long |
| elasticsearch.node.id | Node ID | keyword |
| elasticsearch.node.master | Is the node the master node? | boolean |
| elasticsearch.node.mlockall | Is mlockall enabled on the node? | boolean |
| elasticsearch.node.name | Node name. | keyword |
| version |  | long |

### Index summary

An example event for `index_summary` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "ephemeral_id": "2b6da727-313f-41fc-84af-3cd928f265c1",
        "type": "metricbeat",
        "version": "7.14.0"
    },
    "elastic_agent": {
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "version": "7.14.0",
        "snapshot": true
    },
    "@timestamp": "2021-07-30T14:47:15.391Z",
    "elasticsearch": {
        "cluster": {
            "name": "docker-cluster",
            "id": "bvF4SoDLQU-sdM3YY8JI8Q"
        },
        "index": {
            "summary": {
                "primaries": {
                    "docs": {
                        "deleted": 7226,
                        "count": 50723
                    },
                    "store": {
                        "size": {
                            "bytes": 36769186
                        }
                    },
                    "segments": {
                        "memory": {
                            "bytes": 1790592
                        },
                        "count": 222
                    }
                },
                "total": {
                    "docs": {
                        "deleted": 7226,
                        "count": 50723
                    },
                    "store": {
                        "size": {
                            "bytes": 36769186
                        }
                    },
                    "segments": {
                        "memory": {
                            "bytes": 1790592
                        },
                        "count": 222
                    }
                }
            }
        }
    },
    "ecs": {
        "version": "1.10.0"
    },
    "service": {
        "address": "http://elasticsearch:9200",
        "name": "elasticsearch",
        "type": "elasticsearch"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "elasticsearch.index_summary"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.11.10-arch1-1",
            "codename": "Core",
            "name": "CentOS Linux",
            "type": "linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "8979eb4aa312c3dccea3823dd92f92f5",
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "index_summary"
    },
    "event": {
        "duration": 12151260,
        "agent_id_status": "verified",
        "ingested": "2021-07-30T14:47:16.373343461Z",
        "module": "elasticsearch",
        "dataset": "elasticsearch.index_summary"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.cluster.id | Elasticsearch cluster id. | keyword |
| elasticsearch.cluster.name | Elasticsearch cluster name. | keyword |
| elasticsearch.cluster.state.id | Elasticsearch state id. | keyword |
| elasticsearch.index.summary.primaries.bulk.operations.count |  | long |
| elasticsearch.index.summary.primaries.bulk.size.bytes |  | long |
| elasticsearch.index.summary.primaries.bulk.time.avg.bytes |  | long |
| elasticsearch.index.summary.primaries.bulk.time.avg.ms |  | long |
| elasticsearch.index.summary.primaries.bulk.time.count.ms |  | long |
| elasticsearch.index.summary.primaries.docs.count | Total number of documents in the index. | long |
| elasticsearch.index.summary.primaries.docs.deleted | Total number of deleted documents in the index. | long |
| elasticsearch.index.summary.primaries.indexing.index.count |  | long |
| elasticsearch.index.summary.primaries.indexing.index.time.ms |  | long |
| elasticsearch.index.summary.primaries.search.query.count |  | long |
| elasticsearch.index.summary.primaries.search.query.time.ms |  | long |
| elasticsearch.index.summary.primaries.segments.count | Total number of index segments. | long |
| elasticsearch.index.summary.primaries.segments.memory.bytes | Total number of memory used by the segments in bytes. | long |
| elasticsearch.index.summary.primaries.store.size.bytes | Total size of the index in bytes. | long |
| elasticsearch.index.summary.total.bulk.operations.count |  | long |
| elasticsearch.index.summary.total.bulk.size.bytes |  | long |
| elasticsearch.index.summary.total.bulk.time.avg.bytes |  | long |
| elasticsearch.index.summary.total.bulk.time.avg.ms |  | long |
| elasticsearch.index.summary.total.docs.count | Total number of documents in the index. | long |
| elasticsearch.index.summary.total.docs.deleted | Total number of deleted documents in the index. | long |
| elasticsearch.index.summary.total.indexing.index.count |  | long |
| elasticsearch.index.summary.total.indexing.index.time.ms |  | long |
| elasticsearch.index.summary.total.indexing.is_throttled |  | boolean |
| elasticsearch.index.summary.total.indexing.throttle_time.ms |  | long |
| elasticsearch.index.summary.total.search.query.count |  | long |
| elasticsearch.index.summary.total.search.query.time.ms |  | long |
| elasticsearch.index.summary.total.segments.count | Total number of index segments. | long |
| elasticsearch.index.summary.total.segments.memory.bytes | Total number of memory used by the segments in bytes. | long |
| elasticsearch.index.summary.total.store.size.bytes | Total size of the index in bytes. | long |
| elasticsearch.node.id | Node ID | keyword |
| elasticsearch.node.master | Is the node the master node? | boolean |
| elasticsearch.node.mlockall | Is mlockall enabled on the node? | boolean |
| elasticsearch.node.name | Node name. | keyword |

### Machine Learning Jobs

If you have Machine Learning jobs, this data stream will interrogate the 
[Machine Learning Anomaly Detection API](https://www.elastic.co/guide/en/elasticsearch/reference/current/ml-apis.html)
and  requires [Machine Learning](https://www.elastic.co/products/x-pack/machine-learning) to be enabled.

An example event for `ml_job` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "elasticsearch": {
        "cluster": {
            "id": "8l_zoGznQRmtoX9iSC-goA",
            "name": "docker-cluster"
        },
        "ml": {
            "job": {
                "data_counts": {
                    "invalid_date_count": 0,
                    "processed_record_count": 1216
                },
                "forecasts_stats": {
                    "total": 1
                },
                "id": "low_request_rate",
                "model_size": {
                    "memory_status": "ok"
                },
                "state": "opened"
            }
        },
        "node": {
            "id": "a14cf47ef7f2"
        }
    },
    "event": {
        "dataset": "elasticsearch.ml.job",
        "duration": 115000,
        "module": "elasticsearch"
    },
    "metricset": {
        "name": "ml_job",
        "period": 10000
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.cluster.id | Elasticsearch cluster id. | keyword |
| elasticsearch.cluster.name | Elasticsearch cluster name. | keyword |
| elasticsearch.cluster.state.id | Elasticsearch state id. | keyword |
| elasticsearch.ml.job.data.invalid_date.count | The number of records with either a missing date field or a date that could not be parsed. | long |
| elasticsearch.ml.job.data_counts.invalid_date_count |  | long |
| elasticsearch.ml.job.data_counts.processed_record_count | Processed data events. | long |
| elasticsearch.ml.job.forecasts_stats.total |  | long |
| elasticsearch.ml.job.id | Unique ml job id. | keyword |
| elasticsearch.ml.job.model_size.memory_status |  | keyword |
| elasticsearch.ml.job.state | Job state. | keyword |
| elasticsearch.node.id | Node ID | keyword |
| elasticsearch.node.master | Is the node the master node? | boolean |
| elasticsearch.node.mlockall | Is mlockall enabled on the node? | boolean |
| elasticsearch.node.name | Node name. | keyword |

### Node

`node` interrogates the
https://www.elastic.co/guide/en/elasticsearch/reference/master/cluster-nodes-info.html[Cluster API endpoint] of
Elasticsearch to get cluster nodes information. It only fetches the data from the `_local` node so it must
run on each Elasticsearch node.

An example event for `node` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "27d29977-878e-4309-81ed-8788662503ad",
        "ephemeral_id": "f8f510e7-9503-4e3d-af7f-da2992648d31",
        "type": "metricbeat",
        "version": "7.15.0"
    },
    "elastic_agent": {
        "id": "27d29977-878e-4309-81ed-8788662503ad",
        "version": "7.15.0",
        "snapshot": true
    },
    "@timestamp": "2021-08-03T12:27:26.083Z",
    "elasticsearch": {
        "cluster": {
            "name": "docker-cluster",
            "id": "icut8oAwR--oCfUTlFaPMg"
        },
        "node": {
            "jvm": {
                "memory": {
                    "heap": {
                        "init": {
                            "bytes": 1073741824
                        },
                        "max": {
                            "bytes": 1073741824
                        }
                    },
                    "nonheap": {
                        "init": {
                            "bytes": 7667712
                        },
                        "max": {
                            "bytes": 0
                        }
                    }
                },
                "version": "16.0.1"
            },
            "process": {
                "mlockall": false
            },
            "name": "2b8824139b92",
            "id": "saWHxJSZQF6VqGZvEb45Uw",
            "version": "7.15.0"
        }
    },
    "ecs": {
        "version": "1.10.0"
    },
    "service": {
        "address": "http://elasticsearch:9200",
        "name": "elasticsearch",
        "type": "elasticsearch"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "elasticsearch.node"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.11.10-arch1-1",
            "codename": "Core",
            "name": "CentOS Linux",
            "type": "linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.24.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "1292624d19b2cee1a317ad634c9a8358",
        "mac": [
            "02:42:ac:18:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "node"
    },
    "event": {
        "duration": 9853150,
        "agent_id_status": "verified",
        "ingested": "2021-08-03T12:27:27.080460943Z",
        "module": "elasticsearch",
        "dataset": "elasticsearch.node"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.cluster.id | Elasticsearch cluster id. | keyword |
| elasticsearch.cluster.name | Elasticsearch cluster name. | keyword |
| elasticsearch.cluster.state.id | Elasticsearch state id. | keyword |
| elasticsearch.node.id | Node ID | keyword |
| elasticsearch.node.jvm.memory.heap.init.bytes | Heap init used by the JVM in bytes. | long |
| elasticsearch.node.jvm.memory.heap.max.bytes | Heap max used by the JVM in bytes. | long |
| elasticsearch.node.jvm.memory.nonheap.init.bytes | Non-Heap init used by the JVM in bytes. | long |
| elasticsearch.node.jvm.memory.nonheap.max.bytes | Non-Heap max used by the JVM in bytes. | long |
| elasticsearch.node.jvm.version | JVM version. | keyword |
| elasticsearch.node.master | Is the node the master node? | boolean |
| elasticsearch.node.mlockall | Is mlockall enabled on the node? | boolean |
| elasticsearch.node.name | Node name. | keyword |
| elasticsearch.node.process.mlockall | If process locked in memory. | boolean |
| elasticsearch.node.version | Node version. | keyword |

### Node stats

`node_stats` interrogates the
https://www.elastic.co/guide/en/elasticsearch/reference/master/cluster-nodes-stats.html[Cluster API endpoint] of
Elasticsearch to get the cluster nodes statistics. The data received is only for the local node so the Agent has
to be run on each Elasticsearch node.

NOTE: The indices stats are node-specific. That means for example the total number of docs reported by all nodes together is not the total number of documents in all indices as there can also be replicas.

An example event for `node_stats` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "type": "metricbeat",
        "ephemeral_id": "2b6da727-313f-41fc-84af-3cd928f265c1",
        "version": "7.14.0"
    },
    "elastic_agent": {
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "version": "7.14.0",
        "snapshot": true
    },
    "@timestamp": "2021-07-30T14:47:15.407Z",
    "elasticsearch": {
        "node": {
            "stats": {
                "jvm": {
                    "mem": {
                        "pools": {
                            "young": {
                                "max": {
                                    "bytes": 0
                                },
                                "used": {
                                    "bytes": 33554432
                                },
                                "peak": {
                                    "bytes": 633339904
                                },
                                "peak_max": {
                                    "bytes": 0
                                }
                            },
                            "old": {
                                "max": {
                                    "bytes": 1073741824
                                },
                                "used": {
                                    "bytes": 248498176
                                },
                                "peak": {
                                    "bytes": 371192832
                                },
                                "peak_max": {
                                    "bytes": 1073741824
                                }
                            },
                            "survivor": {
                                "max": {
                                    "bytes": 0
                                },
                                "peak": {
                                    "bytes": 67829936
                                },
                                "peak_max": {
                                    "bytes": 0
                                },
                                "used": {
                                    "bytes": 3283184
                                }
                            }
                        }
                    },
                    "gc": {
                        "collectors": {
                            "young": {
                                "collection": {
                                    "ms": 6100,
                                    "count": 425
                                }
                            },
                            "old": {
                                "collection": {
                                    "ms": 0,
                                    "count": 0
                                }
                            }
                        }
                    }
                },
                "indices": {
                    "docs": {
                        "deleted": 7226,
                        "count": 50805
                    },
                    "store": {
                        "size": {
                            "bytes": 37101213
                        }
                    },
                    "segments": {
                        "memory": {
                            "bytes": 1805548
                        },
                        "count": 227
                    }
                },
                "fs": {
                    "summary": {
                        "total": {
                            "bytes": 958613114880
                        },
                        "available": {
                            "bytes": 261931741184
                        },
                        "free": {
                            "bytes": 310698074112
                        }
                    }
                }
            },
            "name": "e7e895f7c41e",
            "id": "6XuAxHXaRbeX6LUrxIfAxg"
        },
        "cluster": {
            "name": "docker-cluster",
            "id": "bvF4SoDLQU-sdM3YY8JI8Q"
        }
    },
    "ecs": {
        "version": "1.10.0"
    },
    "service": {
        "address": "http://elasticsearch:9200",
        "name": "elasticsearch",
        "type": "elasticsearch"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "elasticsearch.node_stats"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.11.10-arch1-1",
            "codename": "Core",
            "name": "CentOS Linux",
            "type": "linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "8979eb4aa312c3dccea3823dd92f92f5",
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "node_stats"
    },
    "event": {
        "duration": 32401229,
        "agent_id_status": "verified",
        "ingested": "2021-07-30T14:47:16.373437564Z",
        "module": "elasticsearch",
        "dataset": "elasticsearch.node_stats"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.cluster.id | Elasticsearch cluster id. | keyword |
| elasticsearch.cluster.name | Elasticsearch cluster name. | keyword |
| elasticsearch.cluster.state.id | Elasticsearch state id. | keyword |
| elasticsearch.node.id | Node ID | keyword |
| elasticsearch.node.master | Is the node the master node? | boolean |
| elasticsearch.node.mlockall | Is mlockall enabled on the node? | boolean |
| elasticsearch.node.name | Node name. | keyword |
| elasticsearch.node.stats.fs.io_stats.total.operations.count |  | long |
| elasticsearch.node.stats.fs.io_stats.total.read.operations.count |  | long |
| elasticsearch.node.stats.fs.io_stats.total.write.operations.count |  | long |
| elasticsearch.node.stats.fs.summary.available.bytes |  | long |
| elasticsearch.node.stats.fs.summary.free.bytes |  | long |
| elasticsearch.node.stats.fs.summary.total.bytes |  | long |
| elasticsearch.node.stats.fs.total.available_in_bytes |  | long |
| elasticsearch.node.stats.fs.total.total_in_bytes |  | long |
| elasticsearch.node.stats.indices.docs.count | Total number of existing documents. | long |
| elasticsearch.node.stats.indices.docs.deleted | Total number of deleted documents. | long |
| elasticsearch.node.stats.indices.fielddata.memory.bytes |  | long |
| elasticsearch.node.stats.indices.indexing.index_time.ms |  | long |
| elasticsearch.node.stats.indices.indexing.index_total.count |  | long |
| elasticsearch.node.stats.indices.indexing.throttle_time.ms |  | long |
| elasticsearch.node.stats.indices.query_cache.memory.bytes |  | long |
| elasticsearch.node.stats.indices.request_cache.memory.bytes |  | long |
| elasticsearch.node.stats.indices.search.query_time.ms |  | long |
| elasticsearch.node.stats.indices.search.query_total.count |  | long |
| elasticsearch.node.stats.indices.segments.count | Total number of segments. | long |
| elasticsearch.node.stats.indices.segments.doc_values.memory.bytes |  | long |
| elasticsearch.node.stats.indices.segments.fixed_bit_set.memory.bytes |  | long |
| elasticsearch.node.stats.indices.segments.index_writer.memory.bytes |  | long |
| elasticsearch.node.stats.indices.segments.memory.bytes | Total size of segments in bytes. | long |
| elasticsearch.node.stats.indices.segments.norms.memory.bytes |  | long |
| elasticsearch.node.stats.indices.segments.points.memory.bytes |  | long |
| elasticsearch.node.stats.indices.segments.stored_fields.memory.bytes |  | long |
| elasticsearch.node.stats.indices.segments.term_vectors.memory.bytes |  | long |
| elasticsearch.node.stats.indices.segments.terms.memory.bytes |  | long |
| elasticsearch.node.stats.indices.segments.version_map.memory.bytes |  | long |
| elasticsearch.node.stats.indices.store.size.bytes | Total size of the store in bytes. | long |
| elasticsearch.node.stats.jvm.gc.collectors.old.collection.count |  | long |
| elasticsearch.node.stats.jvm.gc.collectors.old.collection.ms |  | long |
| elasticsearch.node.stats.jvm.gc.collectors.young.collection.count |  | long |
| elasticsearch.node.stats.jvm.gc.collectors.young.collection.ms |  | long |
| elasticsearch.node.stats.jvm.mem.heap.max.bytes |  | long |
| elasticsearch.node.stats.jvm.mem.heap.used.bytes |  | long |
| elasticsearch.node.stats.jvm.mem.heap.used.pct |  | double |
| elasticsearch.node.stats.jvm.mem.pools.old.max.bytes | Max bytes. | long |
| elasticsearch.node.stats.jvm.mem.pools.old.peak.bytes | Peak bytes. | long |
| elasticsearch.node.stats.jvm.mem.pools.old.peak_max.bytes | Peak max bytes. | long |
| elasticsearch.node.stats.jvm.mem.pools.old.used.bytes | Used bytes. | long |
| elasticsearch.node.stats.jvm.mem.pools.survivor.max.bytes | Max bytes. | long |
| elasticsearch.node.stats.jvm.mem.pools.survivor.peak.bytes | Peak bytes. | long |
| elasticsearch.node.stats.jvm.mem.pools.survivor.peak_max.bytes | Peak max bytes. | long |
| elasticsearch.node.stats.jvm.mem.pools.survivor.used.bytes | Used bytes. | long |
| elasticsearch.node.stats.jvm.mem.pools.young.max.bytes | Max bytes. | long |
| elasticsearch.node.stats.jvm.mem.pools.young.peak.bytes | Peak bytes. | long |
| elasticsearch.node.stats.jvm.mem.pools.young.peak_max.bytes | Peak max bytes. | long |
| elasticsearch.node.stats.jvm.mem.pools.young.used.bytes | Used bytes. | long |
| elasticsearch.node.stats.os.cgroup.cpu.cfs.quota.us |  | long |
| elasticsearch.node.stats.os.cgroup.cpu.stat.elapsed_periods.count |  | long |
| elasticsearch.node.stats.os.cgroup.cpu.stat.time_throttled.ns |  | long |
| elasticsearch.node.stats.os.cgroup.cpu.stat.times_throttled.count |  | long |
| elasticsearch.node.stats.os.cgroup.cpuacct.usage.ns |  | long |
| elasticsearch.node.stats.os.cgroup.memory.control_group |  | keyword |
| elasticsearch.node.stats.os.cgroup.memory.limit.bytes |  | long |
| elasticsearch.node.stats.os.cgroup.memory.usage.bytes |  | long |
| elasticsearch.node.stats.os.cpu.load_avg.1m |  | half_float |
| elasticsearch.node.stats.process.cpu.pct |  | double |
| elasticsearch.node.stats.thread_pool.bulk.queue.count |  | long |
| elasticsearch.node.stats.thread_pool.bulk.rejected.count |  | long |
| elasticsearch.node.stats.thread_pool.get.queue.count |  | long |
| elasticsearch.node.stats.thread_pool.get.rejected.count |  | long |
| elasticsearch.node.stats.thread_pool.index.queue.count |  | long |
| elasticsearch.node.stats.thread_pool.index.rejected.count |  | long |
| elasticsearch.node.stats.thread_pool.search.queue.count |  | long |
| elasticsearch.node.stats.thread_pool.search.rejected.count |  | long |
| elasticsearch.node.stats.thread_pool.write.queue.count |  | long |
| elasticsearch.node.stats.thread_pool.write.rejected.count |  | long |

### Pending tasks

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.cluster.id | Elasticsearch cluster id. | keyword |
| elasticsearch.cluster.name | Elasticsearch cluster name. | keyword |
| elasticsearch.cluster.pending_task.insert_order | Insert order | long |
| elasticsearch.cluster.pending_task.priority | Priority | keyword |
| elasticsearch.cluster.pending_task.source | Source. For example: put-mapping | keyword |
| elasticsearch.cluster.pending_task.time_in_queue.ms | Time in queue | long |
| elasticsearch.cluster.state.id | Elasticsearch state id. | keyword |
| elasticsearch.node.id | Node ID | keyword |
| elasticsearch.node.master | Is the node the master node? | boolean |
| elasticsearch.node.mlockall | Is mlockall enabled on the node? | boolean |
| elasticsearch.node.name | Node name. | keyword |

# Shard

`shard` interrogates the
https://www.elastic.co/guide/en/elasticsearch/reference/6.2/cluster-state.html[Cluster State API endpoint] to fetch 
information about all shards.

An example event for `shard` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "type": "metricbeat",
        "ephemeral_id": "2b6da727-313f-41fc-84af-3cd928f265c1",
        "version": "7.14.0"
    },
    "elastic_agent": {
        "id": "60e15e27-7080-4c28-9900-5a087c2ff74c",
        "version": "7.14.0",
        "snapshot": true
    },
    "@timestamp": "2021-07-30T14:41:17.832Z",
    "ecs": {
        "version": "1.10.0"
    },
    "elasticsearch": {
        "node": {
            "name": "6XuAxHXaRbeX6LUrxIfAxg"
        },
        "cluster": {
            "name": "docker-cluster",
            "id": "bvF4SoDLQU-sdM3YY8JI8Q",
            "state": {
                "id": "mOYQ8E-ORnGSnnp9sB4BCw"
            }
        },
        "index": {
            "name": ".async-search"
        },
        "shard": {
            "number": 0,
            "relocating_node": {},
            "state": "STARTED",
            "primary": true
        }
    },
    "service": {
        "address": "http://elasticsearch:9200",
        "name": "elasticsearch",
        "type": "elasticsearch"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "elasticsearch.shard"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.11.10-arch1-1",
            "codename": "Core",
            "name": "CentOS Linux",
            "family": "redhat",
            "type": "linux",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "8979eb4aa312c3dccea3823dd92f92f5",
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "shard"
    },
    "event": {
        "duration": 4139652,
        "agent_id_status": "verified",
        "ingested": "2021-07-30T14:41:18.844042490Z",
        "module": "elasticsearch",
        "dataset": "elasticsearch.shard"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| elasticsearch.cluster.id | Elasticsearch cluster id. | keyword |
| elasticsearch.cluster.name | Elasticsearch cluster name. | keyword |
| elasticsearch.cluster.state.id | Elasticsearch state id. | keyword |
| elasticsearch.index.name |  | keyword |
| elasticsearch.node.id | Node ID | keyword |
| elasticsearch.node.master | Is the node the master node? | boolean |
| elasticsearch.node.mlockall | Is mlockall enabled on the node? | boolean |
| elasticsearch.node.name | Node name. | keyword |
| elasticsearch.shard.number | The number of this shard. | long |
| elasticsearch.shard.primary | True if this is the primary shard. | boolean |
| elasticsearch.shard.relocating_node.id | The node the shard was relocated from. It has the exact same value than relocating_node.name for compatibility purposes. | keyword |
| elasticsearch.shard.relocating_node.name | The node the shard was relocated from. | keyword |
| elasticsearch.shard.source_node.name |  | keyword |
| elasticsearch.shard.source_node.uuid |  | keyword |
| elasticsearch.shard.state | The state of this shard. | keyword |
