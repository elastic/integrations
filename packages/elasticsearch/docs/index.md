# Index

## Metrics

An example event for `index` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "elasticsearch": {
        "cluster": {
            "id": "8l_zoGznQRmtoX9iSC-goA",
            "name": "docker-cluster"
        },
        "index": {
            "hidden": false,
            "name": ".kibana-event-log-8.0.0-000001",
            "primaries": {
                "docs": {
                    "count": 2
                },
                "indexing": {
                    "index_time_in_millis": 109,
                    "index_total": 1,
                    "throttle_time_in_millis": 0
                },
                "merges": {
                    "total_size_in_bytes": 0
                },
                "refresh": {
                    "total_time_in_millis": 366
                },
                "segments": {
                    "count": 2
                },
                "store": {
                    "size_in_bytes": 11301
                }
            },
            "shards": {
                "total": 1
            },
            "status": "green",
            "total": {
                "docs": {
                    "count": 2
                },
                "fielddata": {
                    "memory_size_in_bytes": 0
                },
                "indexing": {
                    "index_time_in_millis": 109,
                    "index_total": 1,
                    "throttle_time_in_millis": 0
                },
                "merges": {
                    "total_size_in_bytes": 0
                },
                "refresh": {
                    "total_time_in_millis": 366
                },
                "search": {
                    "query_time_in_millis": 0,
                    "query_total": 1
                },
                "segments": {
                    "count": 2,
                    "doc_values_memory_in_bytes": 152,
                    "fixed_bit_set_memory_in_bytes": 96,
                    "index_writer_memory_in_bytes": 0,
                    "memory_in_bytes": 4392,
                    "norms_memory_in_bytes": 0,
                    "points_memory_in_bytes": 0,
                    "stored_fields_memory_in_bytes": 976,
                    "term_vectors_memory_in_bytes": 0,
                    "terms_memory_in_bytes": 3264,
                    "version_map_memory_in_bytes": 0
                },
                "store": {
                    "size_in_bytes": 11301
                }
            },
            "uuid": "3765e_aCRh28_UoF-iWnuQ"
        }
    },
    "event": {
        "dataset": "elasticsearch.index",
        "duration": 115000,
        "module": "elasticsearch"
    },
    "metricset": {
        "name": "index",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:35043",
        "type": "elasticsearch"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| ccr_auto_follow_stats.follower.failed_read_requests |  | alias |
| ccr_auto_follow_stats.number_of_failed_follow_indices |  | alias |
| ccr_auto_follow_stats.number_of_failed_remote_cluster_state_requests |  | alias |
| ccr_auto_follow_stats.number_of_successful_follow_indices |  | alias |
| ccr_stats.bytes_read |  | alias |
| ccr_stats.failed_read_requests |  | alias |
| ccr_stats.failed_write_requests |  | alias |
| ccr_stats.follower_aliases_version |  | alias |
| ccr_stats.follower_global_checkpoint |  | alias |
| ccr_stats.follower_index |  | alias |
| ccr_stats.follower_mapping_version |  | alias |
| ccr_stats.follower_max_seq_no |  | alias |
| ccr_stats.follower_settings_version |  | alias |
| ccr_stats.last_requested_seq_no |  | alias |
| ccr_stats.leader_global_checkpoint |  | alias |
| ccr_stats.leader_index |  | alias |
| ccr_stats.leader_max_seq_no |  | alias |
| ccr_stats.operations_read |  | alias |
| ccr_stats.operations_written |  | alias |
| ccr_stats.outstanding_read_requests |  | alias |
| ccr_stats.outstanding_write_requests |  | alias |
| ccr_stats.remote_cluster |  | alias |
| ccr_stats.shard_id |  | alias |
| ccr_stats.successful_read_requests |  | alias |
| ccr_stats.successful_write_requests |  | alias |
| ccr_stats.total_read_remote_exec_time_millis |  | alias |
| ccr_stats.total_read_time_millis |  | alias |
| ccr_stats.total_write_time_millis |  | alias |
| ccr_stats.write_buffer_operation_count |  | alias |
| ccr_stats.write_buffer_size_in_bytes |  | alias |
| cluster_state.master_node |  | alias |
| cluster_state.nodes_hash |  | alias |
| cluster_state.state_uuid |  | alias |
| cluster_state.status |  | alias |
| cluster_state.version |  | alias |
| cluster_stats.indices.count |  | alias |
| cluster_stats.indices.shards.total |  | alias |
| cluster_stats.nodes.count.total |  | alias |
| cluster_stats.nodes.jvm.max_uptime_in_millis |  | alias |
| cluster_stats.nodes.jvm.mem.heap_max_in_bytes |  | alias |
| cluster_stats.nodes.jvm.mem.heap_used_in_bytes |  | alias |
| cluster_uuid |  | alias |
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
| index_recovery.shards.start_time_in_millis |  | alias |
| index_recovery.shards.stop_time_in_millis |  | alias |
| index_stats.index |  | alias |
| index_stats.primaries.docs.count |  | alias |
| index_stats.primaries.indexing.index_time_in_millis |  | alias |
| index_stats.primaries.indexing.index_total |  | alias |
| index_stats.primaries.indexing.throttle_time_in_millis |  | alias |
| index_stats.primaries.merges.total_size_in_bytes |  | alias |
| index_stats.primaries.refresh.total_time_in_millis |  | alias |
| index_stats.primaries.segments.count |  | alias |
| index_stats.primaries.store.size_in_bytes |  | alias |
| index_stats.total.fielddata.memory_size_in_bytes |  | alias |
| index_stats.total.indexing.index_time_in_millis |  | alias |
| index_stats.total.indexing.index_total |  | alias |
| index_stats.total.indexing.throttle_time_in_millis |  | alias |
| index_stats.total.merges.total_size_in_bytes |  | alias |
| index_stats.total.query_cache.memory_size_in_bytes |  | alias |
| index_stats.total.refresh.total_time_in_millis |  | alias |
| index_stats.total.request_cache.memory_size_in_bytes |  | alias |
| index_stats.total.search.query_time_in_millis |  | alias |
| index_stats.total.search.query_total |  | alias |
| index_stats.total.segments.count |  | alias |
| index_stats.total.segments.doc_values_memory_in_bytes |  | alias |
| index_stats.total.segments.fixed_bit_set_memory_in_bytes |  | alias |
| index_stats.total.segments.index_writer_memory_in_bytes |  | alias |
| index_stats.total.segments.memory_in_bytes |  | alias |
| index_stats.total.segments.norms_memory_in_bytes |  | alias |
| index_stats.total.segments.points_memory_in_bytes |  | alias |
| index_stats.total.segments.stored_fields_memory_in_bytes |  | alias |
| index_stats.total.segments.term_vectors_memory_in_bytes |  | alias |
| index_stats.total.segments.terms_memory_in_bytes |  | alias |
| index_stats.total.segments.version_map_memory_in_bytes |  | alias |
| index_stats.total.store.size_in_bytes |  | alias |
| indices_stats._all.primaries.indexing.index_time_in_millis |  | alias |
| indices_stats._all.primaries.indexing.index_total |  | alias |
| indices_stats._all.total.indexing.index_total |  | alias |
| indices_stats._all.total.search.query_time_in_millis |  | alias |
| indices_stats._all.total.search.query_total |  | alias |
| job_stats.forecasts_stats.total |  | alias |
| job_stats.job_id |  | alias |
| license.status |  | alias |
| license.type |  | alias |
| node_stats.fs.io_stats.total.operations |  | alias |
| node_stats.fs.io_stats.total.read_operations |  | alias |
| node_stats.fs.io_stats.total.write_operations |  | alias |
| node_stats.fs.summary.available.bytes |  | alias |
| node_stats.fs.summary.total.bytes |  | alias |
| node_stats.fs.total.available_in_bytes |  | alias |
| node_stats.fs.total.total_in_bytes |  | alias |
| node_stats.indices.docs.count |  | alias |
| node_stats.indices.fielddata.memory_size_in_bytes |  | alias |
| node_stats.indices.indexing.index_time_in_millis |  | alias |
| node_stats.indices.indexing.index_total |  | alias |
| node_stats.indices.indexing.throttle_time_in_millis |  | alias |
| node_stats.indices.query_cache.memory_size_in_bytes |  | alias |
| node_stats.indices.request_cache.memory_size_in_bytes |  | alias |
| node_stats.indices.search.query_time_in_millis |  | alias |
| node_stats.indices.search.query_total |  | alias |
| node_stats.indices.segments.count |  | alias |
| node_stats.indices.segments.doc_values_memory_in_bytes |  | alias |
| node_stats.indices.segments.fixed_bit_set_memory_in_bytes |  | alias |
| node_stats.indices.segments.index_writer_memory_in_bytes |  | alias |
| node_stats.indices.segments.memory_in_bytes |  | alias |
| node_stats.indices.segments.norms_memory_in_bytes |  | alias |
| node_stats.indices.segments.points_memory_in_bytes |  | alias |
| node_stats.indices.segments.stored_fields_memory_in_bytes |  | alias |
| node_stats.indices.segments.term_vectors_memory_in_bytes |  | alias |
| node_stats.indices.segments.terms_memory_in_bytes |  | alias |
| node_stats.indices.segments.version_map_memory_in_bytes |  | alias |
| node_stats.indices.store.size.bytes |  | alias |
| node_stats.indices.store.size_in_bytes |  | alias |
| node_stats.jvm.gc.collectors.old.collection_count |  | alias |
| node_stats.jvm.gc.collectors.old.collection_time_in_millis |  | alias |
| node_stats.jvm.gc.collectors.young.collection_count |  | alias |
| node_stats.jvm.gc.collectors.young.collection_time_in_millis |  | alias |
| node_stats.jvm.mem.heap_max_in_bytes |  | alias |
| node_stats.jvm.mem.heap_used_in_bytes |  | alias |
| node_stats.jvm.mem.heap_used_percent |  | alias |
| node_stats.node_id |  | alias |
| node_stats.os.cgroup.cpu.cfs_quota_micros |  | alias |
| node_stats.os.cgroup.cpu.stat.number_of_elapsed_periods |  | alias |
| node_stats.os.cgroup.cpu.stat.number_of_times_throttled |  | alias |
| node_stats.os.cgroup.cpu.stat.time_throttled_nanos |  | alias |
| node_stats.os.cgroup.cpuacct.usage_nanos |  | alias |
| node_stats.os.cgroup.memory.control_group |  | alias |
| node_stats.os.cgroup.memory.limit_in_bytes |  | alias |
| node_stats.os.cgroup.memory.usage_in_bytes |  | alias |
| node_stats.os.cpu.load_average.1m |  | alias |
| node_stats.process.cpu.percent |  | alias |
| node_stats.thread_pool.bulk.queue |  | alias |
| node_stats.thread_pool.bulk.rejected |  | alias |
| node_stats.thread_pool.get.queue |  | alias |
| node_stats.thread_pool.get.rejected |  | alias |
| node_stats.thread_pool.index.queue |  | alias |
| node_stats.thread_pool.index.rejected |  | alias |
| node_stats.thread_pool.search.queue |  | alias |
| node_stats.thread_pool.search.rejected |  | alias |
| node_stats.thread_pool.write.queue |  | alias |
| node_stats.thread_pool.write.rejected |  | alias |
| shard.index |  | alias |
| shard.node |  | alias |
| shard.primary |  | alias |
| shard.shard |  | alias |
| shard.state |  | alias |
| source_node.name |  | alias |
| source_node.uuid |  | alias |
| stack_stats.apm.found |  | alias |
| stack_stats.xpack.ccr.available |  | alias |
| stack_stats.xpack.ccr.enabled |  | alias |
| timestamp |  | alias |

