# Node stats

## Metrics

An example event for `node_stats` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "elasticsearch": {
        "cluster": {
            "id": "w3oo88LcQ1i-7K4f-wrEgQ",
            "name": "docker-cluster"
        },
        "node": {
            "id": "EjV2AqqvQNq5ZF5cVlaPDQ",
            "master": true,
            "mlockall": false,
            "name": "foo",
            "stats": {
                "fs": {
                    "io_stats": {},
                    "summary": {
                        "available": {
                            "bytes": 45897547776
                        },
                        "free": {
                            "bytes": 49114263552
                        },
                        "total": {
                            "bytes": 62725623808
                        }
                    }
                },
                "indices": {
                    "docs": {
                        "count": 9207,
                        "deleted": 43
                    },
                    "fielddata": {
                        "memory": {
                            "bytes": 0
                        }
                    },
                    "indexing": {
                        "index_time": {
                            "ms": 21
                        },
                        "index_total": {
                            "count": 4
                        },
                        "throttle_time": {
                            "ms": 0
                        }
                    },
                    "query_cache": {
                        "memory": {
                            "bytes": 0
                        }
                    },
                    "request_cache": {
                        "memory": {
                            "bytes": 3736
                        }
                    },
                    "search": {
                        "query_time": {
                            "ms": 83
                        },
                        "query_total": {
                            "count": 18
                        }
                    },
                    "segments": {
                        "count": 63,
                        "doc_values": {
                            "memory": {
                                "bytes": 117620
                            }
                        },
                        "fixed_bit_set": {
                            "memory": {
                                "bytes": 3912
                            }
                        },
                        "index_writer": {
                            "memory": {
                                "bytes": 0
                            }
                        },
                        "memory": {
                            "bytes": 330956
                        },
                        "norms": {
                            "memory": {
                                "bytes": 2688
                            }
                        },
                        "points": {
                            "memory": {
                                "bytes": 0
                            }
                        },
                        "stored_fields": {
                            "memory": {
                                "bytes": 31000
                            }
                        },
                        "term_vectors": {
                            "memory": {
                                "bytes": 0
                            }
                        },
                        "terms": {
                            "memory": {
                                "bytes": 179648
                            }
                        },
                        "version_map": {
                            "memory": {
                                "bytes": 0
                            }
                        }
                    },
                    "store": {
                        "size": {
                            "bytes": 18049725
                        }
                    }
                },
                "jvm": {
                    "gc": {
                        "collectors": {
                            "old": {
                                "collection": {
                                    "count": 0,
                                    "ms": 0
                                }
                            },
                            "young": {
                                "collection": {
                                    "count": 10,
                                    "ms": 290
                                }
                            }
                        }
                    },
                    "mem": {
                        "heap": {
                            "max": {
                                "bytes": 1073741824
                            },
                            "used": {
                                "bytes": 177654272,
                                "pct": 16
                            }
                        }
                    }
                },
                "os": {
                    "cgroup": {
                        "cpu": {
                            "cfs": {
                                "quota": {
                                    "us": -1
                                }
                            },
                            "stat": {
                                "elapsed_periods": {
                                    "count": 0
                                },
                                "times_throttled": {
                                    "count": 0
                                }
                            }
                        },
                        "cpuacct": {
                            "usage": {
                                "ns": 57724017512
                            }
                        },
                        "memory": {
                            "control_group": "/",
                            "limit": {
                                "bytes": 9223372036854771712
                            },
                            "usage": {
                                "bytes": 1508503552
                            }
                        }
                    },
                    "cpu": {
                        "load_avg": {
                            "1m": 2.06
                        }
                    }
                },
                "process": {
                    "cpu": {
                        "pct": 32
                    }
                },
                "thread_pool": {
                    "get": {
                        "queue": {
                            "count": 0
                        },
                        "rejected": {
                            "count": 0
                        }
                    },
                    "search": {
                        "queue": {
                            "count": 0
                        },
                        "rejected": {
                            "count": 0
                        }
                    },
                    "write": {
                        "queue": {
                            "count": 0
                        },
                        "rejected": {
                            "count": 0
                        }
                    }
                }
            }
        }
    },
    "event": {
        "dataset": "elasticsearch.node.stats",
        "duration": 115000,
        "module": "elasticsearch"
    },
    "metricset": {
        "name": "node_stats",
        "period": 10000
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
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

