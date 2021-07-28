# Garbage collection

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

