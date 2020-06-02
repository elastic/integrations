# Redis Integration

This integration periodically fetches logs and metrics from [https://redis.io/](Redis) servers.

## Compatibility

The `log` and `slowlog` datasets were tested with logs from Redis versions 1.2.6, 2.4.6, and 3.0.2, so we expect
compatibility with any version 1.x, 2.x, or 3.x.

The `info`, `key` and `keyspace` datasets were tested with Redis 3.2.12, 4.0.11 and 5.0-rc4, and are expected to work
with all versions >= 3.0.

## Logs

### log

The `log` dataset collects the Redis standard logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| process.pid | Process id. | long |
| redis.log.role | The role of the Redis instance. Can be one of `master`, `slave`, `child` (for RDF/AOF writing child), or `sentinel`. | keyword |


### slowlog

The `slowlog` dataset collects the Redis slow logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| process.pid | Process id. | long |
| redis.log.role | The role of the Redis instance. Can be one of `master`, `slave`, `child` (for RDF/AOF writing child), or `sentinel`. | keyword |


## Metrics

### info

The `info` dataset collects information and statistics from Redis by running the `INFO` command and parsing the returned
result.

An example event for `info` looks as following:

```$json
TODO
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| os.full | Operating system name, including the version or code name. | keyword |
| process.pid | Process id. | long |
| redis.info.clients.biggest_input_buf | Biggest input buffer among current client connections (replaced by max_input_buffer). | long |
| redis.info.clients.blocked | Number of clients pending on a blocking call (BLPOP, BRPOP, BRPOPLPUSH). | long |
| redis.info.clients.connected | Number of client connections (excluding connections from slaves). | long |
| redis.info.clients.longest_output_list | Longest output list among current client connections (replaced by max_output_buffer). | long |
| redis.info.clients.max_input_buffer | Biggest input buffer among current client connections (on redis 5.0). | long |
| redis.info.clients.max_output_buffer | Longest output list among current client connections. | long |
| redis.info.cluster.enabled | Indicates that the Redis cluster is enabled. | boolean |
| redis.info.cpu.used.sys | System CPU consumed by the Redis server. | scaled_float |
| redis.info.cpu.used.sys_children | User CPU consumed by the Redis server. | scaled_float |
| redis.info.cpu.used.user | System CPU consumed by the background processes. | scaled_float |
| redis.info.cpu.used.user_children | User CPU consumed by the background processes. | scaled_float |
| redis.info.memory.active_defrag.is_running | Flag indicating if active defragmentation is active | boolean |
| redis.info.memory.allocator | Memory allocator. | keyword |
| redis.info.memory.allocator_stats.active | Active memeory | long |
| redis.info.memory.allocator_stats.allocated | Allocated memory | long |
| redis.info.memory.allocator_stats.fragmentation.bytes | Fragmented bytes | long |
| redis.info.memory.allocator_stats.fragmentation.ratio | Fragmentation ratio | float |
| redis.info.memory.allocator_stats.resident | Resident memory | long |
| redis.info.memory.allocator_stats.rss.bytes | Resident bytes | long |
| redis.info.memory.allocator_stats.rss.ratio | Resident ratio | float |
| redis.info.memory.fragmentation.bytes | Bytes between used_memory_rss and used_memory | long |
| redis.info.memory.fragmentation.ratio | Ratio between used_memory_rss and used_memory | float |
| redis.info.memory.max.policy | Eviction policy to use when memory limit is reached. | keyword |
| redis.info.memory.max.value | Memory limit. | long |
| redis.info.memory.used.dataset | The size in bytes of the dataset | long |
| redis.info.memory.used.lua | Used memory by the Lua engine. | long |
| redis.info.memory.used.peak | Peak memory consumed by Redis. | long |
| redis.info.memory.used.rss | Number of bytes that Redis allocated as seen by the operating system (a.k.a resident set size). | long |
| redis.info.memory.used.value | Total number of bytes allocated by Redis. | long |
| redis.info.persistence.aof.bgrewrite.last_status | Status of the last AOF rewrite operatio | keyword |
| redis.info.persistence.aof.buffer.size | Size of the AOF buffer | long |
| redis.info.persistence.aof.copy_on_write.last_size | The size in bytes of copy-on-write allocations during the last RBD save operation | long |
| redis.info.persistence.aof.enabled | Flag indicating AOF logging is activated | boolean |
| redis.info.persistence.aof.fsync.delayed | Delayed fsync counter | long |
| redis.info.persistence.aof.fsync.pending | Number of fsync pending jobs in background I/O queue | long |
| redis.info.persistence.aof.rewrite.buffer.size | Size of the AOF rewrite buffer | long |
| redis.info.persistence.aof.rewrite.current_time.sec | Duration of the on-going AOF rewrite operation if any | long |
| redis.info.persistence.aof.rewrite.in_progress | Flag indicating a AOF rewrite operation is on-going | boolean |
| redis.info.persistence.aof.rewrite.last_time.sec | Duration of the last AOF rewrite operation in seconds | long |
| redis.info.persistence.aof.rewrite.scheduled | Flag indicating an AOF rewrite operation will be scheduled once the on-going RDB save is complete. | boolean |
| redis.info.persistence.aof.size.base | AOF file size on latest startup or rewrite | long |
| redis.info.persistence.aof.size.current | AOF current file size | long |
| redis.info.persistence.aof.write.last_status | Status of the last write operation to the AOF | keyword |
| redis.info.persistence.loading | Flag indicating if the load of a dump file is on-going | boolean |
| redis.info.persistence.rdb.bgsave.current_time.sec | Duration of the on-going RDB save operation if any | long |
| redis.info.persistence.rdb.bgsave.in_progress | Flag indicating a RDB save is on-going | boolean |
| redis.info.persistence.rdb.bgsave.last_status | Status of the last RDB save operation | keyword |
| redis.info.persistence.rdb.bgsave.last_time.sec | Duration of the last RDB save operation in seconds | long |
| redis.info.persistence.rdb.copy_on_write.last_size | The size in bytes of copy-on-write allocations during the last RBD save operation | long |
| redis.info.persistence.rdb.last_save.changes_since | Number of changes since the last dump | long |
| redis.info.persistence.rdb.last_save.time | Epoch-based timestamp of last successful RDB save | long |
| redis.info.replication.backlog.active | Flag indicating replication backlog is active | long |
| redis.info.replication.backlog.first_byte_offset | The master offset of the replication backlog buffer | long |
| redis.info.replication.backlog.histlen | Size in bytes of the data in the replication backlog buffer | long |
| redis.info.replication.backlog.size | Total size in bytes of the replication backlog buffer | long |
| redis.info.replication.connected_slaves | Number of connected slaves | long |
| redis.info.replication.master.last_io_seconds_ago | Number of seconds since the last interaction with master | long |
| redis.info.replication.master.link_status | Status of the link (up/down) | keyword |
| redis.info.replication.master.offset | The server's current replication offset | long |
| redis.info.replication.master.second_offset | The offset up to which replication IDs are accepted | long |
| redis.info.replication.master.sync.in_progress | Indicate the master is syncing to the slave | boolean |
| redis.info.replication.master.sync.last_io_seconds_ago | Number of seconds since last transfer I/O during a SYNC operation | long |
| redis.info.replication.master.sync.left_bytes | Number of bytes left before syncing is complete | long |
| redis.info.replication.master_offset | The server's current replication offset | long |
| redis.info.replication.role | Role of the instance (can be "master", or "slave"). | keyword |
| redis.info.replication.slave.is_readonly | Flag indicating if the slave is read-only | boolean |
| redis.info.replication.slave.offset | The replication offset of the slave instance | long |
| redis.info.replication.slave.priority | The priority of the instance as a candidate for failover | long |
| redis.info.server.arch_bits |  | keyword |
| redis.info.server.build_id |  | keyword |
| redis.info.server.config_file |  | keyword |
| redis.info.server.gcc_version |  | keyword |
| redis.info.server.git_dirty |  | keyword |
| redis.info.server.git_sha1 |  | keyword |
| redis.info.server.hz |  | long |
| redis.info.server.lru_clock |  | long |
| redis.info.server.mode |  | keyword |
| redis.info.server.multiplexing_api |  | keyword |
| redis.info.server.run_id |  | keyword |
| redis.info.server.tcp_port |  | long |
| redis.info.server.uptime |  | long |
| redis.info.slowlog.count | Count of slow operations | long |
| redis.info.stats.active_defrag.hits | Number of value reallocations performed by active the defragmentation process | long |
| redis.info.stats.active_defrag.key_hits | Number of keys that were actively defragmented | long |
| redis.info.stats.active_defrag.key_misses | Number of keys that were skipped by the active defragmentation process | long |
| redis.info.stats.active_defrag.misses | Number of aborted value reallocations started by the active defragmentation process | long |
| redis.info.stats.commands_processed | Total number of commands processed. | long |
| redis.info.stats.connections.received | Total number of connections received. | long |
| redis.info.stats.connections.rejected | Total number of connections rejected. | long |
| redis.info.stats.instantaneous.input_kbps | The network's read rate per second in KB/sec | scaled_float |
| redis.info.stats.instantaneous.ops_per_sec | Number of commands processed per second | long |
| redis.info.stats.instantaneous.output_kbps | The network's write rate per second in KB/sec | scaled_float |
| redis.info.stats.keys.evicted | Number of evicted keys due to maxmemory limit | long |
| redis.info.stats.keys.expired | Total number of key expiration events | long |
| redis.info.stats.keyspace.hits | Number of successful lookup of keys in the main dictionary | long |
| redis.info.stats.keyspace.misses | Number of failed lookup of keys in the main dictionary | long |
| redis.info.stats.latest_fork_usec | Duration of the latest fork operation in microseconds | long |
| redis.info.stats.migrate_cached_sockets | The number of sockets open for MIGRATE purposes | long |
| redis.info.stats.net.input.bytes | Total network input in bytes. | long |
| redis.info.stats.net.output.bytes | Total network output in bytes. | long |
| redis.info.stats.pubsub.channels | Global number of pub/sub channels with client subscriptions | long |
| redis.info.stats.pubsub.patterns | Global number of pub/sub pattern with client subscriptions | long |
| redis.info.stats.slave_expires_tracked_keys | The number of keys tracked for expiry purposes (applicable only to writable slaves) | long |
| redis.info.stats.sync.full | The number of full resyncs with slaves | long |
| redis.info.stats.sync.partial.err | The number of denied partial resync requests | long |
| redis.info.stats.sync.partial.ok | The number of accepted partial resync requests | long |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |


### key

The `key` dataset collects information about Redis keys.

For each key matching one of the configured patterns, an event is sent to Elasticsearch with information about this key,
what includes the type, its length when available, and its TTL.

Patterns are configured as a list containing these fields:

* `pattern` (required): pattern for key names, as accepted by the Redis KEYS or SCAN commands.
* `limit` (optional): safeguard when using patterns with wildcards to avoid collecting too many keys (Default: 0, no limit)
* `keyspace` (optional): Identifier of the database to use to look for the keys (Default: 0)

An example event for `key` looks as following:

```$json
TODO
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| redis.key.expire.ttl | Seconds to expire. | long |
| redis.key.id | Unique id for this key (With the form <keyspace>:<name>). | keyword |
| redis.key.length | Length of the key (Number of elements for lists, length for strings, cardinality for sets). | long |
| redis.key.name | Key name. | keyword |
| redis.key.type | Key type as shown by `TYPE` command. | keyword |


### keyspace

The `keyspace` dataset collects information about the Redis keyspaces. For each keyspace, an event is sent to
Elasticsearch. The keyspace information is fetched from the `INFO` command.

An example event for `keyspace` looks as following:

```$json
TODO
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| redis.keyspace.avg_ttl | Average ttl. | long |
| redis.keyspace.expires |  | long |
| redis.keyspace.id | Keyspace identifier. | keyword |
| redis.keyspace.keys | Number of keys in the keyspace. | long |

