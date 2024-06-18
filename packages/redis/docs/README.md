# Redis Integration

This integration periodically fetches logs and metrics from [Redis](https://redis.io/) servers.

## Compatibility

The `log` and `slowlog` datasets were tested with logs from Redis versions 1.2.6, 2.4.6, and 3.0.2, so we expect
compatibility with any version 1.x, 2.x, or 3.x.

The `info`, `key` and `keyspace` datasets were tested with Redis 3.2.12, 4.0.11 and 5.0-rc4, and are expected to work
with all versions `>= 3.0`.

## Logs

### log

The `log` dataset collects the Redis standard logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| redis.log.role | The role of the Redis instance. Can be one of `master`, `slave`, `child` (for RDF/AOF writing child), or `sentinel`. | keyword |


### slowlog

The `slowlog` dataset collects the Redis slow logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| redis.log.role | The role of the Redis instance. Can be one of `master`, `slave`, `child` (for RDF/AOF writing child), or `sentinel`. | keyword |


## Metrics

### info

The `info` dataset collects information and statistics from Redis by running the `INFO` command and parsing the returned
result.

An example event for `info` looks as following:

```json
{
    "@timestamp": "2020-06-25T10:16:10.138Z",
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "redis.info",
        "duration": 374411,
        "module": "redis"
    },
    "metricset": {
        "name": "info",
        "period": 10000
    },
    "redis": {
        "info": {
            "clients": {
                "biggest_input_buf": 0,
                "blocked": 0,
                "connected": 5,
                "longest_output_list": 0,
                "max_input_buffer": 0,
                "max_output_buffer": 0
            },
            "cluster": {
                "enabled": false
            },
            "cpu": {
                "used": {
                    "sys": 1.66,
                    "sys_children": 0,
                    "user": 0.39,
                    "user_children": 0.01
                }
            },
            "memory": {
                "active_defrag": {},
                "allocator": "jemalloc-4.0.3",
                "allocator_stats": {
                    "fragmentation": {},
                    "rss": {}
                },
                "fragmentation": {
                    "ratio": 2.71
                },
                "max": {
                    "policy": "noeviction",
                    "value": 0
                },
                "used": {
                    "lua": 37888,
                    "peak": 945016,
                    "rss": 2453504,
                    "value": 904992
                }
            },
            "persistence": {
                "aof": {
                    "bgrewrite": {
                        "last_status": "ok"
                    },
                    "buffer": {},
                    "copy_on_write": {},
                    "enabled": false,
                    "fsync": {},
                    "rewrite": {
                        "buffer": {},
                        "current_time": {
                            "sec": -1
                        },
                        "in_progress": false,
                        "last_time": {
                            "sec": -1
                        },
                        "scheduled": false
                    },
                    "size": {},
                    "write": {
                        "last_status": "ok"
                    }
                },
                "loading": false,
                "rdb": {
                    "bgsave": {
                        "current_time": {
                            "sec": -1
                        },
                        "in_progress": false,
                        "last_status": "ok",
                        "last_time": {
                            "sec": -1
                        }
                    },
                    "copy_on_write": {},
                    "last_save": {
                        "changes_since": 35,
                        "time": 1548663522
                    }
                }
            },
            "replication": {
                "backlog": {
                    "active": 0,
                    "first_byte_offset": 0,
                    "histlen": 0,
                    "size": 1048576
                },
                "connected_slaves": 0,
                "master": {
                    "offset": 0,
                    "sync": {}
                },
                "master_offset": 0,
                "role": "master",
                "slave": {}
            },
            "server": {
                "arch_bits": "64",
                "build_id": "b9a4cd86ce8027d3",
                "config_file": "",
                "gcc_version": "6.4.0",
                "git_dirty": "0",
                "git_sha1": "00000000",
                "hz": 10,
                "lru_clock": 5159690,
                "mode": "standalone",
                "multiplexing_api": "epoll",
                "run_id": "0f681cb959aa47413ec40ff383715c923f9cbefd",
                "tcp_port": 6379,
                "uptime": 707
            },
            "slowlog": {
                "count": 0
            },
            "stats": {
                "active_defrag": {},
                "commands_processed": 265,
                "connections": {
                    "received": 848,
                    "rejected": 0
                },
                "instantaneous": {
                    "input_kbps": 0.18,
                    "ops_per_sec": 6,
                    "output_kbps": 1.39
                },
                "keys": {
                    "evicted": 0,
                    "expired": 0
                },
                "keyspace": {
                    "hits": 15,
                    "misses": 0
                },
                "latest_fork_usec": 0,
                "migrate_cached_sockets": 0,
                "net": {
                    "input": {
                        "bytes": 7300
                    },
                    "output": {
                        "bytes": 219632
                    }
                },
                "pubsub": {
                    "channels": 0,
                    "patterns": 0
                },
                "sync": {
                    "full": 0,
                    "partial": {
                        "err": 0,
                        "ok": 0
                    }
                }
            }
        }
    },
    "service": {
        "address": "localhost:6379",
        "type": "redis"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| os | The OS fields contain information about the operating system. | group |  |
| os.full | Operating system name, including the version or code name. | keyword |  |
| os.full.text | Multi-field of `os.full`. | match_only_text |  |
| process | These fields contain information about a process. These fields can help you correlate metrics information with a process id/name from a log message.  The `process.pid` often stays in the metric itself and is copied to the global field for correlation. | group |  |
| redis.info.clients.biggest_input_buf | Biggest input buffer among current client connections (replaced by max_input_buffer). | long | gauge |
| redis.info.clients.blocked | Number of clients pending on a blocking call (BLPOP, BRPOP, BRPOPLPUSH). | long | gauge |
| redis.info.clients.connected | Number of client connections (excluding connections from slaves). | long | gauge |
| redis.info.clients.longest_output_list | Longest output list among current client connections (replaced by max_output_buffer). | long | gauge |
| redis.info.clients.max_input_buffer | Biggest input buffer among current client connections (on redis 5.0). | long | gauge |
| redis.info.clients.max_output_buffer | Longest output list among current client connections. | long | gauge |
| redis.info.cluster.enabled | Indicates that the Redis cluster is enabled. | boolean |  |
| redis.info.cpu.used.sys | System CPU consumed by the Redis server. | scaled_float | gauge |
| redis.info.cpu.used.sys_children | User CPU consumed by the Redis server. | scaled_float | gauge |
| redis.info.cpu.used.user | System CPU consumed by the background processes. | scaled_float | gauge |
| redis.info.cpu.used.user_children | User CPU consumed by the background processes. | scaled_float | gauge |
| redis.info.memory.active_defrag.is_running | Flag indicating if active defragmentation is active | boolean |  |
| redis.info.memory.allocator | Memory allocator. | keyword |  |
| redis.info.memory.allocator_stats.active | Active memeory | long | gauge |
| redis.info.memory.allocator_stats.allocated | Allocated memory | long | gauge |
| redis.info.memory.allocator_stats.fragmentation.bytes | Fragmented bytes | long | gauge |
| redis.info.memory.allocator_stats.fragmentation.ratio | Fragmentation ratio | float | gauge |
| redis.info.memory.allocator_stats.resident | Resident memory | long | gauge |
| redis.info.memory.allocator_stats.rss.bytes | Resident bytes | long | gauge |
| redis.info.memory.allocator_stats.rss.ratio | Resident ratio | float | gauge |
| redis.info.memory.fragmentation.bytes | Bytes between used_memory_rss and used_memory | long | gauge |
| redis.info.memory.fragmentation.ratio | Ratio between used_memory_rss and used_memory | float | gauge |
| redis.info.memory.max.policy | Eviction policy to use when memory limit is reached. | keyword |  |
| redis.info.memory.max.value | Memory limit. | long | gauge |
| redis.info.memory.used.dataset | The size in bytes of the dataset | long | gauge |
| redis.info.memory.used.lua | Used memory by the Lua engine. | long | gauge |
| redis.info.memory.used.peak | Peak memory consumed by Redis. | long | gauge |
| redis.info.memory.used.rss | Number of bytes that Redis allocated as seen by the operating system (a.k.a resident set size). | long | gauge |
| redis.info.memory.used.value | Total number of bytes allocated by Redis. | long | gauge |
| redis.info.persistence.aof.bgrewrite.last_status | Status of the last AOF rewrite operatio | keyword |  |
| redis.info.persistence.aof.buffer.size | Size of the AOF buffer | long | gauge |
| redis.info.persistence.aof.copy_on_write.last_size | The size in bytes of copy-on-write allocations during the last RBD save operation | long | gauge |
| redis.info.persistence.aof.enabled | Flag indicating AOF logging is activated | boolean |  |
| redis.info.persistence.aof.fsync.delayed | Delayed fsync counter | long | gauge |
| redis.info.persistence.aof.fsync.pending | Number of fsync pending jobs in background I/O queue | long | gauge |
| redis.info.persistence.aof.rewrite.buffer.size | Size of the AOF rewrite buffer | long | gauge |
| redis.info.persistence.aof.rewrite.current_time.sec | Duration of the on-going AOF rewrite operation if any | long | gauge |
| redis.info.persistence.aof.rewrite.in_progress | Flag indicating a AOF rewrite operation is on-going | boolean |  |
| redis.info.persistence.aof.rewrite.last_time.sec | Duration of the last AOF rewrite operation in seconds | long | gauge |
| redis.info.persistence.aof.rewrite.scheduled | Flag indicating an AOF rewrite operation will be scheduled once the on-going RDB save is complete. | boolean |  |
| redis.info.persistence.aof.size.base | AOF file size on latest startup or rewrite | long | gauge |
| redis.info.persistence.aof.size.current | AOF current file size | long | gauge |
| redis.info.persistence.aof.write.last_status | Status of the last write operation to the AOF | keyword |  |
| redis.info.persistence.loading | Flag indicating if the load of a dump file is on-going | boolean |  |
| redis.info.persistence.rdb.bgsave.current_time.sec | Duration of the on-going RDB save operation if any | long | gauge |
| redis.info.persistence.rdb.bgsave.in_progress | Flag indicating a RDB save is on-going | boolean |  |
| redis.info.persistence.rdb.bgsave.last_status | Status of the last RDB save operation | keyword |  |
| redis.info.persistence.rdb.bgsave.last_time.sec | Duration of the last RDB save operation in seconds | long | gauge |
| redis.info.persistence.rdb.copy_on_write.last_size | The size in bytes of copy-on-write allocations during the last RBD save operation | long | gauge |
| redis.info.persistence.rdb.last_save.changes_since | Number of changes since the last dump | long | gauge |
| redis.info.persistence.rdb.last_save.time | Epoch-based timestamp of last successful RDB save | long | gauge |
| redis.info.replication.backlog.active | Flag indicating replication backlog is active | long |  |
| redis.info.replication.backlog.first_byte_offset | The master offset of the replication backlog buffer | long | gauge |
| redis.info.replication.backlog.histlen | Size in bytes of the data in the replication backlog buffer | long | gauge |
| redis.info.replication.backlog.size | Total size in bytes of the replication backlog buffer | long | gauge |
| redis.info.replication.connected_slaves | Number of connected slaves | long | gauge |
| redis.info.replication.master.last_io_seconds_ago | Number of seconds since the last interaction with master | long | gauge |
| redis.info.replication.master.link_status | Status of the link (up/down) | keyword |  |
| redis.info.replication.master.offset | The server's current replication offset | long | gauge |
| redis.info.replication.master.second_offset | The offset up to which replication IDs are accepted | long | gauge |
| redis.info.replication.master.sync.in_progress | Indicate the master is syncing to the slave | boolean |  |
| redis.info.replication.master.sync.last_io_seconds_ago | Number of seconds since last transfer I/O during a SYNC operation | long | gauge |
| redis.info.replication.master.sync.left_bytes | Number of bytes left before syncing is complete | long | gauge |
| redis.info.replication.master_offset | The server's current replication offset | long | gauge |
| redis.info.replication.role | Role of the instance (can be "master", or "slave"). | keyword |  |
| redis.info.replication.slave.is_readonly | Flag indicating if the slave is read-only | boolean |  |
| redis.info.replication.slave.offset | The replication offset of the slave instance | long | gauge |
| redis.info.replication.slave.priority | The priority of the instance as a candidate for failover | long |  |
| redis.info.server.arch_bits |  | keyword |  |
| redis.info.server.build_id |  | keyword |  |
| redis.info.server.config_file |  | keyword |  |
| redis.info.server.gcc_version |  | keyword |  |
| redis.info.server.git_dirty |  | keyword |  |
| redis.info.server.git_sha1 |  | keyword |  |
| redis.info.server.hz |  | long |  |
| redis.info.server.lru_clock |  | long |  |
| redis.info.server.mode |  | keyword |  |
| redis.info.server.multiplexing_api |  | keyword |  |
| redis.info.server.run_id |  | keyword |  |
| redis.info.server.tcp_port |  | long |  |
| redis.info.server.uptime |  | long | gauge |
| redis.info.slowlog.count | Count of slow operations | long | gauge |
| redis.info.stats.active_defrag.hits | Number of value reallocations performed by active the defragmentation process | long | gauge |
| redis.info.stats.active_defrag.key_hits | Number of keys that were actively defragmented | long | gauge |
| redis.info.stats.active_defrag.key_misses | Number of keys that were skipped by the active defragmentation process | long | gauge |
| redis.info.stats.active_defrag.misses | Number of aborted value reallocations started by the active defragmentation process | long | gauge |
| redis.info.stats.commands_processed | Total number of commands processed. | long | counter |
| redis.info.stats.connections.received | Total number of connections received. | long | counter |
| redis.info.stats.connections.rejected | Total number of connections rejected. | long | counter |
| redis.info.stats.instantaneous.input_kbps | The network's read rate per second in KB/sec | scaled_float | gauge |
| redis.info.stats.instantaneous.ops_per_sec | Number of commands processed per second | long | gauge |
| redis.info.stats.instantaneous.output_kbps | The network's write rate per second in KB/sec | scaled_float | gauge |
| redis.info.stats.keys.evicted | Number of evicted keys due to maxmemory limit | long | gauge |
| redis.info.stats.keys.expired | Total number of key expiration events | long | gauge |
| redis.info.stats.keyspace.hits | Number of successful lookup of keys in the main dictionary | long | gauge |
| redis.info.stats.keyspace.misses | Number of failed lookup of keys in the main dictionary | long | gauge |
| redis.info.stats.latest_fork_usec | Duration of the latest fork operation in microseconds | long | gauge |
| redis.info.stats.migrate_cached_sockets | The number of sockets open for MIGRATE purposes | long | gauge |
| redis.info.stats.net.input.bytes | Total network input in bytes. | long | counter |
| redis.info.stats.net.output.bytes | Total network output in bytes. | long | counter |
| redis.info.stats.pubsub.channels | Global number of pub/sub channels with client subscriptions | long | gauge |
| redis.info.stats.pubsub.patterns | Global number of pub/sub pattern with client subscriptions | long | gauge |
| redis.info.stats.slave_expires_tracked_keys | The number of keys tracked for expiry purposes (applicable only to writable slaves) | long | gauge |
| redis.info.stats.sync.full | The number of full resyncs with slaves | long | gauge |
| redis.info.stats.sync.partial.err | The number of denied partial resync requests | long | gauge |
| redis.info.stats.sync.partial.ok | The number of accepted partial resync requests | long | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### key

The `key` dataset collects information about Redis keys.

For each key matching one of the configured patterns, an event is sent to Elasticsearch with information about this key,
what includes the type, its length when available, and its TTL.

Patterns are configured as a list containing these fields:

* `pattern` (required): pattern for key names, as accepted by the Redis KEYS or SCAN commands.
* `limit` (optional): safeguard when using patterns with wildcards to avoid collecting too many keys (Default: 0, no limit)
* `keyspace` (optional): Identifier of the database to use to look for the keys (Default: 0)

An example event for `key` looks as following:

```json
{
    "@timestamp": "2020-06-25T10:16:10.138Z",
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "redis.key",
        "duration": 374411,
        "module": "redis"
    },
    "metricset": {
        "name": "key",
        "period": 10000
    },
    "redis": {
        "key": {
            "expire": {
                "ttl": 360
            },
            "id": "0:foo",
            "length": 3,
            "name": "foo",
            "type": "string"
        }
    },
    "service": {
        "address": "localhost:6379",
        "type": "redis"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| redis.key.expire.ttl | Seconds to expire. | long | gauge |
| redis.key.id | Unique id for this key (With the form `\<keyspace\>:\<name\>`). | keyword |  |
| redis.key.length | Length of the key (Number of elements for lists, length for strings, cardinality for sets). | long | gauge |
| redis.key.name | Key name. | keyword |  |
| redis.key.type | Key type as shown by `TYPE` command. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### keyspace

The `keyspace` dataset collects information about the Redis keyspaces. For each keyspace, an event is sent to
Elasticsearch. The keyspace information is fetched from the `INFO` command.

An example event for `keyspace` looks as following:

```json
{
    "@timestamp": "2020-06-25T10:16:10.138Z",
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "redis.keyspace",
        "duration": 374411,
        "module": "redis"
    },
    "metricset": {
        "name": "keyspace",
        "period": 10000
    },
    "redis": {
        "keyspace": {
            "avg_ttl": 359459,
            "expires": 0,
            "id": "db0",
            "keys": 1
        }
    },
    "service": {
        "address": "localhost:6379",
        "type": "redis"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| redis.keyspace.avg_ttl | Average ttl. | long | gauge |
| redis.keyspace.expires |  | long |  |
| redis.keyspace.id | Keyspace identifier. | keyword |  |
| redis.keyspace.keys | Number of keys in the keyspace. | long |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
