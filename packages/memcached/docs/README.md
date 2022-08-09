# Memcahed integration
Memcached is an in-memory key-value store for small chunks of arbitrary data (strings, objects) from results of database calls, API calls, or page rendering. 
As a result of its speed, scalability, simple design, efficient memory management and API support for most popular languages; Memcached is a popular choice for high-performance, large-scale caching use cases.
# Compatibility
 The Memcached Integration has been tested with 1.5 and 1.6 versions of Memcached. It is expected to work with all versions >= 1.5
## Metrics
The below metrics are fetched from memcached:

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| event.dataset | Event module | constant_keyword |  |  |
| event.kind | Event kind | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| event.type | Event type | constant_keyword |  |  |
| memcached.stats.cmd.get | Number of "get" commands received since server startup not counting if they were successful or not. | long |  | counter |
| memcached.stats.cmd.set | Number of "set" commands serviced since server startup. | long |  | counter |
| memcached.stats.connections.current | Number of open connections to this Memcached server, should be the same value on all servers during normal operation. | long |  | counter |
| memcached.stats.connections.total | Numer of successful connection attempts to this server since it has been started. | long |  | counter |
| memcached.stats.current.bytes | Number of bytes currently used for caching items. | long | byte | gauge |
| memcached.stats.evictions | Number of objects removed from the cache to free up memory for new items when Memcached reaches it's maximum memory setting (limit_maxbytes). | long |  | counter |
| memcached.stats.get.hits | Cache HitRate: Its the ratio of number of successful "get" commands (cache hits) since startup and the "cmd_get" value. | long |  | gauge |
| memcached.stats.get.misses | Number of failed "get" requests as nothing was cached for this key or the cached value was too old. | long |  | counter |
| memcached.stats.items.current | Number of items currently in this server's cache. | long |  | gauge |
| memcached.stats.items.total | Number of items ever stored on the server. The count increases by every new item stored in the cache. | long |  | counter |
| memcached.stats.limit.bytes | Number of bytes the server is allowed to use for storage. | long | byte | gauge |
| memcached.stats.pid | Current process ID of the Memcached task. | long |  |  |
| memcached.stats.read.bytes | Total number of bytes received by the server from the network. | long | byte | counter |
| memcached.stats.threads | Number of threads used by the current Memcached server process. | long |  | counter |
| memcached.stats.uptime.sec | Memcached server uptime. | long | s | gauge |
| memcached.stats.written.bytes | Total number of bytes sent to the network by the server. | long | byte | counter |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |


An example event for `stats` looks as following:

```json
{
    "@timestamp": "2022-06-24T06:06:06.337Z",
    "agent": {
        "ephemeral_id": "5c05824c-146b-464f-9030-b1e1eccc7c36",
        "id": "a6434521-6e0b-4509-be07-c1591bcfe768",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "memcached.stats",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "a6434521-6e0b-4509-be07-c1591bcfe768",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "memcached.stats",
        "duration": 9903333,
        "ingested": "2022-06-24T06:06:09Z",
        "kind": "metric",
        "module": "memcached"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.112.7"
        ],
        "mac": [
            "02:42:c0:a8:70:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "memcached": {
        "stats": {
            "bytes": {},
            "cmd": {
                "get": 0,
                "set": 0
            },
            "connections": {
                "current": 2,
                "total": 24
            },
            "current": {
                "bytes": 0
            },
            "evictions": 0,
            "get": {
                "hits": 0,
                "misses": 0
            },
            "items": {
                "current": 0,
                "total": 0
            },
            "limit": {
                "bytes": 67108864
            },
            "pid": 1,
            "read": {
                "bytes": 12
            },
            "threads": 4,
            "uptime": {
                "sec": 28
            },
            "written": {
                "bytes": 2206
            }
        }
    },
    "metricset": {
        "name": "stats",
        "period": 10000
    },
    "service": {
        "address": "tcp://elastic-package-service-memcached-1:11211",
        "type": "memcached"
    },
    "tags": [
        "memcached_stats"
    ]
}
```
