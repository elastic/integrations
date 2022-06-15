# Memcahed integration
Memcached is an in-memory key-value store for small chunks of arbitrary data (strings, objects) from results of database calls, API calls, or page rendering. 
As a result of its speed, scalability, simple design, efficient memory management and API support for most popular languages; Memcached is a popular choice for high-performance, large-scale caching use cases.


## Metrics
The below metrics are fetched from memcached:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event module | constant_keyword |
| event.kind | Event kind | constant_keyword |
| event.module | Event module | constant_keyword |
| event.type | Event type | constant_keyword |
| memcached.stats.bytes.current | Number of bytes currently used for caching items. | long |
| memcached.stats.bytes.limit | Number of bytes the server is allowed to use for storage. | long |
| memcached.stats.cmd.get | Number of "get" commands received since server startup not counting if they were successful or not. | long |
| memcached.stats.cmd.set | Number of "set" commands serviced since server startup. | long |
| memcached.stats.connections.current | Number of open connections to this Memcached server, should be the same value on all servers during normal operation. | long |
| memcached.stats.connections.total | Numer of successful connection attempts to this server since it has been started. | long |
| memcached.stats.evictions | Number of objects removed from the cache to free up memory for new items when Memcached reaches it's maximum memory setting (limit_maxbytes). | long |
| memcached.stats.get.hits | Cache HitRate: Its the ratio of number of successful "get" commands (cache hits) since startup and the "cmd_get" value. | long |
| memcached.stats.get.misses | Number of failed "get" requests as nothing was cached for this key or the cached value was too old. | long |
| memcached.stats.items.current | Number of items currently in this server's cache. | long |
| memcached.stats.items.total | Number of items ever stored on the server. The count increases by every new item stored in the cache. | long |
| memcached.stats.pid | Current process ID of the Memcached task. | long |
| memcached.stats.read.bytes | Total number of bytes received by the server from the network. | long |
| memcached.stats.threads | Number of threads used by the current Memcached server process. | long |
| memcached.stats.uptime.sec | Memcached server uptime. | long |
| memcached.stats.written.bytes | Total number of bytes sent to the network by the server. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


An example event for `stats` looks as following:

```json
{
    "@timestamp": "2022-06-11T12:05:02.226Z",
    "agent": {
        "ephemeral_id": "38b65793-f402-44c0-8b4f-355eed71af3d",
        "id": "0d8f7a52-a060-474e-8197-c31b96b1abe4",
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
        "id": "0d8f7a52-a060-474e-8197-c31b96b1abe4",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "memcached.stats",
        "duration": 8651834,
        "ingested": "2022-06-11T12:05:03Z",
        "kind": "metric",
        "module": "memcached"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.24.0.7"
        ],
        "mac": [
            "02:42:ac:18:00:07"
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
            "bytes": {
                "current": 0,
                "limit": 67108864
            },
            "cmd": {
                "get": 0,
                "set": 0
            },
            "connections": {
                "current": 2,
                "total": 33
            },
            "evictions": 20,
            "get": {
                "hits": 0,
                "misses": 0
            },
            "items": {
                "current": 0,
                "total": 0
            },
            "pid": 1,
            "read": {
                "bytes": 12
            },
            "threads": 4,
            "uptime": {
                "sec": 33
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
        "address": "tcp://elastic-package-service_memcached_1:11211",
        "type": "memcached"
    }
}
```
