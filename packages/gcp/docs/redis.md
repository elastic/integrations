# Redis

## Metrics

The `redis` dataset fetches metrics from [Redis](https://cloud.google.com/memorystore/) in Google Cloud Platform. It contains all metrics exported from the [GCP Redis Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-redis).

## Sample Event
    
An example event for `redis` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev",
            "name": "elastic-obs-integrations-dev"
        },
        "instance": {
            "id": "4751091017865185079",
            "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
        },
        "machine": {
            "type": "e2-medium"
        },
        "provider": "gcp",
        "availability_zone": "us-central1-c",
        "region": "us-central1"
    },
    "event": {
        "dataset": "gcp.redis",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "redis": {
            "clients": {
                "blocked": 1
            }
        },
        "labels": {
            "user": {
                "goog-gke-node": ""
            }
        }
    },
    "host": {
        "id": "4751091017865185079",
        "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
    },
    "metricset": {
        "name": "redis",
        "period": 10000
    },
    "service": {
        "type": "gcp"
    }
}
```

## Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |
| error.message | Error message. | match_only_text |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gcp.labels.metadata.\* |  | object |
| gcp.labels.metrics.\* |  | object |
| gcp.labels.resource.\* |  | object |
| gcp.labels.system.\* |  | object |
| gcp.labels.user.\* |  | object |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |
| gcp.redis.clients.blocked | Number of blocked clients. | long |
| gcp.redis.clients.connected | Number of client connections. | long |
| gcp.redis.commands.calls | Total number of calls for this command in one minute. | long |
| gcp.redis.commands.total_time | The amount of time in microseconds that this command took in the last second. | long |
| gcp.redis.commands.usec_per_call | Average time per call over 1 minute by command. | double |
| gcp.redis.keyspace.avg_ttl | Average TTL for keys in this database. | double |
| gcp.redis.keyspace.keys | Number of keys stored in this database. | long |
| gcp.redis.keyspace.keys_with_expiration | Number of keys with an expiration in this database. | long |
| gcp.redis.persistence.rdb.bgsave_in_progress | Flag indicating a RDB save is on-going. | boolean |
| gcp.redis.replication.master.slaves.lag | The number of seconds that replica is lagging behind primary. | long |
| gcp.redis.replication.master.slaves.offset | The number of bytes that have been acknowledged by replicas. | long |
| gcp.redis.replication.master_repl_offset | The number of bytes that master has produced and sent to replicas. | long |
| gcp.redis.replication.offset_diff | The largest number of bytes that have not been replicated across all replicas. This is the biggest difference between replication byte offset (master) and replication byte offset (replica) of all replicas. | byte |
| gcp.redis.replication.role | Returns a value indicating the node role. 1 indicates primary and 0 indicates replica. | long |
| gcp.redis.server.uptime | Uptime in seconds. | long |
| gcp.redis.stats.cache_hit_ratio | Cache Hit ratio as a fraction. | double |
| gcp.redis.stats.connections.total | Total number of connections accepted by the server. | long |
| gcp.redis.stats.cpu_utilization | CPU-seconds consumed by the Redis server, broken down by system/user space and parent/child relationship. | double |
| gcp.redis.stats.evicted_keys | Number of evicted keys due to maxmemory limit. | long |
| gcp.redis.stats.expired_keys | Total number of key expiration events. | long |
| gcp.redis.stats.keyspace_hits | Number of successful lookup of keys in the main dictionary. | long |
| gcp.redis.stats.keyspace_misses | Number of failed lookup of keys in the main dictionary. | long |
| gcp.redis.stats.memory.maxmemory | Maximum amount of memory Redis can consume. | long |
| gcp.redis.stats.memory.system_memory_overload_duration | The amount of time in microseconds the instance is in system memory overload mode. | long |
| gcp.redis.stats.memory.system_memory_usage_ratio | Memory usage as a ratio of maximum system memory. | double |
| gcp.redis.stats.memory.usage | Total number of bytes allocated by Redis. | byte |
| gcp.redis.stats.memory.usage_ratio | Memory usage as a ratio of maximum memory. | double |
| gcp.redis.stats.network_traffic | Total number of bytes sent to/from redis (includes bytes from commands themselves, payload data, and delimiters). | byte |
| gcp.redis.stats.pubsub.channels | Global number of pub/sub channels with client subscriptions. | long |
| gcp.redis.stats.pubsub.patterns | Global number of pub/sub pattern with client subscriptions. | long |
| gcp.redis.stats.reject_connections_count | Number of connections rejected because of maxclients limit. | long |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
