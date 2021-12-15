# etcd Integration

This integration is used to collect metrics from [etcd v2 and v3 servers](https://etcd.io/).
This integration periodically fetches metrics from [etcd monitoring server APIs](https://etcd.io/docs/v3.1/op-guide/monitoring/). 

## Compatibility

The etcd package was tested with etcd 3.5.1.

## Metrics

When using etcd v2, metrics are collected using etcd v2 API. When using v3, metrics are retrieved from the /metrics endpoint.

When using v3, datasets are bundled into `metrics`. When using v2, datasets available are `leader`, `self` and `store`.

### metrics

This is the `metrics` dataset of the etcd package, in charge of retrieving generic metrics from a etcd v3 instance.

An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "etcd": {
        "api_version": "3",
        "disk": {
            "backend_commit_duration": {
                "ns": {
                    "bucket": {
                        "+Inf": 7,
                        "1000000": 5,
                        "1024000000": 7,
                        "128000000": 7,
                        "16000000": 7,
                        "2000000": 7,
                        "2048000000": 7,
                        "256000000": 7,
                        "32000000": 7,
                        "4000000": 7,
                        "4096000000": 7,
                        "512000000": 7,
                        "64000000": 7,
                        "8000000": 7,
                        "8192000000": 7
                    },
                    "count": 7,
                    "sum": 4332557
                }
            },
            "mvcc_db_total_size": {
                "bytes": 41369600
            },
            "wal_fsync_duration": {
                "ns": {
                    "bucket": {
                        "+Inf": 3,
                        "1000000": 0,
                        "1024000000": 3,
                        "128000000": 3,
                        "16000000": 2,
                        "2000000": 0,
                        "2048000000": 3,
                        "256000000": 3,
                        "32000000": 3,
                        "4000000": 0,
                        "4096000000": 3,
                        "512000000": 3,
                        "64000000": 3,
                        "8000000": 2,
                        "8192000000": 3
                    },
                    "count": 3,
                    "sum": 40943916.00000001
                }
            }
        },
        "memory": {
            "go_memstats_alloc": {
                "bytes": 9952840
            }
        },
        "network": {
            "client_grpc_received": {
                "bytes": 0
            },
            "client_grpc_sent": {
                "bytes": 0
            }
        },
        "server": {
            "grpc_handled": {
                "count": 0
            },
            "grpc_started": {
                "count": 0
            },
            "has_leader": 1,
            "leader_changes": {
                "count": 1
            },
            "proposals_committed": {
                "count": 110024
            },
            "proposals_failed": {
                "count": 0
            },
            "proposals_pending": {
                "count": 0
            }
        }
    },
    "event": {
        "dataset": "etcd.metrics",
        "duration": 115000,
        "module": "etcd"
    },
    "metricset": {
        "name": "metrics"
    },
    "service": {
        "address": "127.0.0.1:2379",
        "type": "etcd"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| etcd.api_version | Etcd API version for metrics retrieval | keyword |
| etcd.disk.backend_commit_duration.ns.bucket.\* | Latency for writing backend changes to disk | object |
| etcd.disk.backend_commit_duration.ns.count | Backend commits count | long |
| etcd.disk.backend_commit_duration.ns.sum | Backend commits latency sum | long |
| etcd.disk.mvcc_db_total_size.bytes | Size of stored data at MVCC | long |
| etcd.disk.wal_fsync_duration.ns.bucket.\* | Latency for writing ahead logs to disk | object |
| etcd.disk.wal_fsync_duration.ns.count | Write ahead logs count | long |
| etcd.disk.wal_fsync_duration.ns.sum | Write ahead logs latency sum | long |
| etcd.memory.go_memstats_alloc.bytes | Memory allocated bytes as of MemStats Go | long |
| etcd.network.client_grpc_received.bytes | gRPC received bytes total | long |
| etcd.network.client_grpc_sent.bytes | gRPC sent bytes total | long |
| etcd.server.grpc_handled.count | Number of received gRPC requests | long |
| etcd.server.grpc_started.count | Number of sent gRPC requests | long |
| etcd.server.has_leader | Whether a leader exists in the cluster | byte |
| etcd.server.leader_changes.count | Number of leader changes seen at the cluster | long |
| etcd.server.proposals_committed.count | Number of consensus proposals commited | long |
| etcd.server.proposals_failed.count | Number of consensus proposals failed | long |
| etcd.server.proposals_pending.count | Number of consensus proposals pending | long |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.ip | Host ip addresses. | ip |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### leader

This is the `leader` dataset of the etcd package, in charge of retrieving generic metrics about leader from a etcd v2 instance.

An example event for `leader` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "etcd": {
        "api_version": "2",
        "leader": {
            "followers": {},
            "leader": "8e9e05c52164694d"
        }
    },
    "event": {
        "dataset": "etcd.leader",
        "duration": 115000,
        "module": "etcd"
    },
    "metricset": {
        "name": "leader"
    },
    "service": {
        "address": "127.0.0.1:2379",
        "type": "etcd"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| etcd.api_version | Etcd API version for metrics retrieval | keyword |
| etcd.leader.followers.counts.followers.counts.fail | Failed Raft RPC requests | integer |
| etcd.leader.followers.counts.followers.counts.success | Successful Raft RPC requests | integer |
| etcd.leader.followers.latency.followers.latency.average |  | scaled_float |
| etcd.leader.followers.latency.followers.latency.current |  | scaled_float |
| etcd.leader.followers.latency.followers.latency.maximum |  | scaled_float |
| etcd.leader.followers.latency.followers.latency.minimum |  | integer |
| etcd.leader.followers.latency.followers.latency.standardDeviation |  | scaled_float |
| etcd.leader.leader | ID of actual leader | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.ip | Host ip addresses. | ip |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### self

This is the `self` dataset of the etcd package, in charge of retrieving generic metrics about self from a etcd v2 instance.

An example event for `self` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "etcd": {
        "api_version": "2",
        "self": {
            "id": "8e9e05c52164694d",
            "leaderinfo": {
                "leader": "8e9e05c52164694d",
                "start_time": "2019-03-25T18:00:33.457653099+01:00",
                "uptime": "20.338096195s"
            },
            "name": "default",
            "recv": {
                "append_request": {
                    "count": 0
                },
                "bandwidth_rate": 0,
                "pkg_rate": 0
            },
            "send": {
                "append_request": {
                    "count": 0
                },
                "bandwidth_rate": 0,
                "pkg_rate": 0
            },
            "start_time": "2019-03-25T18:00:32.755273186+01:00",
            "state": "StateLeader"
        }
    },
    "event": {
        "dataset": "etcd.self",
        "duration": 115000,
        "module": "etcd"
    },
    "metricset": {
        "name": "self"
    },
    "service": {
        "address": "127.0.0.1:2379",
        "type": "etcd"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| etcd.api_version | Etcd API version for metrics retrieval | keyword |
| etcd.self.id | The unique identifier for the member | keyword |
| etcd.self.leaderinfo.leader | ID of the current leader member | keyword |
| etcd.self.leaderinfo.start_time | The time when this node was started | keyword |
| etcd.self.leaderinfo.uptime | Amount of time the leader has been leader | keyword |
| etcd.self.name | This member’s name | keyword |
| etcd.self.recv.append_request.count | Number of append requests this node has processed | integer |
| etcd.self.recv.bandwidth_rate | Number of bytes per second this node is receiving (follower only) | scaled_float |
| etcd.self.recv.pkg_rate | Number of requests per second this node is receiving (follower only) | scaled_float |
| etcd.self.send.append_request.count | Number of requests that this node has sent | integer |
| etcd.self.send.bandwidth_rate | Number of bytes per second this node is sending (leader only). This value is undefined on single member clusters. | scaled_float |
| etcd.self.send.pkg_rate | Number of requests per second this node is sending (leader only). This value is undefined on single member clusters. | scaled_float |
| etcd.self.start_time | The time when this node was started | keyword |
| etcd.self.state | Either leader or follower | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.ip | Host ip addresses. | ip |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### store

This is the `store` dataset of the etcd package, in charge of retrieving generic metrics about store from a etcd v2 instance.

An example event for `store` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "etcd": {
        "api_version": "2",
        "store": {
            "compare_and_delete": {
                "fail": 0,
                "success": 0
            },
            "compare_and_swap": {
                "fail": 0,
                "success": 0
            },
            "create": {
                "fail": 0,
                "success": 1
            },
            "delete": {
                "fail": 0,
                "success": 0
            },
            "expire": {
                "count": 0
            },
            "gets": {
                "fail": 4,
                "success": 2
            },
            "sets": {
                "fail": 0,
                "success": 12
            },
            "update": {
                "fail": 0,
                "success": 0
            },
            "watchers": 0
        }
    },
    "event": {
        "dataset": "etcd.store",
        "duration": 115000,
        "module": "etcd"
    },
    "metricset": {
        "name": "store"
    },
    "service": {
        "address": "127.0.0.1:2379",
        "type": "etcd"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| etcd.api_version | Etcd API version for metrics retrieval | keyword |
| etcd.store.compare_and_delete.fail |  | integer |
| etcd.store.compare_and_delete.success |  | integer |
| etcd.store.compare_and_swap.fail |  | integer |
| etcd.store.compare_and_swap.success |  | integer |
| etcd.store.create.fail |  | integer |
| etcd.store.create.success |  | integer |
| etcd.store.delete.fail |  | integer |
| etcd.store.delete.success |  | integer |
| etcd.store.expire.count |  | integer |
| etcd.store.gets.fail |  | integer |
| etcd.store.gets.success |  | integer |
| etcd.store.sets.fail |  | integer |
| etcd.store.sets.success |  | integer |
| etcd.store.update.fail |  | integer |
| etcd.store.update.success |  | integer |
| etcd.store.watchers |  | integer |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.ip | Host ip addresses. | ip |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
