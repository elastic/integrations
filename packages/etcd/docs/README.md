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
    "agent": {
        "name": "380a29000462",
        "id": "6ab520e2-97a1-4ffd-83c4-4b141cb153fa",
        "ephemeral_id": "137bf29d-a4b8-4f3e-abf5-89164e923ba8",
        "type": "metricbeat",
        "version": "8.12.0"
    },
    "@timestamp": "2023-11-08T21:09:29.748Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "etcd.metrics"
    },
    "service": {
        "address": "http://etcd:2379/metrics",
        "type": "prometheus"
    },
    "elastic_agent": {
        "id": "6ab520e2-97a1-4ffd-83c4-4b141cb153fa",
        "version": "8.12.0",
        "snapshot": true
    },
    "host": {
        "hostname": "380a29000462",
        "os": {
            "kernel": "5.10.102.1-microsoft-standard-WSL2",
            "codename": "focal",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "20.04.6 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "ip": [
            "172.25.0.4"
        ],
        "containerized": true,
        "name": "380a29000462",
        "mac": [
            "02-42-AC-19-00-04"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 10000,
        "name": "collector"
    },
    "prometheus": {
        "grpc_server_started_total": {}
    },
    "event": {
        "duration": 19492282,
        "agent_id_status": "verified",
        "ingested": "2023-11-08T21:09:29Z",
        "module": "etcd",
        "dataset": "etcd.metrics"
    },
    "etcd": {
        "server": {
            "grpc_started": {
                "count": 14
            }
        },
        "labels": {
            "grpc_method": "Snapshot",
            "grpc_type": "server_stream",
            "instance": "etcd:2379",
            "grpc_service": "etcdserverpb.Maintenance",
            "fingerprint": "TkIF3QTQ+iB4SVuYV1fMrGCLYcg=",
            "job": "prometheus"
        }
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| etcd.disk.backend_commit_duration_seconds.histogram | Latency for writing backend changes to disk | histogram |  |
| etcd.disk.mvcc_db_total_size.bytes | Size of stored data at MVCC | long | gauge |
| etcd.disk.wal_fsync_duration_seconds.histogram | Latency for writing ahead logs to disk | histogram |  |
| etcd.labels.\* | etcd labels. | keyword |  |
| etcd.labels.fingerprint | Unique fingerprint of the etcd labels. | keyword |  |
| etcd.memory.go_memstats_alloc.bytes | Memory allocated bytes as of MemStats Go | long | gauge |
| etcd.memory.go_memstats_alloc.total.bytes | Memory allocated bytes as of MemStats Go | long | counter |
| etcd.network.client_grpc_received.bytes | gRPC received bytes total | long | counter |
| etcd.network.client_grpc_sent.bytes | gRPC sent bytes total | long | counter |
| etcd.server.grpc_handled.count | Number of received gRPC requests | long | counter |
| etcd.server.grpc_started.count | Number of sent gRPC requests | long | counter |
| etcd.server.has_leader.count | Whether a leader exists in the cluster | long | gauge |
| etcd.server.leader_changes.count | Number of leader changes seen at the cluster | long | counter |
| etcd.server.proposals_committed.count | Number of consensus proposals commited | long | gauge |
| etcd.server.proposals_failed.count | Number of consensus proposals failed | long | counter |
| etcd.server.proposals_pending.count | Number of consensus proposals pending | long | gauge |
| event.dataset | Event dataset | constant_keyword |  |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


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
