# etcd Integration

This integration is used to collect metrics from [etcd v2 and v3 instances](https://etcd.io/).

It periodically fetches metrics from [etcd metrics APIs](https://etcd.io/docs/v3.1/op-guide/monitoring/). 

## Compatibility

The etcd package was tested with etcd `3.5.x`.

## Metrics

For etcd v2, metrics are collected through the etcd v2 APIs, whereas for v3, they are fetched from the `/metrics` endpoint.

When using v3, datasets are bundled within `metrics` data stream, while for v2, available datasets include `leader`, `self`, and `store`.

The ETCD v2 APIs are not enabled by default. However, you can enable ETCD v2 APIs when using ETCD v3 and above by utilizing the --enable-v2 flag, provided it is supported.


### metrics

This is the `metrics` dataset of the etcd package, in charge of retrieving generic metrics from a etcd v3 instance.

An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2023-11-30T11:12:42.472Z",
    "agent": {
        "ephemeral_id": "422daded-456e-40fe-bd1f-a2913d37b309",
        "id": "a4b14fa0-9721-4a94-8b4b-bebf87bd1ba4",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "etcd.metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "a4b14fa0-9721-4a94-8b4b-bebf87bd1ba4",
        "snapshot": true,
        "version": "8.12.0"
    },
    "etcd": {
        "labels": {
            "fingerprint": "oB5wpx/JWEU93sgnFX12WX4GmEk=",
            "grpc_code": "Aborted",
            "grpc_method": "Authenticate",
            "grpc_service": "etcdserverpb.Auth",
            "grpc_type": "unary",
            "instance": "elastic-package-service-etcd-1:2379",
            "job": "prometheus"
        },
        "server": {
            "grpc_handled": {
                "count": 0
            }
        }
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "etcd.metrics",
        "duration": 15662716,
        "ingested": "2023-11-30T11:12:52Z",
        "module": "etcd"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "d03b51e638e64b05b5cf16c41d2058c0",
        "ip": [
            "172.18.0.7"
        ],
        "mac": [
            "02-42-AC-12-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.102.1-microsoft-standard-WSL2",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service-etcd-1:2379/metrics",
        "type": "prometheus"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| etcd.disk.backend_commit_duration_seconds.histogram | Latency for writing backend changes to disk | histogram |  |  |
| etcd.disk.mvcc_db_total_size.bytes | Size of stored data at MVCC | long | byte | gauge |
| etcd.disk.wal_fsync_duration_seconds.histogram | Latency for writing ahead logs to disk | histogram |  |  |
| etcd.labels.\* | etcd labels. | keyword |  |  |
| etcd.labels.fingerprint | Unique fingerprint of the etcd labels. | keyword |  |  |
| etcd.memory.go_memstats_alloc.bytes | Current allocated bytes as of MemStats Go | long | byte | gauge |
| etcd.memory.go_memstats_alloc.total.bytes | Total allocated bytes, including released memory as of MemStats Go | long | byte | counter |
| etcd.network.client_grpc_received.bytes | gRPC received bytes total | long | byte | counter |
| etcd.network.client_grpc_sent.bytes | gRPC sent bytes total | long | byte | counter |
| etcd.network.peer_received_bytes_total | The total number of bytes received from peers. | long | byte | counter |
| etcd.network.peer_received_failures_total | The total number of receive failures from peers. | long |  | counter |
| etcd.network.peer_round_trip_time_seconds.histogram | Round-Trip-Time histogram between peers. | histogram |  |  |
| etcd.network.peer_sent_bytes_total | The total number of bytes sent to peers. | long | byte | counter |
| etcd.network.peer_sent_failures_total | The total number of send failures from peers. | long |  | counter |
| etcd.process_start_time.sec | Start time of the process since unix epoch in seconds. | long | s | gauge |
| etcd.server.grpc_handled.count | Number of received gRPC requests | long |  | counter |
| etcd.server.grpc_started.count | Number of sent gRPC requests | long |  | counter |
| etcd.server.has_leader.count | Whether a leader exists in the cluster | long |  | gauge |
| etcd.server.leader_changes.count | Number of leader changes seen at the cluster | long |  | counter |
| etcd.server.proposals_applied_total | The total number of consensus proposals applied. | long |  | gauge |
| etcd.server.proposals_committed.count | Number of consensus proposals commited | long |  | gauge |
| etcd.server.proposals_failed.count | Number of consensus proposals failed | long |  | counter |
| etcd.server.proposals_pending.count | Number of consensus proposals pending | long |  | gauge |
| etcd.store.expires_total | Total number of expired keys. | long |  | counter |
| etcd.store.reads_total | Total number of reads action by (get/getRecursive), local to this member. | long |  | counter |
| etcd.store.watchers | Count of currently active watchers. | long |  | gauge |
| etcd.store.writes_total | Total number of writes (e.g. set/compareAndDelete) seen by this member. | long |  | counter |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |  |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


### leader

This is the `leader` dataset of the etcd package, in charge of retrieving generic metrics about leader from a etcd v2 instance.

An example event for `leader` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "etcd": {
        "leader": {
            "follower": {
                "leader": "91bc3c398fb3c146",
                "latency": {
                    "ms": 0.001169
                },
                "failed_operations": 0,
                "id": "8211f1d0f64f3269",
                "success_operations": 5
            }
        },
        "api_version": "2"
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
| etcd.leader.follower.failed_operations | failed Raft RPC requests | long |
| etcd.leader.follower.id | ID of follower | keyword |
| etcd.leader.follower.latency.ms |  | scaled_float |
| etcd.leader.follower.leader | ID of actual leader | keyword |
| etcd.leader.follower.success_operations | successful Raft RPC requests | long |
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
