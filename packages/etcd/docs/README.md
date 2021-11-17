# etcd Integration

This integration periodically fetches metrics from [etcd](https://etcd.io/) servers. 

## Compatibility

The etcd `metrics` stream was tested with etcd 3.5.1.

## Metrics

### Metrics

The etcd `metrics` stream collects data from the etcd `metrics` module.

It's highly recommended to replace `127.0.0.1` with your server’s IP address and make sure that this page accessible to only you.

An example event for `server` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "etcd": {
        "api_version": "3",
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
        "dataset": "etcd",
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

