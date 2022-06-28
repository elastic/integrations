# Redis Enterprise

Redis Enterprise integration provides monitoring of [redis](https://redis.com/) cluster. Monitoring is done via prometheus exported port of redis enterprise cluster. Once a redis enterprise [cluster](https://redis.com/redis-enterprise/technology/redis-enterprise-cluster-architecture/) is installed, corresponding prometheus port(8070) is available for monitoring, which needs to be passed to the hosts.

# Metrics

## Node Metrics

Captures all the node specific exported metrics, matching pattern **"node_*"** 

An example event for `node` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "568be3db-2d32-48aa-90e0-7cb44847f801",
        "ephemeral_id": "2581e222-62e9-4621-b2fe-4b1ece7ea497",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "568be3db-2d32-48aa-90e0-7cb44847f801",
        "version": "8.1.0",
        "snapshot": false
    },
    "@timestamp": "2022-06-28T07:43:07.624Z",
    "ecs": {
        "version": "8.2.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "redisenterprise.node"
    },
    "service": {
        "address": "https://host.docker.internal:8070/metrics",
        "type": "prometheus"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "family": "debian",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.21.0.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02:42:ac:15:00:07"
        ],
        "architecture": "x86_64"
    },
    "redisenterprise": {
        "node": {
            "metrics": {
                "node_cpu_idle": 0.5973333333333333,
                "node_ingress_bytes_max": 166.222,
                "node_conns": 0,
                "node_cpu_nice_median": 0,
                "node_persistent_storage_free": 190999141693667.56,
                "node_cpu_irqs_min": 0.002,
                "node_available_memory": 8786428546,
                "node_egress_bytes_max": 8322.556,
                "node_egress_bytes": 8319.259333333333,
                "node_ingress_bytes_median": 166.222,
                "node_cpu_steal_min": 0,
                "node_ephemeral_storage_free": 96407604792.889,
                "node_cpu_idle_max": 0.604,
                "node_cpu_user_min": 0.303,
                "node_cpu_nice": 0,
                "node_free_memory": 8887082097.778,
                "node_egress_bytes_median": 8322,
                "node_cpu_system_median": 0.077,
                "node_cpu_system_min": 0.072,
                "node_cpu_idle_median": 0.599,
                "node_persistent_storage_avail": 190999141693667.56,
                "node_cpu_user_median": 0.311,
                "node_cpu_idle_min": 0.589,
                "node_cpu_system_max": 0.084,
                "node_cpu_nice_min": 0,
                "node_cpu_system": 0.07766666666666666,
                "node_provisional_memory_no_overbooking": 5231211866.778,
                "node_cpu_iowait_min": 0.002,
                "node_cpu_irqs_median": 0.002,
                "node_cpu_iowait": 0.0026666666666666666,
                "node_available_memory_no_overbooking": 8789974771.778,
                "node_cpu_steal": 0,
                "node_ingress_bytes": 166.222,
                "node_cur_aof_rewrites": 0,
                "node_cpu_user_max": 0.312,
                "node_cpu_user": 0.30866666666666664,
                "node_cpu_nice_max": 0,
                "node_cpu_iowait_max": 0.003,
                "node_cpu_irqs": 0.0023333333333333335,
                "node_cpu_iowait_median": 0.003,
                "node_cpu_steal_max": 0,
                "node_cpu_irqs_max": 0.003,
                "node_cpu_steal_median": 0,
                "node_ingress_bytes_min": 166.222,
                "node_ephemeral_storage_avail": 85653466680.889,
                "node_provisional_memory": 5227665641,
                "node_egress_bytes_min": 8313.222,
                "node_total_req": 0
            },
            "labels": {
                "cluster": "run1.local",
                "node": "1",
                "instance": "host.docker.internal:8070",
                "job": "prometheus"
            }
        }
    },
    "metricset": {
        "period": 10000,
        "name": "collector"
    },
    "event": {
        "duration": 171118333,
        "agent_id_status": "verified",
        "ingested": "2022-06-28T07:43:08Z",
        "module": "prometheus",
        "dataset": "redisenterprise.node"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| redisenterprise.node.metrics.node_\* | Node prometheus metrics | float | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


## Proxy Metrics

Captures all the proxy specific exported metrics, matching pattern **"listener_*"**

An example event for `proxy` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "568be3db-2d32-48aa-90e0-7cb44847f801",
        "ephemeral_id": "2581e222-62e9-4621-b2fe-4b1ece7ea497",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "568be3db-2d32-48aa-90e0-7cb44847f801",
        "version": "8.1.0",
        "snapshot": false
    },
    "@timestamp": "2022-06-28T07:40:37.851Z",
    "ecs": {
        "version": "8.2.0"
    },
    "service": {
        "address": "https://host.docker.internal:8070/metrics",
        "type": "prometheus"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "redisenterprise.proxy"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "20.04.3 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.21.0.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02:42:ac:15:00:07"
        ],
        "architecture": "x86_64"
    },
    "redisenterprise": {
        "proxy": {
            "metrics": {
                "listener_egress_bytes": 0,
                "listener_last_req_time": 0,
                "listener_other_res": 0,
                "listener_ingress_bytes_max": 0,
                "listener_total_connections_received_max": 0,
                "listener_other_req": 0,
                "listener_other_res_max": 0,
                "listener_write_req_max": 0,
                "listener_cmd_touch_max": 0,
                "listener_egress_bytes_max": 0,
                "listener_auth_cmds_max": 0,
                "listener_read_res": 0,
                "listener_read_req": 0,
                "listener_total_res": 0,
                "listener_max_connections_exceeded_max": 0,
                "listener_total_req": 0,
                "listener_read_started_res_max": 0,
                "listener_acc_other_latency": 0,
                "listener_cmd_get_max": 0,
                "listener_acc_latency": 0,
                "listener_read_req_max": 0,
                "listener_write_res_max": 0,
                "listener_total_started_res_max": 0,
                "listener_write_started_res_max": 0,
                "listener_write_req": 0,
                "listener_write_started_res": 0,
                "listener_total_res_max": 0,
                "listener_cmd_flush": 0,
                "listener_write_res": 0,
                "listener_cmd_touch": 0,
                "listener_cmd_flush_max": 0,
                "listener_auth_errors_max": 0,
                "listener_last_res_time": 0,
                "listener_acc_read_latency_max": 0,
                "listener_acc_write_latency_max": 0,
                "listener_total_connections_received": 0,
                "listener_conns": 0,
                "listener_total_req_max": 0,
                "listener_acc_write_latency": 0,
                "listener_acc_other_latency_max": 0,
                "listener_read_res_max": 0,
                "listener_cmd_set": 0,
                "listener_acc_read_latency": 0,
                "listener_monitor_sessions_count": 0,
                "listener_other_started_res_max": 0,
                "listener_max_connections_exceeded": 0,
                "listener_ingress_bytes": 0,
                "listener_other_started_res": 0,
                "listener_auth_cmds": 0,
                "listener_read_started_res": 0,
                "listener_cmd_get": 0,
                "listener_other_req_max": 0,
                "listener_total_started_res": 0,
                "listener_auth_errors": 0,
                "listener_cmd_set_max": 0,
                "listener_acc_latency_max": 0
            },
            "labels": {
                "bdb": "1",
                "cluster": "run1.local",
                "node": "1",
                "proxy": "1:1:1",
                "instance": "host.docker.internal:8070",
                "listener": "1:1",
                "job": "prometheus"
            }
        }
    },
    "metricset": {
        "period": 10000,
        "name": "collector"
    },
    "event": {
        "duration": 182527333,
        "agent_id_status": "verified",
        "ingested": "2022-06-28T07:40:38Z",
        "module": "prometheus",
        "dataset": "redisenterprise.proxy"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| redisenterprise.proxy.metrics.listener_\* | Proxy prometheus metrics | float | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |

