# Redis Enterprise

Redis Enterprise integration provides monitoring of [redis](https://redis.com/) cluster. Monitoring is done via prometheus exported port of redis enterprise cluster. Once a redis enterprise [cluster](https://redis.com/redis-enterprise/technology/redis-enterprise-cluster-architecture/) is installed, prometheus port is available for monitoring. The url of the host:port(8070) needs to be passed to the hosts in the settings.

Redis Enterpise integration is tested with redislabs/redis:5.2.2-24 version.

# Metrics

## Node Metrics

Captures all the node specific exported metrics, matching pattern **"node_*"** 

An example event for `node` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "24604ad6-3068-42da-8377-93b8c074e3c5",
        "ephemeral_id": "dfaeed76-a109-4737-a7d5-a2a60b4d7e45",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "24604ad6-3068-42da-8377-93b8c074e3c5",
        "version": "8.1.0",
        "snapshot": false
    },
    "@timestamp": "2022-07-06T03:51:58.326Z",
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
        "dataset": "redisenterprise.node"
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
            "172.27.0.4"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02:42:ac:1b:00:04"
        ],
        "architecture": "x86_64"
    },
    "redisenterprise": {
        "node": {
            "metrics": {
                "provisional_memory": 0,
                "cpu_nice_median": 0,
                "cpu_system_min": 0.1,
                "cpu_irqs_max": 0.003,
                "persistent_storage_free": 188243338446620.44,
                "cpu_user_min": 0.372,
                "egress_bytes_median": 9010.444,
                "cpu_user_median": 0.407,
                "cpu_iowait_median": 0.012,
                "ephemeral_storage_free": 81585035491.556,
                "cpu_steal_median": 0,
                "egress_bytes_min": 9005.889,
                "cpu_idle_min": 0.439,
                "cpu_irqs_median": 0.003,
                "ingress_bytes_min": 375.444,
                "provisional_memory_no_overbooking": 0,
                "conns": 1,
                "cpu_iowait_max": 0.013,
                "cpu_steal_min": 0,
                "cpu_steal": 0,
                "cpu_iowait": 0.009666666666666667,
                "cpu_irqs": 0.0026666666666666666,
                "egress_bytes_max": 9010.556,
                "cpu_user": 0.4033333333333333,
                "free_memory": 2654072832,
                "ingress_bytes_max": 570.556,
                "available_memory_no_overbooking": 2561415223.333,
                "ingress_bytes_median": 375.444,
                "cpu_idle": 0.4716666666666667,
                "cpu_nice_max": 0,
                "cpu_system": 0.10200000000000002,
                "cpu_idle_median": 0.467,
                "cpu_iowait_min": 0.004,
                "cpu_nice_min": 0,
                "cur_aof_rewrites": 0,
                "cpu_system_max": 0.105,
                "persistent_storage_avail": 188243338446620.44,
                "cpu_nice": 0,
                "cpu_steal_max": 0,
                "cpu_irqs_min": 0.002,
                "cpu_idle_max": 0.509,
                "available_memory": 2561371532.667,
                "ingress_bytes": 440.48133333333334,
                "ephemeral_storage_avail": 70830897379.556,
                "egress_bytes": 9008.963,
                "cpu_user_max": 0.431,
                "cpu_system_median": 0.101,
                "total_req": 0
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
        "duration": 131953542,
        "agent_id_status": "verified",
        "ingested": "2022-07-06T03:51:58Z",
        "module": "prometheus",
        "dataset": "redisenterprise.node"
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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| redisenterprise.node.labels.\* | Label fields | object |
| redisenterprise.node.metrics.\* | Node prometheus metrics | float |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


## Proxy Metrics

Captures all the proxy specific exported metrics, matching pattern **"listener_*"**

An example event for `proxy` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "24604ad6-3068-42da-8377-93b8c074e3c5",
        "ephemeral_id": "dfaeed76-a109-4737-a7d5-a2a60b4d7e45",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "24604ad6-3068-42da-8377-93b8c074e3c5",
        "version": "8.1.0",
        "snapshot": false
    },
    "@timestamp": "2022-07-06T03:53:58.638Z",
    "ecs": {
        "version": "8.2.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "redisenterprise.proxy"
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
            "type": "linux",
            "family": "debian",
            "version": "20.04.3 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.27.0.4"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02:42:ac:1b:00:04"
        ],
        "architecture": "x86_64"
    },
    "redisenterprise": {
        "proxy": {
            "metrics": {
                "listener_egress_bytes": 0,
                "listener_last_req_time": 1657079277,
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
                "listener_write_started_res": 0,
                "listener_total_res_max": 0,
                "listener_write_started_res_max": 0,
                "listener_write_req": 0,
                "listener_write_res": 0,
                "listener_cmd_flush": 0,
                "listener_cmd_touch": 0,
                "listener_cmd_flush_max": 0,
                "listener_auth_errors_max": 0,
                "listener_last_res_time": 1657079277,
                "listener_acc_read_latency_max": 0,
                "listener_acc_write_latency_max": 0,
                "listener_total_connections_received": 0,
                "listener_conns": 1,
                "listener_total_req_max": 0,
                "listener_acc_write_latency": 0,
                "listener_acc_other_latency_max": 0,
                "listener_read_res_max": 0,
                "listener_acc_read_latency": 0,
                "listener_monitor_sessions_count": 0,
                "listener_cmd_set": 0,
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
                "proxy": "1:1:1",
                "bdb": "1",
                "cluster": "run1.local",
                "node": "1",
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
        "duration": 192104250,
        "agent_id_status": "verified",
        "ingested": "2022-07-06T03:53:59Z",
        "module": "prometheus",
        "dataset": "redisenterprise.proxy"
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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| redisenterprise.proxy.labels.\* | Label fields | object |
| redisenterprise.proxy.metrics.listener_\* | Proxy prometheus metrics | float |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |

