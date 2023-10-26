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
        "id": "7e41e302-9e9a-4531-979f-f3930596fdff",
        "ephemeral_id": "a8f693e3-7571-4e2c-b3fb-3b480f693da7",
        "type": "metricbeat",
        "version": "8.9.0"
    },
    "elastic_agent": {
        "id": "7e41e302-9e9a-4531-979f-f3930596fdff",
        "version": "8.9.0",
        "snapshot": false
    },
    "@timestamp": "22023-10-18T06:38:28.857Z",
    "ecs": {
        "version": "8.5.1"
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
            "version": "20.04.4 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "ip": [
            "172.28.0.7"
        ],
        "containerized": false,
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-1C-00-07"
        ],
        "architecture": "aarch64"
    },
    "redisenterprise": {
        "node": {
            "metrics": {
                "provisional_memory": {
                    "value": 0
                },
                "cpu_nice_median": {
                    "value": 0
                },
                "bigstore_kv_ops": {
                    "value": 0
                },
                "cpu_irqs_max": {
                    "value": 0.003
                },
                "overbooking_depth": {
                    "value": -787923186
                },
                "cpu_iowait_median": {
                    "value": 0.002
                },
                "ephemeral_storage_free": {
                    "value": 52956240554.667
                },
                "cpu_idle_min": {
                    "value": 0.732
                },
                "cpu_irqs_median": {
                    "value": 0.003
                },
                "provisional_memory_no_overbooking": {
                    "value": 0
                },
                "cpu_iowait_max": {
                    "value": 0.003
                },
                "cpu_steal": {
                    "value": 0
                },
                "cpu_iowait": {
                    "value": 0.002
                },
                "cpu_irqs": {
                    "value": 0.0030000000000000005
                },
                "egress_bytes_max": {
                    "value": 723.111
                },
                "ingress_bytes_max": {
                    "value": 388
                },
                "available_memory_no_overbooking": {
                    "value": 708776494.444
                },
                "ingress_bytes_median": {
                    "value": 230.444
                },
                "provisional_flash": {
                    "value": 40303892254.444
                },
                "cpu_nice_max": {
                    "value": 0
                },
                "cpu_idle_median": {
                    "value": 0.734
                },
                "cpu_iowait_min": {
                    "value": 0.001
                },
                "cpu_nice_min": {
                    "value": 0
                },
                "cur_aof_rewrites": {
                    "value": 0
                },
                "cpu_system_max": {
                    "value": 0.041
                },
                "persistent_storage_avail": {
                    "value": 49739524778.667
                },
                "cpu_irqs_min": {
                    "value": 0.003
                },
                "cpu_idle_max": {
                    "value": 0.75
                },
                "ephemeral_storage_avail": {
                    "value": 49739524778.667
                },
                "egress_bytes": {
                    "value": 371.48133333333334
                },
                "cpu_system_median": {
                    "value": 0.04
                },
                "total_req": {
                    "value": 0
                },
                "cpu_system_min": {
                    "value": 0.039
                },
                "persistent_storage_free": {
                    "value": 52956240554.667
                },
                "cpu_user_min": {
                    "value": 0.191
                },
                "egress_bytes_median": {
                    "value": 211.333
                },
                "cpu_user_median": {
                    "value": 0.194
                },
                "cpu_steal_median": {
                    "value": 0
                },
                "egress_bytes_min": {
                    "value": 180
                },
                "available_flash": {
                    "value": 52849017014.444
                },
                "ingress_bytes_min": {
                    "value": 184.444
                },
                "conns": {
                    "value": 0
                },
                "cpu_steal_min": {
                    "value": 0
                },
                "cpu_user": {
                    "value": 0.19699999999999998
                },
                "available_flash_no_overbooking": {
                    "value": 52849017014.444
                },
                "free_memory": {
                    "value": 809787392
                },
                "cpu_idle": {
                    "value": 0.7386666666666667
                },
                "cpu_system": {
                    "value": 0.04
                },
                "provisional_flash_no_overbooking": {
                    "value": 40303892254.444
                },
                "cpu_steal_max": {
                    "value": 0
                },
                "cpu_nice": {
                    "value": 0
                },
                "available_memory": {
                    "value": 709455065.111
                },
                "ingress_bytes": {
                    "value": 267.6293333333333
                },
                "bigstore_free": {
                    "value": 52956186396.444
                },
                "cpu_user_max": {
                    "value": 0.206
                }
            },
            "labels": {
                "cluster": "cluster.local",
                "node": "1",
                "instance": "host.docker.internal:8070",
                "job": "prometheus",
                "addr": "172.17.0.2",
                "cnm_version": "7.2.4-64"
            }
        }
    },
    "metricset": {
        "period": 10000,
        "name": "collector"
    },
    "event": {
        "duration": 618983084,
        "agent_id_status": "verified",
        "ingested": "2023-10-18T06:38:30Z",
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
| redisenterprise.node.metrics.node_\* | Node prometheus metrics | object |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


## Proxy Metrics

Captures all the proxy specific exported metrics, matching pattern **"listener_*"**

An example event for `proxy` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "56370311-c973-4a5b-b93b-e42fd47da568",
        "type": "metricbeat",
        "ephemeral_id": "5d1146d0-7ec9-44be-baa0-3aefc54e6ffd",
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "56370311-c973-4a5b-b93b-e42fd47da568",
        "version": "8.3.0",
        "snapshot": true
    },
    "@timestamp": "2022-07-12T07:34:55.576Z",
    "ecs": {
        "version": "8.5.1"
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
            "version": "20.04.4 LTS (Focal Fossa)",
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
                "listener_max_connections_exceeded_max": 0,
                "listener_total_res": 0,
                "listener_total_req": 0,
                "listener_read_started_res_max": 0,
                "listener_acc_other_latency": 0,
                "listener_cmd_get_max": 0,
                "listener_acc_latency": 0,
                "listener_read_req_max": 0,
                "listener_write_res_max": 0,
                "listener_total_started_res_max": 0,
                "listener_write_started_res_max": 0,
                "listener_total_res_max": 0,
                "listener_write_started_res": 0,
                "listener_write_req": 0,
                "listener_cmd_flush": 0,
                "listener_write_res": 0,
                "listener_cmd_touch": 0,
                "listener_cmd_flush_max": 0,
                "listener_last_res_time": 0,
                "listener_auth_errors_max": 0,
                "listener_acc_read_latency_max": 0,
                "listener_acc_write_latency_max": 0,
                "listener_total_connections_received": 0,
                "listener_conns": 0,
                "listener_total_req_max": 0,
                "listener_acc_write_latency": 0,
                "listener_acc_other_latency_max": 0,
                "listener_read_res_max": 0,
                "listener_monitor_sessions_count": 0,
                "listener_acc_read_latency": 0,
                "listener_cmd_set": 0,
                "listener_other_started_res_max": 0,
                "listener_max_connections_exceeded": 0,
                "listener_ingress_bytes": 0,
                "listener_other_started_res": 0,
                "listener_auth_cmds": 0,
                "listener_read_started_res": 0,
                "listener_cmd_get": 0,
                "listener_other_req_max": 0,
                "listener_auth_errors": 0,
                "listener_total_started_res": 0,
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
        "duration": 312732042,
        "agent_id_status": "verified",
        "ingested": "2022-07-12T07:34:56Z",
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
| redisenterprise.proxy.metrics.listener_\* | Proxy prometheus metrics | object |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |

