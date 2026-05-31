# Redis Enterprise

Redis Enterprise integration provides monitoring of [redis](https://redis.com/) cluster. Monitoring is done via prometheus exported port of redis enterprise cluster. Once a redis enterprise [cluster](https://redis.com/redis-enterprise/technology/redis-enterprise-cluster-architecture/) is installed, prometheus port is available for monitoring. The url of the host:port(8070) needs to be passed to the hosts in the settings.

## Compatibility
Tested with Redis Enterprise v7.2.4.

# Metrics

## Node Metrics

Captures all the node specific exported metrics, matching pattern **"node_*"** 

An example event for `node` looks as following:

```json
{
    "@timestamp": "2026-02-09T06:43:38.254Z",
    "agent": {
        "ephemeral_id": "de16bec6-bbcd-4a55-a439-5cc9e9562358",
        "id": "ff44ae54-7fbd-4eaa-97ab-d61a3d1094e7",
        "name": "elastic-agent-94391",
        "type": "metricbeat",
        "version": "9.2.2"
    },
    "data_stream": {
        "dataset": "redisenterprise.node",
        "namespace": "64311",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ff44ae54-7fbd-4eaa-97ab-d61a3d1094e7",
        "snapshot": false,
        "version": "9.2.2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "redisenterprise.node",
        "duration": 68315542,
        "ingested": "2026-02-09T06:43:41Z",
        "module": "prometheus"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-94391",
        "ip": [
            "172.18.0.4",
            "172.27.0.2"
        ],
        "mac": [
            "2A-8C-19-BD-BB-92",
            "F6-24-06-AC-B3-B9"
        ],
        "name": "elastic-agent-94391",
        "os": {
            "family": "",
            "kernel": "6.12.67-linuxkit",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "redisenterprise": {
        "node": {
            "available_memory": {
                "value": 2145286826.667
            },
            "available_memory_no_overbooking": {
                "value": 2144885418.667
            },
            "conns": {
                "value": 0
            },
            "cpu_idle": {
                "value": 0.9463333333333331
            },
            "cpu_idle_max": {
                "value": 0.95
            },
            "cpu_idle_median": {
                "value": 0.947
            },
            "cpu_idle_min": {
                "value": 0.942
            },
            "cpu_iowait": {
                "value": 0
            },
            "cpu_iowait_max": {
                "value": 0
            },
            "cpu_iowait_median": {
                "value": 0
            },
            "cpu_iowait_min": {
                "value": 0
            },
            "cpu_irqs": {
                "value": 0.0036666666666666666
            },
            "cpu_irqs_max": {
                "value": 0.004
            },
            "cpu_irqs_median": {
                "value": 0.004
            },
            "cpu_irqs_min": {
                "value": 0.003
            },
            "cpu_nice": {
                "value": 0
            },
            "cpu_nice_max": {
                "value": 0
            },
            "cpu_nice_median": {
                "value": 0
            },
            "cpu_nice_min": {
                "value": 0
            },
            "cpu_steal": {
                "value": 0
            },
            "cpu_steal_max": {
                "value": 0
            },
            "cpu_steal_median": {
                "value": 0
            },
            "cpu_steal_min": {
                "value": 0
            },
            "cpu_system": {
                "value": 0.008666666666666668
            },
            "cpu_system_max": {
                "value": 0.009
            },
            "cpu_system_median": {
                "value": 0.009
            },
            "cpu_system_min": {
                "value": 0.008
            },
            "cpu_user": {
                "value": 0.035333333333333335
            },
            "cpu_user_max": {
                "value": 0.039
            },
            "cpu_user_median": {
                "value": 0.034
            },
            "cpu_user_min": {
                "value": 0.033
            },
            "cur_aof_rewrites": {
                "value": 0
            },
            "egress_bytes": {
                "value": 0
            },
            "egress_bytes_max": {
                "value": 0
            },
            "egress_bytes_median": {
                "value": 0
            },
            "egress_bytes_min": {
                "value": 0
            },
            "ephemeral_storage_avail": {
                "value": 888414001379.556
            },
            "ephemeral_storage_free": {
                "value": 938163845347.556
            },
            "free_memory": {
                "value": 2135573845.333
            },
            "ingress_bytes": {
                "value": 0
            },
            "ingress_bytes_max": {
                "value": 0
            },
            "ingress_bytes_median": {
                "value": 0
            },
            "ingress_bytes_min": {
                "value": 0
            },
            "labels": {
                "cluster": "cluster.local",
                "instance": "svc-redisenterprise:8070",
                "job": "prometheus",
                "node": "1"
            },
            "persistent_storage_avail": {
                "value": 888414001379.556
            },
            "persistent_storage_free": {
                "value": 938163845347.556
            },
            "provisional_memory": {
                "value": 666208775.667
            },
            "provisional_memory_no_overbooking": {
                "value": 666728967.667
            },
            "total_req": {
                "value": 0
            }
        }
    },
    "service": {
        "address": "http://svc-redisenterprise:8070/metrics",
        "type": "prometheus"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| redisenterprise.node.\*.value | Node metrics. | object | gauge |
| redisenterprise.node.labels.addr | Network address or IP address of the node. | keyword |  |
| redisenterprise.node.labels.cluster | name of the cluster to which the node belongs. | keyword |  |
| redisenterprise.node.labels.cnm_version | Version of the Redis Enterprise cluster node management software that the node is running. | keyword |  |
| redisenterprise.node.labels.instance | The \<host\>:\<port\> or network address or endpoint of the Redis Enterprise node. | keyword |  |
| redisenterprise.node.labels.job | Configured job name like prometheus. | keyword |  |
| redisenterprise.node.labels.logical_name | Logical name or role of the node within the cluster. | keyword |  |
| redisenterprise.node.labels.node | Specific node within the cluster | keyword |  |
| redisenterprise.node.labels.path | Specifies the file path to the certificate file associated with the node and role. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


## Proxy Metrics

Captures all the proxy specific exported metrics, matching pattern **"listener_*"**

An example event for `proxy` looks as following:

```json
{
    "@timestamp": "2026-02-09T06:45:42.104Z",
    "agent": {
        "ephemeral_id": "cea9ce9b-cb06-43d2-85c7-1556f7c0be87",
        "id": "614462d0-9730-4fc0-9e8e-8a93d8cae093",
        "name": "elastic-agent-74425",
        "type": "metricbeat",
        "version": "9.2.2"
    },
    "data_stream": {
        "dataset": "redisenterprise.proxy",
        "namespace": "63975",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "614462d0-9730-4fc0-9e8e-8a93d8cae093",
        "snapshot": false,
        "version": "9.2.2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "redisenterprise.proxy",
        "duration": 26680375,
        "ingested": "2026-02-09T06:45:45Z",
        "module": "prometheus"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "elastic-agent-74425",
        "ip": [
            "172.18.0.4",
            "172.27.0.2"
        ],
        "mac": [
            "3A-76-21-99-38-85",
            "DE-E3-D9-70-BE-C4"
        ],
        "name": "elastic-agent-74425",
        "os": {
            "family": "",
            "kernel": "6.12.67-linuxkit",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "redisenterprise": {
        "proxy": {
            "labels": {
                "bdb": "1",
                "cluster": "cluster.local",
                "endpoint": "1:1",
                "instance": "svc-redisenterprise:8070",
                "job": "prometheus",
                "node": "1",
                "port": "12000",
                "proxy": "1:1:1"
            },
            "listener_acc_latency": {
                "counter": 0
            },
            "listener_acc_latency_max": {
                "counter": 0
            },
            "listener_acc_other_latency": {
                "counter": 0
            },
            "listener_acc_other_latency_max": {
                "counter": 0
            },
            "listener_acc_read_latency": {
                "counter": 0
            },
            "listener_acc_read_latency_max": {
                "counter": 0
            },
            "listener_acc_write_latency": {
                "counter": 0
            },
            "listener_acc_write_latency_max": {
                "counter": 0
            },
            "listener_auth_cmds": {
                "counter": 0
            },
            "listener_auth_cmds_max": {
                "counter": 0
            },
            "listener_auth_errors": {
                "counter": 0
            },
            "listener_auth_errors_max": {
                "counter": 0
            },
            "listener_cmd_flush": {
                "counter": 0
            },
            "listener_cmd_flush_max": {
                "counter": 0
            },
            "listener_cmd_get": {
                "counter": 0
            },
            "listener_cmd_get_max": {
                "counter": 0
            },
            "listener_cmd_set": {
                "counter": 0
            },
            "listener_cmd_set_max": {
                "counter": 0
            },
            "listener_cmd_touch": {
                "counter": 0
            },
            "listener_cmd_touch_max": {
                "counter": 0
            },
            "listener_conns": {
                "counter": 0
            },
            "listener_egress_bytes": {
                "counter": 0
            },
            "listener_egress_bytes_max": {
                "counter": 0
            },
            "listener_ingress_bytes": {
                "counter": 0
            },
            "listener_ingress_bytes_max": {
                "counter": 0
            },
            "listener_last_req_time": {
                "counter": 0
            },
            "listener_last_res_time": {
                "counter": 0
            },
            "listener_max_connections_exceeded": {
                "counter": 0
            },
            "listener_max_connections_exceeded_max": {
                "counter": 0
            },
            "listener_monitor_sessions_count": {
                "counter": 0
            },
            "listener_other_req": {
                "counter": 0
            },
            "listener_other_req_max": {
                "counter": 0
            },
            "listener_other_res": {
                "counter": 0
            },
            "listener_other_res_max": {
                "counter": 0
            },
            "listener_other_started_res": {
                "counter": 0
            },
            "listener_other_started_res_max": {
                "counter": 0
            },
            "listener_read_req": {
                "counter": 0
            },
            "listener_read_req_max": {
                "counter": 0
            },
            "listener_read_res": {
                "counter": 0
            },
            "listener_read_res_max": {
                "counter": 0
            },
            "listener_read_started_res": {
                "counter": 0
            },
            "listener_read_started_res_max": {
                "counter": 0
            },
            "listener_total_connections_received": {
                "counter": 0
            },
            "listener_total_connections_received_max": {
                "counter": 0
            },
            "listener_total_req": {
                "counter": 0
            },
            "listener_total_req_max": {
                "counter": 0
            },
            "listener_total_res": {
                "counter": 0
            },
            "listener_total_res_max": {
                "counter": 0
            },
            "listener_total_started_res": {
                "counter": 0
            },
            "listener_total_started_res_max": {
                "counter": 0
            },
            "listener_write_req": {
                "counter": 0
            },
            "listener_write_req_max": {
                "counter": 0
            },
            "listener_write_res": {
                "counter": 0
            },
            "listener_write_res_max": {
                "counter": 0
            },
            "listener_write_started_res": {
                "counter": 0
            },
            "listener_write_started_res_max": {
                "counter": 0
            }
        }
    },
    "service": {
        "address": "http://svc-redisenterprise:8070/metrics",
        "type": "prometheus"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| redisenterprise.proxy.\*.counter | Proxy metrics. | object | counter |
| redisenterprise.proxy.labels.bdb | Managed database, indicating which database is being referred to. | keyword |  |
| redisenterprise.proxy.labels.cluster | Cluster name. | keyword |  |
| redisenterprise.proxy.labels.endpoint | Endpoint id. | keyword |  |
| redisenterprise.proxy.labels.instance | Host address of cluster's instance expressed in the form of an IP:PORT. | keyword |  |
| redisenterprise.proxy.labels.job | Type of the job. | keyword |  |
| redisenterprise.proxy.labels.node | The node that is being monitored. | keyword |  |
| redisenterprise.proxy.labels.port | The port number to connect to the database. | keyword |  |
| redisenterprise.proxy.labels.proxy | Proxy that is bound to the database.. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |

