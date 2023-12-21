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
    "agent": {
        "name": "docker-fleet-agent",
        "id": "8412e9e5-6fd3-4587-bc60-1fba76200570",
        "type": "metricbeat",
        "ephemeral_id": "cc4072b4-71a6-40be-ad91-7245b283f11d",
        "version": "8.10.4"
    },
    "@timestamp": "2023-10-27T08:01:51.865Z",
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
            "type": "linux",
            "family": "debian",
            "version": "20.04.6 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.19.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "5bf910baf91142d6b435357818c88ef5",
        "mac": [
            "02-42-AC-13-00-07"
        ],
        "architecture": "aarch64"
    },
    "elastic_agent": {
        "id": "8412e9e5-6fd3-4587-bc60-1fba76200570",
        "version": "8.10.4",
        "snapshot": false
    },
    "redisenterprise": {
        "node": {
            "labels": {
                "cluster": "cluster.local",
                "node": "1",
                "instance": "host.docker.internal:8070",
                "job": "prometheus"
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
                "value": 0.037
            },
            "persistent_storage_avail": {
                "value": 50210169287.111
            },
            "cpu_irqs_min": {
                "value": 0.003
            },
            "cpu_idle_max": {
                "value": 0.751
            },
            "ephemeral_storage_avail": {
                "value": 50210169287.111
            },
            "egress_bytes": {
                "value": 1342.5556666666669
            },
            "cpu_system_median": {
                "value": 0.036
            },
            "total_req": {
                "value": 0
            },
            "cpu_system_min": {
                "value": 0.034
            },
            "persistent_storage_free": {
                "value": 53426885063.111
            },
            "cpu_user_min": {
                "value": 0.192
            },
            "egress_bytes_median": {
                "value": 1569.778
            },
            "cpu_user_median": {
                "value": 0.195
            },
            "cpu_steal_median": {
                "value": 0
            },
            "egress_bytes_min": {
                "value": 885.889
            },
            "ingress_bytes_min": {
                "value": 242
            },
            "conns": {
                "value": 0
            },
            "cpu_steal_min": {
                "value": 0
            },
            "cpu_user": {
                "value": 0.19533333333333336
            },
            "free_memory": {
                "value": 257662065.778
            },
            "cpu_idle": {
                "value": 0.7493333333333334
            },
            "cpu_system": {
                "value": 0.03566666666666667
            },
            "cpu_steal_max": {
                "value": 0
            },
            "cpu_nice": {
                "value": 0
            },
            "available_memory": {
                "value": 146729029.556
            },
            "ingress_bytes": {
                "value": 258.815
            },
            "cpu_user_max": {
                "value": 0.199
            }
        }
    },
    "metricset": {
        "period": 10000,
        "name": "collector"
    },
    "event": {
        "duration": 240631792,
        "agent_id_status": "verified",
        "ingested": "2023-10-27T08:01:52Z",
        "module": "prometheus",
        "dataset": "redisenterprise.node"
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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
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
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |


## Proxy Metrics

Captures all the proxy specific exported metrics, matching pattern **"listener_*"**

An example event for `proxy` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "e275fc30-5606-41f2-a4f9-c30819350b25",
        "ephemeral_id": "d53c023d-a17d-40d1-b9bc-4850df49633a",
        "type": "metricbeat",
        "version": "8.10.4"
    },
    "@timestamp": "2023-10-27T09:02:20.616Z",
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
    "elastic_agent": {
        "id": "e275fc30-5606-41f2-a4f9-c30819350b25",
        "version": "8.10.4",
        "snapshot": false
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "20.04.6 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.22.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "5bf910baf91142d6b435357818c88ef5",
        "mac": [
            "02-42-AC-16-00-07"
        ],
        "architecture": "aarch64"
    },
    "redisenterprise": {
        "proxy": {
            "listener_resp2_clients_max": {
                "counter": 0
            },
            "listener_egress_bytes": {
                "counter": 0
            },
            "listener_last_req_time": {
                "counter": 0
            },
            "listener_other_res": {
                "counter": 0
            },
            "listener_ingress_bytes_max": {
                "counter": 0
            },
            "listener_total_connections_received_max": {
                "counter": 0
            },
            "listener_other_req": {
                "counter": 0
            },
            "listener_resp3_clients_max": {
                "counter": 0
            },
            "listener_sconn_hello_setuser_max": {
                "counter": 0
            },
            "listener_other_res_max": {
                "counter": 0
            },
            "listener_write_req_max": {
                "counter": 0
            },
            "listener_cmd_touch_max": {
                "counter": 0
            },
            "listener_egress_bytes_max": {
                "counter": 0
            },
            "listener_sconn_hello_setresp": {
                "counter": 0
            },
            "listener_auth_cmds_max": {
                "counter": 0
            },
            "listener_read_res": {
                "counter": 0
            },
            "listener_resp3_clients": {
                "counter": 0
            },
            "listener_read_req": {
                "counter": 0
            },
            "listener_total_res": {
                "counter": 0
            },
            "listener_max_connections_exceeded_max": {
                "counter": 0
            },
            "listener_sconn_hello_setuser": {
                "counter": 0
            },
            "listener_total_req": {
                "counter": 0
            },
            "listener_read_started_res_max": {
                "counter": 0
            },
            "listener_acc_other_latency": {
                "counter": 0
            },
            "listener_cmd_get_max": {
                "counter": 0
            },
            "listener_acc_latency": {
                "counter": 0
            },
            "listener_read_req_max": {
                "counter": 0
            },
            "listener_write_res_max": {
                "counter": 0
            },
            "listener_sconn_hello_failed": {
                "counter": 0
            },
            "listener_total_started_res_max": {
                "counter": 0
            },
            "listener_write_started_res": {
                "counter": 0
            },
            "listener_write_req": {
                "counter": 0
            },
            "listener_total_res_max": {
                "counter": 0
            },
            "listener_write_started_res_max": {
                "counter": 0
            },
            "listener_cmd_flush": {
                "counter": 0
            },
            "listener_write_res": {
                "counter": 0
            },
            "labels": {
                "bdb": "1",
                "cluster": "cluster.local",
                "node": "1",
                "proxy": "1:1:1",
                "endpoint": "1:1",
                "instance": "host.docker.internal:8070",
                "port": "12000",
                "job": "prometheus"
            },
            "listener_cmd_touch": {
                "counter": 0
            },
            "listener_cmd_flush_max": {
                "counter": 0
            },
            "listener_last_res_time": {
                "counter": 0
            },
            "listener_auth_errors_max": {
                "counter": 0
            },
            "listener_sconn_hello_failed_max": {
                "counter": 0
            },
            "listener_acc_read_latency_max": {
                "counter": 0
            },
            "listener_acc_write_latency_max": {
                "counter": 0
            },
            "listener_total_connections_received": {
                "counter": 0
            },
            "listener_conns": {
                "counter": 0
            },
            "listener_total_req_max": {
                "counter": 0
            },
            "listener_acc_write_latency": {
                "counter": 0
            },
            "listener_acc_other_latency_max": {
                "counter": 0
            },
            "listener_read_res_max": {
                "counter": 0
            },
            "listener_cmd_set": {
                "counter": 0
            },
            "listener_acc_read_latency": {
                "counter": 0
            },
            "listener_monitor_sessions_count": {
                "counter": 0
            },
            "listener_resp2_clients": {
                "counter": 0
            },
            "listener_other_started_res_max": {
                "counter": 0
            },
            "listener_max_connections_exceeded": {
                "counter": 0
            },
            "listener_ingress_bytes": {
                "counter": 0
            },
            "listener_other_started_res": {
                "counter": 0
            },
            "listener_auth_cmds": {
                "counter": 0
            },
            "listener_read_started_res": {
                "counter": 0
            },
            "listener_cmd_get": {
                "counter": 0
            },
            "listener_other_req_max": {
                "counter": 0
            },
            "listener_total_started_res": {
                "counter": 0
            },
            "listener_auth_errors": {
                "counter": 0
            },
            "listener_cmd_set_max": {
                "counter": 0
            },
            "listener_acc_latency_max": {
                "counter": 0
            },
            "listener_sconn_hello_setresp_max": {
                "counter": 0
            }
        }
    },
    "metricset": {
        "period": 10000,
        "name": "collector"
    },
    "event": {
        "duration": 395309250,
        "agent_id_status": "verified",
        "ingested": "2023-10-27T09:02:21Z",
        "module": "prometheus",
        "dataset": "redisenterprise.proxy"
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
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
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
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |

