# Envoy Proxy

This integration is for Envoy proxy [access logs](https://www.envoyproxy.io/docs/envoy/v1.10.0/configuration/access_log) and [statsd metrics](https://www.envoyproxy.io/docs/envoy/latest/operations/stats_overview). It supports both standalone deployment and Envoy proxy deployment in Kubernetes.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Requires version ^8.15.0 of Elastic Agent

## Compatibility

This integration was tested using Envoy proxy version 1.32.1

## Setup

### Logs

Update `paths` in the integration configuration to the location of your envoyproxy logs if access logs are not being written to `/var/log/envoy.log` (default location).

For Kubernetes deployment see [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-kubernetes-autodiscovery.html) for autodiscovery with Elastic Agent.

### Stats

Add the following to your envoy configuration and set `address` to the IP address of the Elastic Agent running this integration.

> NOTE: Hostnames are not supported by Envoy and must use the IP address where Elastic Agent is installed

```yaml
stats_sinks:
  - name: graphite_statsd
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.stat_sinks.graphite_statsd.v3.GraphiteStatsdSink
      address:
        socket_address:
          address: 127.0.0.1 # Replace with the IP of elastic-agent
          port_value: 8125
```

## Logs reference

An example event for `log` looks as following:

```json
{
    "@timestamp": "2019-04-08T16:16:55.931Z",
    "agent": {
        "ephemeral_id": "b251a806-74d2-4f75-bb84-142e7f931c17",
        "id": "c3ca3082-b848-456d-b798-5b7c6044cec3",
        "name": "elastic-agent-33100",
        "type": "filebeat",
        "version": "8.15.1"
    },
    "data_stream": {
        "dataset": "envoyproxy.log",
        "namespace": "34940",
        "type": "logs"
    },
    "destination": {
        "address": "172.27.0.3",
        "ip": "172.27.0.3",
        "port": 80
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c3ca3082-b848-456d-b798-5b7c6044cec3",
        "snapshot": false,
        "version": "8.15.1"
    },
    "envoyproxy": {
        "log": {
            "authority": "localhost:8000",
            "log_type": "ACCESS",
            "proxy_type": "http",
            "request_id": "c219f6da-2b7f-483e-9ced-ec323d9330a9",
            "upstream_service_time": 4000000
        }
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2024-11-14T14:19:50.685Z",
        "dataset": "envoyproxy.log",
        "duration": 5000000,
        "ingested": "2024-11-14T14:19:51Z",
        "kind": "event",
        "original": "[2019-04-08T16:16:55.931Z] \"GET /service/1 HTTP/1.1\" 200 - 0 89 5 4 \"-\" \"curl/7.54.0\" \"c219f6da-2b7f-483e-9ced-ec323d9330a9\" \"localhost:8000\" \"172.27.0.3:80\"",
        "outcome": "success",
        "type": [
            "connection",
            "protocol"
        ]
    },
    "http": {
        "request": {
            "body": {
                "bytes": 89
            },
            "method": "GET"
        },
        "response": {
            "body": {
                "bytes": 0
            },
            "status_code": 200
        },
        "version": "1.1"
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "30",
            "inode": "57",
            "path": "/tmp/service_logs/envoy.log"
        },
        "offset": 82
    },
    "network": {
        "protocol": "http"
    },
    "related": {
        "ip": [
            "172.27.0.3"
        ]
    },
    "tags": [
        "preserve_original_event",
        "envoy-proxy",
        "forwarded"
    ],
    "url": {
        "domain": "localhost:8000",
        "path": "/service/1"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "curl",
        "original": "curl/7.54.0",
        "version": "7.54.0"
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
| envoyproxy.log.authority |  | keyword |
| envoyproxy.log.log_type |  | keyword |
| envoyproxy.log.proxy_type |  | keyword |
| envoyproxy.log.request_id |  | keyword |
| envoyproxy.log.response_flags |  | keyword |
| envoyproxy.log.upstream_service_time |  | long |
| input.type | Type of Filebeat input. | keyword |
| kubernetes.container.name | Kubernetes container name | keyword |
| kubernetes.labels.\* | Kubernetes labels map | object |
| kubernetes.namespace | Kubernetes namespace | keyword |
| kubernetes.node.name | Kubernetes node name | keyword |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset. | long |


## Stats reference

An example event for `stats` looks as following:

```json
{
    "@timestamp": "2024-12-02T13:39:34.540Z",
    "agent": {
        "ephemeral_id": "1076a4ee-a067-4a6d-8b03-1c1d2f559873",
        "id": "3d2a68b1-45d8-418b-bdcd-63a1bc7f6458",
        "name": "elastic-agent-79840",
        "type": "metricbeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "envoyproxy.stats",
        "namespace": "10169",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "3d2a68b1-45d8-418b-bdcd-63a1bc7f6458",
        "snapshot": false,
        "version": "8.16.0"
    },
    "envoy": {
        "envoy_http_downstream_rq_xx": {
            "count": 1
        },
        "http_conn_manager_prefix": "ingress_http",
        "response_code_class": "2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "envoyproxy.stats",
        "ingested": "2024-12-02T13:39:34Z",
        "kind": "metric",
        "module": "statsd"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-79840",
        "ip": [
            "172.18.0.4",
            "172.19.0.2"
        ],
        "mac": [
            "02-42-AC-12-00-04",
            "02-42-AC-13-00-02"
        ],
        "name": "elastic-agent-79840",
        "os": {
            "kernel": "6.10.11-linuxkit",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "service": {
        "type": "statsd"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| envoy.\*.count | Envoyproxy counters | object | counter |
| envoy.\*.max | Envoyproxy max timers metric | object |  |
| envoy.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.\*.median | Envoyproxy median timers metric | object |  |
| envoy.\*.min | Envoyproxy min timers metric | object |  |
| envoy.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.\*.value | Envoyproxy gauges | object | gauge |
| envoy.cipher_suite | SSL cipher suite | keyword |  |
| envoy.clientssl_prefix | Stats prefix for the Client SSL Auth network filter | keyword |  |
| envoy.cluster_name | Cluster name tag | keyword |  |
| envoy.connection_limit_prefix | Stats prefix for the Connection limit filter | keyword |  |
| envoy.dns_filter_prefix | Stats prefix for the dns filter | keyword |  |
| envoy.dynamo_operation | Operation name for the Dynamo http filter | keyword |  |
| envoy.dynamo_partition_id | Partition ID for the Dynamo http filter | keyword |  |
| envoy.dynamo_table | Table name for the Dynamo http filter | keyword |  |
| envoy.ext_authz_prefix | Stats prefix for the ext_authz HTTP filter | keyword |  |
| envoy.fault_downstream_cluster | Downstream cluster for the Fault http filter | keyword |  |
| envoy.grpc_bridge_method | Request method name for the GRPC Bridge http filter | keyword |  |
| envoy.grpc_bridge_service | Request service name GRPC Bridge http filter | keyword |  |
| envoy.http_conn_manager_prefix | Stats prefix for HttpConnectionManager | keyword |  |
| envoy.http_user_agent | User agent for a connection | keyword |  |
| envoy.listener_address | Listener port tag | keyword |  |
| envoy.local_http_ratelimit_prefix | Stats prefix for the Local Ratelimit network filter | keyword |  |
| envoy.local_listener_ratelimit_prefix | Stats prefix for the Local Ratelimit listener filter | keyword |  |
| envoy.local_network_ratelimit_prefix | Stats prefix for the Local Ratelimit network filter | keyword |  |
| envoy.mongo_callsite | Request callsite for the Mongo Proxy network filter | keyword |  |
| envoy.mongo_cmd | Request command for the Mongo Proxy network filter | keyword |  |
| envoy.mongo_collection | Request collection for the Mongo Proxy network filter | keyword |  |
| envoy.mongo_prefix | Stats prefix for the Mongo Proxy network filter | keyword |  |
| envoy.proxy_protocol_prefix | Stats prefix for the proxy protocol listener filter. | keyword |  |
| envoy.proxy_protocol_version | Proxy Protocol version for a connection (Proxy Protocol listener filter). | keyword |  |
| envoy.ratelimit_prefix | Stats prefix for the Ratelimit network filter | keyword |  |
| envoy.rbac_http_prefix | Stats prefix for the RBAC http filter | keyword |  |
| envoy.rbac_policy_name | Policy name for the RBAC http filter | keyword |  |
| envoy.rbac_prefix | Stats prefix for the RBAC network filter | keyword |  |
| envoy.rds_route_config | Route config name for RDS updates | keyword |  |
| envoy.redis_prefix | Stats prefix for the Redis Proxy network filter | keyword |  |
| envoy.response_code | Request response code | keyword |  |
| envoy.response_code_class | Request response code class | keyword |  |
| envoy.route | Request route given by the Router http filter | keyword |  |
| envoy.scoped_rds_config | Scoped route config name for RDS updates | keyword |  |
| envoy.ssl_cipher | SSL cipher for a connection | keyword |  |
| envoy.ssl_curve | SSL curve for a connection | keyword |  |
| envoy.ssl_sigalg | SSL signature algorithm for a connection | keyword |  |
| envoy.ssl_version | SSL version for a connection | keyword |  |
| envoy.tcp_prefix | Stats prefix for the TCP Proxy network filter | keyword |  |
| envoy.thrift_prefix | Stats prefix for the Thrift Proxy network filter | keyword |  |
| envoy.udp_prefix | Stats prefix for the UDP Proxy network filter | keyword |  |
| envoy.virtual_cluster | Request virtual cluster given by the Router http filter | keyword |  |
| envoy.virtual_host | Request virtual host given by the Router http filter | keyword |  |
| envoy.worker_id | Listener manager worker id | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| input.type | Type of Filebeat input. | keyword |  |
| log.offset | Log offset. | long |  |
| service.address | Service address | keyword |  |
| tags | User defined tags. | keyword |  |

