# Envoy Proxy

This integration is for Envoy proxy [access logs](https://www.envoyproxy.io/docs/envoy/v1.10.0/configuration/access_log) and [statsd metrics](https://www.envoyproxy.io/docs/envoy/latest/operations/stats_overview). It supports both standalone deployment and Envoy proxy deployment in Kubernetes.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Logs

Update the path to your logs in the integration if access logs are not being written to `/var/log/envoy.log` (default location).

For Kubernetes deployment see [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-kubernetes-autodiscovery.html) for autodiscovery with Elastic Agent.

### Stats

Update your Envoy config to point statsd output to the IP address of the agent running this integration.

> NOTE: Hostnames are not supported by Envoy and must use the IP address where Elastic Agent is installed

```yaml
stats_sinks:
  - name: graphite_statsd
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.stat_sinks.graphite_statsd.v3.GraphiteStatsdSink
      address:
        socket_address:
          address: 127.0.0.1
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
    "@timestamp": "2024-11-14T14:22:18.283Z",
    "agent": {
        "ephemeral_id": "08892539-8525-4ceb-afb8-95ea3c128d4c",
        "id": "13047bf7-6360-4d6d-b1a0-9a923610b76e",
        "name": "elastic-agent-25985",
        "type": "metricbeat",
        "version": "8.15.1"
    },
    "data_stream": {
        "dataset": "envoyproxy.stats",
        "namespace": "42696",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "13047bf7-6360-4d6d-b1a0-9a923610b76e",
        "snapshot": false,
        "version": "8.15.1"
    },
    "envoyproxy": {
        "envoy_http_downstream_cx_destroy_remote": {
            "count": 1
        },
        "http_conn_manager_prefix": "ingress_http"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "envoyproxy.stats",
        "ingested": "2024-11-14T14:22:18Z",
        "kind": "metric",
        "module": "statsd"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-25985",
        "id": "0fba6dd9e2a445ca80a4261bd56fec54",
        "ip": [
            "172.18.0.4",
            "172.31.0.2"
        ],
        "mac": [
            "02-42-AC-12-00-04",
            "02-42-AC-1F-00-02"
        ],
        "name": "elastic-agent-25985",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.6.31-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
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
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| envoyproxy.\*.count | Envoyproxy counters | object | counter |
| envoyproxy.\*.max | Envoyproxy max timers metric | object |  |
| envoyproxy.\*.mean | Envoyproxy mean timers metric | object |  |
| envoyproxy.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoyproxy.\*.median | Envoyproxy median timers metric | object |  |
| envoyproxy.\*.min | Envoyproxy min timers metric | object |  |
| envoyproxy.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoyproxy.\*.value | Envoyproxy gauges | object | gauge |
| envoyproxy.cipher_suite | SSL cipher suite | keyword |  |
| envoyproxy.clientssl_prefix | Stats prefix for the Client SSL Auth network filter | keyword |  |
| envoyproxy.cluster_name | Cluster name tag | keyword |  |
| envoyproxy.connection_limit_prefix | Stats prefix for the Connection limit filter | keyword |  |
| envoyproxy.dns_filter_prefix | Stats prefix for the dns filter | keyword |  |
| envoyproxy.dynamo_operation | Operation name for the Dynamo http filter | keyword |  |
| envoyproxy.dynamo_partition_id | Partition ID for the Dynamo http filter | keyword |  |
| envoyproxy.dynamo_table | Table name for the Dynamo http filter | keyword |  |
| envoyproxy.ext_authz_prefix | Stats prefix for the ext_authz HTTP filter | keyword |  |
| envoyproxy.fault_downstream_cluster | Downstream cluster for the Fault http filter | keyword |  |
| envoyproxy.grpc_bridge_method | Request method name for the GRPC Bridge http filter | keyword |  |
| envoyproxy.grpc_bridge_service | Request service name GRPC Bridge http filter | keyword |  |
| envoyproxy.http_conn_manager_prefix | Stats prefix for HttpConnectionManager | keyword |  |
| envoyproxy.http_user_agent | User agent for a connection | keyword |  |
| envoyproxy.listener_address | Listener port tag | keyword |  |
| envoyproxy.local_http_ratelimit_prefix | Stats prefix for the Local Ratelimit network filter | keyword |  |
| envoyproxy.local_listener_ratelimit_prefix | Stats prefix for the Local Ratelimit listener filter | keyword |  |
| envoyproxy.local_network_ratelimit_prefix | Stats prefix for the Local Ratelimit network filter | keyword |  |
| envoyproxy.mongo_callsite | Request callsite for the Mongo Proxy network filter | keyword |  |
| envoyproxy.mongo_cmd | Request command for the Mongo Proxy network filter | keyword |  |
| envoyproxy.mongo_collection | Request collection for the Mongo Proxy network filter | keyword |  |
| envoyproxy.mongo_prefix | Stats prefix for the Mongo Proxy network filter | keyword |  |
| envoyproxy.proxy_protocol_prefix | Stats prefix for the proxy protocol listener filter. | keyword |  |
| envoyproxy.proxy_protocol_version | Proxy Protocol version for a connection (Proxy Protocol listener filter). | keyword |  |
| envoyproxy.ratelimit_prefix | Stats prefix for the Ratelimit network filter | keyword |  |
| envoyproxy.rbac_http_prefix | Stats prefix for the RBAC http filter | keyword |  |
| envoyproxy.rbac_policy_name | Policy name for the RBAC http filter | keyword |  |
| envoyproxy.rbac_prefix | Stats prefix for the RBAC network filter | keyword |  |
| envoyproxy.rds_route_config | Route config name for RDS updates | keyword |  |
| envoyproxy.redis_prefix | Stats prefix for the Redis Proxy network filter | keyword |  |
| envoyproxy.response_code | Request response code | keyword |  |
| envoyproxy.response_code_class | Request response code class | keyword |  |
| envoyproxy.route | Request route given by the Router http filter | keyword |  |
| envoyproxy.scoped_rds_config | Scoped route config name for RDS updates | keyword |  |
| envoyproxy.ssl_cipher | SSL cipher for a connection | keyword |  |
| envoyproxy.ssl_curve | SSL curve for a connection | keyword |  |
| envoyproxy.ssl_sigalg | SSL signature algorithm for a connection | keyword |  |
| envoyproxy.ssl_version | SSL version for a connection | keyword |  |
| envoyproxy.tcp_prefix | Stats prefix for the TCP Proxy network filter | keyword |  |
| envoyproxy.thrift_prefix | Stats prefix for the Thrift Proxy network filter | keyword |  |
| envoyproxy.udp_prefix | Stats prefix for the UDP Proxy network filter | keyword |  |
| envoyproxy.virtual_cluster | Request virtual cluster given by the Router http filter | keyword |  |
| envoyproxy.virtual_host | Request virtual host given by the Router http filter | keyword |  |
| envoyproxy.worker_id | Listener manager worker id | keyword |  |
| input.type | Type of Filebeat input. | keyword |  |
| log.offset | Log offset. | long |  |
| tags | User defined tags. | keyword |  |

