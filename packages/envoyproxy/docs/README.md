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

Update your Envoy config to point statsd output to the agents IP.

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
    "@timestamp": "2019-04-06T06:20:05.972Z",
    "agent": {
        "ephemeral_id": "56211845-a50f-4eac-b02f-85202fae2d9a",
        "id": "da88c03c-0c6b-4998-ad72-2ca34550d7aa",
        "name": "elastic-agent-65996",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "data_stream": {
        "dataset": "envoyproxy.log",
        "namespace": "21844",
        "type": "logs"
    },
    "destination": {
        "address": "127.0.0.1",
        "bytes": 0,
        "ip": "127.0.0.1",
        "port": 9200
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "da88c03c-0c6b-4998-ad72-2ca34550d7aa",
        "snapshot": false,
        "version": "8.15.0"
    },
    "envoyproxy": {
        "log": {
            "authority": "-",
            "log_type": "ACCESS",
            "proxy_type": "tcp",
            "request_id": "-",
            "response_flags": [
                "UF",
                "URX"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2024-09-23T12:28:25.950Z",
        "dataset": "envoyproxy.log",
        "duration": 0,
        "ingested": "2024-09-23T12:28:26Z",
        "kind": "event",
        "original": "ACCESS [2019-04-06T06:20:05.972Z] \"- - -\" 0 UF,URX 0 0 0 - \"-\" \"-\" \"-\" \"-\" \"127.0.0.1:9200\"",
        "outcome": "failure",
        "type": [
            "connection",
            "connection"
        ]
    },
    "input": {
        "type": "log"
    },
    "kubernetes": {
        "container": {
            "name": "ambassador"
        },
        "labels": {
            "service": "ambassador"
        },
        "namespace": "default",
        "node": {
            "name": "minikube"
        },
        "pod": {
            "name": "ambassador-76c58d9df4-jwhsg",
            "uid": "e57d545e-2a9d-11e9-995f-08002730e0dc"
        }
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/envoy.log"
        },
        "offset": 1263
    },
    "network": {
        "transport": "tcp"
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "source": {
        "bytes": 0
    },
    "tags": [
        "preserve_original_event",
        "envoy-proxy",
        "forwarded"
    ]
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
    "@timestamp": "2024-10-07T16:44:58.823Z",
    "agent": {
        "ephemeral_id": "ba3ce7a8-014c-47bf-b028-d28e8aff0ece",
        "id": "03cf6855-47b2-4244-a94f-31d360efaf98",
        "name": "elastic-agent-63319",
        "type": "metricbeat",
        "version": "8.15.2"
    },
    "data_stream": {
        "dataset": "envoyproxy.stats",
        "namespace": "98577",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "03cf6855-47b2-4244-a94f-31d360efaf98",
        "snapshot": false,
        "version": "8.15.2"
    },
    "envoyproxy": {
        "cluster_name": "service_test",
        "envoy_cluster_warming_state": {
            "value": 0
        }
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "envoyproxy.stats",
        "ingested": "2024-10-07T16:44:58Z",
        "module": "statsd"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-63319",
        "id": "93db770e92a444c98362aee1860ae326",
        "ip": [
            "172.18.0.4",
            "192.168.16.2"
        ],
        "mac": [
            "02-42-AC-12-00-04",
            "02-42-C0-A8-10-02"
        ],
        "name": "elastic-agent-63319",
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

