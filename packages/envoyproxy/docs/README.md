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
        "ephemeral_id": "ee68951f-ee1f-45ae-8e2b-47fadcd1aa7d",
        "id": "75199e22-366d-48f5-95d2-29840b5c0730",
        "name": "elastic-agent-18673",
        "type": "filebeat",
        "version": "9.0.0"
    },
    "data_stream": {
        "dataset": "envoyproxy.log",
        "namespace": "46375",
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
        "id": "75199e22-366d-48f5-95d2-29840b5c0730",
        "snapshot": true,
        "version": "9.0.0"
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
        "created": "2025-02-11T12:38:13.677Z",
        "dataset": "envoyproxy.log",
        "duration": 5000000,
        "ingested": "2025-02-11T12:38:14Z",
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
            "device_id": "64768",
            "fingerprint": "64a922ed2775bc79e703cb91d8c21d2b5fa2924b41167308d87dfdcb05962d51",
            "inode": "273536519",
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
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset. | long |


## Stats reference

An example event for `stats` looks as following:

```json
{
    "@timestamp": "2024-12-03T22:18:52.507Z",
    "agent": {
        "ephemeral_id": "1aff9b9a-ad64-464e-ad78-7f4155a3b307",
        "id": "030b4965-b64c-4213-a2ef-933fae9376eb",
        "name": "elastic-agent-70658",
        "type": "metricbeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "envoyproxy.stats",
        "namespace": "50029",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "030b4965-b64c-4213-a2ef-933fae9376eb",
        "snapshot": false,
        "version": "8.16.0"
    },
    "envoy": {
        "listener": {
            "address": "0.0.0.0_443",
            "ssl": {
                "curve": "P-256"
            },
            "ssl_curves": {
                "count": 1
            }
        }
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "envoyproxy.stats",
        "ingested": "2024-12-03T22:18:52Z",
        "kind": "metric",
        "module": "statsd"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-70658",
        "ip": [
            "172.18.0.4",
            "172.19.0.2"
        ],
        "mac": [
            "02-42-AC-12-00-04",
            "02-42-AC-13-00-02"
        ],
        "name": "elastic-agent-70658",
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
| envoy.cluster.\*.count | Envoyproxy counters | object | counter |
| envoy.cluster.\*.max | Envoyproxy max timers metric | object |  |
| envoy.cluster.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.cluster.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.cluster.\*.median | Envoyproxy median timers metric | object |  |
| envoy.cluster.\*.min | Envoyproxy min timers metric | object |  |
| envoy.cluster.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.cluster.\*.value | Envoyproxy gauges | object | gauge |
| envoy.cluster.ext_authz.prefix | Stats prefix for the ext_authz HTTP filter | keyword |  |
| envoy.cluster.grpc.bridge_method | Request method name for the GRPC Bridge http filter | keyword |  |
| envoy.cluster.grpc.bridge_service | Request service name GRPC Bridge http filter | keyword |  |
| envoy.cluster.name | Cluster name tag | keyword |  |
| envoy.cluster.ratelimit.prefix | Stats prefix for the Ratelimit network filter | keyword |  |
| envoy.cluster.response_code | Request response code | keyword |  |
| envoy.cluster_manager.\*.count | Envoyproxy counters | object | counter |
| envoy.cluster_manager.\*.max | Envoyproxy max timers metric | object |  |
| envoy.cluster_manager.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.cluster_manager.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.cluster_manager.\*.median | Envoyproxy median timers metric | object |  |
| envoy.cluster_manager.\*.min | Envoyproxy min timers metric | object |  |
| envoy.cluster_manager.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.cluster_manager.\*.value | Envoyproxy gauges | object | gauge |
| envoy.connection_limit.\*.count | Envoyproxy counters | object | counter |
| envoy.connection_limit.\*.max | Envoyproxy max timers metric | object |  |
| envoy.connection_limit.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.connection_limit.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.connection_limit.\*.median | Envoyproxy median timers metric | object |  |
| envoy.connection_limit.\*.min | Envoyproxy min timers metric | object |  |
| envoy.connection_limit.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.connection_limit.\*.value | Envoyproxy gauges | object | gauge |
| envoy.connection_limit.prefix | Stats prefix for the Connection limit filter | keyword |  |
| envoy.dns_filter.\*.count | Envoyproxy counters | object | counter |
| envoy.dns_filter.\*.max | Envoyproxy max timers metric | object |  |
| envoy.dns_filter.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.dns_filter.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.dns_filter.\*.median | Envoyproxy median timers metric | object |  |
| envoy.dns_filter.\*.min | Envoyproxy min timers metric | object |  |
| envoy.dns_filter.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.dns_filter.\*.value | Envoyproxy gauges | object | gauge |
| envoy.dns_filter.prefix | Stats prefix for the dns filter | keyword |  |
| envoy.filesystem.\*.count | Envoyproxy counters | object | counter |
| envoy.filesystem.\*.max | Envoyproxy max timers metric | object |  |
| envoy.filesystem.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.filesystem.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.filesystem.\*.median | Envoyproxy median timers metric | object |  |
| envoy.filesystem.\*.min | Envoyproxy min timers metric | object |  |
| envoy.filesystem.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.filesystem.\*.value | Envoyproxy gauges | object | gauge |
| envoy.http.\*.count | Envoyproxy counters | object | counter |
| envoy.http.\*.max | Envoyproxy max timers metric | object |  |
| envoy.http.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.http.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.http.\*.median | Envoyproxy median timers metric | object |  |
| envoy.http.\*.min | Envoyproxy min timers metric | object |  |
| envoy.http.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.http.\*.value | Envoyproxy gauges | object | gauge |
| envoy.http.conn_manager_prefix | Stats prefix for HttpConnectionManager | keyword |  |
| envoy.http.dynamodb.operation | Operation name for the Dynamo http filter | keyword |  |
| envoy.http.dynamodb.partition_id | Partition ID for the Dynamo http filter | keyword |  |
| envoy.http.dynamodb.table | Table name for the Dynamo http filter | keyword |  |
| envoy.http.fault_downstream_cluster | Downstream cluster for the Fault http filter | keyword |  |
| envoy.http.rbac.http_prefix | Stats prefix for the RBAC http filter | keyword |  |
| envoy.http.rbac.policy_name | Policy name for the RBAC http filter | keyword |  |
| envoy.http.rbac.prefix | Stats prefix for the RBAC network filter | keyword |  |
| envoy.http.rds.route_config | Route config name for RDS updates | keyword |  |
| envoy.http.rds.scoped_config | Scoped route config name for RDS updates | keyword |  |
| envoy.http.response_code_class | Request response code class | keyword |  |
| envoy.http.route | Request route given by the Router http filter | keyword |  |
| envoy.http.user_agent | User agent for a connection | keyword |  |
| envoy.listener.\*.count | Envoyproxy counters | object | counter |
| envoy.listener.\*.max | Envoyproxy max timers metric | object |  |
| envoy.listener.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.listener.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.listener.\*.median | Envoyproxy median timers metric | object |  |
| envoy.listener.\*.min | Envoyproxy min timers metric | object |  |
| envoy.listener.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.listener.\*.value | Envoyproxy gauges | object | gauge |
| envoy.listener.address | Listener port tag | keyword |  |
| envoy.listener.ssl.cipher | SSL cipher for a connection | keyword |  |
| envoy.listener.ssl.cipher_suite | SSL cipher suite | keyword |  |
| envoy.listener.ssl.clientssl_prefix | Stats prefix for the Client SSL Auth network filter | keyword |  |
| envoy.listener.ssl.curve | SSL curve for a connection | keyword |  |
| envoy.listener.ssl.sigalg | SSL signature algorithm for a connection | keyword |  |
| envoy.listener.ssl.version | SSL version for a connection | keyword |  |
| envoy.listener.worker_id | Listener manager worker id | keyword |  |
| envoy.local_http_ratelimit.\*.count | Envoyproxy counters | object | counter |
| envoy.local_http_ratelimit.\*.max | Envoyproxy max timers metric | object |  |
| envoy.local_http_ratelimit.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.local_http_ratelimit.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.local_http_ratelimit.\*.median | Envoyproxy median timers metric | object |  |
| envoy.local_http_ratelimit.\*.min | Envoyproxy min timers metric | object |  |
| envoy.local_http_ratelimit.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.local_http_ratelimit.\*.value | Envoyproxy gauges | object | gauge |
| envoy.local_http_ratelimit.prefix | Stats prefix for the Local Ratelimit network filter | keyword |  |
| envoy.local_listener_ratelimit.\*.count | Envoyproxy counters | object | counter |
| envoy.local_listener_ratelimit.\*.max | Envoyproxy max timers metric | object |  |
| envoy.local_listener_ratelimit.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.local_listener_ratelimit.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.local_listener_ratelimit.\*.median | Envoyproxy median timers metric | object |  |
| envoy.local_listener_ratelimit.\*.min | Envoyproxy min timers metric | object |  |
| envoy.local_listener_ratelimit.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.local_listener_ratelimit.\*.value | Envoyproxy gauges | object | gauge |
| envoy.local_listener_ratelimit.prefix | Stats prefix for the Local Ratelimit listener filter | keyword |  |
| envoy.local_network_ratelimit.\*.count | Envoyproxy counters | object | counter |
| envoy.local_network_ratelimit.\*.max | Envoyproxy max timers metric | object |  |
| envoy.local_network_ratelimit.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.local_network_ratelimit.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.local_network_ratelimit.\*.median | Envoyproxy median timers metric | object |  |
| envoy.local_network_ratelimit.\*.min | Envoyproxy min timers metric | object |  |
| envoy.local_network_ratelimit.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.local_network_ratelimit.\*.value | Envoyproxy gauges | object | gauge |
| envoy.local_network_ratelimit.prefix | Stats prefix for the Local Ratelimit network filter | keyword |  |
| envoy.mongo.\*.count | Envoyproxy counters | object | counter |
| envoy.mongo.\*.max | Envoyproxy max timers metric | object |  |
| envoy.mongo.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.mongo.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.mongo.\*.median | Envoyproxy median timers metric | object |  |
| envoy.mongo.\*.min | Envoyproxy min timers metric | object |  |
| envoy.mongo.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.mongo.\*.value | Envoyproxy gauges | object | gauge |
| envoy.mongo.callsite | Request callsite for the Mongo Proxy network filter | keyword |  |
| envoy.mongo.cmd | Request command for the Mongo Proxy network filter | keyword |  |
| envoy.mongo.collection | Request collection for the Mongo Proxy network filter | keyword |  |
| envoy.mongo.prefix | Stats prefix for the Mongo Proxy network filter | keyword |  |
| envoy.proxy_proto.\*.count | Envoyproxy counters | object | counter |
| envoy.proxy_proto.\*.max | Envoyproxy max timers metric | object |  |
| envoy.proxy_proto.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.proxy_proto.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.proxy_proto.\*.median | Envoyproxy median timers metric | object |  |
| envoy.proxy_proto.\*.min | Envoyproxy min timers metric | object |  |
| envoy.proxy_proto.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.proxy_proto.\*.value | Envoyproxy gauges | object | gauge |
| envoy.proxy_proto.prefix | Stats prefix for the proxy protocol listener filter. | keyword |  |
| envoy.proxy_proto.version | Proxy Protocol version for a connection (Proxy Protocol listener filter). | keyword |  |
| envoy.redis.\*.count | Envoyproxy counters | object | counter |
| envoy.redis.\*.max | Envoyproxy max timers metric | object |  |
| envoy.redis.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.redis.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.redis.\*.median | Envoyproxy median timers metric | object |  |
| envoy.redis.\*.min | Envoyproxy min timers metric | object |  |
| envoy.redis.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.redis.\*.value | Envoyproxy gauges | object | gauge |
| envoy.redis.prefix | Stats prefix for the Redis Proxy network filter | keyword |  |
| envoy.runtime.\*.count | Envoyproxy counters | object | counter |
| envoy.runtime.\*.max | Envoyproxy max timers metric | object |  |
| envoy.runtime.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.runtime.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.runtime.\*.median | Envoyproxy median timers metric | object |  |
| envoy.runtime.\*.min | Envoyproxy min timers metric | object |  |
| envoy.runtime.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.runtime.\*.value | Envoyproxy gauges | object | gauge |
| envoy.server.\*.count | Envoyproxy counters | object | counter |
| envoy.server.\*.max | Envoyproxy max timers metric | object |  |
| envoy.server.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.server.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.server.\*.median | Envoyproxy median timers metric | object |  |
| envoy.server.\*.min | Envoyproxy min timers metric | object |  |
| envoy.server.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.server.\*.value | Envoyproxy gauges | object | gauge |
| envoy.tcp.\*.count | Envoyproxy counters | object | counter |
| envoy.tcp.\*.max | Envoyproxy max timers metric | object |  |
| envoy.tcp.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.tcp.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.tcp.\*.median | Envoyproxy median timers metric | object |  |
| envoy.tcp.\*.min | Envoyproxy min timers metric | object |  |
| envoy.tcp.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.tcp.\*.value | Envoyproxy gauges | object | gauge |
| envoy.tcp.prefix | Stats prefix for the TCP Proxy network filter | keyword |  |
| envoy.thread_local_cluster_manager.\*.count | Envoyproxy counters | object | counter |
| envoy.thread_local_cluster_manager.\*.max | Envoyproxy max timers metric | object |  |
| envoy.thread_local_cluster_manager.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.thread_local_cluster_manager.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.thread_local_cluster_manager.\*.median | Envoyproxy median timers metric | object |  |
| envoy.thread_local_cluster_manager.\*.min | Envoyproxy min timers metric | object |  |
| envoy.thread_local_cluster_manager.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.thread_local_cluster_manager.\*.value | Envoyproxy gauges | object | gauge |
| envoy.thrift.\*.count | Envoyproxy counters | object | counter |
| envoy.thrift.\*.max | Envoyproxy max timers metric | object |  |
| envoy.thrift.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.thrift.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.thrift.\*.median | Envoyproxy median timers metric | object |  |
| envoy.thrift.\*.min | Envoyproxy min timers metric | object |  |
| envoy.thrift.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.thrift.\*.value | Envoyproxy gauges | object | gauge |
| envoy.thrift.prefix | Stats prefix for the Thrift Proxy network filter | keyword |  |
| envoy.tls_inspector.\*.count | Envoyproxy counters | object | counter |
| envoy.tls_inspector.\*.max | Envoyproxy max timers metric | object |  |
| envoy.tls_inspector.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.tls_inspector.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.tls_inspector.\*.median | Envoyproxy median timers metric | object |  |
| envoy.tls_inspector.\*.min | Envoyproxy min timers metric | object |  |
| envoy.tls_inspector.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.tls_inspector.\*.value | Envoyproxy gauges | object | gauge |
| envoy.udp.\*.count | Envoyproxy counters | object | counter |
| envoy.udp.\*.max | Envoyproxy max timers metric | object |  |
| envoy.udp.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.udp.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.udp.\*.median | Envoyproxy median timers metric | object |  |
| envoy.udp.\*.min | Envoyproxy min timers metric | object |  |
| envoy.udp.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.udp.\*.value | Envoyproxy gauges | object | gauge |
| envoy.udp.prefix | Stats prefix for the UDP Proxy network filter | keyword |  |
| envoy.vhost.\*.count | Envoyproxy counters | object | counter |
| envoy.vhost.\*.max | Envoyproxy max timers metric | object |  |
| envoy.vhost.\*.mean | Envoyproxy mean timers metric | object |  |
| envoy.vhost.\*.mean_rate | Envoyproxy mean rate timers metric | object |  |
| envoy.vhost.\*.median | Envoyproxy median timers metric | object |  |
| envoy.vhost.\*.min | Envoyproxy min timers metric | object |  |
| envoy.vhost.\*.stddev | Envoyproxy standard deviation timers metric | object |  |
| envoy.vhost.\*.value | Envoyproxy gauges | object | gauge |
| envoy.vhost.cluster | Request virtual cluster given by the Router http filter | keyword |  |
| envoy.vhost.host | Request virtual host given by the Router http filter | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| input.type | Type of Filebeat input. | keyword |  |
| log.offset | Log offset. | long |  |
| service.address | Service address | keyword |  |
| tags | User defined tags. | keyword |  |

