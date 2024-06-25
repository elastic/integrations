# Load Balancing

## Logs

The `loadbalancing_logs` dataset collects logs of the requests sent to and handled by GCP Load Balancers.

An example event for `loadbalancing` looks as following:

```json
{
    "@timestamp": "2020-06-08T23:41:30.078Z",
    "agent": {
        "ephemeral_id": "f4dde373-2ff7-464b-afdb-da94763f219b",
        "id": "5d3eee86-91a9-4afa-af92-c6b79bd866c0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.0"
    },
    "cloud": {
        "project": {
            "id": "PROJECT_ID"
        },
        "region": "global"
    },
    "data_stream": {
        "dataset": "gcp.loadbalancing_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "81.2.69.193",
        "ip": "81.2.69.193",
        "nat": {
            "ip": "10.5.3.1",
            "port": 9090
        },
        "port": 8080
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5d3eee86-91a9-4afa-af92-c6b79bd866c0",
        "snapshot": true,
        "version": "8.6.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "created": "2020-06-08T23:41:30.588Z",
        "dataset": "gcp.loadbalancing_logs",
        "id": "1oek5rg3l3fxj7",
        "ingested": "2023-01-13T15:02:22Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "gcp": {
        "load_balancer": {
            "backend_service_name": "",
            "cache_hit": true,
            "cache_id": "SFO-fbae48ad",
            "cache_lookup": true,
            "forwarding_rule_name": "FORWARDING_RULE_NAME",
            "status_details": "response_from_cache",
            "target_proxy_name": "TARGET_PROXY_NAME",
            "url_map_name": "URL_MAP_NAME"
        }
    },
    "http": {
        "request": {
            "bytes": 577,
            "method": "GET",
            "referrer": "https://developer.mozilla.org/en-US/docs/Web/JavaScript"
        },
        "response": {
            "bytes": 157,
            "status_code": 304
        },
        "version": "2.0"
    },
    "input": {
        "type": "gcp-pubsub"
    },
    "log": {
        "level": "INFO",
        "logger": "projects/PROJECT_ID/logs/requests"
    },
    "network": {
        "protocol": "http"
    },
    "related": {
        "ip": [
            "89.160.20.156",
            "81.2.69.193",
            "10.5.3.1"
        ]
    },
    "source": {
        "address": "89.160.20.156",
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.156",
        "port": 9989
    },
    "tags": [
        "forwarded",
        "gcp-loadbalancing_logs"
    ],
    "url": {
        "domain": "81.2.69.193",
        "extension": "jpg",
        "original": "http://81.2.69.193:8080/static/us/three-cats.jpg",
        "path": "/static/us/three-cats.jpg",
        "port": 8080,
        "scheme": "http"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.14.6",
            "name": "Mac OS X",
            "version": "10.14.6"
        },
        "version": "83.0.4103.61"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gcp.load_balancer.backend_service_name | The backend service to which the load balancer is sending traffic | keyword |
| gcp.load_balancer.cache_hit | Whether or not an entity was served from cache (with or without validation). | boolean |
| gcp.load_balancer.cache_id | Indicates the location and cache instance that the cache response was served from. For example, a cache response served from a cache in Amsterdam would have a cacheId value of AMS-85e2bd4b, where AMS is the IATA code, and 85e2bd4b is an opaque identifier of the cache instance  (because some Cloud CDN locations have multiple discrete caches). | keyword |
| gcp.load_balancer.cache_lookup | Whether or not a cache lookup was attempted. | boolean |
| gcp.load_balancer.forwarding_rule_name | The name of the forwarding rule | keyword |
| gcp.load_balancer.status_details | Explains why the load balancer returned the HTTP status that it did. See https://cloud.google.com/cdn/docs/cdn-logging-monitoring#statusdetail_http_success_messages for specific messages. | keyword |
| gcp.load_balancer.target_proxy_name | The target proxy name | keyword |
| gcp.load_balancer.url_map_name | The URL map name | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


## Metrics

The `loadbalancing_metrics` dataset fetches HTTPS, HTTP, and Layer 3 metrics from [Load Balancing](https://cloud.google.com/load-balancing/) in Google Cloud Platform. It contains all metrics exported from the [GCP Load Balancing Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-loadbalancing).

An example event for `loadbalancing` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-observability"
        },
        "provider": "gcp",
        "region": "us-central1",
        "availability_zone": "us-central1-a"
    },
    "event": {
        "dataset": "gcp.loadbalancing_metrics",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "labels": {
            "metrics": {
                "client_network": "ocp-be-c5kjr-network",
                "client_subnetwork": "ocp-be-c5kjr-worker-subnet",
                "client_zone": "us-central1-a"
            },
            "resource": {
                "backend_name": "ocp-be-c5kjr-master-us-central1-a",
                "backend_scope": "us-central1-a",
                "backend_scope_type": "ZONE",
                "backend_subnetwork_name": "ocp-be-c5kjr-master-subnet",
                "backend_target_name": "ocp-be-c5kjr-api-internal",
                "backend_target_type": "BACKEND_SERVICE",
                "backend_type": "INSTANCE_GROUP",
                "forwarding_rule_name": "ocp-be-c5kjr-api-internal",
                "load_balancer_name": "ocp-be-c5kjr-api-internal",
                "network_name": "ocp-be-c5kjr-network",
                "region": "us-central1"
            }
        },
        "loadbalancing_metrics": {
            "l3": {
                "internal": {
                    "egress_packets": {
                        "count": 100
                    },
                    "egress": {
                        "bytes": 1247589
                    }
                }
            }
        }
    },
    "metricset": {
        "name": "loadbalancing",
        "period": 10000
    },
    "service": {
        "type": "gcp"
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
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| gcp.labels.metadata.\* |  | object |  |
| gcp.labels.metrics.\* |  | object |  |
| gcp.labels.resource.\* |  | object |  |
| gcp.labels.system.\* |  | object |  |
| gcp.labels.user.\* |  | object |  |
| gcp.labels_fingerprint | Hashed value of the labels field. | keyword |  |
| gcp.loadbalancing_metrics.https.backend_latencies.value | A distribution of the latency calculated from when the request was sent by the proxy to the backend until the proxy received from the backend the last byte of response. | object |  |
| gcp.loadbalancing_metrics.https.backend_request.bytes | Delta of the number of bytes sent as requests from HTTP/S load balancer to backends. | long | gauge |
| gcp.loadbalancing_metrics.https.backend_request.count | Delta of the number of requests served by backends of HTTP/S load balancer. | long | gauge |
| gcp.loadbalancing_metrics.https.backend_response.bytes | Delta of the number of bytes sent as responses from backends (or cache) to external HTTP(S) load balancer. | long | gauge |
| gcp.loadbalancing_metrics.https.external.regional.backend_latencies.value | A distribution of the latency calculated from when the request was sent by the proxy to the backend until the proxy received from the backend the last byte of response. | object |  |
| gcp.loadbalancing_metrics.https.external.regional.total_latencies.value | A distribution of the latency calculated from when the request was received by the proxy until the proxy got ACK from client on last response byte. | object |  |
| gcp.loadbalancing_metrics.https.frontend_tcp_rtt.value | A distribution of the RTT measured for each connection between client and proxy. | object |  |
| gcp.loadbalancing_metrics.https.internal.backend_latencies.value | A distribution of the latency calculated from when the request was sent by the internal HTTP/S load balancer proxy to the backend until the proxy received from the backend the last byte of response. | object |  |
| gcp.loadbalancing_metrics.https.internal.total_latencies.value | A distribution of the latency calculated from when the request was received by the internal HTTP/S load balancer proxy until the proxy got ACK from client on last response byte. | object |  |
| gcp.loadbalancing_metrics.https.request.bytes | Delta of the number of bytes sent as requests from clients to HTTP/S load balancer. | long | gauge |
| gcp.loadbalancing_metrics.https.request.count | Delta of the number of requests served by HTTP/S load balancer. | long | gauge |
| gcp.loadbalancing_metrics.https.response.bytes | Delta of the number of bytes sent as responses from HTTP/S load balancer to clients. | long | gauge |
| gcp.loadbalancing_metrics.https.total_latencies.value | A distribution of the latency calculated from when the request was received by the external HTTP/S load balancer proxy until the proxy got ACK from client on last response byte. | object |  |
| gcp.loadbalancing_metrics.l3.external.egress.bytes | Delta of the number of bytes sent from external TCP/UDP network load balancer backend to client of the flow. For TCP flows it's counting bytes on application stream only. | long | gauge |
| gcp.loadbalancing_metrics.l3.external.egress_packets.count | Delta of the number of packets sent from external TCP/UDP network load balancer backend to client of the flow. | long | gauge |
| gcp.loadbalancing_metrics.l3.external.ingress.bytes | Delta of the number of bytes sent from client to external TCP/UDP network load balancer backend. For TCP flows it's counting bytes on application stream only. | long | gauge |
| gcp.loadbalancing_metrics.l3.external.ingress_packets.count | Delta of the number of packets sent from client to external TCP/UDP network load balancer backend. | long | gauge |
| gcp.loadbalancing_metrics.l3.external.rtt_latencies.value | A distribution of the round trip time latency, measured over TCP connections for the external network load balancer. | object |  |
| gcp.loadbalancing_metrics.l3.internal.egress.bytes | Delta of the number of bytes sent from ILB backend to client (for TCP flows it's counting bytes on application stream only). | long | gauge |
| gcp.loadbalancing_metrics.l3.internal.egress_packets.count | Delta of the number of packets sent from ILB backend to client of the flow. | long | gauge |
| gcp.loadbalancing_metrics.l3.internal.ingress.bytes | Delta of the number of bytes sent from client to ILB backend (for TCP flows it's counting bytes on application stream only). | long | gauge |
| gcp.loadbalancing_metrics.l3.internal.ingress_packets.count | Delta of the number of packets sent from client to ILB backend. | long | gauge |
| gcp.loadbalancing_metrics.l3.internal.rtt_latencies.value | A distribution of RTT measured over TCP connections for internal TCP/UDP load balancer flows. | object |  |
| gcp.loadbalancing_metrics.tcp_ssl_proxy.closed_connections.value | Delta of the number of connections that were terminated over TCP/SSL proxy. | long | gauge |
| gcp.loadbalancing_metrics.tcp_ssl_proxy.egress.bytes | Delta of the number of bytes sent from VM to client using proxy. | long | gauge |
| gcp.loadbalancing_metrics.tcp_ssl_proxy.frontend_tcp_rtt.value | A distribution of the smoothed RTT (in ms) measured by the proxy's TCP stack, each minute application layer bytes pass from proxy to client. | object |  |
| gcp.loadbalancing_metrics.tcp_ssl_proxy.ingress.bytes | Delta of the number of bytes sent from client to VM using proxy. | long | gauge |
| gcp.loadbalancing_metrics.tcp_ssl_proxy.new_connections.value | Delta of the number of connections that were created over TCP/SSL proxy. | long | gauge |
| gcp.loadbalancing_metrics.tcp_ssl_proxy.open_connections.value | Current number of outstanding connections through the TCP/SSL proxy. | long | gauge |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
