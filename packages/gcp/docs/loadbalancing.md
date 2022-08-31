# Load Balancing

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
        "loadbalancing": {
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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |
| error.message | Error message. | match_only_text |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gcp.labels.metadata.\* |  | object |
| gcp.labels.metrics.\* |  | object |
| gcp.labels.resource.\* |  | object |
| gcp.labels.system.\* |  | object |
| gcp.labels.user.\* |  | object |
| gcp.loadbalancing.https.backend_request.bytes | The number of bytes sent as requests from HTTP/S load balancer to backends. | long |
| gcp.loadbalancing.https.backend_request.count | The number of requests served by backends of HTTP/S load balancer. | long |
| gcp.loadbalancing.https.backend_response.bytes | The number of bytes sent as responses from backends (or cache) to external HTTP(S) load balancer. | long |
| gcp.loadbalancing.https.request.bytes | The number of bytes sent as requests from clients to HTTP/S load balancer. | long |
| gcp.loadbalancing.https.request.count | The number of requests served by HTTP/S load balancer. | long |
| gcp.loadbalancing.https.response.bytes | The number of bytes sent as responses from HTTP/S load balancer to clients. | long |
| gcp.loadbalancing.l3.external.egress.bytes | The number of bytes sent from external TCP/UDP network load balancer backend to client of the flow. For TCP flows it's counting bytes on application stream only. | long |
| gcp.loadbalancing.l3.external.egress_packets.count | The number of packets sent from external TCP/UDP network load balancer backend to client of the flow. | long |
| gcp.loadbalancing.l3.external.ingress.bytes | The number of bytes sent from client to external TCP/UDP network load balancer backend. For TCP flows it's counting bytes on application stream only. | long |
| gcp.loadbalancing.l3.external.ingress_packets.count | The number of packets sent from client to external TCP/UDP network load balancer backend. | long |
| gcp.loadbalancing.l3.internal.egress.bytes | The number of bytes sent from ILB backend to client (for TCP flows it's counting bytes on application stream only). | long |
| gcp.loadbalancing.l3.internal.egress_packets.count | The number of packets sent from ILB backend to client of the flow. | long |
| gcp.loadbalancing.l3.internal.ingress.bytes | The number of bytes sent from client to ILB backend (for TCP flows it's counting bytes on application stream only). | long |
| gcp.loadbalancing.l3.internal.ingress_packets.count | The number of packets sent from client to ILB backend. | long |
| gcp.loadbalancing.tcp_ssl_proxy.closed_connections.value | Number of connections that were terminated over TCP/SSL proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.egress.bytes | Number of bytes sent from VM to client using proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.ingress.bytes | Number of bytes sent from client to VM using proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.new_connections.value | Number of connections that were created over TCP/SSL proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.open_connections.value | Current number of outstanding connections through the TCP/SSL proxy. | long |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
