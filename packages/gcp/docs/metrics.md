# Google Cloud Project Metrics Integration

The Google Cloud Project Metrics integration collects and parses Google Cloud billing, compute, storage metrics.

## Metrics

### Billing

This is the `billing` dataset.

An example event for `billing` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "01475F-5B1080-1137E7"
        },
        "project": {
            "id": "elastic-bi",
            "name": "elastic-containerlib-prod"
        },
        "provider": "gcp"
    },
    "event": {
        "dataset": "gcp.billing",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "billing": {
            "billing_account_id": "01475F-5B1080-1137E7",
            "cost_type": "regular",
            "invoice_month": "202106",
            "project_id": "containerlib-prod-12763",
            "project_name": "elastic-containerlib-prod",
            "total": 4717.170681
        }
    },
    "metricset": {
        "name": "billing",
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
| gcp.billing.cost_type | Cost types include regular, tax, adjustment, and rounding_error. | keyword |
| gcp.billing.invoice_month | Billing report month. | keyword |
| gcp.billing.project_id | Project ID of the billing report belongs to. | keyword |
| gcp.billing.total | Total billing amount. | float |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### Compute

This is the `compute` dataset.

An example event for `compute` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-observability",
            "name": "elastic-observability"
        },
        "instance": {
            "id": "1113015278728017638",
            "name": "gke-apm-ci-k8s-cluster-pool-2-e8852348-58mx"
        },
        "provider": "gcp",
        "availability_zone": "us-central1-c",
        "region": "us-central1"
    },
    "event": {
        "dataset": "gcp.compute",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "compute": {
            "instance": {
                "disk": {
                    "read_bytes_count": {
                        "value": 989296850
                    },
                    "read_ops_count": {
                        "value": 14862
                    },
                    "write_bytes_count": {
                        "value": 1323095
                    },
                    "write_ops_count": {
                        "value": 105
                    }
                }
            }
        },
        "labels": {
            "metrics": {
                "device_name": "gke-apm-ci-k8s-cluster-pool-2-e8852348-58mx",
                "device_type": "permanent",
                "storage_type": "pd-standard"
            }
        }
    },
    "host": {
        "disk": {
            "read": {
                "bytes": 989296850
            },
            "write": {
                "bytes": 1323095
            }
        },
        "id": "1113015278728017638",
        "name": "gke-apm-ci-k8s-cluster-pool-2-e8852348-58mx"
    },
    "metricset": {
        "name": "compute",
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
| cloud.region | Region in which this host, resource, or service is located. | keyword |
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
| gcp.compute.instance.cpu.reserved_cores.value | Number of cores reserved on the host of the instance | double |
| gcp.compute.instance.cpu.usage_time.value | Usage for all cores in seconds | double |
| gcp.compute.instance.cpu.utilization.value | The fraction of the allocated CPU that is currently in use on the instance | double |
| gcp.compute.instance.disk.read_bytes_count.value | Count of bytes read from disk | long |
| gcp.compute.instance.disk.read_ops_count.value | Count of disk read IO operations | long |
| gcp.compute.instance.disk.write_bytes_count.value | Count of bytes written to disk | long |
| gcp.compute.instance.disk.write_ops_count.value | Count of disk write IO operations | long |
| gcp.compute.instance.firewall.dropped_bytes_count.value | Incoming bytes dropped by the firewall | long |
| gcp.compute.instance.firewall.dropped_packets_count.value | Incoming packets dropped by the firewall | long |
| gcp.compute.instance.memory.balloon.ram_size.value | The total amount of memory in the VM. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.memory.balloon.ram_used.value | Memory currently used in the VM. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.memory.balloon.swap_in_bytes_count.value | The amount of memory read into the guest from its own swap space. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.memory.balloon.swap_out_bytes_count.value | The amount of memory written from the guest to its own swap space. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.network.received_bytes_count.value | Count of bytes received from the network | long |
| gcp.compute.instance.network.received_packets_count.value | Count of packets received from the network | long |
| gcp.compute.instance.network.sent_bytes_count.value | Count of bytes sent over the network | long |
| gcp.compute.instance.network.sent_packets_count.value | Count of packets sent over the network | long |
| gcp.compute.instance.uptime.value | How long the VM has been running, in seconds | long |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### GKE

This is the `gke` dataset.

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
| cloud.region | Region in which this host, resource, or service is located. | keyword |
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
| gcp.compute.instance.cpu.reserved_cores.value | Number of cores reserved on the host of the instance | double |
| gcp.compute.instance.cpu.usage_time.value | Usage for all cores in seconds | double |
| gcp.compute.instance.cpu.utilization.value | The fraction of the allocated CPU that is currently in use on the instance | double |
| gcp.compute.instance.disk.read_bytes_count.value | Count of bytes read from disk | long |
| gcp.compute.instance.disk.read_ops_count.value | Count of disk read IO operations | long |
| gcp.compute.instance.disk.write_bytes_count.value | Count of bytes written to disk | long |
| gcp.compute.instance.disk.write_ops_count.value | Count of disk write IO operations | long |
| gcp.compute.instance.firewall.dropped_bytes_count.value | Incoming bytes dropped by the firewall | long |
| gcp.compute.instance.firewall.dropped_packets_count.value | Incoming packets dropped by the firewall | long |
| gcp.compute.instance.memory.balloon.ram_size.value | The total amount of memory in the VM. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.memory.balloon.ram_used.value | Memory currently used in the VM. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.memory.balloon.swap_in_bytes_count.value | The amount of memory read into the guest from its own swap space. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.memory.balloon.swap_out_bytes_count.value | The amount of memory written from the guest to its own swap space. This metric is only available for VMs that belong to the e2 family. | long |
| gcp.compute.instance.network.received_bytes_count.value | Count of bytes received from the network | long |
| gcp.compute.instance.network.received_packets_count.value | Count of packets received from the network | long |
| gcp.compute.instance.network.sent_bytes_count.value | Count of bytes sent over the network | long |
| gcp.compute.instance.network.sent_packets_count.value | Count of packets sent over the network | long |
| gcp.compute.instance.uptime.value | How long the VM has been running, in seconds | long |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### Load Balancing

This is the `loadbalancing` dataset.

An example event for `loadbalancing` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-observability"
        },
        "provider": "gcp"
    },
    "event": {
        "dataset": "gcp.loadbalancing",
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
                    "egress_packets_count": {
                        "value": 0
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
| gcp.loadbalancing.https.backend_request_bytes_count.value | The number of bytes sent as requests from HTTP/S load balancer to backends. | long |
| gcp.loadbalancing.https.backend_request_count.value | The number of requests served by backends of HTTP/S load balancer. | long |
| gcp.loadbalancing.https.request_bytes_count.value | The number of bytes sent as requests from clients to HTTP/S load balancer. | long |
| gcp.loadbalancing.https.request_count.value | The number of requests served by HTTP/S load balancer. | long |
| gcp.loadbalancing.https.response_bytes_count.value | The number of bytes sent as responses from HTTP/S load balancer to clients. | long |
| gcp.loadbalancing.l3.internal.egress_bytes_count.value | The number of bytes sent from ILB backend to client (for TCP flows it's counting bytes on application stream only). | long |
| gcp.loadbalancing.l3.internal.egress_packets_count.value | The number of packets sent from ILB backend to client of the flow. | long |
| gcp.loadbalancing.l3.internal.ingress_bytes_count.value | The number of bytes sent from client to ILB backend (for TCP flows it's counting bytes on application stream only). | long |
| gcp.loadbalancing.l3.internal.ingress_packets_count.value | The number of packets sent from client to ILB backend. | long |
| gcp.loadbalancing.tcp_ssl_proxy.closed_connections.value | Number of connections that were terminated over TCP/SSL proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.egress_bytes_count.value | Number of bytes sent from VM to client using proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.ingress_bytes_count.value | Number of bytes sent from client to VM using proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.new_connections.value | Number of connections that were created over TCP/SSL proxy. | long |
| gcp.loadbalancing.tcp_ssl_proxy.open_connections.value | Current number of outstanding connections through the TCP/SSL proxy. | long |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### PubSub

This is the `pubsub` dataset.

An example event for `pubsub` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-observability"
        },
        "provider": "gcp"
    },
    "event": {
        "dataset": "gcp.pubsub",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "labels": {
            "resource": {
                "subscription_id": "test-subscription-1"
            }
        },
        "pubsub": {
            "subscription": {
                "backlog_bytes": {
                    "value": 0
                }
            }
        }
    },
    "metricset": {
        "name": "pubsub",
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
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
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
| gcp.pubsub.snapshot.backlog_bytes.value | Total byte size of the messages retained in a snapshot. | long |
| gcp.pubsub.snapshot.backlog_bytes_by_region.value | Total byte size of the messages retained in a snapshot, broken down by Cloud region. | long |
| gcp.pubsub.snapshot.config_updates_count.value | Cumulative count of configuration changes, grouped by operation type and result. | long |
| gcp.pubsub.snapshot.num_messages.value | Number of messages retained in a snapshot. | long |
| gcp.pubsub.snapshot.num_messages_by_region.value | Number of messages retained in a snapshot, broken down by Cloud region. | long |
| gcp.pubsub.snapshot.oldest_message_age.value | Age (in seconds) of the oldest message retained in a snapshot. | long |
| gcp.pubsub.snapshot.oldest_message_age_by_region.value | Age (in seconds) of the oldest message retained in a snapshot, broken down by Cloud region. | long |
| gcp.pubsub.subscription.ack_message_count.value | Cumulative count of messages acknowledged by Acknowledge requests, grouped by delivery type. | long |
| gcp.pubsub.subscription.backlog_bytes.value | Total byte size of the unacknowledged messages (a.k.a. backlog messages) in a subscription. | long |
| gcp.pubsub.subscription.byte_cost.value | Cumulative cost of operations, measured in bytes. This is used to measure quota utilization. | long |
| gcp.pubsub.subscription.config_updates_count.value | Cumulative count of configuration changes for each subscription, grouped by operation type and result. | long |
| gcp.pubsub.subscription.dead_letter_message_count.value | Cumulative count of messages published to dead letter topic, grouped by result. | long |
| gcp.pubsub.subscription.mod_ack_deadline_message_count.value | Cumulative count of messages whose deadline was updated by ModifyAckDeadline requests, grouped by delivery type. | long |
| gcp.pubsub.subscription.mod_ack_deadline_message_operation_count.value | Cumulative count of ModifyAckDeadline message operations, grouped by result. | long |
| gcp.pubsub.subscription.mod_ack_deadline_request_count.value | Cumulative count of ModifyAckDeadline requests, grouped by result. | long |
| gcp.pubsub.subscription.num_outstanding_messages.value | Number of messages delivered to a subscription's push endpoint, but not yet acknowledged. | long |
| gcp.pubsub.subscription.num_undelivered_messages.value | Number of unacknowledged messages (a.k.a. backlog messages) in a subscription. | long |
| gcp.pubsub.subscription.oldest_retained_acked_message_age.value | Age (in seconds) of the oldest acknowledged message retained in a subscription. | long |
| gcp.pubsub.subscription.oldest_retained_acked_message_age_by_region.value | Age (in seconds) of the oldest acknowledged message retained in a subscription, broken down by Cloud region. | long |
| gcp.pubsub.subscription.oldest_unacked_message_age.value | Age (in seconds) of the oldest unacknowledged message (a.k.a. backlog message) in a subscription. | long |
| gcp.pubsub.subscription.oldest_unacked_message_age_by_region.value | Age (in seconds) of the oldest unacknowledged message in a subscription, broken down by Cloud region. | long |
| gcp.pubsub.subscription.pull_ack_message_operation_count.value | Cumulative count of acknowledge message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long |
| gcp.pubsub.subscription.pull_ack_request_count.value | Cumulative count of acknowledge requests, grouped by result. | long |
| gcp.pubsub.subscription.pull_message_operation_count.value | Cumulative count of pull message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long |
| gcp.pubsub.subscription.pull_request_count.value | Cumulative count of pull requests, grouped by result. | long |
| gcp.pubsub.subscription.push_request_count.value | Cumulative count of push attempts, grouped by result. Unlike pulls, the push server implementation does not batch user messages. So each request only contains one user message. The push server retries on errors, so a given user message can appear multiple times. | long |
| gcp.pubsub.subscription.push_request_latencies.value | Distribution of push request latencies (in microseconds), grouped by result. | long |
| gcp.pubsub.subscription.retained_acked_bytes.value | Total byte size of the acknowledged messages retained in a subscription. | long |
| gcp.pubsub.subscription.retained_acked_bytes_by_region.value | Total byte size of the acknowledged messages retained in a subscription, broken down by Cloud region. | long |
| gcp.pubsub.subscription.seek_request_count.value | Cumulative count of seek attempts, grouped by result. | long |
| gcp.pubsub.subscription.sent_message_count.value | Cumulative count of messages sent by Cloud Pub/Sub to subscriber clients, grouped by delivery type. | long |
| gcp.pubsub.subscription.streaming_pull_ack_message_operation_count.value | Cumulative count of StreamingPull acknowledge message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long |
| gcp.pubsub.subscription.streaming_pull_ack_request_count.value | Cumulative count of streaming pull requests with non-empty acknowledge ids, grouped by result. | long |
| gcp.pubsub.subscription.streaming_pull_message_operation_count.value | Cumulative count of streaming pull message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric \<code\>subscription/mod_ack_deadline_message_operation_count | long |
| gcp.pubsub.subscription.streaming_pull_mod_ack_deadline_message_operation_count.value | Cumulative count of StreamingPull ModifyAckDeadline operations, grouped by result. | long |
| gcp.pubsub.subscription.streaming_pull_mod_ack_deadline_request_count.value | Cumulative count of streaming pull requests with non-empty ModifyAckDeadline fields, grouped by result. | long |
| gcp.pubsub.subscription.streaming_pull_response_count.value | Cumulative count of streaming pull responses, grouped by result. | long |
| gcp.pubsub.subscription.unacked_bytes_by_region.value | Total byte size of the unacknowledged messages in a subscription, broken down by Cloud region. | long |
| gcp.pubsub.topic.byte_cost.value | Cost of operations, measured in bytes. This is used to measure utilization for quotas. | long |
| gcp.pubsub.topic.config_updates_count.value | Cumulative count of configuration changes, grouped by operation type and result. | long |
| gcp.pubsub.topic.message_sizes.value | Distribution of publish message sizes (in bytes) | long |
| gcp.pubsub.topic.oldest_retained_acked_message_age_by_region.value | Age (in seconds) of the oldest acknowledged message retained in a topic, broken down by Cloud region. | long |
| gcp.pubsub.topic.oldest_unacked_message_age_by_region.value | Age (in seconds) of the oldest unacknowledged message in a topic, broken down by Cloud region. | long |
| gcp.pubsub.topic.retained_acked_bytes_by_region.value | Total byte size of the acknowledged messages retained in a topic, broken down by Cloud region. | long |
| gcp.pubsub.topic.send_message_operation_count.value | Cumulative count of publish message operations, grouped by result. For a definition of message operations, see Cloud Pub/Sub metric subscription/mod_ack_deadline_message_operation_count. | long |
| gcp.pubsub.topic.send_request_count.value | Cumulative count of publish requests, grouped by result. | long |
| gcp.pubsub.topic.streaming_pull_response_count.value | Cumulative count of streaming pull responses, grouped by result. | long |
| gcp.pubsub.topic.unacked_bytes_by_region.value | Total byte size of the unacknowledged messages in a topic, broken down by Cloud region. | long |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### Metrics

This is the `metrics` dataset.

An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-observability",
            "name": "elastic-observability"
        },
        "instance": {
            "id": "4049989596327614796",
            "name": "nchaulet-loadtest-horde-master"
        },
        "machine": {
            "type": "n1-standard-8"
        },
        "provider": "gcp"
    },
    "cloud.availability_zone": "us-central1-a",
    "cloud.region": "us-central1",
    "event": {
        "dataset": "gcp.metrics",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "labels": {},
        "metrics": {
            "instance": {
                "uptime_total": {
                    "value": 791820
                }
            }
        }
    },
    "host": {
        "id": "4049989596327614796",
        "name": "nchaulet-loadtest-horde-master"
    },
    "metricset": {
        "name": "metrics",
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
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### Storage

This is the `storage` dataset.

An example event for `storage` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-observability"
        },
        "provider": "gcp"
    },
    "event": {
        "dataset": "gcp.storage",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "labels": {
            "metrics": {
                "storage_class": "MULTI_REGIONAL"
            },
            "resource": {
                "bucket_name": "fstuermer-log-data-categorization-7-6-0",
                "location": "us"
            }
        },
        "storage": {
            "storage": {
                "total_bytes": {
                    "value": 4472520191
                }
            }
        }
    },
    "metricset": {
        "name": "storage",
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
| cloud.region | Region in which this host, resource, or service is located. | keyword |
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
| gcp.storage.api.request_count.value | Delta count of API calls, grouped by the API method name and response code. | long |
| gcp.storage.authz.acl_based_object_access_count.value | Delta count of requests that result in an object being granted access solely due to object ACLs. | long |
| gcp.storage.authz.acl_operations_count.value | Usage of ACL operations broken down by type. | long |
| gcp.storage.authz.object_specific_acl_mutation_count.value | Delta count of changes made to object specific ACLs. | long |
| gcp.storage.network.received_bytes_count.value | Delta count of bytes received over the network, grouped by the API method name and response code. | long |
| gcp.storage.network.sent_bytes_count.value | Delta count of bytes sent over the network, grouped by the API method name and response code. | long |
| gcp.storage.storage.object_count.value | Total number of objects per bucket, grouped by storage class. This value is measured once per day, and the value is repeated at each sampling interval throughout the day. | long |
| gcp.storage.storage.total_byte_seconds.value | Delta count of bytes received over the network, grouped by the API method name and response code. | long |
| gcp.storage.storage.total_bytes.value | Total size of all objects in the bucket, grouped by storage class. This value is measured once per day, and the value is repeated at each sampling interval throughout the day. | long |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |

