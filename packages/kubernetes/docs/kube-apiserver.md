# kube-apiserver

## Metrics

### apiserver

This is the `apiserver` dataset of the Kubernetes package, in charge of retrieving metrics
from the Kubernetes API (available at `/metrics`).

This metricset needs access to the `apiserver` component of Kubernetes, accessible typically
by any POD via the `kubernetes.default` service or via environment
variables (`KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT`).

If Leader Election is activated (default behaviour) only the `elastic agent` which holds the leadership lock
will retrieve metrics from the `apiserver`.
This is relevant in multi-node kubernetes cluster and prevents duplicate data.

When the API uses https, the pod will need to authenticate using its default token and trust
the server using the appropriate CA file.

Configuration example using https and token based authentication:


In order to access the `/metrics` path of the API service, some Kubernetes environments might
require the following permission to be added to a ClusterRole.

```yaml
rules:
- nonResourceURLs:
  - /metrics
  verbs:
  - get
```

An example event for `apiserver` looks as following:

```json
{
    "kubernetes": {
        "apiserver": {
            "request": {
                "duration": {
                    "us": {
                        "bucket": {
                            "50000": 22,
                            "100000": 22,
                            "150000": 22,
                            "200000": 22,
                            "250000": 22,
                            "300000": 22,
                            "350000": 22,
                            "400000": 22,
                            "450000": 22,
                            "500000": 22,
                            "600000": 22,
                            "700000": 22,
                            "800000": 22,
                            "900000": 22,
                            "1000000": 22,
                            "1250000": 22,
                            "1500000": 22,
                            "1750000": 22,
                            "2000000": 22,
                            "2500000": 22,
                            "3000000": 22,
                            "3500000": 22,
                            "4000000": 22,
                            "4500000": 22,
                            "5000000": 22,
                            "6000000": 22,
                            "7000000": 22,
                            "8000000": 22,
                            "9000000": 22,
                            "10000000": 22,
                            "15000000": 22,
                            "20000000": 22,
                            "25000000": 22,
                            "30000000": 22,
                            "40000000": 22,
                            "50000000": 22,
                            "60000000": 22,
                            "+Inf": 22
                        },
                        "count": 22,
                        "sum": 110989.42699999998
                    }
                },
                "component": "apiserver",
                "resource": "roles",
                "scope": "resource",
                "verb": "DELETE",
                "version": "v1",
                "group": "rbac.authorization.k8s.io"
            }
        }
    },
    "agent": {
        "name": "kind-control-plane",
        "id": "d5aadb7a-c9ec-4563-b83a-1c4bb5f1471f",
        "ephemeral_id": "7ae929a5-2943-43de-98e8-693dc0c381d7",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "@timestamp": "2022-07-27T08:47:36.182Z",
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "address": "https://10.96.0.1:443/metrics",
        "type": "kubernetes"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "kubernetes.apiserver"
    },
    "elastic_agent": {
        "id": "d5aadb7a-c9ec-4563-b83a-1c4bb5f1471f",
        "version": "8.4.0",
        "snapshot": false
    },
    "host": {
        "hostname": "kind-control-plane",
        "os": {
            "kernel": "5.10.47-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "family": "debian",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": true,
        "ip": [
            "10.244.0.1",
            "10.244.0.1",
            "10.244.0.1",
            "10.244.0.1",
            "10.244.0.1",
            "172.23.0.2",
            "172.18.0.2",
            "fc00:f853:ccd:e793::2",
            "fe80::42:acff:fe12:2"
        ],
        "name": "kind-control-plane",
        "mac": [
            "02:42:ac:12:00:02",
            "02:42:ac:17:00:02",
            "06:9c:33:01:a5:e7",
            "06:f8:26:c9:76:70",
            "0e:c0:30:20:74:c5",
            "76:48:b8:c1:a7:ee",
            "d6:f7:d3:28:f5:9c"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 30000,
        "name": "apiserver"
    },
    "event": {
        "duration": 253700715,
        "agent_id_status": "verified",
        "ingested": "2022-07-27T08:47:36Z",
        "module": "kubernetes",
        "dataset": "kubernetes.apiserver"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| kubernetes.apiserver.audit.event.count | Number of audit events | long |  | counter |
| kubernetes.apiserver.audit.rejected.count | Number of audit rejected events | long |  | counter |
| kubernetes.apiserver.client.request.count | Number of requests as client | long |  | counter |
| kubernetes.apiserver.etcd.object.count | Number of kubernetes objects at etcd | long |  | gauge |
| kubernetes.apiserver.process.cpu.sec | CPU seconds | double |  | counter |
| kubernetes.apiserver.process.fds.open.count | Number of open file descriptors | long |  | gauge |
| kubernetes.apiserver.process.memory.resident.bytes | Bytes in resident memory | long | byte | gauge |
| kubernetes.apiserver.process.memory.virtual.bytes | Bytes in virtual memory | long | byte | gauge |
| kubernetes.apiserver.process.started.sec | Seconds since the process started | double |  | gauge |
| kubernetes.apiserver.request.code | HTTP code | keyword |  |  |
| kubernetes.apiserver.request.component | Component handling the request | keyword |  |  |
| kubernetes.apiserver.request.content_type | Request HTTP content type | keyword |  |  |
| kubernetes.apiserver.request.count | Number of requests | long |  | counter |
| kubernetes.apiserver.request.current.count | Inflight requests | long |  | counter |
| kubernetes.apiserver.request.dry_run | Wether the request uses dry run | keyword |  |  |
| kubernetes.apiserver.request.duration.us.bucket.\* | Request duration, histogram buckets | object |  |  |
| kubernetes.apiserver.request.duration.us.count | Request duration, number of operations | long |  | counter |
| kubernetes.apiserver.request.duration.us.sum | Request duration, sum in microseconds | long | micros | counter |
| kubernetes.apiserver.request.group | API group for the resource | keyword |  |  |
| kubernetes.apiserver.request.handler | Request handler | keyword |  |  |
| kubernetes.apiserver.request.host | Request host | keyword |  |  |
| kubernetes.apiserver.request.kind | Kind of request | keyword |  |  |
| kubernetes.apiserver.request.longrunning.count | Number of requests active long running requests | long |  | counter |
| kubernetes.apiserver.request.method | HTTP method | keyword |  |  |
| kubernetes.apiserver.request.resource | Requested resource | keyword |  |  |
| kubernetes.apiserver.request.scope | Request scope (cluster, namespace, resource) | keyword |  |  |
| kubernetes.apiserver.request.subresource | Requested subresource | keyword |  |  |
| kubernetes.apiserver.request.verb | HTTP verb | keyword |  |  |
| kubernetes.apiserver.request.version | version for the group | keyword |  |  |
| kubernetes.apiserver.response.size.bytes.bucket.\* | Response size distribution in bytes for each group, version, verb, resource, subresource, scope and component. | object |  |  |
| kubernetes.apiserver.response.size.bytes.count | Number of responses to requests | long |  | counter |
| kubernetes.apiserver.response.size.bytes.sum | Sum of responses sizes in bytes | long | byte | counter |
| kubernetes.apiserver.watch.events.kind | Resource kind of the watch event | keyword |  |  |
| kubernetes.apiserver.watch.events.size.bytes.bucket.\* | Watch event size distribution in bytes | object |  |  |
| kubernetes.apiserver.watch.events.size.bytes.count | Number of watch events | long |  | counter |
| kubernetes.apiserver.watch.events.size.bytes.sum | Sum of watch events sizes in bytes | long | byte | counter |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
