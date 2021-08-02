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
    "@timestamp": "2020-06-25T12:30:34.616Z",
    "metricset": {
        "name": "apiserver",
        "period": 30000
    },
    "service": {
        "address": "10.96.0.1:443",
        "type": "kubernetes"
    },
    "event": {
        "dataset": "kubernetes.apiserver",
        "module": "kubernetes",
        "duration": 114780772
    },
    "kubernetes": {
        "apiserver": {
            "request": {
                "client": "metrics-server/v0.0.0 (linux/amd64) kubernetes/$Format",
                "version": "v1",
                "count": 3,
                "scope": "cluster",
                "content_type": "application/vnd.kubernetes.protobuf",
                "code": "200",
                "verb": "LIST",
                "component": "apiserver",
                "resource": "nodes"
            }
        }
    },
    "ecs": {
        "version": "1.5.0"
    },
    "agent": {
        "version": "8.0.0",
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat"
    },
    "host": {
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false,
        "ip": [
            "172.17.0.11"
        ],
        "mac": [
            "02:42:ac:11:00:0b"
        ],
        "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "os": {
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)"
        }
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
| ecs.version | ECS version | keyword |  |  |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| kubernetes.apiserver.audit.event.count | Number of audit events | long |  | counter |
| kubernetes.apiserver.audit.rejected.count | Number of audit rejected events | long |  | counter |
| kubernetes.apiserver.client.request.count | Number of requests as client | long |  | counter |
| kubernetes.apiserver.etcd.object.count | Number of kubernetes objects at etcd | long |  | gauge |
| kubernetes.apiserver.http.request.count | Request count for response | long |  | counter |
| kubernetes.apiserver.http.request.duration.us.count | Request count for duration | long | micros | counter |
| kubernetes.apiserver.http.request.duration.us.percentile.\* | Request duration microseconds percentiles | object |  |  |
| kubernetes.apiserver.http.request.duration.us.sum | Request duration microseconds cumulative sum | double | micros | counter |
| kubernetes.apiserver.http.request.size.bytes.count | Request count for size | long | byte | counter |
| kubernetes.apiserver.http.request.size.bytes.percentile.\* | Request size percentiles | object |  |  |
| kubernetes.apiserver.http.request.size.bytes.sum | Request size cumulative sum | long | byte | counter |
| kubernetes.apiserver.http.response.size.bytes.count | Response count | long |  | counter |
| kubernetes.apiserver.http.response.size.bytes.percentile.\* | Response size percentiles | object |  |  |
| kubernetes.apiserver.http.response.size.bytes.sum | Response size cumulative sum | long | byte | counter |
| kubernetes.apiserver.process.cpu.sec | CPU seconds | double |  | counter |
| kubernetes.apiserver.process.fds.open.count | Number of open file descriptors | long |  | gauge |
| kubernetes.apiserver.process.memory.resident.bytes | Bytes in resident memory | long | byte | gauge |
| kubernetes.apiserver.process.memory.virtual.bytes | Bytes in virtual memory | long | byte | gauge |
| kubernetes.apiserver.process.started.sec | Seconds since the process started | double |  | gauge |
| kubernetes.apiserver.request.client | Client executing requests | keyword |  |  |
| kubernetes.apiserver.request.code | HTTP code | keyword |  |  |
| kubernetes.apiserver.request.component | Component handling the request | keyword |  |  |
| kubernetes.apiserver.request.content_type | Request HTTP content type | keyword |  |  |
| kubernetes.apiserver.request.count | Number of requests | long |  | counter |
| kubernetes.apiserver.request.current.count | Inflight requests | long |  | counter |
| kubernetes.apiserver.request.dry_run | Wether the request uses dry run | keyword |  |  |
| kubernetes.apiserver.request.duration.us.bucket.\* | Request duration, histogram buckets | object |  |  |
| kubernetes.apiserver.request.duration.us.count | Request duration, number of operations | long |  | counter |
| kubernetes.apiserver.request.duration.us.sum | Request duration, sum in microseconds | long |  | counter |
| kubernetes.apiserver.request.group | API group for the resource | keyword |  |  |
| kubernetes.apiserver.request.handler | Request handler | keyword |  |  |
| kubernetes.apiserver.request.host | Request host | keyword |  |  |
| kubernetes.apiserver.request.kind | Kind of request | keyword |  |  |
| kubernetes.apiserver.request.latency.bucket.\* | Request latency histogram buckets | object |  |  |
| kubernetes.apiserver.request.latency.count | Request latency, number of requests | long |  | counter |
| kubernetes.apiserver.request.latency.sum | Requests latency, sum of latencies in microseconds | long |  | counter |
| kubernetes.apiserver.request.longrunning.count | Number of requests active long running requests | long |  | counter |
| kubernetes.apiserver.request.method | HTTP method | keyword |  |  |
| kubernetes.apiserver.request.resource | Requested resource | keyword |  |  |
| kubernetes.apiserver.request.scope | Request scope (cluster, namespace, resource) | keyword |  |  |
| kubernetes.apiserver.request.subresource | Requested subresource | keyword |  |  |
| kubernetes.apiserver.request.verb | HTTP verb | keyword |  |  |
| kubernetes.apiserver.request.version | version for the group | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Service address | keyword |  |  |
| service.type | Service type | keyword |  |  |
