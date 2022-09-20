# kube-controller-manager

## Metrics

### controllermanager

This is the `controllermanager` dataset for the Kubernetes package. It collects from
Kubernetes controller component `metrics` endpoint.

An example event for `controllermanager` looks as following:

```json
{
    "kubernetes": {
        "controllermanager": {
            "verb": "GET",
            "client": {
                "request": {
                    "duration": {
                        "us": {
                            "bucket": {
                                "1000": 10787,
                                "2000": 13002,
                                "4000": 13442,
                                "8000": 13533,
                                "16000": 13558,
                                "32000": 13568,
                                "64000": 13571,
                                "128000": 13571,
                                "256000": 13571,
                                "512000": 13571,
                                "+Inf": 13571
                            },
                            "count": 13571,
                            "sum": 12994981.660999978
                        }
                    }
                }
            },
            "url": "https://172.18.0.2:6443/apis?timeout=32s"
        }
    },
    "agent": {
        "name": "kind-control-plane",
        "id": "d5aadb7a-c9ec-4563-b83a-1c4bb5f1471f",
        "ephemeral_id": "7ae929a5-2943-43de-98e8-693dc0c381d7",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "@timestamp": "2022-07-27T08:44:46.219Z",
    "ecs": {
        "version": "8.0.0"
    },
    "service": {
        "address": "https://0.0.0.0:10257/metrics",
        "type": "kubernetes"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "kubernetes.controllermanager"
    },
    "host": {
        "hostname": "kind-control-plane",
        "os": {
            "kernel": "5.10.47-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
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
    "elastic_agent": {
        "id": "d5aadb7a-c9ec-4563-b83a-1c4bb5f1471f",
        "version": "8.4.0",
        "snapshot": false
    },
    "metricset": {
        "period": 10000,
        "name": "controllermanager"
    },
    "event": {
        "duration": 59137358,
        "agent_id_status": "verified",
        "ingested": "2022-07-27T08:44:46Z",
        "module": "kubernetes",
        "dataset": "kubernetes.controllermanager"
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
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |  |
| kubernetes.controllermanager.client.request.count | Number of requests as client | long |  | counter |
| kubernetes.controllermanager.client.request.duration.us.bucket.\* | Response latency distribution, histogram buckets | object |  |  |
| kubernetes.controllermanager.client.request.duration.us.count | Request duration, number of operations | long |  | counter |
| kubernetes.controllermanager.client.request.duration.us.sum | Request duration, sum in microseconds | long | micros | counter |
| kubernetes.controllermanager.code | HTTP code | keyword |  |  |
| kubernetes.controllermanager.host | Request host | keyword |  |  |
| kubernetes.controllermanager.leader.is_master | Whether the node is master | boolean |  |  |
| kubernetes.controllermanager.method | HTTP method | keyword |  |  |
| kubernetes.controllermanager.name | Name for the resource | keyword |  |  |
| kubernetes.controllermanager.node.collector.count | Number of nodes | long |  | gauge |
| kubernetes.controllermanager.node.collector.eviction.count | Number of node evictions | long |  | counter |
| kubernetes.controllermanager.node.collector.health.pct | Percentage of healthy nodes | long |  | gauge |
| kubernetes.controllermanager.node.collector.unhealthy.count | Number of unhealthy nodes | long |  | gauge |
| kubernetes.controllermanager.process.cpu.sec | CPU seconds | double |  | counter |
| kubernetes.controllermanager.process.fds.max.count | Maximum number of open file descriptors | long |  | gauge |
| kubernetes.controllermanager.process.fds.open.count | Number of open file descriptors | long |  | gauge |
| kubernetes.controllermanager.process.memory.resident.bytes | Bytes in resident memory | long | byte | gauge |
| kubernetes.controllermanager.process.memory.virtual.bytes | Bytes in virtual memory | long | byte | gauge |
| kubernetes.controllermanager.process.started.sec | Seconds since the process started | double |  | gauge |
| kubernetes.controllermanager.url | Request url | keyword |  |  |
| kubernetes.controllermanager.verb | Request verb | keyword |  |  |
| kubernetes.controllermanager.workqueue.adds.count | Workqueue add count | long |  | counter |
| kubernetes.controllermanager.workqueue.depth.count | Workqueue depth count | long |  | gauge |
| kubernetes.controllermanager.workqueue.longestrunning.sec | Longest running processors | double |  | gauge |
| kubernetes.controllermanager.workqueue.retries.count | Workqueue number of retries | long |  | counter |
| kubernetes.controllermanager.workqueue.unfinished.sec | Unfinished processors | double |  | gauge |
| kubernetes.controllermanager.zone | Infrastructure zone | keyword |  |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
