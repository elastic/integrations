# kube-scheduler

## Metrics

### scheduler

This is the `scheduler` dataset of the Kubernetes package. It collects metrics
from Kubernetes Scheduler component.

An example event for `scheduler` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:35:59.624Z",
    "agent": {
        "version": "8.0.0",
        "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
        "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
        "name": "minikube",
        "type": "metricbeat"
    },
    "host": {
        "hostname": "minikube",
        "architecture": "x86_64",
        "os": {
            "kernel": "4.19.81",
            "codename": "Core",
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux"
        },
        "name": "minikube",
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false,
        "ip": [
            "192.168.64.10",
            "fe80::a883:2fff:fe7f:6b12",
            "172.17.0.1",
            "fe80::42:d4ff:fe8c:9493",
            "fe80::2859:80ff:fe9e:fcd6",
            "fe80::d83a:d9ff:fee9:7052",
            "fe80::880a:b6ff:fe18:ba76",
            "fe80::f447:faff:fe80:e88b",
            "fe80::9cc3:ffff:fe95:e48e",
            "fe80::6c1c:29ff:fe50:d40c",
            "fe80::b4f3:11ff:fe60:14ed",
            "fe80::20f2:2aff:fe96:1e7b",
            "fe80::5434:baff:fede:5720",
            "fe80::a878:91ff:fe29:81f7"
        ],
        "mac": [
            "aa:83:2f:7f:6b:12",
            "02:42:d4:8c:94:93",
            "2a:59:80:9e:fc:d6",
            "da:3a:d9:e9:70:52",
            "8a:0a:b6:18:ba:76",
            "f6:47:fa:80:e8:8b",
            "9e:c3:ff:95:e4:8e",
            "6e:1c:29:50:d4:0c",
            "b6:f3:11:60:14:ed",
            "22:f2:2a:96:1e:7b",
            "56:34:ba:de:57:20",
            "aa:78:91:29:81:f7"
        ]
    },
    "ecs": {
        "version": "1.5.0"
    },
    "event": {
        "duration": 7245648,
        "dataset": "kubernetes.scheduler",
        "module": "kubernetes"
    },
    "metricset": {
        "name": "scheduler",
        "period": 10000
    },
    "service": {
        "address": "localhost:10251",
        "type": "kubernetes"
    },
    "kubernetes": {
        "scheduler": {
            "name": "kube-scheduler",
            "leader": {
                "is_master": true
            }
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
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |  |
| kubernetes.scheduler.client.request.count | Number of requests as client | long |  | counter |
| kubernetes.scheduler.code | HTTP code | keyword |  |  |
| kubernetes.scheduler.handler | Request handler | keyword |  |  |
| kubernetes.scheduler.host | Request host | keyword |  |  |
| kubernetes.scheduler.http.request.count | Request count | long |  | counter |
| kubernetes.scheduler.http.request.duration.us.count | Request count for duration | long | micros | counter |
| kubernetes.scheduler.http.request.duration.us.percentile.\* | Request duration microseconds percentiles | object |  |  |
| kubernetes.scheduler.http.request.duration.us.sum | Request duration microseconds cumulative sum | double | micros | counter |
| kubernetes.scheduler.http.request.size.bytes.count | Request count for size | long | byte | counter |
| kubernetes.scheduler.http.request.size.bytes.percentile.\* | Request size percentiles | object |  |  |
| kubernetes.scheduler.http.request.size.bytes.sum | Request size cumulative sum | long | byte | counter |
| kubernetes.scheduler.http.response.size.bytes.count | Response count | long |  | counter |
| kubernetes.scheduler.http.response.size.bytes.percentile.\* | Response size percentiles | object |  |  |
| kubernetes.scheduler.http.response.size.bytes.sum | Response size cumulative sum | long | byte | counter |
| kubernetes.scheduler.leader.is_master | Whether the node is master | boolean |  |  |
| kubernetes.scheduler.method | HTTP method | keyword |  |  |
| kubernetes.scheduler.name | Name for the resource | keyword |  |  |
| kubernetes.scheduler.operation | Scheduling operation | keyword |  |  |
| kubernetes.scheduler.process.cpu.sec | CPU seconds | double |  | counter |
| kubernetes.scheduler.process.fds.open.count | Number of open file descriptors | long |  | gauge |
| kubernetes.scheduler.process.memory.resident.bytes | Bytes in resident memory | long | byte | gauge |
| kubernetes.scheduler.process.memory.virtual.bytes | Bytes in virtual memory | long | byte | gauge |
| kubernetes.scheduler.process.started.sec | Seconds since the process started | double |  | gauge |
| kubernetes.scheduler.result | Schedule attempt result | keyword |  |  |
| kubernetes.scheduler.scheduling.duration.seconds.count | Scheduling count | long |  | counter |
| kubernetes.scheduler.scheduling.duration.seconds.percentile.\* | Scheduling duration percentiles | object |  |  |
| kubernetes.scheduler.scheduling.duration.seconds.sum | Scheduling duration cumulative sum | double |  | counter |
| kubernetes.scheduler.scheduling.e2e.duration.us.bucket.\* | End to end scheduling duration microseconds | object |  |  |
| kubernetes.scheduler.scheduling.e2e.duration.us.count | End to end scheduling count | long | micros | counter |
| kubernetes.scheduler.scheduling.e2e.duration.us.sum | End to end scheduling duration microseconds sum | long | micros | counter |
| kubernetes.scheduler.scheduling.pod.attempts.count | Pod attempts count | long |  | counter |
| kubernetes.scheduler.scheduling.pod.preemption.victims.bucket.\* | Pod preemption victims | long |  |  |
| kubernetes.scheduler.scheduling.pod.preemption.victims.count | Pod preemption victims count | long |  | counter |
| kubernetes.scheduler.scheduling.pod.preemption.victims.sum | Pod preemption victims sum | long |  | counter |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |
