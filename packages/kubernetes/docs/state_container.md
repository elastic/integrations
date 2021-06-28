## Metrics

### state_container

This is the `state_container` dataset of the Kubernetes package. It collects container related
metrics from `kube_state_metrics`.

An example event for `state_container` looks as following:

```$json
{
    "@timestamp": "2020-06-25T12:36:34.469Z",
    "host": {
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
        },
        "id": "b0e83d397c054b8a99a431072fe4617b",
        "containerized": false
    },
    "event": {
        "dataset": "kubernetes.container",
        "module": "kubernetes",
        "duration": 8554499
    },
    "kubernetes": {
        "node": {
            "name": "minikube"
        },
        "labels": {
            "component": "kube-scheduler",
            "tier": "control-plane"
        },
        "container": {
            "image": "k8s.gcr.io/kube-scheduler:v1.17.0",
            "name": "kube-scheduler",
            "cpu": {
                "request": {
                    "cores": 0.1
                }
            },
            "status": {
                "phase": "running",
                "ready": true,
                "restarts": 10
            },
            "id": "docker://b00b185f2b304a7ece804d1af28eb232f825255f716bcc85ef5bd20d5a4f45d4"
        },
        "pod": {
            "name": "kube-scheduler-minikube",
            "uid": "9cdbd5ea-7638-4e86-a706-a5b222d86f26"
        },
        "namespace": "kube-system"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "agent": {
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "container": {
        "runtime": "docker",
        "id": "b00b185f2b304a7ece804d1af28eb232f825255f716bcc85ef5bd20d5a4f45d4"
    },
    "service": {
        "address": "kube-state-metrics:8080",
        "type": "kubernetes"
    },
    "metricset": {
        "name": "state_container",
        "period": 10000
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
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
| container.runtime | Runtime managing this container | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version | keyword |
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
| kubernetes.annotations.* | Kubernetes annotations map | object |
| kubernetes.container.cpu.limit.cores | Container CPU cores limit | float |
| kubernetes.container.cpu.limit.nanocores | Container CPU nanocores limit | long |
| kubernetes.container.cpu.request.cores | Container CPU requested cores | float |
| kubernetes.container.cpu.request.nanocores | Container CPU requested nanocores | long |
| kubernetes.container.id | Container id | keyword |
| kubernetes.container.image | Kubernetes container image | keyword |
| kubernetes.container.memory.limit.bytes | Container memory limit in bytes | long |
| kubernetes.container.memory.request.bytes | Container requested memory in bytes | long |
| kubernetes.container.name | Kubernetes container name | keyword |
| kubernetes.container.status.phase | Container phase (running, waiting, terminated) | keyword |
| kubernetes.container.status.ready | Container ready status | boolean |
| kubernetes.container.status.reason | Waiting (ContainerCreating, CrashLoopBackoff, ErrImagePull, ImagePullBackoff) or termination (Completed, ContainerCannotRun, Error, OOMKilled) reason. | keyword |
| kubernetes.container.status.restarts | Container restarts count | integer |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |
| kubernetes.labels.* | Kubernetes labels map | object |
| kubernetes.namespace | Kubernetes namespace | keyword |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |
| kubernetes.node.name | Kubernetes node name | keyword |
| kubernetes.pod.ip | Kubernetes pod IP | ip |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| kubernetes.selectors.* | Kubernetes Service selectors map | object |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |
| service.address | Service address | keyword |
| service.type | Service type | keyword |
