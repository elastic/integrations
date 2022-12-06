# events

## Metrics

### event

This is the `event` dataset of the Kubernetes package. It collects Kubernetes events
related metrics.

If Leader Election is activated (default behaviour) only the `elastic agent` which holds the leadership lock
will retrieve events related metrics.
This is relevant in multi-node kubernetes cluster and prevents duplicate data.

An example event for `event` looks as following:

```json
{
    "@timestamp": "2020-06-25T12:30:27.575Z",
    "metricset": {
        "name": "event"
    },
    "agent": {
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
        "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "event": {
        "dataset": "kubernetes.event",
        "module": "kubernetes"
    },
    "service": {
        "type": "kubernetes"
    },
    "kubernetes": {
        "event": {
            "metadata": {
                "uid": "604e39e0-862f-4615-9cec-8cb62299dea3",
                "resource_version": "485630",
                "timestamp": {
                    "created": "2020-06-25T07:20:25.000Z"
                },
                "name": "monitor.161bb862545e3099",
                "namespace": "beats",
                "self_link": "/api/v1/namespaces/beats/events/monitor.161bb862545e3099",
                "generate_name": ""
            },
            "timestamp": {
                "first_occurrence": "2020-06-25T07:20:25.000Z",
                "last_occurrence": "2020-06-25T12:30:27.000Z"
            },
            "message": "Failed to find referenced backend beats/monitor: Elasticsearch.elasticsearch.k8s.elastic.co \"monitor\" not found",
            "reason": "AssociationError",
            "type": "Warning",
            "count": 1861,
            "source": {
                "host": "",
                "component": "kibana-association-controller"
            },
            "involved_object": {
                "api_version": "kibana.k8s.elastic.co/v1",
                "resource_version": "101842",
                "name": "monitor",
                "kind": "Kibana",
                "uid": "45a19de5-5eef-4090-a2d3-dbceb0a28af8"
            }
        }
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
        "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
        "architecture": "x86_64",
        "os": {
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.19.81",
            "codename": "Core"
        }
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.mac | Host mac addresses. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |
| kubernetes.annotations.\* | Kubernetes annotations map | object |  |
| kubernetes.container.image | Kubernetes container image | keyword |  |
| kubernetes.container.name | Kubernetes container name | keyword |  |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |  |
| kubernetes.event.count | Count field records the number of times the particular event has occurred | long | counter |
| kubernetes.event.involved_object.api_version | API version of the object | keyword |  |
| kubernetes.event.involved_object.kind | API kind of the object | keyword |  |
| kubernetes.event.involved_object.name | name of the object | keyword |  |
| kubernetes.event.involved_object.resource_version | resource version of the object | keyword |  |
| kubernetes.event.involved_object.uid | uid version of the object | keyword |  |
| kubernetes.event.message | Message recorded for the given event | text |  |
| kubernetes.event.metadata.generate_name | Generate name of the event | keyword |  |
| kubernetes.event.metadata.name | Name of the event | keyword |  |
| kubernetes.event.metadata.namespace | Namespace in which event was generated | keyword |  |
| kubernetes.event.metadata.resource_version | Version of the event resource | keyword |  |
| kubernetes.event.metadata.self_link | URL representing the event | keyword |  |
| kubernetes.event.metadata.timestamp.created | Timestamp of creation of the given event | date |  |
| kubernetes.event.metadata.uid | Unique identifier to the event object | keyword |  |
| kubernetes.event.reason | Reason recorded for the given event | keyword |  |
| kubernetes.event.source.component | Component from which the event is generated | keyword |  |
| kubernetes.event.source.host | Node name on which the event is generated | keyword |  |
| kubernetes.event.timestamp.first_occurrence | Timestamp of first occurrence of event | date |  |
| kubernetes.event.timestamp.last_occurrence | Timestamp of last occurrence of event | date |  |
| kubernetes.event.type | Type of the given event | keyword |  |
| kubernetes.labels.\* | Kubernetes labels map | object |  |
| kubernetes.namespace | Kubernetes namespace | keyword |  |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |  |
| kubernetes.node.name | Kubernetes node name | keyword |  |
| kubernetes.pod.ip | Kubernetes pod IP | ip |  |
| kubernetes.pod.name | Kubernetes pod name | keyword |  |
| kubernetes.pod.uid | Kubernetes pod UID | keyword |  |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |  |
| kubernetes.selectors.\* | Kubernetes Service selectors map | object |  |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |  |
| orchestrator.cluster.name | Name of the cluster. | keyword |  |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
