# Dataproc

## Metrics

The `dataproc` dataset fetches metrics from [Dataproc](https://cloud.google.com/dataproc/) in Google Cloud Platform. It contains all metrics exported from the [GCP Dataproc Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-dataproc).

You can specify a single region to fetch metrics like `us-central1`. Be aware that GCP Dataproc is a regional service. If no region is specified, it will return metrics from all buckets.

## Sample Event
    
An example event for `dataproc` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev",
            "name": "elastic-obs-integrations-dev"
        },
        "instance": {
            "id": "4751091017865185079",
            "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
        },
        "machine": {
            "type": "e2-medium"
        },
        "provider": "gcp",
        "availability_zone": "us-central1-c",
        "region": "us-central1"
    },
    "event": {
        "dataset": "gcp.dataproc",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "dataproc": {
            "cluster": {
                "hdfs": {
                    "datanodes": {
                        "count": 15
                    }
                }
            }
        },
        "labels": {
            "user": {
                "goog-gke-node": ""
            }
        }
    },
    "host": {
        "id": "4751091017865185079",
        "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
    },
    "metricset": {
        "name": "dataproc",
        "period": 10000
    },
    "service": {
        "type": "gcp"
    }
}
```

## Exported fields

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |
| error.message | Error message. | match_only_text |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| gcp.dataproc.batch.spark.executors.count | Indicates the number of Batch Spark executors. | long | gauge |
| gcp.dataproc.cluster.hdfs.datanodes.count | Indicates the number of HDFS DataNodes that are running inside a cluster. | long | gauge |
| gcp.dataproc.cluster.hdfs.storage_capacity.value | Indicates capacity of HDFS system running on cluster in GB. | double | gauge |
| gcp.dataproc.cluster.hdfs.storage_utilization.value | The percentage of HDFS storage currently used. | double | gauge |
| gcp.dataproc.cluster.hdfs.unhealthy_blocks.count | Indicates the number of unhealthy blocks inside the cluster. | long | gauge |
| gcp.dataproc.cluster.job.completion_time.value | The time jobs took to complete from the time the user submits a job to the time Dataproc reports it is completed. | object |  |
| gcp.dataproc.cluster.job.duration.value | The time jobs have spent in a given state. | object |  |
| gcp.dataproc.cluster.job.failed.count | Indicates the delta of the number of jobs that have failed on a cluster. | long | gauge |
| gcp.dataproc.cluster.job.running.count | Indicates the number of jobs that are running on a cluster. | long | gauge |
| gcp.dataproc.cluster.job.submitted.count | Indicates the delta of the number of jobs that have been submitted to a cluster. | long | gauge |
| gcp.dataproc.cluster.operation.completion_time.value | The time operations took to complete from the time the user submits a operation to the time Dataproc reports it is completed. | object |  |
| gcp.dataproc.cluster.operation.duration.value | The time operations have spent in a given state. | object |  |
| gcp.dataproc.cluster.operation.failed.count | Indicates the delta of the number of operations that have failed on a cluster. | long | gauge |
| gcp.dataproc.cluster.operation.running.count | Indicates the number of operations that are running on a cluster. | long | gauge |
| gcp.dataproc.cluster.operation.submitted.count | Indicates the delta of the number of operations that have been submitted to a cluster. | long | gauge |
| gcp.dataproc.cluster.yarn.allocated_memory_percentage.value | The percentage of YARN memory is allocated. | double | gauge |
| gcp.dataproc.cluster.yarn.apps.count | Indicates the number of active YARN applications. | long | gauge |
| gcp.dataproc.cluster.yarn.containers.count | Indicates the number of YARN containers. | long | gauge |
| gcp.dataproc.cluster.yarn.memory_size.value | Indicates the YARN memory size in GB. | double | gauge |
| gcp.dataproc.cluster.yarn.nodemanagers.count | Indicates the number of YARN NodeManagers running inside cluster. | long | gauge |
| gcp.dataproc.cluster.yarn.pending_memory_size.value | The current memory request, in GB, that is pending to be fulfilled by the scheduler. | double | gauge |
| gcp.dataproc.cluster.yarn.virtual_cores.count | Indicates the number of virtual cores in YARN. | long | gauge |
| gcp.labels.metadata.\* |  | object |  |
| gcp.labels.metrics.\* |  | object |  |
| gcp.labels.resource.\* |  | object |  |
| gcp.labels.system.\* |  | object |  |
| gcp.labels.user.\* |  | object |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |
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
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
