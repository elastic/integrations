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

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
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
| gcp.labels_fingerprint | Hashed value of the labels field. | keyword |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
