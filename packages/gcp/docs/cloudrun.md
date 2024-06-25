# Cloud Run

The `cloudrun` dataset fetches metrics from [Cloud Run](https://cloud.google.com/run) in Google Cloud Platform. It contains metrics exported from the [GCP Cloud Run Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-run).

## Metrics

An example event for `cloudrun` looks as following:

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
        "dataset": "gcp.cloudrun_metrics",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "cloudrun_metrics": {
            "container": {
                "instance": {
                    "count": 421
                }
            }
        }
    },
    "host": {
        "id": "4751091017865185079",
        "name": "gke-cluster-1-default-pool-6617a8aa-5clh"
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

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |  |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| gcp.cloudrun_metrics.container.billable_instance_time | Delta of billable time aggregated across all container instances. For a given container instance, billable time occurs when the container instance is starting or at least one request is being processed. Billable time is rounded up to the nearest 100 milliseconds. | double |  | gauge |
| gcp.cloudrun_metrics.container.cpu.allocation_time.sec | Delta of container CPU allocation in seconds. | double | s | gauge |
| gcp.cloudrun_metrics.container.cpu.utilizations | Container CPU utilization distribution across all container instances. | object |  |  |
| gcp.cloudrun_metrics.container.instance.count | Number of container instances that exist, broken down by state. | long |  | gauge |
| gcp.cloudrun_metrics.container.max_request_concurrencies | Distribution of the maximum number number of concurrent requests being served by each container instance over a minute. | object |  |  |
| gcp.cloudrun_metrics.container.memory.allocation_time | Delta of container memory allocation in Gigabytes-seconds. | double |  | gauge |
| gcp.cloudrun_metrics.container.memory.utilizations | Container memory utilization distribution across all container instances. | object |  |  |
| gcp.cloudrun_metrics.container.network.received.bytes | Delta of incoming socket and HTTP response traffic, in bytes. | long | byte | gauge |
| gcp.cloudrun_metrics.container.network.sent.bytes | Delta of outgoing socket and HTTP response traffic, in bytes. | long | byte | gauge |
| gcp.cloudrun_metrics.request.count | Delta of number of requests reaching the revision. Excludes requests that are not reaching your container instances (e.g. unauthorized requests or when maximum number of instances is reached). | long |  | gauge |
| gcp.cloudrun_metrics.request_latencies | Distribution of request latency in milliseconds reaching the revision. Latency is measured from when the request reaches the running container to when it exits. Notably, it does not include container startup latency. | object |  |  |
| gcp.labels.metadata.\* |  | object |  |  |
| gcp.labels.metrics.\* |  | object |  |  |
| gcp.labels.resource.\* |  | object |  |  |
| gcp.labels.system.\* |  | object |  |  |
| gcp.labels.user.\* |  | object |  |  |
| gcp.labels_fingerprint | Hashed value of the labels field. | keyword |  |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |


