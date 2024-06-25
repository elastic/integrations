# Storage

## Metrics

The `storage` dataset fetches metrics from [Storage](https://cloud.google.com/storage/) in Google Cloud Platform. It contains all metrics exported from the [GCP Storage Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-storage).

You can specify a single region to fetch metrics like `us-central1`. Be aware that GCP Storage does not use zones so `us-central1-a` will return nothing. If no region is specified, it will return metrics from all buckets.

## Sample Event
    
An example event for `storage` looks as following:

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
        "dataset": "gcp.storage",
        "duration": 115000,
        "module": "gcp"
    },
    "gcp": {
        "storage": {
            "storage": {
                "total": {
                    "bytes": 4472520191
                }
            },
            "network": {
                "received": {
                    "bytes": 4472520191
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
        "name": "storage",
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
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| gcp.labels.metadata.\* |  | object |  |
| gcp.labels.metrics.\* |  | object |  |
| gcp.labels.resource.\* |  | object |  |
| gcp.labels.system.\* |  | object |  |
| gcp.labels.user.\* |  | object |  |
| gcp.labels_fingerprint | Hashed value of the labels field. | keyword |  |
| gcp.metrics.\*.\*.\*.\* | Metrics that returned from Google Cloud API query. | object |  |
| gcp.storage.api.request.count | Delta count of API calls, grouped by the API method name and response code. | long | gauge |
| gcp.storage.authz.acl_based_object_access.count | Delta count of requests that result in an object being granted access solely due to object ACLs. | long | gauge |
| gcp.storage.authz.acl_operations.count | Usage of ACL operations broken down by type. | long | gauge |
| gcp.storage.authz.object_specific_acl_mutation.count | Delta count of changes made to object specific ACLs. | long | gauge |
| gcp.storage.network.received.bytes | Delta count of bytes received over the network, grouped by the API method name and response code. | long | gauge |
| gcp.storage.network.sent.bytes | Delta count of bytes sent over the network, grouped by the API method name and response code. | long | gauge |
| gcp.storage.storage.object.count | Total number of objects per bucket, grouped by storage class. This value is measured once per day, and the value is repeated at each sampling interval throughout the day. | long | gauge |
| gcp.storage.storage.total.bytes | Total size of all objects in the bucket, grouped by storage class. This value is measured once per day, and the value is repeated at each sampling interval throughout the day. | long | gauge |
| gcp.storage.storage.total_byte_seconds.bytes | Delta count of bytes received over the network, grouped by the API method name and response code. | long | gauge |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
