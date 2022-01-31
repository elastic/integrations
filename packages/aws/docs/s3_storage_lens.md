# s3 storage lens

## Metrics

An example event for `s3_storage_lens` looks as following:

```json
{
    "@timestamp": "2021-11-07T20:38:00.000Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "aws.s3_storage_lens"
    },
    "service": {
        "type": "aws"
    },
    "cloud": {
        "provider": "aws",
        "region": "us-east-1",
        "account": {
            "name": "elastic-beats",
            "id": "428152502467"
        }
    },
    "metricset": {
        "period": 86400000,
        "name": "cloudwatch"
    },
    "event": {
        "duration": 22973251900,
        "agent_id_status": "verified",
        "ingested": "2021-11-08T20:38:37Z",
        "module": "aws",
        "dataset": "aws.s3_storage_lens"
    },
    "aws": {
        "s3_storage_lens": {
            "metrics": {
                "NonCurrentVersionStorageBytes": {
                    "avg": 0
                },
                "DeleteMarkerObjectCount": {
                    "avg": 0
                },
                "GetRequests": {
                    "avg": 0
                },
                "SelectReturnedBytes": {
                    "avg": 0
                },
                "ObjectCount": {
                    "avg": 164195
                },
                "HeadRequests": {
                    "avg": 0
                },
                "ListRequests": {
                    "avg": 0
                },
                "DeleteRequests": {
                    "avg": 0
                },
                "SelectRequests": {
                    "avg": 0
                },
                "5xxErrors": {
                    "avg": 0
                },
                "BytesDownloaded": {
                    "avg": 0
                },
                "BytesUploaded": {
                    "avg": 82537
                },
                "CurrentVersionStorageBytes": {
                    "avg": 154238334
                },
                "StorageBytes": {
                    "avg": 154238334
                },
                "ObjectLockEnabledStorageBytes": {
                    "avg": 0
                },
                "4xxErrors": {
                    "avg": 0
                },
                "PutRequests": {
                    "avg": 145
                },
                "ObjectLockEnabledObjectCount": {
                    "avg": 0
                },
                "EncryptedObjectCount": {
                    "avg": 164191
                },
                "CurrentVersionObjectCount": {
                    "avg": 164195
                },
                "IncompleteMultipartUploadObjectCount": {
                    "avg": 0
                },
                "ReplicatedObjectCount": {
                    "avg": 0
                },
                "AllRequests": {
                    "avg": 145
                },
                "PostRequests": {
                    "avg": 0
                },
                "IncompleteMultipartUploadStorageBytes": {
                    "avg": 0
                },
                "NonCurrentVersionObjectCount": {
                    "avg": 0
                },
                "ReplicatedStorageBytes": {
                    "avg": 0
                },
                "EncryptedStorageBytes": {
                    "avg": 154237917
                },
                "SelectScannedBytes": {
                    "avg": 0
                }
            }
        },
        "cloudwatch": {
            "namespace": "AWS/S3/Storage-Lens"
        },
        "dimensions": {
            "metrics_version": "1.0",
            "storage_class": "STANDARD",
            "aws_region": "eu-central-1",
            "bucket_name": "filebeat-aws-elb-test",
            "aws_account_number": "428152502467",
            "configuration_id": "default-account-dashboard",
            "record_type": "BUCKET"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.\*.metrics.\*.\* | Metrics that returned from Cloudwatch API query. | object |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.\* | Metric dimensions. | object |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.s3_storage_lens.metrics.4xxErrors.avg | The total 4xx errors in scope. | long |
| aws.s3_storage_lens.metrics.5xxErrors.avg | The total 5xx errors in scope. | long |
| aws.s3_storage_lens.metrics.AllRequests.avg | The total number of requests made. | long |
| aws.s3_storage_lens.metrics.BytesDownloaded.avg | The number of bytes in scope that were downloaded. | long |
| aws.s3_storage_lens.metrics.BytesUploaded.avg | The number of bytes uploaded. | long |
| aws.s3_storage_lens.metrics.CurrentVersionObjectCount.avg | The number of objects that are a current version. | long |
| aws.s3_storage_lens.metrics.CurrentVersionStorageBytes.avg | The number of bytes that are a current version. | long |
| aws.s3_storage_lens.metrics.DeleteMarkerObjectCount.avg | The total number of objects with a delete marker. | long |
| aws.s3_storage_lens.metrics.DeleteRequests.avg | The total number of delete requests made. | long |
| aws.s3_storage_lens.metrics.EncryptedObjectCount.avg | The total object counts that are encrypted using Amazon S3 server-side encryption. | long |
| aws.s3_storage_lens.metrics.EncryptedStorageBytes.avg | The total number of encrypted bytes using Amazon S3 server-side encryption. | long |
| aws.s3_storage_lens.metrics.GetRequests.avg | The total number of GET requests made. | long |
| aws.s3_storage_lens.metrics.HeadRequests.avg | The total number of head requests made. | long |
| aws.s3_storage_lens.metrics.IncompleteMultipartUploadObjectCount.avg | The number of objects in scope that are incomplete multipart uploads. | long |
| aws.s3_storage_lens.metrics.IncompleteMultipartUploadStorageBytes.avg | The total bytes in scope with incomplete multipart uploads. | long |
| aws.s3_storage_lens.metrics.ListRequests.avg | The total number of list requests made. | long |
| aws.s3_storage_lens.metrics.NonCurrentVersionObjectCount.avg | The count of the noncurrent version objects. | long |
| aws.s3_storage_lens.metrics.NonCurrentVersionStorageBytes.avg | The number of noncurrent versioned bytes. | long |
| aws.s3_storage_lens.metrics.ObjectCount.avg | The total object count. | long |
| aws.s3_storage_lens.metrics.ObjectLockEnabledObjectCount.avg | The total number of objects in scope that have Object Lock enabled. | long |
| aws.s3_storage_lens.metrics.ObjectLockEnabledStorageBytes.avg | The total number of bytes in scope that have Object Lock enabled. | long |
| aws.s3_storage_lens.metrics.PostRequests.avg | The total number of post requests made. | long |
| aws.s3_storage_lens.metrics.PutRequests.avg | The total number of PUT requests made. | long |
| aws.s3_storage_lens.metrics.ReplicatedObjectCount.avg | The count of replicated objects. | long |
| aws.s3_storage_lens.metrics.ReplicatedStorageBytes.avg | The total number of bytes in scope that are replicated. | long |
| aws.s3_storage_lens.metrics.SelectRequests.avg | The total number of select requests. | long |
| aws.s3_storage_lens.metrics.SelectReturnedBytes.avg | The number of select bytes returned. | long |
| aws.s3_storage_lens.metrics.SelectScannedBytes.avg | The number of select bytes scanned. | long |
| aws.s3_storage_lens.metrics.StorageBytes.avg | The total storage in bytes | long |
| aws.tags.\* | Tag key value pairs from aws resources. | object |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error | These fields can represent errors of any kind. Use them for errors that happen while fetching events or in cases where the event itself contains an error. | group |
| error.message | Error message. | match_only_text |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
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
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
