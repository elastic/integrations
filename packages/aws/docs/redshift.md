# Amazon Redshift

This integration is used to fetch metrics from [Amazon Redshift](https://aws.amazon.com/redshift/).

## Metrics

The `redshift` dataset collects Amazon Redshift metrics.

An example event for `redshift` looks as following:

```json
{
    "@timestamp": "2022-06-27T11:58:00.000Z",
    "agent": {
        "ephemeral_id": "a94b780f-b5b5-49b1-88cd-b7a7835f2996",
        "id": "d745bccd-73a3-41b4-9fd0-4d9bac14f77b",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "aws": {
        "cloudwatch": {
            "namespace": "AWS/Redshift"
        },
        "dimensions": {
            "ClusterIdentifier": "test"
        },
        "redshift": {
            "metrics": {
                "CPUUtilization": {
                    "avg": 2.43551912568288
                },
                "CommitQueueLength": {
                    "avg": 0
                },
                "ConcurrencyScalingActiveClusters": {
                    "avg": 0
                },
                "DatabaseConnections": {
                    "avg": 0
                },
                "HealthStatus": {
                    "avg": 1
                },
                "MaintenanceMode": {
                    "avg": 0
                },
                "MaxConfiguredConcurrencyScalingClusters": {
                    "avg": 1
                },
                "NetworkReceiveThroughput": {
                    "avg": 2585.956001900078
                },
                "NetworkTransmitThroughput": {
                    "avg": 23262.257531749852
                },
                "NumExceededSchemaQuotas": {
                    "avg": 0
                },
                "PercentageDiskSpaceUsed": {
                    "avg": 0.2197265625
                },
                "ReadIOPS": {
                    "avg": 0
                },
                "ReadLatency": {
                    "avg": 0
                },
                "ReadThroughput": {
                    "avg": 0
                },
                "TotalTableCount": {
                    "avg": 7
                },
                "WriteIOPS": {
                    "avg": 0
                },
                "WriteLatency": {
                    "avg": 0
                },
                "WriteThroughput": {
                    "avg": 0
                }
            }
        }
    },
    "cloud": {
        "account": {
            "id": "627286350134",
            "name": "elastic-observability"
        },
        "provider": "aws",
        "region": "us-east-1"
    },
    "data_stream": {
        "dataset": "aws.redshift",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "d745bccd-73a3-41b4-9fd0-4d9bac14f77b",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "aws.redshift",
        "duration": 12571706173,
        "ingested": "2022-06-27T12:13:13Z",
        "module": "aws"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.112.7"
        ],
        "mac": [
            "02:42:c0:a8:70:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.104-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "cloudwatch",
        "period": 300000
    },
    "service": {
        "type": "aws"
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
| aws.dimensions.ClusterIdentifier | This dimension filters the data that you request for a specific Cluster identifier | keyword |
| aws.dimensions.NodeID | This dimension filters the data that you request for a specific NodeID. | keyword |
| aws.dimensions.QueryPriority | This dimension filters the data that you request for a specific query priority. | keyword |
| aws.dimensions.QueueName | This dimension filters the data that you request for a specific WLM queue name. | keyword |
| aws.dimensions.latency | This dimension filters the data that you request for a specific latency (i.e short, medium or long). | keyword |
| aws.dimensions.service_class | This dimension filters the data that you request for a specific WLM service class | keyword |
| aws.dimensions.stage | This dimension filters the data that you request for a specific execution stage for a query. | keyword |
| aws.dimensions.wlmid | This dimension filters the data that you request for a specific WLM identifier. | keyword |
| aws.redshift.metrics.AutoVacuumSpaceFreed.avg | Storage space reclaimed by auto vacuum delete operations. | long |
| aws.redshift.metrics.CPUUtilization.avg | The percentage of CPU utilization. For clusters, this metric represents an aggregation of all nodes (leader and compute) CPU utilization values. | scaled_float |
| aws.redshift.metrics.CommitQueueLength.avg | The number of transactions waiting to commit at a given point in time. | long |
| aws.redshift.metrics.ConcurrencyScalingActiveClusters.avg | The number of concurrency scaling clusters that are actively processing queries at any given time. | integer |
| aws.redshift.metrics.ConcurrencyScalingSeconds.avg | The number of seconds used by concurrency scaling clusters that have active query processing activity. | long |
| aws.redshift.metrics.DatabaseConnections.avg | The number of database connections to a cluster. | long |
| aws.redshift.metrics.HealthStatus.avg | Indicates the health of the cluster. Any value below 1 implies that the cluster was unhealthy | scaled_float |
| aws.redshift.metrics.MaintenanceMode.avg | Indicates whether the cluster is in maintenance mode. Any value greater than 0 means that the cluster was in maintenance mode. | scaled_float |
| aws.redshift.metrics.MaxConfiguredConcurrencyScalingClusters.avg | Maximum number of concurrency scaling clusters configured from the parameter group. | integer |
| aws.redshift.metrics.NetworkReceiveThroughput.avg | The rate at which the node or cluster receives data. | long |
| aws.redshift.metrics.NetworkTransmitThroughput.avg | The rate at which the node or cluster writes data. | long |
| aws.redshift.metrics.NumExceededSchemaQuotas.avg | The number of schemas with exceeded quotas. | long |
| aws.redshift.metrics.PercentageDiskSpaceUsed.avg | The percent of disk space used. | scaled_float |
| aws.redshift.metrics.PercentageQuotaUsed.avg | The percentage of disk or storage space used relative to the configured schema quota. | long |
| aws.redshift.metrics.QueriesCompletedPerSecond.avg | The average number of queries completed per second. | long |
| aws.redshift.metrics.QueryDuration.avg | The average amount of time to complete a query. | long |
| aws.redshift.metrics.QueryRuntimeBreakdown.avg | The total time queries spent running by query stage. | long |
| aws.redshift.metrics.ReadIOPS.avg | The average number of disk read operations per second. | long |
| aws.redshift.metrics.ReadLatency.avg | The average amount of time taken for disk read I/O operations. | long |
| aws.redshift.metrics.ReadThroughput.avg | The average number of bytes read from disk per second. | long |
| aws.redshift.metrics.SchemaQuota.avg | The configured quota for a schema. | long |
| aws.redshift.metrics.StorageUsed.avg | The disk or storage space used by a schema. | long |
| aws.redshift.metrics.TotalTableCount.avg | The number of user tables open at a particular point in time. | long |
| aws.redshift.metrics.WLMQueriesCompletedPerSecond.avg | The average number of queries completed per second for a workload management (WLM) queue. | long |
| aws.redshift.metrics.WLMQueryDuration.avg | The average length of time to complete a query for a workload management (WLM) queue. | long |
| aws.redshift.metrics.WLMQueueLength.avg | The number of queries waiting to enter a workload management (WLM) queue. | long |
| aws.redshift.metrics.WLMQueueWaitTime.avg | The total time queries spent waiting in the workload management (WLM) queue. | long |
| aws.redshift.metrics.WLMRunningQueries.avg | The number of queries running from both the main cluster and concurrency scaling cluster per WLM queue. | long |
| aws.redshift.metrics.WriteIOPS.avg | The average number of write operations per second. | long |
| aws.redshift.metrics.WriteLatency.avg | The average amount of time taken for disk write I/O operations. | long |
| aws.redshift.metrics.WriteThroughput.avg | The average number of bytes written to disk per second. | long |
| aws.tags.\* | Tag key value pairs from aws resources. | object |
| cloud | Fields related to the cloud or infrastructure the events are coming from. | group |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container | Container fields are used for meta information about the specific container that is the source of information. These fields help correlate data based containers from any runtime. | group |
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
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |
| host.architecture | Operating system architecture. | keyword |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
