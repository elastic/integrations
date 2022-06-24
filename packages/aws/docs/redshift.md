# Amazon Redshift

This integration is used to fetch metrics from [Amazon Redshift](https://aws.amazon.com/redshift/).

## Metrics

The `redshift` dataset collects Amazon Redshift metrics.

An example event for `redshift` looks as following:

```json
{
    "@timestamp": "2022-06-15T12:43:00.000Z",
    "agent": {
        "ephemeral_id": "61635543-c809-4a99-acc8-bcff893d2f51",
        "id": "f793915a-7373-423f-9336-8470608ebf56",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "aws": {
        "cloudwatch": {
            "namespace": "AWS/Redshift"
        },
        "dimensions": {
            "ClusterIdentifier": "elastic-package-test-19342"
        },
        "redshift": {
            "status": {
                "maintenance_mode": 0
            }
        }
    },
    "cloud": {
        "account": {
            "id": "627286350134",
            "name": "elastic-observability"
        },
        "provider": "aws",
        "region": "eu-west-1"
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
        "id": "f793915a-7373-423f-9336-8470608ebf56",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "aws.redshift",
        "duration": 1517261817,
        "ingested": "2022-06-15T12:58:21Z",
        "module": "aws"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.96.7"
        ],
        "mac": [
            "02:42:c0:a8:60:07"
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
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
