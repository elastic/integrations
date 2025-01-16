# Rubrik RSC Metrics Integration

This integration periodically fetches metrics from [Rubrik GraphQL API](https://www.rubrik.com/resources/api-integration). It collects a wide range of metrics including virtual machines, filesets, volumes, node statistics, and drives performance.

These metrics help you understand how to properly manage your Rubrik infrastructure.

## Compatibility

The integration uses the [HTTP JSON input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-httpjson.html) to collect metrics from Rubrik APIs.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Configuration

To configure this integration in Elastic, you need the following information:

- Hostname
- Client ID
- Client Secret
- Token URL

For more details on these settings, refer to the [Rubrik official documentation](https://docs.rubrik.com/en-us/saas/saas/adding_a_service_account.html).

### Enabling the integration in Elastic

1. In Kibana, navigate to **Management > Integrations**
2. In the "Search for integrations" search bar, type **Rubrik**
3. Click on "Rubrik RSC Metrics" integration from the search results
4. Click on the **Add Rubrik RSC Metrics Integration** button to add the integration

## Metrics

### Managed Volumes

The `managed_volumes` dataset provides metrics related to the health and status of managed volumes.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| rubrik.managed_volumes.free_size.bytes | Free capacity for the volume across all the channels, in bytes. | long | byte | gauge |
| rubrik.managed_volumes.name | The name of the Managed Volume. | keyword |  |  |
| rubrik.managed_volumes.num_channels.count | Number of channels to divide the volume into. Each channel provides a unique share to write to. | long |  | gauge |
| rubrik.managed_volumes.pending_snapshots.count | The total number of snapshots present for the workload. | long |  | gauge |
| rubrik.managed_volumes.state | State of managed volume. | keyword |  |  |
| rubrik.managed_volumes.total_snapshots.count | The total number of snapshots present for the workload. | long |  | gauge |
| rubrik.managed_volumes.used_size.bytes | Used capacity for the volume across all the channels, in bytes. | long | byte | gauge |
| rubrik.managed_volumes.volume_size.bytes | Maximum capacity for the volume across all the channels, in bytes. | long | byte | gauge |


### Monitoring Jobs

The `monitoring_jobs` dataset provides metrics related to the series of activities on either the RSC or a Rubrik cluster.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| rubrik.monitoring_jobs.all_jobs.count | The total count of all jobs. | long | gauge |
| rubrik.monitoring_jobs.archive_jobs.count | The total count of all archive jobs. | long | gauge |
| rubrik.monitoring_jobs.backup_jobs.count | The total count of all backup jobs. | long | gauge |
| rubrik.monitoring_jobs.cluster_id | The ID of the Cluster associated with the jobs. | keyword |  |
| rubrik.monitoring_jobs.cluster_name | The name of the Cluster associated with the jobs. | keyword |  |
| rubrik.monitoring_jobs.conversion_jobs.count | The total count of all conversion jobs. | long | gauge |
| rubrik.monitoring_jobs.log_backup_jobs.count | The total count of all log backup jobs. | long | gauge |
| rubrik.monitoring_jobs.recovery_jobs.count | The total count of all recovery jobs. | long | gauge |
| rubrik.monitoring_jobs.replication_jobs.count | The total count of all replication jobs. | long | gauge |


### Virtual Machines

The `virtualmachines` dataset provides metrics related to the state of the virtual machines.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| rubrik.virtualmachine.agent_status | The status of the Rubrik Backup Service agent for virtual machines. Supported in v5.0+. | keyword |
| rubrik.virtualmachine.cluster_name | The Rubrik cluster name where this object originated. | keyword |
| rubrik.virtualmachine.id | The object ID. | keyword |
| rubrik.virtualmachine.name | The name of the hierarchy object. | keyword |
| rubrik.virtualmachine.power_status | The power status of VM (ON,OFF,SLEEP etc.). Supported in v5.0+. | keyword |


An example event for `virtualmachines` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "e74cda94-80b2-42d7-a508-21885a2614b5",
        "type": "filebeat",
        "ephemeral_id": "091ede6d-809e-4d2e-9f21-33187c53b7d4",
        "version": "8.16.0"
    },
    "rubrik": {
        "virtualmachine": {
            "agent_status": "UNREGISTERED",
            "cluster_name": "100-rubrik",
            "power_status": "POWERED_OFF",
            "name": "dashboard01",
            "id": "25842075-fd83-4c75-8709-310166ef792d"
        }
    },
    "@timestamp": "2025-01-08T13:08:18.698Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "rubrik.virtualmachines"
    },
    "elastic_agent": {
        "id": "e74cda94-80b2-42d7-a508-21885a2614b5",
        "version": "8.16.0",
        "snapshot": false
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "6.8.0-51-generic",
            "name": "Wolfi",
            "type": "linux",
            "version": "20230201",
            "platform": "wolfi"
        },
        "containerized": false,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-12-00-07"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-08T13:08:19Z",
        "created": "2025-01-08T13:08:18.698Z",
        "kind": "metric",
        "dataset": "rubrik.virtualmachines"
    }
}
```

### Filesets

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| rubrik.fileset.archive_snapshots.count | The number of snapshots that have been archived. | long |  | gauge |
| rubrik.fileset.archive_storage.bytes | The amount of storage used by archived snapshots. | long | byte | gauge |
| rubrik.fileset.compliance_status | The current compliance status of the workload. | keyword |  |  |
| rubrik.fileset.host.os_type | The operating system type of the host. | keyword |  |  |
| rubrik.fileset.local_storage.bytes | The local storage size in bytes. | long | byte | gauge |
| rubrik.fileset.name | The name of the Fileset. | keyword |  |  |
| rubrik.fileset.total_snapshots.count | The total number of snapshots present for the workload. | long |  | gauge |


An example event for `filesets` looks as following:

```json
{
    "agent": {
        "name": "ip-172-31-39-96.eu-north-1.compute.internal",
        "id": "7c37e065-93e1-4e86-a2c9-ee166c4eccbb",
        "type": "filebeat",
        "ephemeral_id": "e897b559-c04a-471f-ba91-b2e6b84a5a3c",
        "version": "8.13.2"
    },
    "rubrik": {
        "fileset": {
            "archive_snapshots": 0,
            "total_snapshots": 6,
            "local_storage": 1286184885,
            "name": "Linux",
            "host": {
                "os_type": "LINUX"
            },
            "archive_storage": 0,
            "compliance_status": "OUT_OF_COMPLIANCE"
        }
    },
    "@timestamp": "2025-01-16T07:23:59.158Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "rubrik.filesets"
    },
    "elastic_agent": {
        "id": "7c37e065-93e1-4e86-a2c9-ee166c4eccbb",
        "version": "8.13.2",
        "snapshot": false
    },
    "host": {
        "hostname": "ip-172-31-39-96.eu-north-1.compute.internal",
        "os": {
            "kernel": "6.1.82-99.168.amzn2023.x86_64",
            "codename": "Amazon Linux",
            "name": "Amazon Linux",
            "type": "linux",
            "family": "redhat",
            "version": "2023",
            "platform": "amzn"
        },
        "containerized": false,
        "ip": [
            "172.31.39.96",
            "fe80::88f:89ff:fea6:2561",
            "172.17.0.1",
            "fe80::42:77ff:fe00:bad7",
            "172.18.0.1",
            "fe80::42:ff:fe6c:4aef",
            "fe80::1803:deff:fef6:6cf3",
            "172.19.0.1",
            "fe80::42:dff:fed2:b9a9",
            "fe80::54a9:a8ff:feb8:2d8d"
        ],
        "name": "ip-172-31-39-96.eu-north-1.compute.internal",
        "id": "ec2130e5d5c423ed85ac1c1a0b96beeb",
        "mac": [
            "02-42-00-6C-4A-EF",
            "02-42-0D-D2-B9-A9",
            "02-42-77-00-BA-D7",
            "0A-8F-89-A6-25-61",
            "1A-03-DE-F6-6C-F3",
            "56-A9-A8-B8-2D-8D"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-16T07:24:09Z",
        "original": "{\"archiveSnapshots\":0,\"archiveStorage\":0,\"complianceStatus\":\"OUT_OF_COMPLIANCE\",\"filesetName\":\"Linux\",\"localStorage\":1286184885,\"osType\":\"LINUX\",\"totalSnapshots\":6}",
        "kind": "metric",
        "dataset": "rubrik.filesets"
    },
    "tags": [
        "preserve_original_event",
        "rubrik.filesets"
    ]
}

```