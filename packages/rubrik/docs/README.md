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
| rubrik.cluster.id | The cluster UUID. | keyword |  |  |
| rubrik.cluster.name | The cluster name. | keyword |  |  |
| rubrik.effective_sla_domain.id | The ID of the SLA domain. | keyword |  |  |
| rubrik.effective_sla_domain.name | The name of the SLA domain. | keyword |  |  |
| rubrik.managed_volumes.free_size.bytes | Free capacity for the volume across all the channels, in bytes. | long | byte | gauge |
| rubrik.managed_volumes.name | The name of the Managed Volume. | keyword |  |  |
| rubrik.managed_volumes.num_channels.count | Number of channels to divide the volume into. Each channel provides a unique share to write to. | long |  | gauge |
| rubrik.managed_volumes.pending_snapshots.count | The total number of snapshots present for the workload. | long |  | gauge |
| rubrik.managed_volumes.state | State of managed volume. | keyword |  |  |
| rubrik.managed_volumes.total_snapshots.count | The total number of snapshots present for the workload. | long |  | gauge |
| rubrik.managed_volumes.used_size.bytes | Used capacity for the volume across all the channels, in bytes. | long | byte | gauge |
| rubrik.managed_volumes.volume_size.bytes | Maximum capacity for the volume across all the channels, in bytes. | long | byte | gauge |


An example event for `managed_volumes` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "9f7dc10d-9fe5-4bc8-98ce-d4cb4661e04c",
        "ephemeral_id": "bc7df02b-35f9-477e-94c6-0e09c44c0b9c",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "rubrik": {
        "cluster": {
            "name": "cluster-1",
            "id": "7562f3f9-f7ff-4828-af2c-87df3bf4f54c"
        },
        "effective_sla_domain": {
            "id": "4031c11d-078e-4f14-8566-717cfffaf359",
            "name": "sla-domain-1"
        },
        "managed_volumes": {
            "num_channels": {
                "count": 1
            },
            "total_snapshots": {
                "count": 0
            },
            "name": "volume-1",
            "pending_snapshots": {
                "count": 0
            },
            "volume_size": {
                "bytes": 1073741824
            },
            "state": "MANAGED_VOLUME_STATE_EXPORTED",
            "used_size": {
                "bytes": 24576
            },
            "free_size": {
                "bytes": 1073717248
            }
        }
    },
    "@timestamp": "2025-01-16T20:40:02.299Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "rubrik.managed_volumes"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "6.8.0-51-generic",
            "name": "Wolfi",
            "family": "",
            "type": "linux",
            "version": "20230201",
            "platform": "wolfi"
        },
        "ip": [
            "172.18.0.4"
        ],
        "containerized": false,
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-12-00-04"
        ],
        "architecture": "x86_64"
    },
    "elastic_agent": {
        "id": "9f7dc10d-9fe5-4bc8-98ce-d4cb4661e04c",
        "version": "8.16.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-16T20:40:03Z",
        "kind": "metric",
        "dataset": "rubrik.managed_volumes"
    },
    "tags": [
        "rubrik.managed_volumes"
    ]
}
```

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
| rubrik.cluster.id | The cluster UUID. | keyword |  |
| rubrik.cluster.name | The cluster name. | keyword |  |
| rubrik.monitoring_jobs.all_jobs.count | The total count of all jobs. | long | gauge |
| rubrik.monitoring_jobs.archive_jobs.count | The total count of all archive jobs. | long | gauge |
| rubrik.monitoring_jobs.backup_jobs.count | The total count of all backup jobs. | long | gauge |
| rubrik.monitoring_jobs.conversion_jobs.count | The total count of all conversion jobs. | long | gauge |
| rubrik.monitoring_jobs.log_backup_jobs.count | The total count of all log backup jobs. | long | gauge |
| rubrik.monitoring_jobs.recovery_jobs.count | The total count of all recovery jobs. | long | gauge |
| rubrik.monitoring_jobs.replication_jobs.count | The total count of all replication jobs. | long | gauge |


An example event for `monitoring_jobs` looks as following:

```json
{
    "agent": {
        "name": "ip-172-31-39-96.eu-north-1.compute.internal",
        "id": "7c37e065-93e1-4e86-a2c9-ee166c4eccbb",
        "type": "filebeat",
        "ephemeral_id": "7a656a0d-e5cc-4f70-9528-8d1338cfe3b8",
        "version": "8.13.2"
    },
    "rubrik": {
        "cluster": {
            "id": "52688802-aefd-4dee-9992-1e0c0623b54f",
            "name": "cluster-1"
        },
        "monitoring_jobs": {
            "log_backup_jobs": {
                "count": 0
            },
            "replication_jobs": {
                "count": 6
            },
            "recovery_jobs": {
                "count": 39
            },
            "archive_jobs": {
                "count": 8
            },
            "backup_jobs": {
                "count": 36092
            },
            "conversion_jobs": {
                "count": 0
            },
            "all_jobs": {
                "count": 668241
            }
        }
    },
    "@timestamp": "2025-01-07T17:22:42.912Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "rubrik.monitoring_jobs"
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
        "ingested": "2025-01-07T17:22:53Z",
        "original": "{\"allJobs\":668241,\"archiveJobs\":{\"count\":8},\"backupJobs\":{\"count\":36092},\"conversionJobs\":{\"count\":0},\"id\":\"7f4f96b3-e777-4bde-ba08-47a40ecaa416\",\"logBackupJobs\":{\"count\":0},\"name\":\"401-rubrik\",\"recoveryJobs\":{\"count\":39},\"replicationJobs\":{\"count\":6}}",
        "created": "2025-01-07T17:22:42.912Z",
        "kind": "metric",
        "dataset": "rubrik.monitoring_jobs"
    },
    "tags": [
        "preserve_original_event"
    ]
}
```

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
| rubrik.cluster.id | The cluster UUID. | keyword |
| rubrik.cluster.name | The cluster name. | keyword |
| rubrik.effective_sla_domain.id | The ID of the SLA domain. | keyword |
| rubrik.effective_sla_domain.name | The name of the SLA domain. | keyword |
| rubrik.virtual_machines.agent_status | The status of the Rubrik Backup Service agent for virtual machines. Supported in v5.0+. | keyword |
| rubrik.virtual_machines.id | The object ID. | keyword |
| rubrik.virtual_machines.name | The name of the hierarchy object. | keyword |
| rubrik.virtual_machines.power_status | The power status of VM (ON,OFF,SLEEP etc.). Supported in v5.0+. | keyword |


An example event for `virtual_machines` looks as following:

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
        "cluster": {
            "name": "cluster-1",
            "id": "7562f3f9-f7ff-4828-af2c-87df3bf4f54c"
        },
        "effective_sla_domain": {
            "id": "4031c11d-078e-4f14-8566-717cfffaf359",
            "name": "sla-domain-1"
        },
        "virtual_machines": {
            "agent_status": "UNREGISTERED",
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
        "dataset": "rubrik.virtual_machines"
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
        "dataset": "rubrik.virtual_machines"
    }
}
```

### Filesets

The `filesets` dataset provides metrics related to the state of the filesets.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| rubrik.cluster.id | The cluster UUID. | keyword |  |  |
| rubrik.cluster.name | The cluster name. | keyword |  |  |
| rubrik.effective_sla_domain.id | The ID of the SLA domain. | keyword |  |  |
| rubrik.effective_sla_domain.name | The name of the SLA domain. | keyword |  |  |
| rubrik.fileset.archive_snapshots.count | The number of snapshots that have been archived. | long |  | gauge |
| rubrik.fileset.archive_storage.bytes | The amount of storage used by archived snapshots. | long | byte | gauge |
| rubrik.fileset.compliance_status | The current compliance status of the workload. | keyword |  |  |
| rubrik.fileset.host_os_type | The operating system type of the host. | keyword |  |  |
| rubrik.fileset.local_storage.bytes | The local storage size in bytes. | long | byte | gauge |
| rubrik.fileset.name | The name of the Fileset. | keyword |  |  |
| rubrik.fileset.total_snapshots.count | The total number of snapshots present for the workload. | long |  | gauge |


An example event for `filesets` looks as following:

```json
{
    "agent": {
        "name": "ip-172-31-39-96",
        "id": "7c37e065-93e1-4e86-a2c9-ee166c4eccbb",
        "type": "filebeat",
        "ephemeral_id": "e897b559-c04a-471f-ba91-b2e6b84a5a3c",
        "version": "8.13.2"
    },
    "rubrik": {
        "cluster": {
            "name": "401-rubrik",
            "id": "7f4f96b3-e777-4bde-ba08-47a40ecaa416"
        },
        "effective_sla_domain": {
            "name": "2 day",
            "id": "1efe5fa8-d97f-5067-afcc-e02525ad0a4e"
        },
        "fileset": {
            "archive_snapshots": {
                "count": 0
            },
            "total_snapshots": {
                "count": 6
            },
            "local_storage": {
                "bytes": 1286184885
            },
            "name": "Linux",
            "host_os_type": "LINUX",
            "archive_storage": {
                "bytes": 0
            },
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
        "hostname": "ip-172-31-39-96",
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
        "name": "ip-172-31-39-96",
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
        "ingested": "2025-01-16T21:07:16Z",
        "original": "{\"archiveSnapshots\":0,\"archiveStorage\":0,\"clusterID\":\"7f4f96b3-e777-4bde-ba08-47a40ecaa416\",\"clusterName\":\"401-rubrik\",\"complianceStatus\":\"OUT_OF_COMPLIANCE\",\"effectiveSlaDomainID\":\"1efe5fa8-d97f-5067-afcc-e02525ad0a4e\",\"effectiveSlaDomainName\":\"2 day\",\"filesetName\":\"Linux\",\"localStorage\":1286184885,\"osType\":\"LINUX\",\"totalSnapshots\":6}",
        "kind": "metric",
        "dataset": "rubrik.filesets"
    },
    "tags": [
        "preserve_original_event",
        "rubrik.filesets"
    ]
}
```

### Drives

The `drives` dataset provides metrics related to the state of the drives.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| rubrik.cluster.id | The cluster UUID. | keyword |  |  |
| rubrik.cluster.name | The cluster name. | keyword |  |  |
| rubrik.drives.capacity.bytes | Disk capacity, in bytes. | long | byte | gauge |
| rubrik.drives.id | ID of the Rubrik cluster disk type. | keyword |  |  |
| rubrik.drives.is_encrypted | Specifies if the disk is encrypted. | boolean |  |  |
| rubrik.drives.node_id | ID of the Rubrik cluster node. | keyword |  |  |
| rubrik.drives.path | Disk path. | keyword |  |  |
| rubrik.drives.status | Represents cluster's knowledge of a disk state. | keyword |  |  |
| rubrik.drives.type | Disk type. | keyword |  |  |
| rubrik.drives.unallocated.bytes | Disk unallocated bytes. | long | byte | gauge |
| rubrik.drives.usable.bytes | Disk usable bytes. | long | byte | gauge |


An example event for `drives` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "a35969d5-ae9b-49a1-87f2-cbc521f2989a",
        "type": "filebeat",
        "ephemeral_id": "e77b39f7-c984-4d5a-ae7e-dba3567aab2f",
        "version": "8.16.0"
    },
    "rubrik": {
        "cluster": {
            "name": "cluster-1",
            "id": "acbd69a0-64d3-4a34-a83e-c4ecddcd34b8"
        },
        "drives": {
            "path": "/mnt/wwn-0x4123a4004a3612c7",
            "usable": {
                "bytes": 1452177072128
            },
            "unallocated": {
                "bytes": 1492201697280
            },
            "is_encrypted": false,
            "id": "sdd",
            "node_id": "1f7c2a2a-8631-416d-abfb-0ab97c2e0fd0",
            "type": "HDD",
            "status": "ACTIVE",
            "capacity": {
                "bytes": 3834792386560
            }
        }
    },
    "@timestamp": "2025-01-15T17:26:20.012Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "rubrik.drives"
    },
    "elastic_agent": {
        "id": "a35969d5-ae9b-49a1-87f2-cbc521f2989a",
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
        "ingested": "2025-01-15T17:26:21Z",
        "created": "2025-01-15T17:26:20.012Z",
        "kind": "metric",
        "dataset": "rubrik.drives"
    }
}
```

### Physical Hosts

The `physical_hosts` dataset provides metrics related to the state of the physical hosts.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| rubrik.cluster.id | The cluster UUID. | keyword |
| rubrik.cluster.name | The cluster name. | keyword |
| rubrik.effective_sla_domain.id | The ID of the SLA domain. | keyword |
| rubrik.effective_sla_domain.name | The name of the SLA domain. | keyword |
| rubrik.physical_hosts.connectivity_status | Connectivity status of host. | keyword |
| rubrik.physical_hosts.id | ID of the physical host. | keyword |
| rubrik.physical_hosts.name | Name of the physical host. | keyword |
| rubrik.physical_hosts.os_type | The operating system type of the physical host. | keyword |


An example event for `physical_hosts` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "0aae3c7e-885b-4e49-9419-379e87197012",
        "ephemeral_id": "3a87f3c5-7e6f-412c-8b8b-ec856a732f8a",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "rubrik": {
        "cluster": {
            "name": "cluster-1",
            "id": "7562f3f9-f7ff-4828-af2c-87df3bf4f54c"
        },
        "effective_sla_domain": {
            "id": "4031c11d-078e-4f14-8566-717cfffaf359",
            "name": "sla-domain-1"
        },
        "physical_hosts": {
            "connectivity_status": "DISCONNECTED",
            "os_type": "WINDOWS",
            "name": "0.0.0.0",
            "id": "aed47d37-4267-4b15-9a4c-be41c215cb52"
        }
    },
    "@timestamp": "2025-01-09T18:54:45.445Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "rubrik.physical_hosts"
    },
    "elastic_agent": {
        "id": "0aae3c7e-885b-4e49-9419-379e87197012",
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
        "ip": [
            "172.18.0.7"
        ],
        "containerized": false,
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-12-00-07"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-09T18:54:46Z",
        "kind": "metric",
        "dataset": "rubrik.physical_hosts"
    },
    "tags": [
        "rubrik.physical_hosts"
    ]
}
```

### MSSQL Databases

The `mssql_databases` dataset provides metrics related to the state of the MSSQL databases.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| rubrik.cluster.id | The cluster UUID. | keyword |
| rubrik.cluster.name | The cluster name. | keyword |
| rubrik.effective_sla_domain.id | The ID of the SLA domain. | keyword |
| rubrik.effective_sla_domain.name | The name of the SLA domain. | keyword |
| rubrik.mssql_databases.id | ID of the database. | keyword |
| rubrik.mssql_databases.is_online | Specifies if the SQL Server database is online. | boolean |
| rubrik.mssql_databases.missed_snapshots.count | Number of missed snapshots. | long |
| rubrik.mssql_databases.name | Name of the database. | keyword |


An example event for `mssql_databases` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "19728c71-8995-495f-acbd-ab53d6a60f02",
        "type": "filebeat",
        "ephemeral_id": "f7b08e7b-5b53-4ee4-b651-ebee08783840",
        "version": "8.16.0"
    },
    "rubrik": {
        "cluster": {
            "name": "cluster-1",
            "id": "f5ce5ffc-42d4-47bc-a64f-d928030892d5"
        },
        "effective_sla_domain": {
            "id": "4031c11d-078e-4f14-8566-717cfffaf359",
            "name": "sla-domain-1"
        },
        "mssql_databases": {
            "name": "name-1",
            "id": "2abed6ca-bbf7-42df-a402-2166a7abebd0",
            "is_online": true
        }
    },
    "@timestamp": "2025-01-15T13:32:41.191Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "rubrik.mssql_databases"
    },
    "elastic_agent": {
        "id": "19728c71-8995-495f-acbd-ab53d6a60f02",
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
        "ip": [
            "172.18.0.7"
        ],
        "containerized": false,
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-12-00-07"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-15T13:32:42Z",
        "created": "2025-01-15T13:32:41.191Z",
        "kind": "metric",
        "dataset": "rubrik.mssql_databases"
    }
}
```

### Tasks

The `tasks` dataset provides metrics related to the state of Rubrik backup and object protection tasks by SLA Domain.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| rubrik.cluster.id | The cluster UUID. | keyword |  |
| rubrik.cluster.name | The cluster name. | keyword |  |
| rubrik.sla_domain.id | The Rubrik SLA domain id. | keyword |  |
| rubrik.sla_domain.name | The Rubrik SLA domain name. | keyword |  |
| rubrik.tasks.canceled.count | The number of tasks that have been canceled. | long | gauge |
| rubrik.tasks.failed.count | The number of tasks that have failed. | long | gauge |
| rubrik.tasks.metric_type | The metric type. | keyword |  |
| rubrik.tasks.missed.count | The number of tasks that have missed. | long | gauge |
| rubrik.tasks.succeeded.count | The number of tasks that have succeeded. | long | gauge |


An example event for `tasks` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "6cc06f03-70ef-4dbc-aada-2891efc09a09",
        "ephemeral_id": "1b4ac717-821e-4363-b42e-5a13ba790f8c",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "rubrik": {
        "sla_domain": {
            "name": "name-1",
            "id": "4755b8b8-116b-4466-affb-c683f9339b10"
        },
        "tasks": {
            "metric_type": "succeeded_tasks",
            "succeeded": {
                "count": 7
            }
        }
    },
    "@timestamp": "2025-01-17T21:58:09.564Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "rubrik.tasks"
    },
    "elastic_agent": {
        "id": "6cc06f03-70ef-4dbc-aada-2891efc09a09",
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
        "ingested": "2025-01-17T21:58:10Z",
        "kind": "metric",
        "dataset": "rubrik.tasks"
    }
}
```

### Global Cluster Performance

The `global_cluster_performance` dataset provides performance related metrics like IOPS, throughput, storage utilization, storage details, streams, and physical ingest of Rubrik Clusters.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| rubrik.cluster.id | The cluster UUID. | keyword |  |  |
| rubrik.cluster.name | The cluster name. | keyword |  |  |
| rubrik.cluster.type | The type of the cluster (e.g., OnPrem, Robo, Polaris). | keyword |  |  |
| rubrik.cluster_performance.available_capacity.bytes | The amount of available storage capacity in bytes. | long | byte | gauge |
| rubrik.cluster_performance.average_daily_growth.bytes | The average daily growth of data in bytes. | long | byte | gauge |
| rubrik.cluster_performance.cdp_capacity.bytes | The amount of storage used by Continuous Data Protection (CDP) in bytes. | long | byte | gauge |
| rubrik.cluster_performance.estimated_runway | The estimated number of days before the cluster reaches full capacity. | long |  |  |
| rubrik.cluster_performance.ingested_snapshot_storage.bytes | The total amount of ingested snapshot storage in bytes. | long | byte | gauge |
| rubrik.cluster_performance.live_mount_capacity.bytes | The amount of storage used by live mounts in bytes. | long | byte | gauge |
| rubrik.cluster_performance.miscellaneous_capacity.bytes | The amount of storage used for miscellaneous purposes in bytes. | long | byte | gauge |
| rubrik.cluster_performance.pending_snapshot_capacity.bytes | The amount of storage reserved for pending snapshots in bytes. | long | byte | gauge |
| rubrik.cluster_performance.physical_snapshot_storage.bytes | The amount of physical storage used by snapshots in bytes. | long | byte | gauge |
| rubrik.cluster_performance.snapshot_capacity.bytes | The total storage capacity used by snapshots in bytes. | long | byte | gauge |
| rubrik.cluster_performance.status | The current connectivity status of the cluster. | keyword |  |  |
| rubrik.cluster_performance.total_capacity.bytes | The total storage capacity of the cluster in bytes. | long | byte | gauge |
| rubrik.cluster_performance.used_capacity.bytes | The amount of used storage capacity in bytes. | long | byte | gauge |


An example event for `global_cluster_performance` looks as following:

```json
{
    "agent": {
        "name": "ip-172-31-39-96",
        "id": "7c37e065-93e1-4e86-a2c9-ee166c4eccbb",
        "type": "filebeat",
        "ephemeral_id": "e897b559-c04a-471f-ba91-b2e6b84a5a3c",
        "version": "8.13.2"
    },
    "rubrik": {
        "cluster": {
            "id": "b1a9e557-0b47-4bc1-841d-e6379e733016",
            "name": "prod-rub1",
            "type": "Robo"
        },
        "cluster_performance": {
            "miscellaneous_capacity": {
                "bytes": 3490865159
            },
            "pending_snapshot_capacity": {
                "bytes": 2064
            },
            "physical_snapshot_storage": {
                "bytes": 313507076073
            },
            "live_mount_capacity": {
                "bytes": 0
            },
            "used_capacity": {
                "bytes": 316997943296
            },
            "ingested_snapshot_storage": {
                "bytes": 436860485632
            },
            "snapshot_capacity": {
                "bytes": 313507076073
            },
            "available_capacity": {
                "bytes": 719592345600
            },
            "total_capacity": {
                "bytes": 1036590288896
            },
            "average_daily_growth": {
                "bytes": 630829064
            },
            "cdp_capacity": {
                "bytes": 0
            },
            "estimated_runway": 1140,
            "status": "Disconnected"
        }
    },
    "@timestamp": "2025-01-31T13:41:37.416Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "rubrik.global_cluster_performance"
    },
    "elastic_agent": {
        "id": "7c37e065-93e1-4e86-a2c9-ee166c4eccbb",
        "version": "8.13.2",
        "snapshot": false
    },
    "host": {
        "hostname": "ip-172-31-39-96",
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
        "name": "ip-172-31-39-96",
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
        "ingested": "2025-01-31T13:41:47Z",
        "original": "{\"estimatedRunway\":1140,\"id\":\"b1a9e557-0b47-4bc1-841d-e6379e733016\",\"metric\":{\"availableCapacity\":719592345600,\"averageDailyGrowth\":630829064,\"cdpCapacity\":0,\"ingestedSnapshotStorage\":436860485632,\"liveMountCapacity\":0,\"miscellaneousCapacity\":3490865159,\"pendingSnapshotCapacity\":2064,\"physicalSnapshotStorage\":313507076073,\"snapshotCapacity\":313507076073,\"totalCapacity\":1036590288896,\"usedCapacity\":316997943296},\"name\":\"prod-rub1\",\"status\":\"Disconnected\",\"type\":\"Robo\"}",
        "kind": "metric",
        "dataset": "rubrik.global_cluster_performance"
    },
    "tags": [
        "preserve_original_event",
        "rubrik.cluster_performance"
    ]
}
```