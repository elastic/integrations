# Hadoop

The Hadoop integration collects and parses data from the Hadoop Events APIs and using the Jolokia Metricbeat Module.

## Compatibility

This module has been tested against `Hadoop version 3.3.1`

## Requirements

In order to ingest data from Hadoop, you must know the full hosts for the NameNode, DataNode, Cluster Metrics, Node Manager and the Hadoop Events API.

## Metrics

### Application Metrics

This is the `application_metrics` dataset.

An example event for `application` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "fe616aca-63f2-4dfd-8a48-82c3f173c36f",
        "ephemeral_id": "8a26946e-0961-4b81-b95a-42a562c407f8",
        "type": "filebeat",
        "version": "7.16.0"
    },
    "elastic_agent": {
        "id": "fe616aca-63f2-4dfd-8a48-82c3f173c36f",
        "version": "7.16.0",
        "snapshot": false
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "hadoop-application_metrics"
    ],
    "input": {
        "type": "httpjson"
    },
    "@timestamp": "2022-01-19T12:20:04.523Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "hadoop.application_metrics"
    },
    "hadoop": {
        "metrics": {
            "application_metrics": {
                "running_containers": -1,
                "resources_allocated": {
                    "mb": -1,
                    "vcores": -1
                },
                "memory_seconds": 118465,
                "vcore_seconds": 82,
                "progress": 100,
                "time": {
                    "elapsed": 22876,
                    "started": 1642570914236,
                    "finished": 1642570937112
                }
            }
        }
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2022-01-19T12:20:05Z",
        "original": "{\"allocatedMB\":-1,\"allocatedVCores\":-1,\"amContainerLogs\":\"https://ip-10-0-13-217.demo.local:8090/node/containerlogs/container_1642069247440_0003_01_000001/root\",\"amHostHttpAddress\":\"ip-10-0-13-217.demo.local:8090\",\"amNodeLabelExpression\":\"\",\"amRPCAddress\":\"ip-10-0-13-217.demo.local:33369\",\"applicationTags\":\"\",\"applicationType\":\"MAPREDUCE\",\"clusterId\":1642123447440,\"clusterUsagePercentage\":0,\"diagnostics\":\"\",\"elapsedTime\":22876,\"finalStatus\":\"SUCCEEDED\",\"finishedTime\":1642570937112,\"id\":\"application_1642069247440_0003\",\"launchTime\":1642570914370,\"logAggregationStatus\":\"DISABLED\",\"masterNodeId\":\"ip-10-0-13-217.demo.local:37641\",\"memorySeconds\":118465,\"name\":\"QuasiMonteCarlo\",\"numAMContainerPreempted\":0,\"numNonAMContainerPreempted\":0,\"preemptedMemorySeconds\":0,\"preemptedResourceMB\":0,\"preemptedResourceSecondsMap\":{},\"preemptedResourceVCores\":0,\"preemptedVcoreSeconds\":0,\"priority\":0,\"progress\":100,\"queue\":\"default\",\"queueUsagePercentage\":0,\"reservedMB\":-1,\"reservedVCores\":-1,\"resourceSecondsMap\":{\"entry\":{\"key\":\"vcores\",\"value\":\"82\"}},\"runningContainers\":-1,\"startedTime\":1642570914236,\"state\":\"FINISHED\",\"timeouts\":{\"timeout\":[{\"expiryTime\":\"UNLIMITED\",\"remainingTimeInSeconds\":-1,\"type\":\"LIFETIME\"}]},\"trackingUI\":\"History\",\"trackingUrl\":\"https://10.0.13.216:9046/proxy/application_1642069247440_0003/\",\"unmanagedApplication\":false,\"user\":\"root\",\"vcoreSeconds\":82}",
        "created": "2022-01-19T12:20:04.523Z",
        "kind": "metric",
        "type": "info",
        "category": "database",
        "dataset": "hadoop.application_metrics"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| hadoop.metrics.application_metrics.memory_seconds |  | long |
| hadoop.metrics.application_metrics.progress |  | long |
| hadoop.metrics.application_metrics.resources_allocated.mb |  | long |
| hadoop.metrics.application_metrics.resources_allocated.vcores |  | long |
| hadoop.metrics.application_metrics.running_containers |  | long |
| hadoop.metrics.application_metrics.time.elapsed |  | long |
| hadoop.metrics.application_metrics.time.finished |  | long |
| hadoop.metrics.application_metrics.time.started |  | long |
| hadoop.metrics.application_metrics.vcore_seconds |  | long |
| input.type |  | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Expanded Cluster Metrics

This is the `expanded_cluster_metrics` dataset.

An example event for `expanded_cluster` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "fe616aca-63f2-4dfd-8a48-82c3f173c36f",
        "ephemeral_id": "8a26946e-0961-4b81-b95a-42a562c407f8",
        "type": "filebeat",
        "version": "7.16.0"
    },
    "elastic_agent": {
        "id": "fe616aca-63f2-4dfd-8a48-82c3f173c36f",
        "version": "7.16.0",
        "snapshot": false
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "hadoop-expanded_cluster_metrics"
    ],
    "input": {
        "type": "httpjson"
    },
    "@timestamp": "2022-01-20T06:03:26.164Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "hadoop.expanded_cluster_metrics"
    },
    "hadoop": {
        "metrics": {
            "expanded_cluster_metrics": {
                "memory": {
                    "total": 6144,
                    "reserved": 0,
                    "available": 6144,
                    "allocated": 0
                },
                "nodes": {
                    "decommissioned": 0,
                    "total": 2,
                    "rebooted": 0,
                    "lost": 0,
                    "unhealthy": 0,
                    "active": 2,
                    "decommissioning": 0,
                    "shutdown": 0
                },
                "containers": {
                    "reserved": 0,
                    "pending": 0,
                    "allocated": 0
                },
                "virtual_cores": {
                    "total": 16,
                    "reserved": 0,
                    "available": 16,
                    "allocated": 0
                },
                "apps": {
                    "running": 0,
                    "submitted": 0,
                    "pending": 0,
                    "completed": 0,
                    "failed": 0,
                    "killed": 0
                }
            }
        }
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2022-01-20T06:03:27Z",
        "original": "{\"clusterMetrics\":{\"activeNodes\":2,\"allocatedMB\":0,\"allocatedVirtualCores\":0,\"appsCompleted\":0,\"appsFailed\":0,\"appsKilled\":0,\"appsPending\":0,\"appsRunning\":0,\"appsSubmitted\":0,\"availableMB\":6144,\"availableVirtualCores\":16,\"containersAllocated\":0,\"containersPending\":0,\"containersReserved\":0,\"crossPartitionMetricsAvailable\":true,\"decommissionedNodes\":0,\"decommissioningNodes\":0,\"lostNodes\":0,\"pendingMB\":0,\"pendingVirtualCores\":0,\"rebootedNodes\":0,\"reservedMB\":0,\"reservedVirtualCores\":0,\"rmSchedulerBusyPercent\":0,\"shutdownNodes\":0,\"totalAllocatedContainersAcrossPartition\":0,\"totalClusterResourcesAcrossPartition\":{\"memory\":6144,\"resourceInformations\":{\"resourceInformation\":[{\"attributes\":{},\"maximumAllocation\":9223372036854776000,\"minimumAllocation\":0,\"name\":\"memory-mb\",\"resourceType\":\"COUNTABLE\",\"units\":\"Mi\",\"value\":6144},{\"attributes\":{},\"maximumAllocation\":9223372036854776000,\"minimumAllocation\":0,\"name\":\"vcores\",\"resourceType\":\"COUNTABLE\",\"units\":\"\",\"value\":16}]},\"vCores\":16},\"totalMB\":6144,\"totalNodes\":2,\"totalReservedResourcesAcrossPartition\":{\"memory\":0,\"resourceInformations\":{\"resourceInformation\":[{\"attributes\":{},\"maximumAllocation\":9223372036854776000,\"minimumAllocation\":0,\"name\":\"memory-mb\",\"resourceType\":\"COUNTABLE\",\"units\":\"Mi\",\"value\":0},{\"attributes\":{},\"maximumAllocation\":9223372036854776000,\"minimumAllocation\":0,\"name\":\"vcores\",\"resourceType\":\"COUNTABLE\",\"units\":\"\",\"value\":0}]},\"vCores\":0},\"totalUsedResourcesAcrossPartition\":{\"memory\":0,\"resourceInformations\":{\"resourceInformation\":[{\"attributes\":{},\"maximumAllocation\":9223372036854776000,\"minimumAllocation\":0,\"name\":\"memory-mb\",\"resourceType\":\"COUNTABLE\",\"units\":\"Mi\",\"value\":0},{\"attributes\":{},\"maximumAllocation\":9223372036854776000,\"minimumAllocation\":0,\"name\":\"vcores\",\"resourceType\":\"COUNTABLE\",\"units\":\"\",\"value\":0}]},\"vCores\":0},\"totalVirtualCores\":16,\"unhealthyNodes\":0,\"utilizedMBPercent\":61,\"utilizedVirtualCoresPercent\":0}}",
        "created": "2022-01-20T06:03:26.164Z",
        "kind": "metric",
        "type": "info",
        "category": "database",
        "dataset": "hadoop.expanded_cluster_metrics"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| hadoop.metrics.expanded_cluster_metrics.apps.completed |  | long |
| hadoop.metrics.expanded_cluster_metrics.apps.failed |  | long |
| hadoop.metrics.expanded_cluster_metrics.apps.killed |  | long |
| hadoop.metrics.expanded_cluster_metrics.apps.pending |  | long |
| hadoop.metrics.expanded_cluster_metrics.apps.running |  | long |
| hadoop.metrics.expanded_cluster_metrics.apps.submitted |  | long |
| hadoop.metrics.expanded_cluster_metrics.containers.allocated |  | long |
| hadoop.metrics.expanded_cluster_metrics.containers.pending |  | long |
| hadoop.metrics.expanded_cluster_metrics.containers.reserved |  | long |
| hadoop.metrics.expanded_cluster_metrics.memory.allocated |  | long |
| hadoop.metrics.expanded_cluster_metrics.memory.available |  | long |
| hadoop.metrics.expanded_cluster_metrics.memory.reserved |  | long |
| hadoop.metrics.expanded_cluster_metrics.memory.total |  | long |
| hadoop.metrics.expanded_cluster_metrics.nodes.active |  | long |
| hadoop.metrics.expanded_cluster_metrics.nodes.decommissioned |  | long |
| hadoop.metrics.expanded_cluster_metrics.nodes.decommissioning |  | long |
| hadoop.metrics.expanded_cluster_metrics.nodes.lost |  | long |
| hadoop.metrics.expanded_cluster_metrics.nodes.rebooted |  | long |
| hadoop.metrics.expanded_cluster_metrics.nodes.shutdown |  | long |
| hadoop.metrics.expanded_cluster_metrics.nodes.total |  | long |
| hadoop.metrics.expanded_cluster_metrics.nodes.unhealthy |  | long |
| hadoop.metrics.expanded_cluster_metrics.virtual_cores.allocated |  | long |
| hadoop.metrics.expanded_cluster_metrics.virtual_cores.available |  | long |
| hadoop.metrics.expanded_cluster_metrics.virtual_cores.reserved |  | long |
| hadoop.metrics.expanded_cluster_metrics.virtual_cores.total |  | long |
| input.type |  | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Jolokia Metrics

This is the `jolokia_metrics` dataset.

An example event for `jolokia` looks as following:

```json
{
    "@timestamp": "2022-03-04T08:29:25.570Z",
    "agent": {
        "ephemeral_id": "b71badb4-568b-499c-abb4-9c1ac833c0df",
        "id": "ec674add-b610-4acb-a420-3eeb4cb3e768",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "hadoop.jolokia_metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "ec674add-b610-4acb-a420-3eeb4cb3e768",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "hadoop.jolokia_metrics",
        "duration": 31080147,
        "ingested": "2022-03-04T08:29:29Z",
        "kind": "metric",
        "module": "hadoop",
        "type": "info"
    },
    "hadoop": {
        "metrics": {
            "namenode": {
                "blocks": {
                    "corrupt": 0,
                    "total": 0
                },
                "capacity": {
                    "remaining": 0,
                    "total": 0,
                    "used": 0
                },
                "data_nodes": {
                    "num_dead": 0,
                    "num_decom_dead": 0,
                    "num_decom_live": 0,
                    "num_decommissioning": 0,
                    "num_live": 0,
                    "stale": 0
                },
                "estimated_capacity_lost_total": 0,
                "files_total": 1,
                "lock_queue_length": 0,
                "missing_repl_one_blocks": 0,
                "num_stale_storages": 0,
                "pending_deletion_blocks": 0,
                "replication_blocks": {
                    "pending": 0,
                    "scheduled": 0,
                    "under": 0
                },
                "total_load": 0,
                "volume_failures_total": 0
            }
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.21.0.6"
        ],
        "mac": [
            "02:42:ac:15:00:06"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.59.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "service": {
        "address": "http://namenode:7777/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "jolokia"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| hadoop.metrics.cluster_metrics.application_master.launch_delay_avg_time |  | float |
| hadoop.metrics.cluster_metrics.application_master.launch_delay_num_ops |  | long |
| hadoop.metrics.cluster_metrics.application_master.register_delay_avg_time |  | float |
| hadoop.metrics.cluster_metrics.application_master.register_delay_num_ops |  | long |
| hadoop.metrics.cluster_metrics.node_managers.num_active |  | long |
| hadoop.metrics.cluster_metrics.node_managers.num_decommissioned |  | long |
| hadoop.metrics.cluster_metrics.node_managers.num_lost |  | long |
| hadoop.metrics.cluster_metrics.node_managers.num_rebooted |  | long |
| hadoop.metrics.cluster_metrics.node_managers.num_unhealthy |  | long |
| hadoop.metrics.datanode.bytes.read |  | long |
| hadoop.metrics.datanode.bytes.write |  | long |
| hadoop.metrics.datanode.cache.capacity |  | long |
| hadoop.metrics.datanode.cache.num_blocks |  | long |
| hadoop.metrics.datanode.cache.used |  | long |
| hadoop.metrics.datanode.dfs_used |  | long |
| hadoop.metrics.datanode.disk_space.capacity |  | long |
| hadoop.metrics.datanode.disk_space.remaining |  | long |
| hadoop.metrics.datanode.estimated_capacity_lost_total |  | long |
| hadoop.metrics.datanode.last_volume_failure_date |  | date |
| hadoop.metrics.datanode.num_blocks_failed.to_cache |  | long |
| hadoop.metrics.datanode.num_blocks_failed.to_uncache |  | long |
| hadoop.metrics.datanode.num_failed_volumes |  | long |
| hadoop.metrics.datanode.tag.context |  | text |
| hadoop.metrics.datanode.tag.hostname |  | text |
| hadoop.metrics.datanode.tag.storage_info |  | text |
| hadoop.metrics.namenode.blocks.corrupt |  | long |
| hadoop.metrics.namenode.blocks.total |  | long |
| hadoop.metrics.namenode.capacity.remaining |  | long |
| hadoop.metrics.namenode.capacity.total |  | long |
| hadoop.metrics.namenode.capacity.used |  | long |
| hadoop.metrics.namenode.data_nodes.num_dead |  | long |
| hadoop.metrics.namenode.data_nodes.num_decom_dead |  | long |
| hadoop.metrics.namenode.data_nodes.num_decom_live |  | long |
| hadoop.metrics.namenode.data_nodes.num_decommissioning |  | long |
| hadoop.metrics.namenode.data_nodes.num_live |  | long |
| hadoop.metrics.namenode.data_nodes.stale |  | long |
| hadoop.metrics.namenode.estimated_capacity_lost_total |  | long |
| hadoop.metrics.namenode.files_total |  | long |
| hadoop.metrics.namenode.lock_queue_length |  | long |
| hadoop.metrics.namenode.memory.available |  | long |
| hadoop.metrics.namenode.memory.reserved |  | long |
| hadoop.metrics.namenode.missing_repl_one_blocks |  | long |
| hadoop.metrics.namenode.num_stale_storages |  | long |
| hadoop.metrics.namenode.pending_deletion_blocks |  | long |
| hadoop.metrics.namenode.replication_blocks.pending |  | long |
| hadoop.metrics.namenode.replication_blocks.scheduled |  | long |
| hadoop.metrics.namenode.replication_blocks.under |  | long |
| hadoop.metrics.namenode.total_load |  | long |
| hadoop.metrics.namenode.volume_failures_total |  | long |
| hadoop.metrics.nodemanager.container.allocated |  | long |
| hadoop.metrics.nodemanager.container.completed |  | long |
| hadoop.metrics.nodemanager.container.failed |  | long |
| hadoop.metrics.nodemanager.container.initing |  | long |
| hadoop.metrics.nodemanager.container.killed |  | long |
| hadoop.metrics.nodemanager.container.launch_duration_avg_time |  | long |
| hadoop.metrics.nodemanager.container.launch_duration_num_ops |  | long |
| hadoop.metrics.nodemanager.container.launched |  | long |
| hadoop.metrics.nodemanager.container.running |  | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| tags | List of keywords used to tag each event. | keyword |
