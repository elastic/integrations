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
    "@timestamp": "2022-02-15T15:33:50.768Z",
    "agent": {
        "ephemeral_id": "46c22a6a-f8ff-4af7-81e9-7190c707dcc8",
        "hostname": "docker-fleet-agent",
        "id": "338b8261-00cb-4693-91af-7f20b7c54df0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "hadoop.application_metrics",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "338b8261-00cb-4693-91af-7f20b7c54df0",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "created": "2022-02-15T15:33:50.768Z",
        "dataset": "hadoop.application_metrics",
        "ingested": "2022-02-15T15:33:51Z",
        "kind": "metric",
        "type": "info"
    },
    "hadoop": {
        "metrics": {
            "application_metrics": {
                "memory_seconds": 96558,
                "progress": 100,
                "resources_allocated": {
                    "mb": -1,
                    "vcores": -1
                },
                "running_containers": -1,
                "time": {
                    "elapsed": 32928,
                    "finished": 1644939222829,
                    "started": 1644939189901
                },
                "vcore_seconds": 54
            }
        }
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "forwarded",
        "hadoop-application_metrics"
    ]
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
    "@timestamp": "2022-02-15T15:36:22.922Z",
    "agent": {
        "ephemeral_id": "55f07b0c-4801-47cf-8887-0c4ca78fe2f7",
        "hostname": "docker-fleet-agent",
        "id": "338b8261-00cb-4693-91af-7f20b7c54df0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "hadoop.expanded_cluster_metrics",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "338b8261-00cb-4693-91af-7f20b7c54df0",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "created": "2022-02-15T15:36:22.922Z",
        "dataset": "hadoop.expanded_cluster_metrics",
        "ingested": "2022-02-15T15:36:23Z",
        "kind": "metric",
        "type": "info"
    },
    "hadoop": {
        "metrics": {
            "expanded_cluster_metrics": {
                "apps": {
                    "completed": 0,
                    "failed": 0,
                    "killed": 0,
                    "pending": 0,
                    "running": 0,
                    "submitted": 0
                },
                "containers": {
                    "allocated": 0,
                    "pending": 0,
                    "reserved": 0
                },
                "memory": {
                    "allocated": 0,
                    "available": 0,
                    "reserved": 0,
                    "total": 0
                },
                "nodes": {
                    "active": 0,
                    "decommissioned": 0,
                    "decommissioning": 0,
                    "lost": 0,
                    "rebooted": 0,
                    "shutdown": 0,
                    "total": 0,
                    "unhealthy": 0
                },
                "virtual_cores": {
                    "allocated": 0,
                    "available": 0,
                    "reserved": 0,
                    "total": 0
                }
            }
        }
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "forwarded",
        "hadoop-expanded_cluster_metrics"
    ]
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
    "@timestamp": "2022-02-15T15:38:29.830Z",
    "agent": {
        "ephemeral_id": "ab14fc01-1509-415a-bed4-88016465fef5",
        "hostname": "docker-fleet-agent",
        "id": "338b8261-00cb-4693-91af-7f20b7c54df0",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "7.17.0"
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
        "id": "338b8261-00cb-4693-91af-7f20b7c54df0",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "hadoop.jolokia_metrics",
        "duration": 87828164,
        "ingested": "2022-02-15T15:38:31Z",
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
                    "remaining": 24162938880,
                    "total": 59167412224,
                    "used": 4096
                },
                "data_nodes": {
                    "num_dead": 0,
                    "num_decom_dead": 0,
                    "num_decom_live": 0,
                    "num_decommissioning": 0,
                    "num_live": 1,
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
            "172.26.0.6"
        ],
        "mac": [
            "02:42:ac:1a:00:06"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.53.1.el7.x86_64",
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
        "address": "http://elastic-package-service_hadoop_1:7777/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
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
