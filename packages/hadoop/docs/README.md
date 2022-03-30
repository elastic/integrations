# Hadoop

This integration is used to collect [Hadoop](https://hadoop.apache.org/) metrics as follows:

   - Application Metrics
   - Cluster Metrics
   - DataNode Metrics
   - NameNode Metrics
   - NodeManager Metrics   

This integration uses Resource Manager API and JMX API to collect above metrics.

## application_metrics

This data stream collects Application metrics.

An example event for `application` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:18:23.507Z",
    "agent": {
        "ephemeral_id": "cb6626ea-ba3d-4856-bec0-107a18d7fa8c",
        "id": "adf6847a-3726-4fe6-a202-147021ff3cbc",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
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
        "id": "adf6847a-3726-4fe6-a202-147021ff3cbc",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "created": "2022-03-28T11:18:23.507Z",
        "dataset": "hadoop.application_metrics",
        "ingested": "2022-03-28T11:18:24Z",
        "kind": "metric",
        "module": "httpjson",
        "type": "info"
    },
    "hadoop": {
        "application_metrics": {
            "allocated": {
                "mb": 2048,
                "v_cores": 1
            },
            "id": "application_1648466210775_0001",
            "memory_seconds": 102907,
            "progress": 0,
            "running_containers": 1,
            "time": {
                "elapsed": 52082,
                "finished": "2022-01-01T00:00:00.000Z",
                "started": "2022-01-01T00:00:00.312Z"
            },
            "vcore_seconds": 51
        }
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "forwarded"
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
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| hadoop.application_metrics.allocated.mb | Total memory allocated to the application's running containers (Mb) | long |
| hadoop.application_metrics.allocated.v_cores | The total number of virtual cores allocated to the application's running containers | long |
| hadoop.application_metrics.id | Application ID | keyword |
| hadoop.application_metrics.memory_seconds | The amount of memory the application has allocated | long |
| hadoop.application_metrics.progress | Application progress (%) | long |
| hadoop.application_metrics.running_containers | Number of containers currently running for the application | long |
| hadoop.application_metrics.time.elapsed | The elapsed time since application started (ms) | long |
| hadoop.application_metrics.time.finished | Application finished time | date |
| hadoop.application_metrics.time.started | Application start time | date |
| hadoop.application_metrics.vcore_seconds | The amount of CPU resources the application has allocated | long |
| input.type | Type of Filebeat input. | keyword |
| tags | User defined tags | keyword |


## cluster_metrics

This data stream collects Cluster metrics.

An example event for `cluster` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:24:18.064Z",
    "agent": {
        "ephemeral_id": "264f535c-5021-4ca6-80ac-8c2d5be921c4",
        "id": "adf6847a-3726-4fe6-a202-147021ff3cbc",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "hadoop.cluster_metrics",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "adf6847a-3726-4fe6-a202-147021ff3cbc",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "hadoop.cluster_metrics",
        "duration": 144752118,
        "ingested": "2022-03-28T11:24:21Z",
        "kind": "metric",
        "module": "http",
        "type": "info"
    },
    "hadoop": {
        "cluster_metrics": {
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
                "available": 8192,
                "reserved": 0,
                "total": 8192
            },
            "nodes": {
                "active": 1,
                "decommissioned": 0,
                "decommissioning": 0,
                "lost": 0,
                "rebooted": 0,
                "shutdown": 0,
                "total": 1,
                "unhealthy": 0
            },
            "virtual_cores": {
                "allocated": 0,
                "available": 8,
                "reserved": 0,
                "total": 8
            }
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.160.7"
        ],
        "mac": [
            "02:42:c0:a8:a0:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.45.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "json",
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service_hadoop_1:8088/ws/v1/cluster/metrics",
        "type": "http"
    },
    "tags": [
        "forwarded"
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
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| hadoop.cluster_metrics.application_master.launch_delay_avg_time | Application Master Launch Delay Average Time (Milliseconds) | long |
| hadoop.cluster_metrics.application_master.launch_delay_num_ops | Application Master Launch Delay Operations (Operations) | long |
| hadoop.cluster_metrics.application_master.register_delay_avg_time | Application Master Register Delay Average Time (Milliseconds) | long |
| hadoop.cluster_metrics.application_master.register_delay_num_ops | Application Master Register Delay Operations (Operations) | long |
| hadoop.cluster_metrics.apps.completed | The number of applications completed | long |
| hadoop.cluster_metrics.apps.failed | The number of applications failed | long |
| hadoop.cluster_metrics.apps.killed | The number of applications killed | long |
| hadoop.cluster_metrics.apps.pending | The number of applications pending | long |
| hadoop.cluster_metrics.apps.running | The number of applications running | long |
| hadoop.cluster_metrics.apps.submitted | The number of applications submitted | long |
| hadoop.cluster_metrics.containers.allocated | The number of containers allocated | long |
| hadoop.cluster_metrics.containers.pending | The number of containers pending | long |
| hadoop.cluster_metrics.containers.reserved | The number of containers reserved | long |
| hadoop.cluster_metrics.memory.allocated | The amount of memory allocated in MB | long |
| hadoop.cluster_metrics.memory.available | The amount of memory available in MB | long |
| hadoop.cluster_metrics.memory.reserved | The amount of memory reserved in MB | long |
| hadoop.cluster_metrics.memory.total | The amount of total memory in MB | long |
| hadoop.cluster_metrics.node_managers.num_active | Number of Node Managers Active | long |
| hadoop.cluster_metrics.node_managers.num_decommissioned | Number of Node Managers Decommissioned | long |
| hadoop.cluster_metrics.node_managers.num_lost | Number of Node Managers Lost | long |
| hadoop.cluster_metrics.node_managers.num_rebooted | Number of Node Managers Rebooted | long |
| hadoop.cluster_metrics.node_managers.num_unhealthy | Number of Node Managers Unhealthy | long |
| hadoop.cluster_metrics.nodes.active | The number of active nodes | long |
| hadoop.cluster_metrics.nodes.decommissioned | The number of nodes decommissioned | long |
| hadoop.cluster_metrics.nodes.decommissioning | The number of nodes being decommissioned | long |
| hadoop.cluster_metrics.nodes.lost | The number of lost nodes | long |
| hadoop.cluster_metrics.nodes.rebooted | The number of nodes rebooted | long |
| hadoop.cluster_metrics.nodes.shutdown | The number of nodes shut down | long |
| hadoop.cluster_metrics.nodes.total | The total number of nodes | long |
| hadoop.cluster_metrics.nodes.unhealthy | The number of unhealthy nodes | long |
| hadoop.cluster_metrics.virtual_cores.allocated | The number of allocated virtual cores | long |
| hadoop.cluster_metrics.virtual_cores.available | The number of available virtual cores | long |
| hadoop.cluster_metrics.virtual_cores.reserved | The number of reserved virtual cores | long |
| hadoop.cluster_metrics.virtual_cores.total | The total number of virtual cores | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


## datanode

This data stream collects Datanode metrics.

An example event for `datanode` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:29:49.768Z",
    "agent": {
        "ephemeral_id": "2aff6d6a-0de8-4735-96c1-45a6da016111",
        "id": "adf6847a-3726-4fe6-a202-147021ff3cbc",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "hadoop.datanode",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "adf6847a-3726-4fe6-a202-147021ff3cbc",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "hadoop.datanode",
        "duration": 711671177,
        "ingested": "2022-03-28T11:29:52Z",
        "kind": "metric",
        "module": "http",
        "type": "info"
    },
    "hadoop": {
        "datanode": {
            "cache": {
                "capacity": 0,
                "used": 0
            },
            "dfs_used": 4543,
            "disk_space": {
                "capacity": 48420556800,
                "remaining": 11991523328
            },
            "estimated_capacity_lost_total": 0,
            "last_volume_failure_date": "2022-01-01T00:00:00.000Z",
            "num_blocks_cached": 0,
            "num_blocks_failed": {
                "to_cache": 0,
                "to_uncache": 0
            },
            "num_failed_volumes": 0
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.160.7"
        ],
        "mac": [
            "02:42:c0:a8:a0:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.45.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "json",
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service_hadoop_1:9864/jmx?qry=Hadoop%3Aname%3DFSDatasetState%2Cservice%3DDataNode",
        "type": "http"
    },
    "tags": [
        "forwarded"
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
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| hadoop.datanode.bytes.read | Data read | long |
| hadoop.datanode.bytes.written | Data written | long |
| hadoop.datanode.cache.capacity | Cache capacity in bytes | long |
| hadoop.datanode.cache.used | Cache used in bytes | long |
| hadoop.datanode.dfs_used | Distributed File System Used | long |
| hadoop.datanode.disk_space.capacity | Disk capacity in bytes | long |
| hadoop.datanode.disk_space.remaining | The remaining disk space left in bytes | long |
| hadoop.datanode.estimated_capacity_lost_total | The estimated capacity lost in bytes | long |
| hadoop.datanode.last_volume_failure_date | The date/time of the last volume failure in milliseconds since epoch | date |
| hadoop.datanode.num_blocks_cached | The number of blocks cached | long |
| hadoop.datanode.num_blocks_failed.to_cache | The number of blocks that failed to cache | long |
| hadoop.datanode.num_blocks_failed.to_uncache | The number of failed blocks to remove from cache | long |
| hadoop.datanode.num_failed_volumes | Number of failed volumes | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


## namenode

This data stream collects Namenode metrics.

An example event for `namenode` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:36:07.166Z",
    "agent": {
        "ephemeral_id": "1304d85b-b3ba-45a5-ad59-c9ec7df3a49f",
        "id": "adf6847a-3726-4fe6-a202-147021ff3cbc",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "hadoop.namenode",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "adf6847a-3726-4fe6-a202-147021ff3cbc",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "hadoop.namenode",
        "duration": 341259289,
        "ingested": "2022-03-28T11:36:09Z",
        "kind": "metric",
        "module": "http",
        "type": "info"
    },
    "hadoop": {
        "namenode": {
            "blocks": {
                "corrupt": 0,
                "missing_repl_one": 0,
                "pending_deletion": 0,
                "pending_replication": 0,
                "scheduled_replication": 0,
                "total": 0,
                "under_replicated": 0
            },
            "capacity": {
                "remaining": 11986817024,
                "total": 48420556800,
                "used": 4096
            },
            "estimated_capacity_lost_total": 0,
            "files_total": 9,
            "lock_queue_length": 0,
            "nodes": {
                "num_dead_data": 0,
                "num_decom_dead_data": 0,
                "num_decom_live_data": 0,
                "num_decommissioning_data": 0,
                "num_live_data": 1
            },
            "num_stale_storages": 0,
            "stale_data_nodes": 0,
            "total_load": 0,
            "volume_failures_total": 0
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.160.7"
        ],
        "mac": [
            "02:42:c0:a8:a0:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.45.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "json",
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service_hadoop_1:9870/jmx?qry=Hadoop%3Aname%3DFSNamesystem%2Cservice%3DNameNode",
        "type": "http"
    },
    "tags": [
        "forwarded"
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
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| hadoop.namenode.blocks.corrupt | Current number of blocks with corrupt replicas. | long |
| hadoop.namenode.blocks.missing_repl_one | Current number of missing blocks with replication factor 1 | long |
| hadoop.namenode.blocks.pending_deletion | Current number of blocks pending deletion | long |
| hadoop.namenode.blocks.pending_replication | Current number of blocks pending to be replicated | long |
| hadoop.namenode.blocks.scheduled_replication | Current number of blocks scheduled for replications | long |
| hadoop.namenode.blocks.total | Current number of allocated blocks in the system | long |
| hadoop.namenode.blocks.under_replicated | Current number of blocks under replicated | long |
| hadoop.namenode.capacity.remaining | Current remaining capacity in bytes | long |
| hadoop.namenode.capacity.total | Current raw capacity of DataNodes in bytes | long |
| hadoop.namenode.capacity.used | Current used capacity across all DataNodes in bytes | long |
| hadoop.namenode.estimated_capacity_lost_total | An estimate of the total capacity lost due to volume failures | long |
| hadoop.namenode.files_total | Current number of files and directories | long |
| hadoop.namenode.lock_queue_length | Number of threads waiting to acquire FSNameSystem lock | long |
| hadoop.namenode.nodes.num_dead_data | Number of datanodes which are currently dead | long |
| hadoop.namenode.nodes.num_decom_dead_data | Number of datanodes which have been decommissioned and are now dead | long |
| hadoop.namenode.nodes.num_decom_live_data | Number of datanodes which have been decommissioned and are now live | long |
| hadoop.namenode.nodes.num_decommissioning_data | Number of datanodes in decommissioning state | long |
| hadoop.namenode.nodes.num_live_data | Number of datanodes which are currently live | long |
| hadoop.namenode.num_stale_storages | Number of storages marked as content stale | long |
| hadoop.namenode.stale_data_nodes | Current number of DataNodes marked stale due to delayed heartbeat | long |
| hadoop.namenode.total_load | Current number of connections | long |
| hadoop.namenode.volume_failures_total | Total number of volume failures across all Datanodes | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


## node_manager

This data stream collects Node Manager metrics.

An example event for `node_manager` looks as following:

```json
{
    "@timestamp": "2022-03-28T11:54:32.506Z",
    "agent": {
        "ephemeral_id": "9948a37a-5732-4d7d-9218-0e9cf30c035a",
        "id": "adf6847a-3726-4fe6-a202-147021ff3cbc",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "hadoop.node_manager",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "adf6847a-3726-4fe6-a202-147021ff3cbc",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "hadoop.node_manager",
        "duration": 12930711,
        "ingested": "2022-03-28T11:54:35Z",
        "kind": "metric",
        "module": "http",
        "type": "info"
    },
    "hadoop": {
        "node_manager": {
            "allocated_containers": 0,
            "container_launch_duration_avg_time": 169,
            "container_launch_duration_num_ops": 2,
            "containers": {
                "completed": 0,
                "failed": 2,
                "initing": 0,
                "killed": 0,
                "launched": 2,
                "running": 0
            }
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.160.7"
        ],
        "mac": [
            "02:42:c0:a8:a0:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.45.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "json",
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service_hadoop_1:8042/jmx?qry=Hadoop%3Aservice%3DNodeManager%2Cname%3DNodeManagerMetrics",
        "type": "http"
    },
    "tags": [
        "forwarded"
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
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| hadoop.node_manager.allocated_containers | Containers Allocated | long |
| hadoop.node_manager.container_launch_duration_avg_time | Container Launch Duration Average Time (Seconds) | long |
| hadoop.node_manager.container_launch_duration_num_ops | Container Launch Duration Operations (Operations) | long |
| hadoop.node_manager.containers.completed | Containers Completed | long |
| hadoop.node_manager.containers.failed | Containers Failed | long |
| hadoop.node_manager.containers.initing | Containers Initializing | long |
| hadoop.node_manager.containers.killed | Containers Killed | long |
| hadoop.node_manager.containers.launched | Containers Launched | long |
| hadoop.node_manager.containers.running | Containers Running | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

