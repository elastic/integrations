# Hadoop

This integration is used to collect [Hadoop](https://hadoop.apache.org/) metrics as follows:

   - Application Metrics
   - Cluster Metrics
   - DataNode Metrics
   - NameNode Metrics
   - NodeManager Metrics   

This integration uses Resource Manager API and JMX API to collect above metrics.

## application

This data stream collects Application metrics.

An example event for `application` looks as following:

```json
{
    "@timestamp": "2022-04-04T16:42:03.866Z",
    "agent": {
        "ephemeral_id": "7ebc1f0a-1beb-4519-81b4-60bdcf7449a3",
        "id": "9944acc9-e39f-40e0-a02a-7529cf504db1",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "hadoop.application",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "9944acc9-e39f-40e0-a02a-7529cf504db1",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "created": "2022-04-04T16:42:03.866Z",
        "dataset": "hadoop.application",
        "ingested": "2022-04-04T16:42:07Z",
        "kind": "metric",
        "module": "httpjson",
        "type": "info"
    },
    "hadoop": {
        "application": {
            "allocated": {
                "mb": 2048,
                "v_cores": 1
            },
            "id": "application_1649090491744_0001",
            "memory_seconds": 24502,
            "progress": 0,
            "running_containers": 1,
            "time": {
                "elapsed": 15947,
                "finished": "2022-01-01T00:00:00.000Z",
                "started": "2022-01-01T00:00:00.906Z"
            },
            "vcore_seconds": 11
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
| hadoop.application.allocated.mb | Total memory allocated to the application's running containers (Mb) | long |
| hadoop.application.allocated.v_cores | The total number of virtual cores allocated to the application's running containers | long |
| hadoop.application.id | Application ID | keyword |
| hadoop.application.memory_seconds | The amount of memory the application has allocated | long |
| hadoop.application.progress | Application progress (%) | long |
| hadoop.application.running_containers | Number of containers currently running for the application | long |
| hadoop.application.time.elapsed | The elapsed time since application started (ms) | long |
| hadoop.application.time.finished | Application finished time | date |
| hadoop.application.time.started | Application start time | date |
| hadoop.application.vcore_seconds | The amount of CPU resources the application has allocated | long |
| input.type | Type of Filebeat input. | keyword |
| tags | User defined tags | keyword |


## cluster

This data stream collects Cluster metrics.

An example event for `cluster` looks as following:

```json
{
    "@timestamp": "2022-04-04T17:22:22.255Z",
    "agent": {
        "ephemeral_id": "a8157f06-f6b6-4eae-b67f-4ad08fa7c170",
        "id": "abf8f8c1-f293-4e16-a8f8-8cf48014d040",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "hadoop.cluster",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "abf8f8c1-f293-4e16-a8f8-8cf48014d040",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "hadoop.cluster",
        "duration": 50350559,
        "ingested": "2022-04-04T17:22:25Z",
        "kind": "metric",
        "module": "http",
        "type": "info"
    },
    "hadoop": {
        "cluster": {
            "application_main": {
                "launch_delay_avg_time": 2115,
                "launch_delay_num_ops": 1,
                "register_delay_avg_time": 0,
                "register_delay_num_ops": 0
            },
            "node_managers": {
                "num_active": 1,
                "num_decommissioned": 0,
                "num_lost": 0,
                "num_rebooted": 0,
                "num_unhealthy": 0
            }
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.27.0.7"
        ],
        "mac": [
            "02:42:ac:1b:00:07"
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
        "name": "json",
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service_hadoop_1:8088/jmx?qry=Hadoop%3Aservice%3DResourceManager%2Cname%3DClusterMetrics",
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
| hadoop.cluster.application_main.launch_delay_avg_time | Application Main Launch Delay Average Time (Milliseconds) | long |
| hadoop.cluster.application_main.launch_delay_num_ops | Application Main Launch Delay Operations (Number of Operations) | long |
| hadoop.cluster.application_main.register_delay_avg_time | Application Main Register Delay Average Time (Milliseconds) | long |
| hadoop.cluster.application_main.register_delay_num_ops | Application Main Register Delay Operations (Number of Operations) | long |
| hadoop.cluster.applications.completed | The number of applications completed | long |
| hadoop.cluster.applications.failed | The number of applications failed | long |
| hadoop.cluster.applications.killed | The number of applications killed | long |
| hadoop.cluster.applications.pending | The number of applications pending | long |
| hadoop.cluster.applications.running | The number of applications running | long |
| hadoop.cluster.applications.submitted | The number of applications submitted | long |
| hadoop.cluster.containers.allocated | The number of containers allocated | long |
| hadoop.cluster.containers.pending | The number of containers pending | long |
| hadoop.cluster.containers.reserved | The number of containers reserved | long |
| hadoop.cluster.memory.allocated | The amount of memory allocated in MB | long |
| hadoop.cluster.memory.available | The amount of memory available in MB | long |
| hadoop.cluster.memory.reserved | The amount of memory reserved in MB | long |
| hadoop.cluster.memory.total | The amount of total memory in MB | long |
| hadoop.cluster.node_managers.num_active | Number of Node Managers Active | long |
| hadoop.cluster.node_managers.num_decommissioned | Number of Node Managers Decommissioned | long |
| hadoop.cluster.node_managers.num_lost | Number of Node Managers Lost | long |
| hadoop.cluster.node_managers.num_rebooted | Number of Node Managers Rebooted | long |
| hadoop.cluster.node_managers.num_unhealthy | Number of Node Managers Unhealthy | long |
| hadoop.cluster.nodes.active | The number of active nodes | long |
| hadoop.cluster.nodes.decommissioned | The number of nodes decommissioned | long |
| hadoop.cluster.nodes.decommissioning | The number of nodes being decommissioned | long |
| hadoop.cluster.nodes.lost | The number of lost nodes | long |
| hadoop.cluster.nodes.rebooted | The number of nodes rebooted | long |
| hadoop.cluster.nodes.shutdown | The number of nodes shut down | long |
| hadoop.cluster.nodes.total | The total number of nodes | long |
| hadoop.cluster.nodes.unhealthy | The number of unhealthy nodes | long |
| hadoop.cluster.virtual_cores.allocated | The number of allocated virtual cores | long |
| hadoop.cluster.virtual_cores.available | The number of available virtual cores | long |
| hadoop.cluster.virtual_cores.reserved | The number of reserved virtual cores | long |
| hadoop.cluster.virtual_cores.total | The total number of virtual cores | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |


## datanode

This data stream collects Datanode metrics.

An example event for `datanode` looks as following:

```json
{
    "@timestamp": "2022-04-04T18:05:39.491Z",
    "agent": {
        "ephemeral_id": "d35434eb-fdea-41eb-94ed-124bc7e4afe7",
        "id": "b712f448-71fa-4826-999f-6266019438db",
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
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "b712f448-71fa-4826-999f-6266019438db",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "hadoop.datanode",
        "duration": 148436877,
        "ingested": "2022-04-04T18:05:42Z",
        "kind": "metric",
        "module": "http",
        "type": "info"
    },
    "hadoop": {
        "datanode": {
            "bytes": {
                "read": 238743,
                "written": 237315
            }
        }
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.29.0.4"
        ],
        "mac": [
            "02:42:ac:1d:00:04"
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
        "name": "json",
        "period": 60000
    },
    "service": {
        "address": "http://elastic-package-service_hadoop_1:9864/jmx?qry=Hadoop%3Aname%3DDataNodeActivity%2A%2Cservice%3DDataNode",
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
| hadoop.datanode.blocks.cached | The number of blocks cached | long |
| hadoop.datanode.blocks.failed.to_cache | The number of blocks that failed to cache | long |
| hadoop.datanode.blocks.failed.to_uncache | The number of failed blocks to remove from cache | long |
| hadoop.datanode.bytes.read | Data read | long |
| hadoop.datanode.bytes.written | Data written | long |
| hadoop.datanode.cache.capacity | Cache capacity in bytes | long |
| hadoop.datanode.cache.used | Cache used in bytes | long |
| hadoop.datanode.dfs_used | Distributed File System Used | long |
| hadoop.datanode.disk_space.capacity | Disk capacity in bytes | long |
| hadoop.datanode.disk_space.remaining | The remaining disk space left in bytes | long |
| hadoop.datanode.estimated_capacity_lost_total | The estimated capacity lost in bytes | long |
| hadoop.datanode.last_volume_failure_date | The date/time of the last volume failure in milliseconds since epoch | date |
| hadoop.datanode.volumes.failed | Number of failed volumes | long |
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
        "version": "8.5.1"
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
        "version": "8.5.1"
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

