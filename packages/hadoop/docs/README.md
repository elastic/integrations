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
        "version": "8.0.0"
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
        "version": "8.0.0"
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
        "version": "8.0.0"
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
        "version": "8.0.0"
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
