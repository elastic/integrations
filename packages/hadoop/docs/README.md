# Hadoop

This integration is used to collect [Hadoop](https://hadoop.apache.org/) metrics as follows:

   - Application Metrics
   - Cluster Metrics
   - DataNode Metrics
   - NameNode Metrics
   - NodeManager Metrics   

This integration uses Resource Manager API and JMX API to collect above metrics.

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
        "version": "8.0.0"
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
        "version": "8.0.0"
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
