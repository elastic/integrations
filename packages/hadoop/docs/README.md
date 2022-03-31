# Hadoop

This integration is used to collect [Hadoop](https://hadoop.apache.org/) metrics as follows:

   - Application Metrics
   - Cluster Metrics
   - DataNode Metrics
   - NameNode Metrics
   - NodeManager Metrics   

This integration uses Resource Manager API and JMX API to collect above metrics.

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
        "version": "8.0.0"
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
        "version": "8.0.0"
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
