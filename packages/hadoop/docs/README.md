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
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "hadoop.application",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "9944acc9-e39f-40e0-a02a-7529cf504db1",
        "snapshot": false,
        "version": "8.0.0"
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


