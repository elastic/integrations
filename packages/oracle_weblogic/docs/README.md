# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Requirements

In order to ingest data from Oracle WebLogic:
- You must know the host for Oracle WebLogic application, add that host while configuring the integration package.
- Add default path for jolokia.
- Configuring Jolokia for Weblogic

    User needs to [download](https://jolokia.org/download.html) and add the JAR file and set environment
     variables for jolokia.

    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=<Port>,host=<hostname>
    ``` 

    (Optional) User can run Jolokia on https by configuring following [paramters](https://jolokia.org/reference/html/agents.html#:~:text=Table%C2%A03.6.-,JVM%20agent%20configuration%20options,-Parameter).

    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=<Port>,host=<hostname>,protocol=<http/https>,keystore=<path-to-keystore>,keystorePassword=<kestore-password>,keyStoreType=<keystore-type>
    ```

## Metrics

### ThreadPool metrics

This `threadpool` data stream gives metrics of ThreadPool.

An example event for `threadpool` looks as following:

```json
{
    "@timestamp": "2022-04-25T15:56:32.787Z",
    "agent": {
        "ephemeral_id": "fa8d802c-63fd-414f-87df-87877f5c4910",
        "id": "8b3c7161-5c36-4f53-a9c1-134be019ef4d",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.threadpool",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "8b3c7161-5c36-4f53-a9c1-134be019ef4d",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "oracle_weblogic.threadpool",
        "duration": 2237552,
        "ingested": "2022-04-25T15:56:36Z",
        "kind": "metric",
        "module": "oracle_weblogic",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.96.7"
        ],
        "mac": [
            "02:42:c0:a8:60:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.4.0-107-generic",
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
    "oracle_weblogic": {
        "threadpool": {
            "queue": {
                "length": 0
            },
            "requests": {
                "completed": 1199967,
                "overload": {
                    "rejected": 0
                },
                "pending": 0
            },
            "threads": {
                "execute": {
                    "idle": 1,
                    "total": 12
                },
                "hogging": 0,
                "standby": 11,
                "stuck": 0
            },
            "throughput": 3.99800099950025,
            "work_manager": {
                "capacity": {
                    "shared": 65536
                }
            }
        }
    },
    "service": {
        "address": "http://elastic-package-service_oracle_weblogic_1:8010/jolokia",
        "type": "jolokia"
    },
    "tags": [
        "oracle_weblogic-threadpool"
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
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| oracle_weblogic.threadpool.queue.length | The number of pending requests in the priority queue. This is the total of internal system requests and user requests. | long |
| oracle_weblogic.threadpool.requests.completed | The number of completed requests in the priority queue. | long |
| oracle_weblogic.threadpool.requests.overload.rejected | Number of requests rejected due to configured Shared Capacity for work managers have been reached. | long |
| oracle_weblogic.threadpool.requests.pending | The number of pending user requests in the priority queue. The priority queue contains requests from internal subsystems and users. This is just the count of all user requests. | long |
| oracle_weblogic.threadpool.threads.daemon | Current number of live daemon threads. | long |
| oracle_weblogic.threadpool.threads.execute.idle | The number of idle threads in the pool. This count does not include standby threads and stuck threads. The count indicates threads that are ready to pick up new work when it arrives. | long |
| oracle_weblogic.threadpool.threads.execute.total | The total number of threads in the pool. | long |
| oracle_weblogic.threadpool.threads.hogging | The threads that are being held by a request right now. These threads will either be declared as stuck after the configured timeout or will return to the pool before that. The self-tuning mechanism will backfill if necessary. | long |
| oracle_weblogic.threadpool.threads.standby | The number of threads in the standby pool. Threads that are not needed to handle the present work load are designated as standby and added to the standby pool. These threads are activated when more threads are needed. | long |
| oracle_weblogic.threadpool.threads.stuck | Number of stuck threads in the thread pool. | long |
| oracle_weblogic.threadpool.threads.total | Current number of live daemon and non-daemon threads. | long |
| oracle_weblogic.threadpool.throughput | The mean number of requests completed per second. | double |
| oracle_weblogic.threadpool.work_manager.capacity.shared | Maximum amount of requests that can be accepted in the priority queue. Note that a request with higher priority will be accepted in place of a lower priority request already in the queue even after the threshold is reached. The lower priority request is kept waiting in the queue till all high priority requests are executed. Also note that further enqueues of the low priority requests are rejected right away. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

