# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Requirements

In order to ingest data from Oracle WebLogic:
- You must know the host for Oracle WebLogic application, add that host while configuring the integration package.
- Add default path for jolokia.
- Configuring Jolokia for Weblogic

    User needs to [download](https://jolokia.org/download.html) and add the JAR file and set environment variables for jolokia.

    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=<Port>,host=<hostname>
    ``` 
    
    (Optional) User can run Jolokia on https by configuring following [paramters](https://jolokia.org/reference/html/agents.html#:~:text=Table%C2%A03.6.-,JVM%20agent%20configuration%20options,-Parameter).

    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=<Port>,host=<hostname>,protocol=<http/https>,keystore=<path-to-keystore>,keystorePassword=<kestore-password>,keyStoreType=<Keystore-type>
    ```

## Metrics

### Console metrics

This `console` data stream gives metrics of JVM, Sockets and Work Manager.

An example event for `console` looks as following:

```json
{
    "@timestamp": "2022-05-05T06:58:01.791Z",
    "agent": {
        "ephemeral_id": "3f5bf92e-f51f-4335-8c37-d865940853e7",
        "id": "ae4feb0c-1754-468b-84aa-ddfd22b991a2",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.console",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "ae4feb0c-1754-468b-84aa-ddfd22b991a2",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "oracle_weblogic.console",
        "duration": 6219455,
        "ingested": "2022-05-05T06:58:05Z",
        "kind": "metric",
        "module": "oracle_weblogic",
        "type": "info"
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
    "oracle_weblogic": {
        "console": {
            "work_manager": {
                "name": "consoleWorkManager",
                "requests": {
                    "daemon": {
                        "completed": 0,
                        "pending": 0
                    },
                    "total": {
                        "completed": 82,
                        "pending": 0
                    }
                },
                "stuck_thread_count": 0
            }
        }
    },
    "service": {
        "address": "http://elastic-package-service_oracle_weblogic_1:8010/jolokia",
        "type": "jolokia"
    },
    "tags": [
        "oracle_weblogic-console"
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
| oracle_weblogic.console.jvm.heap.free.current.bytes | Current amount of memory, in bytes, that is available in the JVM heap. | long |
| oracle_weblogic.console.jvm.heap.free.current.percent | Current percentage of the JVM heap that is free. | long |
| oracle_weblogic.console.jvm.heap.size.current | Current size, in bytes, of the JVM heap. | long |
| oracle_weblogic.console.jvm.heap.size.max | Maximum size, in bytes, of the JVM heap. | long |
| oracle_weblogic.console.jvm.server_name | Server Name. | keyword |
| oracle_weblogic.console.jvm.uptime | Number of milliseconds that the virtual machine has been running. | long |
| oracle_weblogic.console.servlet.execution_time.average | Time, in milliseconds, it took to execute all invocations of the servlet since it was most recently deployed. | long |
| oracle_weblogic.console.servlet.execution_time.high | Time, in milliseconds, that the single longest invocation of the servlet has executed since it was most recently deployed. | long |
| oracle_weblogic.console.servlet.execution_time.low | Time, in milliseconds, that the single shortest invocation of the servlet has executed since it was most recently deployed. | long |
| oracle_weblogic.console.servlet.execution_time.total | Time, in milliseconds, that all invocations of the servlet have executed since it was most recently deployed. | long |
| oracle_weblogic.console.servlet.invocation.total | Total number of times the servlet has been invoked since WebLogic Server started. | long |
| oracle_weblogic.console.servlet.name | Servlet name. | keyword |
| oracle_weblogic.console.servlet.pool_max_capacity | Maximum capacity of this servlet for single thread model servlets. | long |
| oracle_weblogic.console.servlet.reload.total | Total number of times WebLogic Server has reloaded the servlet since it was last deployed. WebLogic Server typically reloads a servlet if it has been modified. | long |
| oracle_weblogic.console.work_manager.name | Work manager name. | keyword |
| oracle_weblogic.console.work_manager.requests.daemon.completed | Number of daemon requests that have been processed. | long |
| oracle_weblogic.console.work_manager.requests.daemon.pending | Number of waiting daemon requests in the queue. | long |
| oracle_weblogic.console.work_manager.requests.total.completed | Total number of requests that have been processed. | long |
| oracle_weblogic.console.work_manager.requests.total.pending | Total number of waiting requests in the queue. | long |
| oracle_weblogic.console.work_manager.stuck_thread_count | Number of stuck threads in the thread pool. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

