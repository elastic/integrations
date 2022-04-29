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
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=<Port>,host=<hostname>,protocol=<http/https>,keystore=<path-to-keystore>,keystorePassword=<kestore-password>,keyStoreType=<Keystore-type>
    ```

## Metrics

### Connections metrics

This `connections` data stream gives metrics of Connections, Sockets and Channels.

An example event for `connections` looks as following:

```json
{
    "@timestamp": "2022-04-26T10:22:57.976Z",
    "agent": {
        "ephemeral_id": "a7cb1e17-4c30-48c5-b22d-c555db3b249f",
        "id": "d43ef722-10ae-4d3e-9bec-9ce28f5345e5",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.connections",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "d43ef722-10ae-4d3e-9bec-9ce28f5345e5",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "oracle_weblogic.connections",
        "duration": 64571052,
        "ingested": "2022-04-26T10:23:01Z",
        "kind": "metric",
        "module": "oracle_weblogic",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.32.7"
        ],
        "mac": [
            "02:42:c0:a8:20:07"
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
    "oracle_weblogic": {
        "connections": {
            "active": {
                "current": 0,
                "high": 0
            },
            "capacity": {
                "current": 0,
                "initial": 0,
                "max": 100
            },
            "created": {
                "total": 0
            },
            "destroyed": {
                "by_error": 0,
                "by_shrinking": 0,
                "total": 0
            },
            "free": {
                "current": 0
            },
            "matched": {
                "total": 0
            },
            "name": "eis/jms/internal/WLSConnectionFactoryJNDINoTX",
            "rejected": {
                "total": 0
            },
            "state": "Running",
            "type": "ConnectorConnectionPoolRuntime"
        }
    },
    "service": {
        "address": "http://elastic-package-service_oracle_weblogic_1:8010/jolokia",
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
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| oracle_weblogic.connections.active.current | Number of connections currently in use by applications. | long |
| oracle_weblogic.connections.active.high | Highest number of active database connections in this data source instance since the data source was instantiated. | long |
| oracle_weblogic.connections.capacity.current | The current count of JDBC connections in the data source's connection pool. | long |
| oracle_weblogic.connections.capacity.initial | The initial count of JDBC connections in the data source's connection pool. | long |
| oracle_weblogic.connections.capacity.max | The maximum count of JDBC connections in the data source's connection pool. | long |
| oracle_weblogic.connections.channel.bytes.received | The number of bytes received on the channel. | long |
| oracle_weblogic.connections.channel.bytes.sent | The number of bytes sent on the channel. | long |
| oracle_weblogic.connections.channel.connections.count | The number of connections in the channel. | long |
| oracle_weblogic.connections.channel.messages.received | The number of messages received on the channel. | long |
| oracle_weblogic.connections.channel.messages.sent | The number of messages sent on the channel. | long |
| oracle_weblogic.connections.channel.sockets.accepted | The number of sockets that have been accepted on the channel. | long |
| oracle_weblogic.connections.created.total | The cumulative total number of database connections created in this data source since the data source was deployed. | long |
| oracle_weblogic.connections.destroyed.by_error | The number of connections destroyed by error. | long |
| oracle_weblogic.connections.destroyed.by_shrinking | The number of connections destroyed by shrinking. | long |
| oracle_weblogic.connections.destroyed.total | The total number of connections destroyed. | long |
| oracle_weblogic.connections.free.current | The number of connections currently free. | long |
| oracle_weblogic.connections.matched.total | The total number of connections matched. | long |
| oracle_weblogic.connections.name | Name of the Connection. | keyword |
| oracle_weblogic.connections.rejected.total | The total number of connections rejected. | long |
| oracle_weblogic.connections.sockets.open.current | The number of sockets currently open. | long |
| oracle_weblogic.connections.sockets.open.max | The maximum number of sockets that can be open. | long |
| oracle_weblogic.connections.sockets.threadpool_readers_percent | The percentage of execute threads from the default queue that can be used as socket readers. | long |
| oracle_weblogic.connections.state | State of the Connection. | keyword |
| oracle_weblogic.connections.type | Type of the Connection. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |

