# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Requirements

In order to ingest data from Oracle WebLogic:
- You must know the host for Oracle WebLogic application, add that host while configuring the integration package.
- Add default path for jolokia.
- Configuring Jolokia for Weblogic

    User need to [download](https://jolokia.org/download.html) and add jar file and set env variables for jolokia

    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=<Port>,host=<hostname>
    ```

## Metrics

### Deployed Application Metrics

This `deployed_application` data stream gives metrics of Deployed Application.

An example event for `deployed_application` looks as following:

```json
{
    "@timestamp": "2022-04-18T05:13:37.988Z",
    "agent": {
        "ephemeral_id": "51dbac58-4f35-4a39-9668-035268d92a34",
        "id": "8fba0284-d0ba-4d62-bde7-b6efb0191fc9",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.deployed_application",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "8fba0284-d0ba-4d62-bde7-b6efb0191fc9",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "oracle_weblogic.deployed_application",
        "duration": 1783900,
        "ingested": "2022-04-18T05:13:41Z",
        "kind": "metric",
        "module": "oracle_weblogic",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.25.0.7"
        ],
        "mac": [
            "02:42:ac:19:00:07"
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
        "deployed_application": {
            "deployment": {
                "state": "Running",
                "state_value": 2
            },
            "session_timeout": 3600,
            "sessions": {
                "open": {
                    "current": 0,
                    "high": 0,
                    "total": 0
                }
            },
            "single_threaded_servlet_pool_size": 5,
            "source_info": "bea_wls_internal.war",
            "status": "DEPLOYED"
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
| oracle_weblogic.deployed_application.deployment.state | Current state of the deployment as an keyword. | keyword |
| oracle_weblogic.deployed_application.deployment.state_value | Current state of the deployment as an integer. | long |
| oracle_weblogic.deployed_application.session_timeout | Session timeout in integer. | long |
| oracle_weblogic.deployed_application.sessions.open.current | Current number of open sessions in this module. | long |
| oracle_weblogic.deployed_application.sessions.open.high | Highest number of open sessions on this server at any one time. | long |
| oracle_weblogic.deployed_application.sessions.open.total | Total number of sessions that were opened. | long |
| oracle_weblogic.deployed_application.single_threaded_servlet_pool_size | Displays the size of this servlet for single thread model servlets. | long |
| oracle_weblogic.deployed_application.source_info | Source info of the deployment as a keyword. | keyword |
| oracle_weblogic.deployed_application.status | Status of the deployment. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |

