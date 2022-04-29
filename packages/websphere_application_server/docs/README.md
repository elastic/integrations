# WebSphere Application Server

This integration is used to collect [WebSphere Application Server](https://www.ibm.com/cloud/websphere-application-server) metrics as follows:

   - JVM metrics

This integration uses Prometheus to collect above metrics.

To open Prometheus endpoint read following [instructions](https://www.ibm.com/docs/en/was/9.0.5?topic=mosh-displaying-pmi-metrics-in-prometheus-format-metrics-app).

### Metrics

## JVM

This data stream collects Java Virtual Memory (JVM) related metrics.

An example event for `jvm` looks as following:

```json
{
    "@timestamp": "2022-04-29T06:39:07.490Z",
    "agent": {
        "ephemeral_id": "5a5fb008-bf8c-4db1-8f45-dc1581c4123f",
        "id": "acde2c0e-ef9e-49b1-bc55-2d9eb16f4269",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "websphere_application_server.jvm",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "acde2c0e-ef9e-49b1-bc55-2d9eb16f4269",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "web",
        "dataset": "websphere_application_server.jvm",
        "duration": 34346199,
        "ingested": "2022-04-29T06:39:10Z",
        "kind": "metric",
        "module": "websphere_application_server",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "192.168.112.7"
        ],
        "mac": [
            "02:42:c0:a8:70:07"
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
        "name": "collector",
        "period": 60000
    },
    "server": {
        "address": "elastic-package-service_websphere_application_server_1:9080"
    },
    "service": {
        "address": "http://elastic-package-service_websphere_application_server_1:9080/metrics",
        "type": "prometheus"
    },
    "tags": [
        "forwarded",
        "websphere_application_server-jvm",
        "prometheus"
    ],
    "websphere_application_server": {
        "jvm": {
            "area": "heap",
            "memory": {
                "committed": 226230272,
                "max": 1516240896,
                "used": 158973952
            }
        }
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
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| websphere_application_server.jvm.area | Name of the area. | keyword |
| websphere_application_server.jvm.memory.committed | The total memory (in Bytes) in the Java virtual machine runtime. | long |
| websphere_application_server.jvm.memory.max | The max memory (in Bytes) in the Java virtual machine runtime. | long |
| websphere_application_server.jvm.memory.used | The amount of used memory (in Bytes) in the Java virtual machine runtime. | long |

