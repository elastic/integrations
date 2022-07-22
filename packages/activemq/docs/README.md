# ActiveMQ Integration

This integration periodically fetches metrics from [ActiveMQ](https://activemq.apache.org/) servers. It can parse broker, queue and topic.
System logs and Audit logs are also collected using this integration.

## Compatibility

The ActiveMQ datasets were tested with ActiveMQ 5.17.1 or higher (independent from operating system).

## Logs

### ActiveMQ Logs

Collects the ActiveMQ System logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-06-24T12:54:26.345Z",
    "activemq": {
        "log": {
            "caller": "org.apache.activemq.broker.BrokerService",
            "thread": "main"
        }
    },
    "agent": {
        "ephemeral_id": "638481bc-60c8-45d2-9610-864f2b414cfa",
        "id": "4052b5b6-59e4-4711-8a2c-f6c667f81bbd",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "activemq.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "4052b5b6-59e4-4711-8a2c-f6c667f81bbd",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "activemq.log",
        "ingested": "2022-06-29T16:10:16Z",
        "kind": "event",
        "type": "info"
    },
    "host": {
        "name": "docker-fleet-agent"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/activemq.log"
        },
        "level": "INFO",
        "offset": 0
    },
    "message": "Using Persistence Adapter: KahaDBPersistenceAdapter[/softwares/apache-activemq-5.17.1/data/kahadb]",
    "tags": [
        "forwarded",
        "activemq-log"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| activemq.log.caller | Name of the caller issuing the logging request (class or resource). | keyword |
| activemq.log.log_stack_trace | The stack trace of this log in plain text. | text |
| activemq.log.message | Description of action taken by user. | text |
| activemq.log.thread | Thread that generated the logging event. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| error.stack_trace | The stack trace of this error in plain text. | wildcard |
| error.stack_trace.text | Multi-field of `error.stack_trace`. | match_only_text |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Log flags | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |


### Audit Logs

Audit logs collects the ActiveMQ Audit logs.

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2022-06-29T16:07:25.492Z",
    "activemq": {
        "audit": {
            "thread": "RMI TCP Connection(1)-127.0.0.1"
        }
    },
    "agent": {
        "ephemeral_id": "34d3eca2-8de6-4429-8ec7-7c470857b23e",
        "id": "4052b5b6-59e4-4711-8a2c-f6c667f81bbd",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "activemq.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "4052b5b6-59e4-4711-8a2c-f6c667f81bbd",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "activemq.audit",
        "ingested": "2022-06-29T16:07:29Z",
        "kind": "event",
        "type": "info"
    },
    "host": {
        "name": "docker-fleet-agent"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/audit.log"
        },
        "level": "INFO",
        "offset": 0
    },
    "message": "called org.apache.activemq.broker.jmx.BrokerView.terminateJVM[0] on localhost at 24-06-2022 13:09:43,996",
    "tags": [
        "forwarded",
        "activemq-audit"
    ],
    "user": {
        "name": "anonymous"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| activemq.audit.thread | Thread that generated the logging event. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


## Metrics

### Broker Metrics

The server broker stream collects data from the ActiveMQ broker module. 

An example event for `broker` looks as following:

```json
{
    "@timestamp": "2022-06-29T16:08:49.982Z",
    "activemq": {
        "broker": {
            "connections": {
                "count": 17
            },
            "consumers": {
                "count": 0
            },
            "mbean": "org.apache.activemq:brokerName=localhost,type=Broker",
            "memory": {
                "broker": {
                    "pct": 0
                },
                "store": {
                    "pct": 0
                },
                "temp": {
                    "pct": 0
                }
            },
            "messages": {
                "count": 17,
                "dequeue": {
                    "count": 0
                },
                "enqueue": {
                    "count": 36
                }
            },
            "name": "localhost",
            "producers": {
                "count": 0
            }
        }
    },
    "agent": {
        "ephemeral_id": "2de2c614-b1b2-42a6-adb9-9ecddfc0dc07",
        "id": "4052b5b6-59e4-4711-8a2c-f6c667f81bbd",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "activemq.broker",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "4052b5b6-59e4-4711-8a2c-f6c667f81bbd",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "activemq.broker",
        "duration": 18482338,
        "ingested": "2022-06-29T16:08:53Z",
        "module": "activemq"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02:42:ac:13:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.66.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "broker",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_activemq_1:8161/api/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "activemq"
    },
    "tags": [
        "forwarded",
        "activemq-broker"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| activemq.broker.connections.count | Total number of connections. | long |  |
| activemq.broker.consumers.count | Number of message consumers. | long |  |
| activemq.broker.mbean | MBean that this event is related to. | keyword |  |
| activemq.broker.memory.broker.pct | The percentage of the memory limit used. | float | percent |
| activemq.broker.memory.store.pct | Percent of store limit used. | float | percent |
| activemq.broker.memory.temp.pct | The percentage of the temp usage limit used. | float | percent |
| activemq.broker.messages.count | Number of unacknowledged messages on the broker. | long |  |
| activemq.broker.messages.dequeue.count | Number of messages that have been acknowledged on the broker. | long |  |
| activemq.broker.messages.enqueue.count | Number of messages that have been sent to the destination. | long |  |
| activemq.broker.name | Broker name. | keyword |  |
| activemq.broker.producers.count | Number of message producers active on destinations on the broker. | long |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |


### Queue Metrics

The server queue stream collects data from the ActiveMQ queue module.

An example event for `queue` looks as following:

```json
{
    "@timestamp": "2022-06-29T16:11:38.323Z",
    "activemq": {
        "queue": {
            "consumers": {
                "count": 0
            },
            "mbean": "org.apache.activemq:brokerName=localhost,destinationName=TEST,destinationType=Queue,type=Broker",
            "memory": {
                "broker": {
                    "pct": 0
                }
            },
            "messages": {
                "dequeue": {
                    "count": 0
                },
                "dispatch": {
                    "count": 0
                },
                "enqueue": {
                    "count": 18,
                    "time": {
                        "avg": 0,
                        "max": 0,
                        "min": 0
                    }
                },
                "expired": {
                    "count": 0
                },
                "inflight": {
                    "count": 0
                },
                "size": {
                    "avg": 1035
                }
            },
            "name": "TEST",
            "producers": {
                "count": 0
            },
            "size": 18
        }
    },
    "agent": {
        "ephemeral_id": "ae634fb6-c546-4958-b1b4-5338a04bf27f",
        "id": "4052b5b6-59e4-4711-8a2c-f6c667f81bbd",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "activemq.queue",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "4052b5b6-59e4-4711-8a2c-f6c667f81bbd",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "activemq.queue",
        "duration": 16655818,
        "ingested": "2022-06-29T16:11:41Z",
        "module": "activemq"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02:42:ac:13:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.66.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "queue",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_activemq_1:8161/api/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "activemq"
    },
    "tags": [
        "forwarded",
        "activemq-queue"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| activemq.queue.consumers.count | Number of consumers subscribed to this destination. | long |  |
| activemq.queue.mbean | MBean that this event is related to. | keyword |  |
| activemq.queue.memory.broker.pct | Percent of memory limit used. | float | percent |
| activemq.queue.messages.dequeue.count | Number of messages that has been acknowledged (and removed) from the destination. | long |  |
| activemq.queue.messages.dispatch.count | Number of messages that has been delivered to consumers, including those not acknowledged. | long |  |
| activemq.queue.messages.enqueue.count | Number of messages that have been sent to the destination. | long |  |
| activemq.queue.messages.enqueue.time.avg | Average time a message was held on this destination. | double |  |
| activemq.queue.messages.enqueue.time.max | The longest time a message was held on this destination. | long |  |
| activemq.queue.messages.enqueue.time.min | The shortest time a message was held on this destination. | long |  |
| activemq.queue.messages.expired.count | Number of messages that have been expired. | long |  |
| activemq.queue.messages.inflight.count | Number of messages that have been dispatched to consumers but not acknowledged by consumers. | long |  |
| activemq.queue.messages.size.avg | Average message size on this destination. | long |  |
| activemq.queue.name | Queue name | keyword |  |
| activemq.queue.producers.count | Number of producers attached to this destination. | long |  |
| activemq.queue.size | Queue size | long |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |


### Topic Metrics

The server topic stream collects data from the ActiveMQ topic module.

An example event for `topic` looks as following:

```json
{
    "@timestamp": "2022-06-29T16:13:05.413Z",
    "activemq": {
        "topic": {
            "consumers": {
                "count": 0
            },
            "mbean": "org.apache.activemq:brokerName=localhost,destinationName=ActiveMQ.Advisory.MasterBroker,destinationType=Topic,type=Broker",
            "memory": {
                "broker": {
                    "pct": 0
                }
            },
            "messages": {
                "dequeue": {
                    "count": 0
                },
                "dispatch": {
                    "count": 0
                },
                "enqueue": {
                    "count": 1,
                    "time": {
                        "avg": 0,
                        "max": 0,
                        "min": 0
                    }
                },
                "expired": {
                    "count": 0
                },
                "inflight": {
                    "count": 0
                },
                "size": {
                    "avg": 1024
                }
            },
            "name": "ActiveMQ.Advisory.MasterBroker",
            "producers": {
                "count": 0
            }
        }
    },
    "agent": {
        "ephemeral_id": "97eb0219-9f47-414b-9e73-6b806294b181",
        "id": "4052b5b6-59e4-4711-8a2c-f6c667f81bbd",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.2.0"
    },
    "data_stream": {
        "dataset": "activemq.topic",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "4052b5b6-59e4-4711-8a2c-f6c667f81bbd",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "activemq.topic",
        "duration": 16295694,
        "ingested": "2022-06-29T16:13:08Z",
        "module": "activemq"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.19.0.7"
        ],
        "mac": [
            "02:42:ac:13:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.66.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.4 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "topic",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_activemq_1:8161/api/jolokia/%3FignoreErrors=true\u0026canonicalNaming=false",
        "type": "activemq"
    },
    "tags": [
        "forwarded",
        "activemq-topic"
    ]
}
```

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| activemq.topic.consumers.count | Number of consumers subscribed to this destination. | long |  |
| activemq.topic.mbean | MBean that this event is related to. | keyword |  |
| activemq.topic.memory.broker.pct | Percent of memory limit used. | float | percent |
| activemq.topic.messages.dequeue.count | Number of messages that has been acknowledged (and removed) from the destination. | long |  |
| activemq.topic.messages.dispatch.count | Number of messages that has been delivered to consumers, including those not acknowledged. | long |  |
| activemq.topic.messages.enqueue.count | Number of messages that have been sent to the destination. | long |  |
| activemq.topic.messages.enqueue.time.avg | Average time a message was held on this destination. | double |  |
| activemq.topic.messages.enqueue.time.max | The longest time a message was held on this destination. | long |  |
| activemq.topic.messages.enqueue.time.min | The shortest time a message was held on this destination. | long |  |
| activemq.topic.messages.expired.count | Number of messages that have been expired. | long |  |
| activemq.topic.messages.inflight.count | Number of messages that have been dispatched to, but not acknowledged by, consumers. | long |  |
| activemq.topic.messages.size.avg | Average message size on this destination. | long |  |
| activemq.topic.name | Topic name | keyword |  |
| activemq.topic.producers.count | Number of producers attached to this destination. | long |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |

