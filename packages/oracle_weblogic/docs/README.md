# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Logs

This integration collects Oracle Weblogic Admin Server, Managed Server and Domain logs. It includes the following datasets for receiving logs from a file:

### Admin Server logs

The `admin_server` data stream collects Admin Server logs from `Adminserver.log`.

An example event for `admin_server` looks as following:

```json
{
    "@timestamp": "2022-03-24T10:29:51.865Z",
    "agent": {
        "ephemeral_id": "1e785926-cb16-442e-9599-91e10ef5228d",
        "id": "2c65d5b2-0806-4fb1-96c2-b9852c73afd0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.admin_server",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "2c65d5b2-0806-4fb1-96c2-b9852c73afd0",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "log"
        ],
        "dataset": "oracle_weblogic.admin_server",
        "ingested": "2022-05-09T11:20:10Z",
        "kind": "event",
        "module": "oracle_weblogic",
        "original": "####\u003cMar 24, 2022 10:29:51,865 AM GMT\u003e \u003cInfo\u003e \u003cServer\u003e \u003cwlsadmin\u003e \u003c\u003e \u003cThread-11\u003e \u003c\u003e \u003c\u003e \u003c\u003e \u003c1648117791865\u003e \u003c[severity-value: 64] [partition-id: 0] [partition-name: DOMAIN] \u003e \u003cBEA-002622\u003e \u003cThe protocol \"admin\" is now configured.\u003e ",
        "type": "admin"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.19.0.6"
        ],
        "mac": [
            "02:42:ac:13:00:06"
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
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/oracle-weblogic-adminserver.log"
        },
        "level": "Info",
        "offset": 0
    },
    "message": "The protocol \"admin\" is now configured.",
    "oracle_weblogic": {
        "admin_server": {
            "diagnostic_context_id": "1648117791865",
            "machine_name": "wlsadmin",
            "message_id": "BEA-002622",
            "meta": "[severity-value: 64] [partition-id: 0] [partition-name: DOMAIN] ",
            "subsystem": "Server",
            "thread_id": "Thread-11"
        }
    },
    "tags": [
        "oracle_weblogic-admin_server"
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
| input.type | Input type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset. | long |
| message | A description of the event or condition. | keyword |
| oracle_weblogic.admin_server.diagnostic_context_id | Context information to correlate messages coming from a specific request or application. | keyword |
| oracle_weblogic.admin_server.machine_name | Machine Name is the DNS name of the computer that hosts the server instance. | keyword |
| oracle_weblogic.admin_server.message_id | A unique identifier for the message. | keyword |
| oracle_weblogic.admin_server.meta | Meta information for the event. | keyword |
| oracle_weblogic.admin_server.server_name | Server Name is the name of the WebLogic Server instance on which the message was generated. | keyword |
| oracle_weblogic.admin_server.subsystem | Indicates the subsystem of WebLogic Server that was the source of the message; for example, Enterprise Java Bean (EJB) container or Java Messaging Service (JMS). | keyword |
| oracle_weblogic.admin_server.thread_id | Thread ID is the ID that the JVM assigns to the thread in which the message originated. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| transaction.id | Unique identifier of the transaction within the scope of its trace. A transaction is the highest level of work measured within a service, such as a request to a server. | keyword |
| user.id | Unique identifier of the user. | keyword |


### Domain logs

The `domain` data stream collects Domain logs from `Domain.log`.

An example event for `domain` looks as following:

```json
{
    "@timestamp": "2022-03-24T10:30:27.263Z",
    "agent": {
        "ephemeral_id": "98841608-fe35-4844-b829-880c24a1cef7",
        "id": "2f35c5e6-c16d-4b67-a955-b81668aca1aa",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.domain",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "2f35c5e6-c16d-4b67-a955-b81668aca1aa",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "log"
        ],
        "dataset": "oracle_weblogic.domain",
        "ingested": "2022-05-09T12:29:51Z",
        "kind": "event",
        "module": "oracle_weblogic",
        "original": "####\u003cMar 24, 2022 10:30:27,263 AM GMT\u003e \u003cWarning\u003e \u003cSocket\u003e \u003cwlsadmin\u003e \u003cAdminServer\u003e \u003c[ACTIVE] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'\u003e \u003c\u003cWLS Kernel\u003e\u003e \u003c\u003e \u003c38f025ff-7924-471b-bac8-a419692aabf9-00000018\u003e \u003c1648117827263\u003e \u003c[severity-value: 16] [rid: 0] [partition-id: 0] [partition-name: DOMAIN] \u003e \u003cBEA-000449\u003e \u003cClosing the socket, as no data read from it on 172.18.0.1:41,972 during the configured idle timeout of 5 seconds.\u003e ",
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
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/oracle-weblogic-domain.log"
        },
        "level": "Warning",
        "offset": 2823
    },
    "message": "Closing the socket, as no data read from it on 172.18.0.1:41,972 during the configured idle timeout of 5 seconds.",
    "oracle_weblogic": {
        "domain": {
            "diagnostic_context_id": "1648117827263",
            "machine_name": "wlsadmin",
            "message_id": "BEA-000449",
            "meta": "[severity-value: 16] [rid: 0] [partition-id: 0] [partition-name: DOMAIN] ",
            "server_name": "AdminServer",
            "subsystem": "Socket",
            "thread_id": "[ACTIVE] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'"
        }
    },
    "tags": [
        "oracle_weblogic-domain"
    ],
    "transaction": {
        "id": "38f025ff-7924-471b-bac8-a419692aabf9-00000018"
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
| host.ip | Host ip addresses. | ip |
| input.type | Input type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset. | long |
| message | A description of the event or condition. | keyword |
| oracle_weblogic.domain.diagnostic_context_id | Context information to correlate messages coming from a specific request or application. | keyword |
| oracle_weblogic.domain.machine_name | Machine Name is the DNS name of the computer that hosts the server instance. | keyword |
| oracle_weblogic.domain.message_id | A unique identifier for the message. | keyword |
| oracle_weblogic.domain.meta | Meta information for the event. | keyword |
| oracle_weblogic.domain.server_name | Server Name is the name of the WebLogic Server instance on which the message was generated. | keyword |
| oracle_weblogic.domain.subsystem | Indicates the subsystem of WebLogic Server that was the source of the message; for example, Enterprise Java Bean (EJB) container or Java Messaging Service (JMS). | keyword |
| oracle_weblogic.domain.thread_id | Thread ID is the ID that the JVM assigns to the thread in which the message originated. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| transaction.id | Unique identifier of the transaction within the scope of its trace. A transaction is the highest level of work measured within a service, such as a request to a server. | keyword |
| user.id | Unique identifier of the user. | keyword |


### Managed Server Logs

The `managed_server` data stream collects Managed Server logs from `Managedserver.log`.

An example event for `managed_server` looks as following:

```json
{
    "@timestamp": "2022-03-24T10:29:56.637Z",
    "agent": {
        "ephemeral_id": "fc2f1df6-97a1-42bf-9f6b-904a765041e3",
        "id": "e27eb192-b14d-4af1-8861-fd7cbadb3643",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.managed_server",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "e27eb192-b14d-4af1-8861-fd7cbadb3643",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "log"
        ],
        "dataset": "oracle_weblogic.managed_server",
        "ingested": "2022-05-09T11:59:45Z",
        "kind": "event",
        "module": "oracle_weblogic",
        "original": "####\u003cMar 24, 2022 10:29:56,637 AM GMT\u003e \u003cInfo\u003e \u003cManagement\u003e \u003c5565e043d1b0\u003e \u003c\u003e \u003cThread-12\u003e \u003c\u003e \u003c\u003e \u003c\u003e \u003c1648117796637\u003e \u003c[severity-value: 64] [partition-id: 0] [partition-name: DOMAIN] \u003e \u003cBEA-141307\u003e \u003cUnable to connect to the Administration Server. Waiting 5 second(s) to retry (attempt number 2 of 3).\u003e ",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.21.0.7"
        ],
        "mac": [
            "02:42:ac:15:00:07"
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
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/oracle-weblogic-managedserver.log"
        },
        "level": "Info",
        "offset": 0
    },
    "message": "Unable to connect to the Administration Server. Waiting 5 second(s) to retry (attempt number 2 of 3).",
    "oracle_weblogic": {
        "managed_server": {
            "diagnostic_context_id": "1648117796637",
            "machine_name": "5565e043d1b0",
            "message_id": "BEA-141307",
            "meta": "[severity-value: 64] [partition-id: 0] [partition-name: DOMAIN] ",
            "subsystem": "Management",
            "thread_id": "Thread-12"
        }
    },
    "tags": [
        "oracle_weblogic-managed_server"
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
| host.ip | Host ip addresses. | ip |
| input.type | Input type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset. | long |
| message | A description of the event or condition. | keyword |
| oracle_weblogic.managed_server.diagnostic_context_id | Context information to correlate messages coming from a specific request or application. | keyword |
| oracle_weblogic.managed_server.machine_name | Machine Name is the DNS name of the computer that hosts the server instance. | keyword |
| oracle_weblogic.managed_server.message_id | A unique identifier for the message. | keyword |
| oracle_weblogic.managed_server.meta | Meta information for the event. | keyword |
| oracle_weblogic.managed_server.server_name | Server Name is the name of the WebLogic Server instance on which the message was generated. | keyword |
| oracle_weblogic.managed_server.subsystem | Indicates the subsystem of WebLogic Server that was the source of the message; for example, Enterprise Java Bean (EJB) container or Java Messaging Service (JMS). | keyword |
| oracle_weblogic.managed_server.thread_id | Thread ID is the ID that the JVM assigns to the thread in which the message originated. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| transaction.id | Unique identifier of the transaction within the scope of its trace. A transaction is the highest level of work measured within a service, such as a request to a server. | keyword |
| user.id | Unique identifier of the user. | keyword |

