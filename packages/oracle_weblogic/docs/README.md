# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Requirements

In order to ingest data from Oracle WebLogic:
- User must add the path where the Jolokia agent is downloaded (For example, `/home/oracle/jolokia-jvm-1.6.0-agent.jar`).
- Configuring Jolokia for WebLogic

    User needs to [download](https://jolokia.org/download.html) and add the JAR file and set environment variables for Jolokia.

    ```
     -javaagent:<path-to-jolokia-agent>=port=<port>,host=<hostname>
    ``` 
    Example configuration:
    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=8005,host=localhost
    ```

    (Optional) User can run Jolokia on https by configuring following [parameters](https://jolokia.org/reference/html/agents.html#:~:text=Table%C2%A03.6.-,JVM%20agent%20configuration%20options,-Parameter).

    ```
     -javaagent:<path-to-jolokia-agent>=port=<port>,host=<hostname>,protocol=<http/https>,keystore=<path-to-keystore>,keystorePassword=<kestore-password>,keyStoreType=<keystore-type>
    ```

    Example configuration:
    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=8005,host=localhost,protocol=https,keystore=/u01/oracle/weblogic.jks,keystorePassword=host@123,keyStoreType=JKS
    ```
### Troubleshooting

- If `host.ip` appears conflicted under the ``logs-*`` data view, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/use-a-data-stream.html#reindex-with-a-data-stream) the ``Admin Server`` data stream. 
- If `host.ip` appears conflicted under the ``metrics-*`` data view, this issue can be resolved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds-reindex.html) the ``Deployed Application`` and ``Threadpool`` data streams.

## Logs

This integration collects Oracle WebLogic Admin Server, Managed Server, Domain and Access logs. It includes the following datasets for receiving logs from a file:

### Access logs

The `access` data stream collects Access logs form `Access.log`.

An example event for `access` looks as following:

```json
{
    "@timestamp": "2022-03-26T18:10:04.000Z",
    "agent": {
        "ephemeral_id": "803b783e-44fb-41f8-ba17-08c31c34aae8",
        "id": "d17bdd23-2a9d-4013-abe7-0652f306d69d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.access",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "d17bdd23-2a9d-4013-abe7-0652f306d69d",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "log"
        ],
        "dataset": "oracle_weblogic.access",
        "ingested": "2022-04-25T06:53:32Z",
        "kind": "event",
        "module": "oracle_weblogic",
        "original": "172.17.32.1 - - [26/Mar/2022:23:40:04 +0530] \"GET /medrec/start.xhtml HTTP/1.1\" 200 8876 ",
        "type": "access"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.17.32.1"
        ],
        "mac": [
            "02:42:ac:12:00:07"
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
    "http": {
        "request": {
            "method": "GET",
            "referrer": "/medrec/start.xhtml"
        },
        "response": {
            "bytes": 8876,
            "status_code": 200
        },
        "version": "1.1"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/oracle-weblogic-access.log"
        },
        "offset": 0
    },
    "oracle_weblogic": {
        "access": {
            "authuser": "-",
            "host_address": "172.17.32.1"
        }
    },
    "tags": [
        "oracle_weblogic-access"
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
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset. | long |
| oracle_weblogic.access.authuser | The User identity allowing them access to an online service, connected device, or other resource. | keyword |
| oracle_weblogic.access.host_address | The physical address of a computer in a network. | keyword |
| tags | List of keywords used to tag each event. | keyword |


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
        "version": "8.5.1"
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
| host.ip | Host ip addresses. | ip |
| input.type | Input type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
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
        "version": "8.5.1"
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
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
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
        "version": "8.5.1"
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
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
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


## Metrics

### Deployed Application Metrics

The `deployed_application` data stream collects metrics of Deployed Application.

An example event for `deployed_application` looks as following:

```json
{
    "@timestamp": "2022-06-01T06:06:16.679Z",
    "agent": {
        "ephemeral_id": "9b5302d4-4654-485a-8708-b8c971d7ebd6",
        "id": "f5ae4eeb-820b-4f24-a94a-df327091d185",
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
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "f5ae4eeb-820b-4f24-a94a-df327091d185",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "oracle_weblogic.deployed_application",
        "duration": 27026922,
        "ingested": "2022-06-01T06:06:20Z",
        "kind": "metric",
        "module": "oracle_weblogic",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.31.0.7"
        ],
        "mac": [
            "02:42:ac:1f:00:07"
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
                "state": {
                    "name": "Running",
                    "value": 2
                }
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
            "source_info": "weblogic.war",
            "status": "DEPLOYED"
        }
    },
    "service": {
        "address": "http://elastic-package-service_wlsadmin_1:8005/jolokia",
        "type": "jolokia"
    },
    "tags": [
        "oracle_weblogic-deployed_application"
    ]
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| oracle_weblogic.deployed_application.deployment.state.name | Current state of the deployment as an keyword. | keyword |  |
| oracle_weblogic.deployed_application.deployment.state.value | Current state of the deployment as an integer. | long | gauge |
| oracle_weblogic.deployed_application.session_timeout | Session timeout in integer. | long | gauge |
| oracle_weblogic.deployed_application.sessions.open.current | Current number of open sessions in this module. | long | gauge |
| oracle_weblogic.deployed_application.sessions.open.high | Highest number of open sessions on this server at any one time. | long | counter |
| oracle_weblogic.deployed_application.sessions.open.total | Total number of sessions that were opened. | long | counter |
| oracle_weblogic.deployed_application.single_threaded_servlet_pool_size | Displays the size of this servlet for single thread model servlets. | long | gauge |
| oracle_weblogic.deployed_application.source_info | Source info of the deployment as a keyword. | keyword |  |
| oracle_weblogic.deployed_application.status | Status of the deployment. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |


### ThreadPool metrics

This `threadpool` data stream collects metrics of ThreadPool.

An example event for `threadpool` looks as following:

```json
{
    "@timestamp": "2023-08-23T11:54:38.053Z",
    "agent": {
        "ephemeral_id": "4a2754ea-5dba-4b59-8d77-c0f70bfccae3",
        "id": "89fbf5a1-dedd-4f8f-a1ee-97a7e3ec1ed2",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.4.0"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.threadpool",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.5.1"
    },
    "elastic_agent": {
        "id": "89fbf5a1-dedd-4f8f-a1ee-97a7e3ec1ed2",
        "snapshot": false,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "oracle_weblogic.threadpool",
        "duration": 55017871,
        "ingested": "2023-08-23T11:54:39Z",
        "kind": "metric",
        "module": "oracle_weblogic",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "e8978f2086c14e13b7a0af9ed0011d19",
        "ip": [
            "172.29.0.9"
        ],
        "mac": [
            "02-42-AC-1D-00-09"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.90.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "oracle_weblogic": {
        "threadpool": {
            "mbean": "com.bea:ServerRuntime=admin-server,Name=ThreadPoolRuntime,Type=ThreadPoolRuntime",
            "queue": {
                "length": 0
            },
            "requests": {
                "completed": 1466,
                "overload": {
                    "rejected": 0
                },
                "pending": 0
            },
            "threads": {
                "execute": {
                    "idle": 1,
                    "total": 15
                },
                "hogging": 0,
                "standby": 14,
                "stuck": 0
            },
            "throughput": 91.5,
            "work_manager": {
                "capacity": {
                    "shared": 65536
                }
            }
        }
    },
    "service": {
        "address": "http://elastic-package-service_wlsadmin_1:8005/jolokia",
        "type": "jolokia"
    },
    "tags": [
        "oracle_weblogic-threadpool"
    ]
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |  |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |  |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| oracle_weblogic.threadpool.mbean | The name of the jolokia mbean. | keyword |  |
| oracle_weblogic.threadpool.queue.length | The number of pending requests in the priority queue. This is the total of internal system requests and user requests. | long | gauge |
| oracle_weblogic.threadpool.requests.completed | The number of completed requests in the priority queue. | long | counter |
| oracle_weblogic.threadpool.requests.overload.rejected | Number of requests rejected due to configured Shared Capacity for work managers have been reached. | long | counter |
| oracle_weblogic.threadpool.requests.pending | The number of pending user requests in the priority queue. The priority queue contains requests from internal subsystems and users. This is just the count of all user requests. | long | gauge |
| oracle_weblogic.threadpool.threads.daemon | Current number of live daemon threads. | long | gauge |
| oracle_weblogic.threadpool.threads.execute.idle | The number of idle threads in the pool. This count does not include standby threads and stuck threads. The count indicates threads that are ready to pick up new work when it arrives. | long | gauge |
| oracle_weblogic.threadpool.threads.execute.total | The total number of threads in the pool. | long | gauge |
| oracle_weblogic.threadpool.threads.hogging | The threads that are being held by a request right now. These threads will either be declared as stuck after the configured timeout or will return to the pool before that. The self-tuning mechanism will backfill if necessary. | long | gauge |
| oracle_weblogic.threadpool.threads.standby | The number of threads in the standby pool. Threads that are not needed to handle the present work load are designated as standby and added to the standby pool. These threads are activated when more threads are needed. | long | gauge |
| oracle_weblogic.threadpool.threads.stuck | Number of stuck threads in the thread pool. | long | gauge |
| oracle_weblogic.threadpool.threads.total | Current number of live threads including both daemon and non-daemon threads. | long | gauge |
| oracle_weblogic.threadpool.throughput | The mean number of requests completed per second. | double | gauge |
| oracle_weblogic.threadpool.work_manager.capacity.shared | Maximum amount of requests that can be accepted in the priority queue. Note that a request with higher priority will be accepted in place of a lower priority request already in the queue even after the threshold is reached. The lower priority request is kept waiting in the queue till all high priority requests are executed. Also note that further enqueues of the low priority requests are rejected right away. | long | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |

