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

    (Optional) User can run Jolokia on https by configuring following [paramters](https://jolokia.org/reference/html/agents.html#:~:text=Table%C2%A03.6.-,JVM%20agent%20configuration%20options,-Parameter).

    ```
     -javaagent:<path-to-jolokia-agent>=port=<port>,host=<hostname>,protocol=<http/https>,keystore=<path-to-keystore>,keystorePassword=<kestore-password>,keyStoreType=<keystore-type>
    ```

    Example configuration:
    ```
     -javaagent:/home/oracle/jolokia-jvm-1.6.0-agent.jar=port=8005,host=localhost,protocol=https,keystore=/u01/oracle/weblogic.jks,keystorePassword=host@123,keyStoreType=JKS
    ```
### Troubleshooting

Conflicts in any field in any data stream can be solved by reindexing the data. 
If host.ip is shown conflicted under ``logs-*`` data view, then this issue can be solved by reindexing the ``Admin Server`` data stream's indices. 
If host.ip is shown conflicted under ``metrics-*`` data view, then this issue can be solved by reindexing the ``Deployed Application`` and ``Threadpool`` data streams' indices.
To reindex the data, the following steps must be performed.

1. Stop the data stream by going to `Integrations -> Oracle WebLogic -> Integration policies` open the configuration of Oracle WebLogic and disable the `Collect Oracle WebLogic metrics` toggle to reindex metrics data stream and disable the `Collect Oracle WebLogic logs` toggle to reindex logs data stream and save the integration.

2. Perform the following steps in the Dev tools

```
POST _reindex
{
  "source": {
    "index": "<index_name>"
  },
  "dest": {
    "index": "temp_index"
  }
}  
```
Example:
```
POST _reindex
{
  "source": {
    "index": "logs-oracle_weblogic.admin_server-default"
  },
  "dest": {
    "index": "temp_index"
  }
}
```

```
DELETE /_data_stream/<data_stream>
```
Example:
```
DELETE /_data_stream/logs-oracle_weblogic.admin_server-default
```

```
DELETE _index_template/<index_template>
```
Example:
```
DELETE _index_template/logs-oracle_weblogic.admin_server
```
3. Go to `Integrations -> Oracle WebLogic -> Settings` and click on `Reinstall Oracle WebLogic`.

4. Perform the following steps in the Dev tools

```
POST _reindex
{
  "conflicts": "proceed",
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "<index_name>",
    "op_type": "create"

  }
}
```
Example:
```
POST _reindex
{
  "conflicts": "proceed",
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "logs-oracle_weblogic.admin_server-default",
    "op_type": "create"

  }
}
```

5. Verify data is reindexed completely.

6. Start the data stream by going to the `Integrations -> Oracle WebLogic -> Integration policies` and open configuration of integration and enable the `Collect Oracle WebLogic metrics` toggle and enable the `Collect Oracle WebLogic logs` toggle save the integration.

7. Perform the following step in the Dev tools

```
DELETE temp_index
```

More details about reindexing can be found [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html).

## Logs

This integration collects Oracle WebLogic Admin Server, Managed Server, Domain and Access logs. It includes the following datasets for receiving logs from a file:

### Access logs

The `access` data stream collects Access logs form `Access.log`.

An example event for `access` looks as following:

```json
{
    "@timestamp": "2023-03-31T05:58:42.000Z",
    "agent": {
        "ephemeral_id": "cc619ca4-d631-4d8d-a374-c61aef9c9c83",
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.2"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.access",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "oracle_weblogic.access",
        "ingested": "2023-03-31T05:59:45Z",
        "kind": "event",
        "module": "oracle_weblogic",
        "original": "127.0.0.1 - - [31/Mar/2023:05:58:42 +0000] \"GET /sample/index.jsp HTTP/1.1\" 200 747 ",
        "type": [
            "access"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "f91b175388d443fca5c155815dfc2279",
        "ip": [
            "192.168.240.7",
            "127.0.0.1"
        ],
        "mac": [
            "02-42-C0-A8-F0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.88.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "http": {
        "request": {
            "method": "GET",
            "referrer": "/sample/index.jsp"
        },
        "response": {
            "bytes": 747,
            "status_code": 200
        },
        "version": "1.1"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/adminserver/logs/access.log"
        },
        "offset": 0
    },
    "oracle_weblogic": {
        "access": {
            "authuser": "-",
            "host_address": "127.0.0.1"
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
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset. | long |
| oracle_weblogic.access.authuser | The User identity allowing them access to an online service, connected device, or other resource. | keyword |
| oracle_weblogic.access.host_address | The physical address of a computer in a network. | keyword |
| tags | User defined tags. | keyword |


### Admin Server logs

The `admin_server` data stream collects Admin Server logs from `Adminserver.log`.

An example event for `admin_server` looks as following:

```json
{
    "@timestamp": "2023-03-31T06:00:30.787Z",
    "agent": {
        "ephemeral_id": "cc619ca4-d631-4d8d-a374-c61aef9c9c83",
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.2"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.admin_server",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "oracle_weblogic.admin_server",
        "ingested": "2023-03-31T06:01:52Z",
        "kind": "event",
        "module": "oracle_weblogic",
        "original": "####\u003cMar 31, 2023 6:00:30,787 AM GMT\u003e \u003cInfo\u003e \u003cSecurity\u003e \u003cwlsadmin\u003e \u003c\u003e \u003cmain\u003e \u003c\u003e \u003c\u003e \u003c\u003e \u003c1680242430787\u003e \u003c[severity-value: 64] [partition-id: 0] [partition-name: DOMAIN] \u003e \u003cBEA-090905\u003e \u003cDisabling the CryptoJ JCE Provider self-integrity check for better startup performance. To enable this check, specify -Dweblogic.security.allowCryptoJDefaultJCEVerification=true.\u003e ",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "f91b175388d443fca5c155815dfc2279",
        "ip": [
            "192.168.240.7"
        ],
        "mac": [
            "02-42-C0-A8-F0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.88.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/adminserver/logs/admin-server.log"
        },
        "level": "Info",
        "offset": 0
    },
    "message": "Disabling the CryptoJ JCE Provider self-integrity check for better startup performance. To enable this check, specify -Dweblogic.security.allowCryptoJDefaultJCEVerification=true.",
    "oracle_weblogic": {
        "admin_server": {
            "diagnostic_context_id": "1680242430787",
            "machine_name": "wlsadmin",
            "message_id": "BEA-090905",
            "meta": "[severity-value: 64] [partition-id: 0] [partition-name: DOMAIN] ",
            "subsystem": "Security",
            "thread_id": "main"
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
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset. | long |
| message | A description of the event or condition. | keyword |
| oracle_weblogic.admin_server.diagnostic_context_id | Context information to correlate messages coming from a specific request or application. | keyword |
| oracle_weblogic.admin_server.machine_name | Machine Name is the DNS name of the computer that hosts the server instance. | keyword |
| oracle_weblogic.admin_server.message_id | A unique identifier for the message. | keyword |
| oracle_weblogic.admin_server.meta | Meta information for the event. | keyword |
| oracle_weblogic.admin_server.server_name | Server Name is the name of the WebLogic Server instance on which the message was generated. | keyword |
| oracle_weblogic.admin_server.subsystem | Indicates the subsystem of WebLogic Server that was the source of the message; for example, Enterprise Java Bean (EJB) container or Java Messaging Service (JMS). | keyword |
| oracle_weblogic.admin_server.thread_id | Thread ID is the ID that the JVM assigns to the thread in which the message originated. | keyword |
| tags | User defined tags. | keyword |


### Domain logs

The `domain` data stream collects Domain logs from `Domain.log`.

An example event for `domain` looks as following:

```json
{
    "@timestamp": "2023-03-31T06:03:51.686Z",
    "agent": {
        "ephemeral_id": "78eaf2b6-72d2-4da3-85e5-5cec12523592",
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.2"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.domain",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "oracle_weblogic.domain",
        "ingested": "2023-03-31T06:05:11Z",
        "kind": "event",
        "module": "oracle_weblogic",
        "original": "####\u003cMar 31, 2023 6:03:51,686 AM GMT\u003e \u003cNotice\u003e \u003cSecurity\u003e \u003cwlsadmin\u003e \u003cadmin-server\u003e \u003c[STANDBY] ExecuteThread: '1' for queue: 'weblogic.kernel.Default (self-tuning)'\u003e \u003c\u003cWLS Kernel\u003e\u003e \u003c\u003e \u003c\u003e \u003c1680242631686\u003e \u003c[severity-value: 32] [partition-id: 0] [partition-name: DOMAIN] \u003e \u003cBEA-090946\u003e \u003cSecurity pre-initializing using security realm: myrealm\u003e ",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "f91b175388d443fca5c155815dfc2279",
        "ip": [
            "192.168.240.7"
        ],
        "mac": [
            "02-42-C0-A8-F0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.88.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/adminserver/domain1.log"
        },
        "level": "Notice",
        "offset": 0
    },
    "message": "Security pre-initializing using security realm: myrealm",
    "oracle_weblogic": {
        "domain": {
            "diagnostic_context_id": "1680242631686",
            "machine_name": "wlsadmin",
            "message_id": "BEA-090946",
            "meta": "[severity-value: 32] [partition-id: 0] [partition-name: DOMAIN] ",
            "server_name": "admin-server",
            "subsystem": "Security",
            "thread_id": "[STANDBY] ExecuteThread: '1' for queue: 'weblogic.kernel.Default (self-tuning)'"
        }
    },
    "tags": [
        "oracle_weblogic-domain"
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
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset. | long |
| message | A description of the event or condition. | keyword |
| oracle_weblogic.domain.diagnostic_context_id | Context information to correlate messages coming from a specific request or application. | keyword |
| oracle_weblogic.domain.machine_name | Machine Name is the DNS name of the computer that hosts the server instance. | keyword |
| oracle_weblogic.domain.message_id | A unique identifier for the message. | keyword |
| oracle_weblogic.domain.meta | Meta information for the event. | keyword |
| oracle_weblogic.domain.server_name | Server Name is the name of the WebLogic Server instance on which the message was generated. | keyword |
| oracle_weblogic.domain.subsystem | Indicates the subsystem of WebLogic Server that was the source of the message; for example, Enterprise Java Bean (EJB) container or Java Messaging Service (JMS). | keyword |
| oracle_weblogic.domain.thread_id | Thread ID is the ID that the JVM assigns to the thread in which the message originated. | keyword |
| tags | User defined tags. | keyword |


### Managed Server Logs

The `managed_server` data stream collects Managed Server logs from `Managedserver.log`.

An example event for `managed_server` looks as following:

```json
{
    "@timestamp": "2023-03-31T06:06:01.741Z",
    "agent": {
        "ephemeral_id": "78eaf2b6-72d2-4da3-85e5-5cec12523592",
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.2"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.managed_server",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "oracle_weblogic.managed_server",
        "ingested": "2023-03-31T06:07:03Z",
        "kind": "event",
        "module": "oracle_weblogic",
        "original": "####\u003cMar 31, 2023 6:06:01,741 AM GMT\u003e \u003cInfo\u003e \u003cSecurity\u003e \u003c63ac405d756d\u003e \u003c\u003e \u003cmain\u003e \u003c\u003e \u003c\u003e \u003c\u003e \u003c1680242761741\u003e \u003c[severity-value: 64] [partition-id: 0] [partition-name: DOMAIN] \u003e \u003cBEA-090905\u003e \u003cDisabling the CryptoJ JCE Provider self-integrity check for better startup performance. To enable this check, specify -Dweblogic.security.allowCryptoJDefaultJCEVerification=true.\u003e ",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "f91b175388d443fca5c155815dfc2279",
        "ip": [
            "192.168.240.7"
        ],
        "mac": [
            "02-42-C0-A8-F0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.88.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/managedserver/managed-server1.log"
        },
        "level": "Info",
        "offset": 0
    },
    "message": "Disabling the CryptoJ JCE Provider self-integrity check for better startup performance. To enable this check, specify -Dweblogic.security.allowCryptoJDefaultJCEVerification=true.",
    "oracle_weblogic": {
        "managed_server": {
            "diagnostic_context_id": "1680242761741",
            "machine_name": "63ac405d756d",
            "message_id": "BEA-090905",
            "meta": "[severity-value: 64] [partition-id: 0] [partition-name: DOMAIN] ",
            "subsystem": "Security",
            "thread_id": "main"
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
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset. | long |
| message | A description of the event or condition. | keyword |
| oracle_weblogic.managed_server.diagnostic_context_id | Context information to correlate messages coming from a specific request or application. | keyword |
| oracle_weblogic.managed_server.machine_name | Machine Name is the DNS name of the computer that hosts the server instance. | keyword |
| oracle_weblogic.managed_server.message_id | A unique identifier for the message. | keyword |
| oracle_weblogic.managed_server.meta | Meta information for the event. | keyword |
| oracle_weblogic.managed_server.server_name | Server Name is the name of the WebLogic Server instance on which the message was generated. | keyword |
| oracle_weblogic.managed_server.subsystem | Indicates the subsystem of WebLogic Server that was the source of the message; for example, Enterprise Java Bean (EJB) container or Java Messaging Service (JMS). | keyword |
| oracle_weblogic.managed_server.thread_id | Thread ID is the ID that the JVM assigns to the thread in which the message originated. | keyword |
| tags | User defined tags. | keyword |


## Metrics

### Deployed Application Metrics

The `deployed_application` data stream collects metrics of Deployed Application.

An example event for `deployed_application` looks as following:

```json
{
    "@timestamp": "2023-03-31T06:03:03.746Z",
    "agent": {
        "ephemeral_id": "d6d9f95a-01e1-479b-84eb-a3ad216b66ac",
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.6.2"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.deployed_application",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "oracle_weblogic.deployed_application",
        "duration": 32517745,
        "ingested": "2023-03-31T06:03:07Z",
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
        "id": "f91b175388d443fca5c155815dfc2279",
        "ip": [
            "192.168.240.7"
        ],
        "mac": [
            "02-42-C0-A8-F0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.88.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
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
            "source_info": "webapp",
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

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| oracle_weblogic.deployed_application.deployment.state.name | Current state of the deployment as an keyword. | keyword |
| oracle_weblogic.deployed_application.deployment.state.value | Current state of the deployment as an integer. | long |
| oracle_weblogic.deployed_application.session_timeout | Session timeout in integer. | long |
| oracle_weblogic.deployed_application.sessions.open.current | Current number of open sessions in this module. | long |
| oracle_weblogic.deployed_application.sessions.open.high | Highest number of open sessions on this server at any one time. | long |
| oracle_weblogic.deployed_application.sessions.open.total | Total number of sessions that were opened. | long |
| oracle_weblogic.deployed_application.single_threaded_servlet_pool_size | Displays the size of this servlet for single thread model servlets. | long |
| oracle_weblogic.deployed_application.source_info | Source info of the deployment as a keyword. | keyword |
| oracle_weblogic.deployed_application.status | Status of the deployment. | keyword |


### ThreadPool metrics

This `threadpool` data stream collects metrics of ThreadPool.

An example event for `threadpool` looks as following:

```json
{
    "@timestamp": "2023-03-31T06:08:16.172Z",
    "agent": {
        "ephemeral_id": "2ba6d383-84c1-4f12-b35c-ff5efe89cc30",
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.6.2"
    },
    "data_stream": {
        "dataset": "oracle_weblogic.threadpool",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "d3c5d9c6-d2b4-46bd-a780-45d859c19723",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "oracle_weblogic.threadpool",
        "duration": 63077291,
        "ingested": "2023-03-31T06:08:20Z",
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
        "id": "f91b175388d443fca5c155815dfc2279",
        "ip": [
            "192.168.240.7"
        ],
        "mac": [
            "02-42-C0-A8-F0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.88.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
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
                "completed": 1394,
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
            "throughput": 84.45777111444278,
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

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
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
| oracle_weblogic.threadpool.threads.total | Current number of live threads including both daemon and non-daemon threads. | long |
| oracle_weblogic.threadpool.throughput | The mean number of requests completed per second. | double |
| oracle_weblogic.threadpool.work_manager.capacity.shared | Maximum amount of requests that can be accepted in the priority queue. Note that a request with higher priority will be accepted in place of a lower priority request already in the queue even after the threshold is reached. The lower priority request is kept waiting in the queue till all high priority requests are executed. Also note that further enqueues of the low priority requests are rejected right away. | long |

