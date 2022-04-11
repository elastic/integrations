# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Logs

This integration is for Oracle Weblogic Domain logs. It includes the following datasets for receiving logs from a file:

### Domain Logs

The `domain` dataset collects Domain logs from Domain.log.

An example event for `domain` looks as following:

```json
{
    "@timestamp": "2022-03-24T10:30:27.263Z",
    "agent": {
        "ephemeral_id": "2b5e0920-5b42-4714-b371-95a4bddb0e12",
        "id": "36a40463-92bb-4f38-b014-e52012f4a0b0",
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
        "version": "8.1.0"
    },
    "elastic_agent": {
        "id": "36a40463-92bb-4f38-b014-e52012f4a0b0",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "log"
        ],
        "dataset": "oracle_weblogic.domain",
        "ingested": "2022-04-11T12:25:11Z",
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
            "192.168.208.6"
        ],
        "mac": [
            "02:42:c0:a8:d0:06"
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
    "oracle_weblogic": {
        "domain": {
            "diagnostic_context_id": "1648117827263",
            "machine_name": "wlsadmin",
            "message_id": "BEA-000449",
            "message_text": "Closing the socket, as no data read from it on 172.18.0.1:41,972 during the configured idle timeout of 5 seconds.",
            "meta": "[severity-value: 16] [rid: 0] [partition-id: 0] [partition-name: DOMAIN] ",
            "server_name": "AdminServer",
            "subsystem": "Socket",
            "thread_id": "[ACTIVE] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'"
        }
    },
    "tags": [
        "oracle-weblogic-domain-logs"
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| oracle_weblogic.domain.diagnostic_context_id | Context information to correlate messages coming from a specific request or application. | keyword |
| oracle_weblogic.domain.machine_name | Machine Name is the DNS name of the computer that hosts the server instance. | keyword |
| oracle_weblogic.domain.message_id | A unique six-digit identifier. | keyword |
| oracle_weblogic.domain.message_text | A description of the event or condition. | keyword |
| oracle_weblogic.domain.meta | Meta information for the event. | keyword |
| oracle_weblogic.domain.server_name | Server Name is the name of the WebLogic Server instance on which the message was generated. | keyword |
| oracle_weblogic.domain.subsystem | Indicates the subsystem of WebLogic Server that was the source of the message; for example, Enterprise Java Bean (EJB) container or Java Messaging Service (JMS). | keyword |
| oracle_weblogic.domain.thread_id | Thread ID is the ID that the JVM assigns to the thread in which the message originated. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| transaction.id | Unique identifier of the transaction within the scope of its trace. A transaction is the highest level of work measured within a service, such as a request to a server. | keyword |
| user.id | Unique identifier of the user. | keyword |

