# Oracle WebLogic integration

The Oracle WebLogic Integration is used to fetch observability data from [Oracle WebLogic web endpoints](https://docs.oracle.com/cd/B16240_01/doc/em.102/b25987/oracle_weblogic.htm) and ingest it into Elasticsearch.

## Compatibility

This integration has been tested against `Oracle WebLogic v12.2.1.3`.

## Logs

This integration is for Oracle Weblogic Access logs . It includes the following datasets for receiving logs from a file:

### Access Logs

The `access` dataset collects Access logs form access.log.

An example event for `access` looks as following:

```json
{
    "@timestamp": "2022-03-26T18:10:04.000Z",
    "agent": {
        "ephemeral_id": "0fd40032-42b0-4d02-bfb2-156ddccb992f",
        "id": "36a40463-92bb-4f38-b014-e52012f4a0b0",
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
        "dataset": "oracle_weblogic.access",
        "ingested": "2022-04-11T12:23:51Z",
        "kind": "event",
        "module": "oracle_weblogic",
        "original": "172.17.32.1 - - [26/Mar/2022:23:40:04 +0530] \"GET /medrec/start.xhtml HTTP/1.1\" 200 8876 ",
        "type": "access"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": "172.17.32.1",
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
        "oracle-weblogic-access-log"
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| oracle_weblogic.access.authuser | The User identity allowing them access to an online service, connected device, or other resource | keyword |
| oracle_weblogic.access.host_address | The physical address of a computer in a network | keyword |
| tags | List of keywords used to tag each event. | keyword |

