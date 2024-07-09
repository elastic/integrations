# Apache Integration

This integration periodically fetches metrics from [Apache](https://httpd.apache.org/) servers. It can parse access and error
logs created by the Apache server.

## Compatibility

The Apache datasets were tested with Apache 2.4.12 and 2.4.46 and are expected to work with
all versions >= 2.2.31 and >= 2.4.16 (independent from operating system).

## Logs

### Access Logs

Access logs collects the Apache access logs.

An example event for `access` looks as following:

```json
{
    "@timestamp": "2024-06-21T13:03:30.000Z",
    "agent": {
        "ephemeral_id": "a8296a9f-087a-48ae-af44-8f064213f161",
        "id": "9326664e-5848-4401-a0fb-4494a1538c2e",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "apache": {
        "access": {
            "remote_addresses": [
                "127.0.0.1"
            ]
        }
    },
    "data_stream": {
        "dataset": "apache.access",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9326664e-5848-4401-a0fb-4494a1538c2e",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "created": "2024-06-21T13:03:44.637Z",
        "dataset": "apache.access",
        "ingested": "2024-06-21T13:03:56Z",
        "kind": "event",
        "outcome": "success"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
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
            "kernel": "3.10.0-1160.118.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "body": {
                "bytes": 45
            },
            "status_code": 200
        },
        "version": "1.1"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/access.log"
        },
        "offset": 0
    },
    "related": {
        "ip": [
            "127.0.0.1"
        ]
    },
    "source": {
        "address": "127.0.0.1",
        "ip": "127.0.0.1"
    },
    "tags": [
        "apache-access"
    ],
    "url": {
        "original": "/",
        "path": "/"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "curl",
        "original": "curl/7.64.0",
        "version": "7.64.0"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| apache.access.http.request_headers | Http request headers. | keyword |  |
| apache.access.identity | The client's identity, as specified in RFC 1413, determined by the identd on the client's machine. | keyword |  |
| apache.access.remote_addresses | An array of remote addresses. It is a list because it is common to include, besides the client IP address, IP addresses from headers like `X-Forwarded-For`. | keyword |  |
| apache.access.response_time | Time to serve the request in microseconds. | long | micros |
| apache.access.ssl.cipher | SSL cipher name. - name: nginx.access | keyword |  |
| apache.access.ssl.protocol | SSL protocol version. | keyword |  |
| apache.access.tls_handshake.error | TLS handshake error. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| input.type | Input type | keyword |  |
| log.offset | Log offset | long |  |


Supported format for the access logs are:

- [Common Log Format](https://en.wikipedia.org/wiki/Common_Log_Format)

  - Defined in apache `LogFormat` by :
 
    >```%h %l %u %t \"%r\" %>s %b```

  - Example:

    > `127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326`

- Combined Log Format

  - Defined in apache `LogFormat` by:

    >I. ```%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"```

    >II. ```%A:%p %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"```

    >III. ```%h:%p %l %u %t \"%{req}i %U %H\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"```

  - Example:

    >I. ```127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://datawarehouse.us.oracle.com/datamining/contents.htm" "Mozilla/4.7 [en] (WinNT; I)"```

    >II. ```127.0.0.1:80 127.0.0.1 - - [20/Jun/2024:16:23:43 +0530] "\x16\x03\x01" 400 226 "-" "-"```

    >III. ```127.0.0.1:80 - - [20/Jun/2024:16:31:41 +0530] "<SCRIPT>NXSSTEST</SCRIPT> / HTTP/1.1" 403 4897 "-" "-"```

- Combined Log Format + X-Forwarded-For header

  - Defined in apache `LogFormat` by:

    >```%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" X-Forwarded-For=\"%{X-Forwarded-For}i\"```

  - Example:

    >```127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://datawarehouse.us.oracle.com/datamining/contents.htm" "Mozilla/4.7 [en] (WinNT; I)" X-Forwarded-For="10.225.192.17, 10.2.2.121"```

### Error Logs

Error logs collects the Apache error logs.

An example event for `error` looks as following:

```json
{
    "@timestamp": "2024-07-03T11:17:00.781Z",
    "agent": {
        "ephemeral_id": "7abcc15c-0d38-4f16-843e-622a20dcfe13",
        "id": "7417c67c-5b97-401f-b722-6becf94a2f17",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "apache": {
        "error": {
            "module": "mpm_event"
        }
    },
    "data_stream": {
        "dataset": "apache.error",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7417c67c-5b97-401f-b722-6becf94a2f17",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "apache.error",
        "ingested": "2024-07-03T11:17:27Z",
        "kind": "event",
        "timezone": "+00:00",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.246.7"
        ],
        "mac": [
            "02-42-C0-A8-F6-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.118.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/error.log"
        },
        "level": "notice",
        "offset": 0
    },
    "message": "AH00489: Apache/2.4.46 (Unix) configured -- resuming normal operations",
    "process": {
        "pid": 1,
        "thread": {
            "id": 139928782480512
        }
    },
    "tags": [
        "apache-error"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache.error.module | The module producing the logged message. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


## Metrics

### Status Metrics

The server status stream collects data from the Apache Status module. It scrapes the status data from the web page
generated by the `mod_status` module.

An example event for `status` looks as following:

```json
{
    "@timestamp": "2022-12-09T03:56:04.531Z",
    "agent": {
        "ephemeral_id": "de9a4641-fef3-4e54-b95a-cd2c722fb9d3",
        "id": "46343e0c-0d8c-464b-a216-cacf63027d6f",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "apache": {
        "status": {
            "bytes_per_request": 0,
            "bytes_per_sec": 0,
            "connections": {
                "async": {
                    "closing": 0,
                    "keep_alive": 0,
                    "writing": 0
                },
                "total": 0
            },
            "cpu": {
                "children_system": 0,
                "children_user": 0,
                "load": 0.133333,
                "system": 0.01,
                "user": 0.01
            },
            "load": {
                "1": 1.79,
                "15": 1.04,
                "5": 1.5
            },
            "requests_per_sec": 0.933333,
            "scoreboard": {
                "closing_connection": 0,
                "dns_lookup": 0,
                "gracefully_finishing": 0,
                "idle_cleanup": 0,
                "keepalive": 0,
                "logging": 0,
                "open_slot": 325,
                "reading_request": 0,
                "sending_reply": 1,
                "starting_up": 0,
                "total": 400,
                "waiting_for_connection": 74
            },
            "total_accesses": 14,
            "total_bytes": 0,
            "uptime": {
                "server_uptime": 15,
                "uptime": 15
            },
            "workers": {
                "busy": 1,
                "idle": 74
            }
        }
    },
    "data_stream": {
        "dataset": "apache.status",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "46343e0c-0d8c-464b-a216-cacf63027d6f",
        "snapshot": false,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "apache.status",
        "duration": 6186792,
        "ingested": "2022-12-09T03:56:04Z",
        "module": "apache"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "66392b0697b84641af8006d87aeb89f1",
        "ip": [
            "172.18.0.7"
        ],
        "mac": [
            "02-42-AC-12-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.49-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "status",
        "period": 30000
    },
    "service": {
        "address": "http://elastic-package-service-apache-1:80/server-status?auto=",
        "type": "apache"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id |  | keyword |  |  |
| apache.status.bytes_per_request | Bytes per request. | scaled_float |  | gauge |
| apache.status.bytes_per_sec | Bytes per second. | scaled_float |  | gauge |
| apache.status.connections.async.closing | Async closed connections. | long |  | gauge |
| apache.status.connections.async.keep_alive | Async keeped alive connections. | long |  | gauge |
| apache.status.connections.async.writing | Async connection writing. | long |  | gauge |
| apache.status.connections.total | Total connections. | long |  | counter |
| apache.status.cpu.children_system | CPU of children system. | scaled_float |  | gauge |
| apache.status.cpu.children_user | CPU of children user. | scaled_float |  | gauge |
| apache.status.cpu.load | CPU Load. | scaled_float |  | gauge |
| apache.status.cpu.system | System cpu. | scaled_float |  | gauge |
| apache.status.cpu.user | CPU user load. | scaled_float |  | gauge |
| apache.status.load.1 | Load average for the last minute. | scaled_float |  | gauge |
| apache.status.load.15 | Load average for the last 15 minutes. | scaled_float |  | gauge |
| apache.status.load.5 | Load average for the last 5 minutes. | scaled_float |  | gauge |
| apache.status.requests_per_sec | Requests per second. | scaled_float |  | gauge |
| apache.status.scoreboard.closing_connection | Closing connections. | long |  | gauge |
| apache.status.scoreboard.dns_lookup | Dns Lookups. | long |  | gauge |
| apache.status.scoreboard.gracefully_finishing | Gracefully finishing. | long |  | gauge |
| apache.status.scoreboard.idle_cleanup | Idle cleanups. | long |  | gauge |
| apache.status.scoreboard.keepalive | Keep alive. | long |  | gauge |
| apache.status.scoreboard.logging | Logging | long |  | gauge |
| apache.status.scoreboard.open_slot | Open slots. | long |  | gauge |
| apache.status.scoreboard.reading_request | Reading requests. | long |  | gauge |
| apache.status.scoreboard.sending_reply | Sending Reply. | long |  | gauge |
| apache.status.scoreboard.starting_up | Starting up. | long |  | gauge |
| apache.status.scoreboard.total | Total. | long |  | gauge |
| apache.status.scoreboard.waiting_for_connection | Waiting for connections. | long |  | gauge |
| apache.status.total_accesses | Total number of access requests. | long |  | counter |
| apache.status.total_bytes | Total number of bytes served. | long | byte | counter |
| apache.status.uptime.server_uptime | Server uptime in seconds. | long |  | counter |
| apache.status.uptime.uptime | Server uptime. | long |  | counter |
| apache.status.workers.busy | Number of busy workers. | long |  | gauge |
| apache.status.workers.idle | Number of idle workers. | long |  | gauge |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |


## ML Modules

These anomaly detection jobs are available in the Machine Learning app in Kibana
when you have data that matches the query specified in the
[manifest](https://github.com/elastic/integrations/blob/main/packages/apache/kibana/ml_module/apache-Logs-ml.json#L11).

### Apache Access Logs

Find unusual activity in HTTP access logs.

| Job | Description |
|---|---|
| visitor_rate_apache | HTTP Access Logs: Detect unusual visitor rates | 
| status_code_rate_apache | HTTP Access Logs: Detect unusual status code rates |
| source_ip_url_count_apache | HTTP Access Logs: Detect unusual source IPs - high distinct count of URLs |
| source_ip_request_rate_apache | HTTP Access Logs: Detect unusual source IPs - high request rates |
| low_request_rate_apache | HTTP Access Logs: Detect low request rates |
