# Nginx Integration

The Nginx integration allows you to monitor [Nginx](https://nginx.org/) servers. Time series [index mode](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds.html) enabled for metrics data stream.

Use the Nginx integration to collect metrics and logs from your server.
Then visualize that data in Kibana, use the Machine Learning app to find unusual activity in HTTP access logs,
create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

For example, if you wanted to be notified if a certain number of client requests failed in a given time period,
you could install the Nginx integration to send logs to Elastic.
Then, you could view the logs stream into Elastic in real time in the Observability Logs app.
You could also set up a new log threshold rule in the Logs app to alert you when there are more than
a certain number of events with a failing status in a given time period.

## Data streams

The Nginx integration collects two types of data: logs and metrics.

**Logs** help you keep a record of events that happen in your Nginx servers.
This includes when a client request or error occurs.

**Metrics** give you insight into the state of your Nginx servers.
This includes information like the total number of active client connections by status,
the total number of client requests, and more.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Each data source was tested with a specific Nginx version.
For more information see the [Logs reference](#logs-reference) and [Metrics reference](#metrics-reference).

Note: On Windows, the module was tested with Nginx installed from the Chocolatey repository.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

**Timezone support**

This data source parses logs that don’t contain timezone information. For these logs, the Elastic Agent reads the local
timezone and uses it when parsing to convert the timestamp to UTC. The timezone to be used for parsing is included
in the event in the `event.timezone` field.

To disable this conversion, the `event.timezone` field can be removed using the `drop_fields` processor.

If logs originate from systems or applications with a timezone that is different than the local one,
the `event.timezone` field can be overwritten with the original timezone using the `add_fields` processor.

### Access Logs

Access logs collects the Nginx access logs.

#### Tested versions

The Nginx access logs stream was tested with Nginx 1.19.5.

An example event for `access` looks as following:

```json
{
    "@timestamp": "2022-12-09T10:39:23.000Z",
    "_tmp": {},
    "agent": {
        "ephemeral_id": "34369a4a-4f24-4a39-9758-85fc2429d7e2",
        "id": "ef5e274d-4b53-45e6-943a-a5bcf1a6f523",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "nginx.access",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ef5e274d-4b53-45e6-943a-a5bcf1a6f523",
        "snapshot": false,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "created": "2022-12-09T10:39:38.896Z",
        "dataset": "nginx.access",
        "ingested": "2022-12-09T10:39:40Z",
        "kind": "event",
        "outcome": "success",
        "timezone": "+00:00",
        "type": [
            "access"
        ]
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
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "body": {
                "bytes": 97
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
    "nginx": {
        "access": {
            "remote_ip_list": [
                "127.0.0.1"
            ]
        }
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
        "nginx-access"
    ],
    "url": {
        "original": "/server-status",
        "path": "/server-status"
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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| nginx.access.remote_ip_list | An array of remote IP addresses. It is a list because it is common to include, besides the client IP address, IP addresses from headers like `X-Forwarded-For`. Real source IP is restored to `source.ip`. | keyword |


### Error Logs

Error logs collects the Nginx error logs.

#### Tested versions

The Nginx error logs stream was tested with Nginx 1.19.5.

An example event for `error` looks as following:

```json
{
    "@timestamp": "2022-12-09T10:40:03.000Z",
    "agent": {
        "ephemeral_id": "34369a4a-4f24-4a39-9758-85fc2429d7e2",
        "id": "ef5e274d-4b53-45e6-943a-a5bcf1a6f523",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.0"
    },
    "data_stream": {
        "dataset": "nginx.error",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ef5e274d-4b53-45e6-943a-a5bcf1a6f523",
        "snapshot": false,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "created": "2022-12-09T10:40:18.973Z",
        "dataset": "nginx.error",
        "ingested": "2022-12-09T10:40:24Z",
        "kind": "event",
        "timezone": "+00:00",
        "type": [
            "error"
        ]
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
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/error.log"
        },
        "level": "warn",
        "offset": 0
    },
    "message": "conflicting server name \"localhost\" on 0.0.0.0:80, ignored",
    "nginx": {
        "error": {}
    },
    "process": {
        "pid": 1,
        "thread": {
            "id": 1
        }
    },
    "tags": [
        "nginx-error"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| nginx.error.connection_id | Connection identifier. | long |


## Metrics reference

### Stub Status Metrics

The Nginx `stubstatus` stream collects data from the Nginx `ngx_http_stub_status` module. It scrapes the server status
data from the web page generated by `ngx_http_stub_status`. Please verify that your Nginx distribution comes with the mentioned
module and it's enabled in the Nginx configuration file:

```
location /nginx_status {
    stub_status;
    allow 127.0.0.1; # only allow requests from localhost
    deny all;        # deny all other hosts
}
```

Replace `127.0.0.1` with your server’s IP address and make sure that this page accessible to only you.

#### Tested versions

The Nginx `stubstatus` stream was tested with Nginx 1.19.5 and is expected to work with all versions >= 1.19.

An example event for `stubstatus` looks as following:

```json
{
    "@timestamp": "2024-02-08T08:12:10.668Z",
    "agent": {
        "ephemeral_id": "c3d516ba-b659-4190-a29d-d28200d74d48",
        "id": "2ea50bee-9250-43d1-8d70-949f242aa275",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "nginx.stubstatus",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2ea50bee-9250-43d1-8d70-949f242aa275",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "nginx.stubstatus",
        "duration": 1156104,
        "ingested": "2024-02-08T08:12:13Z",
        "module": "nginx"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "28da52b32df94b50aff67dfb8f1be3d6",
        "ip": [
            "172.24.0.7"
        ],
        "mac": "02-42-AC-18-00-07",
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.15.0-89-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "stubstatus",
        "period": 10000
    },
    "nginx": {
        "stubstatus": {
            "accepts": 33,
            "active": 1,
            "current": 33,
            "dropped": 0,
            "handled": 33,
            "hostname": "elastic-package-service-nginx-1:80",
            "reading": 0,
            "requests": 33,
            "waiting": 0,
            "writing": 1
        }
    },
    "service": {
        "address": "http://elastic-package-service-nginx-1:80/server-status",
        "type": "nginx"
    },
    "tags": [
        "nginx-stubstatus"
    ]
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id |  | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment.  Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| nginx.stubstatus.accepts | The total number of accepted client connections. | long | counter |
| nginx.stubstatus.active | The current number of active client connections including Waiting connections. | long | gauge |
| nginx.stubstatus.current | The current number of client requests. | long | gauge |
| nginx.stubstatus.dropped | The total number of dropped client connections. | long | counter |
| nginx.stubstatus.handled | The total number of handled client connections. | long | counter |
| nginx.stubstatus.hostname | Nginx hostname. | keyword |  |
| nginx.stubstatus.reading | The current number of connections where Nginx is reading the request header. | long | gauge |
| nginx.stubstatus.requests | The total number of client requests. | long | counter |
| nginx.stubstatus.waiting | The current number of idle client connections waiting for a request. | long | gauge |
| nginx.stubstatus.writing | The current number of connections where Nginx is writing the response back to the client. | long | gauge |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


## ML Modules

These anomaly detection jobs are available in the Machine Learning app in Kibana
when you have data that matches the query specified in the
[manifest](https://github.com/elastic/integrations/blob/main/packages/nginx/kibana/ml_module/nginx-Logs-ml.json).

### Nginx access logs

Find unusual activity in HTTP access logs.

| Job | Description |
|---|---|
| `visitor_rate_nginx` | HTTP Access Logs: Detect unusual visitor rates |
| `status_code_rate_nginx` | HTTP Access Logs: Detect unusual status code rates |
| `source_ip_url_count_nginx` | HTTP Access Logs: Detect unusual source IPs - high distinct count of URLs |
| `source_ip_request_rate_nginx` | HTTP Access Logs: Detect unusual source IPs - high request rates |
| `low_request_rate_nginx` | HTTP Access Logs: Detect low request rates |

