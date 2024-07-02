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
        "version": "8.5.1"
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
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | Date/time when the event was first read by an agent, or by your pipeline. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
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
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| nginx.access.remote_ip_list | An array of remote IP addresses. It is a list because it is common to include, besides the client IP address, IP addresses from headers like `X-Forwarded-For`. Real source IP is restored to `source.ip`. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


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
        "version": "8.5.1"
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
| event.created | Date/time when the event was first read by an agent, or by your pipeline. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
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
| nginx.error.connection_id | Connection identifier. | long |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| tags | List of keywords used to tag each event. | keyword |


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
        "version": "8.0.0"
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
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host is running. | keyword |  |
| container.id | Unique container id. | keyword |  |
| container.image.name | Name of the image the container was built on. | keyword |  |
| container.labels | Image labels. | object |  |
| container.name | Container name. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.module | Event module | constant_keyword |  |
| host.architecture | Operating system architecture. | keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |
| host.ip | Host ip addresses. | ip |  |
| host.mac | Host mac addresses. | keyword |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |
| host.os.name | Operating system name, without the version. | keyword |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |
| host.os.version | Operating system version as a raw string. | keyword |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |
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
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |
| tags | List of keywords used to tag each event. | keyword |  |


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

## SLOs

SLOs are usually defined in terms of metrics such as availability, response time, and throughput, and they are used to ensure that the service meets the needs of its users.
You can use the Nginx integration to measure the availability of the Nginx service. The SLOs gets created automatically during the installation of the integration. The user can view the created SLOs in the Observability -> SLOs page.
>Note: To create and manage SLOs you need an appropriate [license](https://www.elastic.co/subscriptions).

| Events      | Query                             |
|-------------|-----------------------------------|
| Good Query  | `http.response.status_code < 500` |
| Total Query | `http.response.status_code : *`   |