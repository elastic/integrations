# Nginx Ingress Controller Integration

This integration periodically fetches logs from [Nginx Ingress Controller](https://github.com/kubernetes/ingress-nginx)
instances. It can parse access and error logs created by the ingress.

## Compatibility

The integration was tested with the Nginx Ingress Controller v0.30.0 and v0.40.2. The log format is described
[here](https://github.com/kubernetes/ingress-nginx/blob/nginx-0.30.0/docs/user-guide/nginx-configuration/log-format.md).

## Logs

### Access Logs

The `access` data stream collects the Nginx Ingress Controller access logs.

An example event for `access` looks as following:

```json
{
    "nginx_ingress_controller": {
        "access": {
            "http": {
                "request": {
                    "length": 89,
                    "time": 0.001,
                    "id": "529a007902362a5f51385a5fa7049884"
                }
            },
            "remote_ip_list": [
                "192.168.64.1"
            ],
            "upstream": {
                "name": "default-web-8080",
                "alternative_name": "",
                "port": "8080",
                "response": {
                    "length": 59,
                    "status_code": 200,
                    "time": 0.0
                },
                "ip": "172.17.0.5"
            }
        }
    },
    "@timestamp": "2020-02-07T11:48:51.000Z",
    "related": {
        "ip": [
            "192.168.64.1"
        ]
    },
    "http": {
        "request": {
            "method": "post"
        },
        "version": "1.1",
        "response": {
            "body": {
                "bytes": 59
            },
            "status_code": 200
        }
    },
    "source": {
        "address": "192.168.64.1",
        "ip": "192.168.64.1"
    },
    "event": {
        "category": [
            "web"
        ],
        "type": [
            "info"
        ],
        "created": "2020-04-28T11:07:58.223Z",
        "kind": "event",
        "outcome": "success"
    },
    "user_agent": {
        "name": "curl",
        "original": "curl/7.54.0",
        "device": {
            "name": "Other"
        },
        "version": "7.54.0"
    },
    "url": {
        "original": "/products"
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| nginx_ingress_controller.access.http.request.id | The randomly generated ID of the request | text |
| nginx_ingress_controller.access.http.request.length | The request length (including request line, header, and request body) | long |
| nginx_ingress_controller.access.http.request.time | Time elapsed since the first bytes were read from the client | double |
| nginx_ingress_controller.access.remote_ip_list | An array of remote IP addresses. It is a list because it is common to include, besides the client IP address, IP addresses from headers like `X-Forwarded-For`. Real source IP is restored to `source.ip`. | array |
| nginx_ingress_controller.access.upstream.alternative_name | The name of the alternative upstream. | text |
| nginx_ingress_controller.access.upstream.ip | The IP address of the upstream server. If several servers were contacted during request processing, their addresses are separated by commas. | ip |
| nginx_ingress_controller.access.upstream.name | The name of the upstream. | text |
| nginx_ingress_controller.access.upstream.port | The port of the upstream server. | keyword |
| nginx_ingress_controller.access.upstream.response.length | The length of the response obtained from the upstream server | long |
| nginx_ingress_controller.access.upstream.response.status_code | The status code of the response obtained from the upstream server | long |
| nginx_ingress_controller.access.upstream.response.time | The time spent on receiving the response from the upstream server as seconds with millisecond resolution | double |
| related.ip | All of the IPs seen on your event. | ip |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### Error Logs

The `error` data stream collects the Nginx Ingress Controller error logs.

An example event for `error` looks as following:

```json
{
    "agent": {
        "hostname": "953e412c8e77",
        "name": "953e412c8e77",
        "id": "134c7c6b-ea22-42a8-b11f-252178bc893e",
        "type": "filebeat",
        "ephemeral_id": "6bbc060f-2aaf-4112-8f75-cd3e984677d1",
        "version": "7.11.0"
    },
    "nginx_ingress_controller": {
        "error": {
            "thread_id": 7,
            "source": {
                "file": "client_config.go",
                "line_number": 608
            }
        }
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/error.log"
        },
        "offset": 361,
        "level": "W"
    },
    "elastic_agent": {
        "id": "f16cd630-3fbe-11eb-b685-fb7c02bf7a78",
        "version": "7.11.0",
        "snapshot": true
    },
    "message": "Neither --kubeconfig nor --master was specified.  Using the inClusterConfig.  This might not work.",
    "input": {
        "type": "log"
    },
    "@timestamp": "2020-12-16T16:53:33.833531Z",
    "ecs": {
        "version": "1.6.0"
    },
    "data_stream": {
        "namespace": "ep",
        "type": "logs",
        "dataset": "nginx_ingress_controller.error"
    },
    "host": {
        "hostname": "953e412c8e77",
        "os": {
            "kernel": "4.9.184-linuxkit",
            "codename": "Core",
            "name": "CentOS Linux",
            "family": "redhat",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.28.0.6"
        ],
        "name": "953e412c8e77",
        "id": "8f83e81de7426941b2a8cab44942c76a",
        "mac": [
            "02:42:ac:1c:00:06"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "ingested": "2020-12-16T16:53:57.900401700Z",
        "timezone": "+00:00",
        "created": "2020-12-16T16:53:56.860Z",
        "kind": "event",
        "category": [
            "web"
        ],
        "type": [
            "info"
        ],
        "dataset": "nginx_ingress_controller.error"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| nginx_ingress_controller.error.source.file | Source file | keyword |
| nginx_ingress_controller.error.source.line_number | Source line number | long |
| nginx_ingress_controller.error.thread_id | Thread ID | long |
| tags | List of keywords used to tag each event. | keyword |
