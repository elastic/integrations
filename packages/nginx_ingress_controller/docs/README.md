# Nginx Ingress Controller Integration

This integration periodically fetches logs from [Nginx Ingress Controller](https://github.com/kubernetes/ingress-nginx)
instances. It can parse access and error logs created by the ingress.

## Compatibility

The integration was tested with the Nginx Ingress Controller in versions v0.30.0 and v0.40.2. The log format is described
[here](https://github.com/kubernetes/ingress-nginx/blob/nginx-0.30.0/docs/user-guide/nginx-configuration/log-format.md).

## Logs

### Access Logs

The `access` data stream collects the Nginx Ingress Controller access logs.

An example event for `access` looks as following:

```$json
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
| ecs.version | ECS version | keyword |
| event.created | Date/time when the event was first read by an agent, or by your pipeline. | date |
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
| http.request.method | HTTP request method. The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.file.path | Log path | keyword |
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
| source.address | IP address, domain or unix socket. | keyword |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
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

```$json
{}
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
| ecs.version | ECS version | keyword |
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
| log.file.path | Log path | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
