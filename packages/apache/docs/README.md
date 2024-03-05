# Apache Integration

This integration periodically fetches metrics from [Apache](https://httpd.apache.org/) servers. It can parse access and error
logs created by the Apache server.

## Compatibility

The Apache datasets were tested with Apache 2.4.12 and 2.4.46 and are expected to work with
all versions >= 2.2.31 and >= 2.4.16 (independent from operating system).

## Logs

### Access Logs

Access logs collects the Apache access logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache.access.ssl.cipher | SSL cipher name. | keyword |
| apache.access.ssl.protocol | SSL protocol version. | keyword |
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
| destination.domain | Destination domain | keyword |
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
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.file.path | Log path | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.domain | Source domain | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source | ip |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string | keyword |
| user_agent.version | Version of the user agent | keyword |


### Error Logs

Error logs collects the Apache error logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache.error.module | The module producing the logged message. | keyword |
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
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.file.path | Log path | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | Source IP address. | keyword |
| source.port | Source port. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |


## Metrics

### Status Metrics

The server status stream collects data from the Apache Status module. It scrapes the status data from the web page
generated by the `mod_status` module.

An example event for `status` looks as following:

```$json
{
    "@timestamp": "2020-12-03T16:31:04.445Z",
    "data_stream": {
        "type": "metrics",
        "dataset": "apache.status",
        "namespace": "ep"
    },
    "elastic_agent": {
        "version": "7.11.0",
        "id": "6c69e2bc-7bb3-4bac-b7e9-41f22558321c",
        "snapshot": true
    },
    "host": {
        "os": {
            "platform": "centos",
            "version": "7 (Core)",
            "family": "redhat",
            "name": "CentOS Linux",
            "kernel": "4.9.184-linuxkit",
            "codename": "Core"
        },
        "id": "06c26569966fd125c15acac5d7feffb6",
        "name": "4942ef7a8cfc",
        "containerized": true,
        "ip": [
            "192.168.0.4"
        ],
        "mac": [
            "02:42:c0:a8:00:04"
        ],
        "hostname": "4942ef7a8cfc",
        "architecture": "x86_64"
    },
    "agent": {
        "hostname": "4942ef7a8cfc",
        "ephemeral_id": "8371d3a3-5321-4436-9fd5-cafcabfe4c57",
        "id": "af6f66ef-d7d0-4784-b9bb-3fddbcc151b5",
        "name": "4942ef7a8cfc",
        "type": "metricbeat",
        "version": "7.11.0"
    },
    "metricset": {
        "name": "status",
        "period": 30000
    },
    "service": {
        "address": "http://elastic-package-service_apache_1:80/server-status?auto=",
        "type": "apache"
    },
    "apache": {
        "status": {
            "load": {
                "5": 1.89,
                "15": 1.07,
                "1": 1.53
            },
            "total_accesses": 11,
            "connections": {
                "total": 0,
                "async": {
                    "closing": 0,
                    "writing": 0,
                    "keep_alive": 0
                }
            },
            "requests_per_sec": 0.916667,
            "scoreboard": {
                "starting_up": 0,
                "keepalive": 0,
                "sending_reply": 1,
                "logging": 0,
                "gracefully_finishing": 0,
                "dns_lookup": 0,
                "closing_connection": 0,
                "open_slot": 325,
                "total": 400,
                "idle_cleanup": 0,
                "waiting_for_connection": 74,
                "reading_request": 0
            },
            "bytes_per_sec": 0,
            "bytes_per_request": 0,
            "uptime": {
                "server_uptime": 12,
                "uptime": 12
            },
            "total_bytes": 0,
            "workers": {
                "busy": 1,
                "idle": 74
            },
            "cpu": {
                "load": 0.583333,
                "user": 0.03,
                "system": 0.04,
                "children_user": 0,
                "children_system": 0
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| apache.status.bytes_per_request | Bytes per request. | scaled_float |
| apache.status.bytes_per_sec | Bytes per second. | scaled_float |
| apache.status.connections.async.closing | Async closed connections. | long |
| apache.status.connections.async.keep_alive | Async keeped alive connections. | long |
| apache.status.connections.async.writing | Async connection writing. | long |
| apache.status.connections.total | Total connections. | long |
| apache.status.cpu.children_system | CPU of children system. | scaled_float |
| apache.status.cpu.children_user | CPU of children user. | scaled_float |
| apache.status.cpu.load | CPU Load. | scaled_float |
| apache.status.cpu.system | System cpu. | scaled_float |
| apache.status.cpu.user | CPU user load. | scaled_float |
| apache.status.load.1 | Load average for the last minute. | scaled_float |
| apache.status.load.15 | Load average for the last 15 minutes. | scaled_float |
| apache.status.load.5 | Load average for the last 5 minutes. | scaled_float |
| apache.status.requests_per_sec | Requests per second. | scaled_float |
| apache.status.scoreboard.closing_connection | Closing connections. | long |
| apache.status.scoreboard.dns_lookup | Dns Lookups. | long |
| apache.status.scoreboard.gracefully_finishing | Gracefully finishing. | long |
| apache.status.scoreboard.idle_cleanup | Idle cleanups. | long |
| apache.status.scoreboard.keepalive | Keep alive. | long |
| apache.status.scoreboard.logging | Logging | long |
| apache.status.scoreboard.open_slot | Open slots. | long |
| apache.status.scoreboard.reading_request | Reading requests. | long |
| apache.status.scoreboard.sending_reply | Sending Reply. | long |
| apache.status.scoreboard.starting_up | Starting up. | long |
| apache.status.scoreboard.total | Total. | long |
| apache.status.scoreboard.waiting_for_connection | Waiting for connections. | long |
| apache.status.total_accesses | Total number of access requests. | long |
| apache.status.total_bytes | Total number of bytes served. | long |
| apache.status.uptime.server_uptime | Server uptime in seconds. | long |
| apache.status.uptime.uptime | Server uptime. | long |
| apache.status.workers.busy | Number of busy workers. | long |
| apache.status.workers.idle | Number of idle workers. | long |
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
| service.address | Service address | keyword |
| service.type | Service type | keyword |

