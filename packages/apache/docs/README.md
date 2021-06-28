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

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| apache.access.ssl.cipher | SSL cipher name. | keyword |  |  |
| apache.access.ssl.protocol | SSL protocol version. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| destination.domain | Destination domain | keyword |  |  |
| ecs.version | ECS version | keyword |  |  |
| error.message | Error message. | text |  |  |
| event.category | Event category. This contains high-level information about the contents of the event. It is more generic than `event.action`, in the sense that typically a category contains multiple actions. Warning: In future versions of ECS, we plan to provide a list of acceptable values for this field, please use with caution. | keyword |  |  |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |  |  |
| event.kind | The kind of the event. This gives information about what type of information the event contains, without being specific to the contents of the event.  Examples are `event`, `state`, `alarm`. Warning: In future versions of ECS, we plan to provide a list of acceptable values for this field, please use with caution. | keyword |  |  |
| event.outcome | The outcome of the event. If the event describes an action, this fields contains the outcome of that action. Examples outcomes are `success` and `failure`. Warning: In future versions of ECS, we plan to provide a list of acceptable values for this field, please use with caution. | keyword |  |  |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |  |  |
| http.request.referrer | Referrer for this HTTP request. | keyword |  |  |
| http.response.body.bytes | Size in bytes of the response body. | long | byte | gauge |
| http.response.status_code | HTTP response status code. | long |  |  |
| http.version | HTTP version. | keyword |  |  |
| input.type | Input type | keyword |  |  |
| log.file.path | Log path | keyword |  |  |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |  |  |
| log.offset | Log offset | long |  |  |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |  |  |
| process.pid | Process id. | long |  |  |
| process.thread.id | Thread ID. | long |  |  |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |  |  |
| source.as.number | Unique number allocated to the autonomous system. | long |  |  |
| source.as.organization.name | Organization name. | keyword |  |  |
| source.domain | Source domain | keyword |  |  |
| source.geo.city_name | City name. | keyword |  |  |
| source.geo.continent_name | Name of the continent. | keyword |  |  |
| source.geo.country_iso_code | Country ISO code. | keyword |  |  |
| source.geo.country_name | Country name. | keyword |  |  |
| source.geo.location | Longitude and latitude. | geo_point |  |  |
| source.geo.region_iso_code | Region ISO code. | keyword |  |  |
| source.geo.region_name | Region name. | keyword |  |  |
| source.ip | IP address of the source | ip |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |  |  |
| tls.version | Numeric part of the version parsed from the original string. | keyword |  |  |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |  |  |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |  |  |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |  |  |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | keyword |  |  |
| url.path | Path of the request, such as "/search". | keyword |  |  |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |  |  |
| user.name | Short name or login of the user. | keyword |  |  |
| user_agent.device.name | Name of the device. | keyword |  |  |
| user_agent.name | Name of the user agent. | keyword |  |  |
| user_agent.original | Unparsed user_agent string. | keyword |  |  |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |  |  |
| user_agent.os.name | Operating system name, without the version | keyword |  |  |
| user_agent.os.version | Operating system version as a raw string | keyword |  |  |
| user_agent.version | Version of the user agent | keyword |  |  |


### Error Logs

Error logs collects the Apache error logs.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| apache.error.module | The module producing the logged message. | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version | keyword |  |  |
| error.message | Error message. | text |  |  |
| event.category | Event category. This contains high-level information about the contents of the event. It is more generic than `event.action`, in the sense that typically a category contains multiple actions. Warning: In future versions of ECS, we plan to provide a list of acceptable values for this field, please use with caution. | keyword |  |  |
| event.kind | The kind of the event. This gives information about what type of information the event contains, without being specific to the contents of the event.  Examples are `event`, `state`, `alarm`. Warning: In future versions of ECS, we plan to provide a list of acceptable values for this field, please use with caution. | keyword |  |  |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |  |  |
| event.type | Reserved for future usage. Please avoid using this field for user data. | keyword |  |  |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |  |  |
| http.request.referrer | Referrer for this HTTP request. | keyword |  |  |
| http.response.body.bytes | Size in bytes of the response body. | long | byte | gauge |
| http.response.status_code | HTTP response status code. | long |  |  |
| http.version | HTTP version. | keyword |  |  |
| input.type | Input type | keyword |  |  |
| log.file.path | Log path | keyword |  |  |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |  |  |
| log.offset | Log offset | long |  |  |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |  |  |
| process.pid | Process id. | long |  |  |
| process.thread.id | Thread ID. | long |  |  |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |  |  |
| source.as.number | Unique number allocated to the autonomous system. | long |  |  |
| source.as.organization.name | Organization name. | keyword |  |  |
| source.geo.city_name | City name. | keyword |  |  |
| source.geo.continent_name | Name of the continent. | keyword |  |  |
| source.geo.country_iso_code | Country ISO code. | keyword |  |  |
| source.geo.country_name | Country name. | keyword |  |  |
| source.geo.location | Longitude and latitude. | geo_point |  |  |
| source.geo.region_iso_code | Region ISO code. | keyword |  |  |
| source.geo.region_name | Region name. | keyword |  |  |
| source.ip | Source IP address. | ip |  |  |
| source.port | Source port. | long |  |  |
| tags | List of keywords used to tag each event. | keyword |  |  |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |  |  |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |  |  |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | keyword |  |  |
| url.path | Path of the request, such as "/search". | keyword |  |  |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |  |  |
| user.name | Short name or login of the user. | keyword |  |  |
| user_agent.device.name | Name of the device. | keyword |  |  |
| user_agent.name | Name of the user agent. | keyword |  |  |
| user_agent.original | Unparsed user_agent string. | keyword |  |  |
| user_agent.os.name | Operating system name, without the version. | keyword |  |  |


## Metrics

### Status Metrics

The server status stream collects data from the Apache Status module. It scrapes the status data from the web page
generated by the `mod_status` module.

An example event for `status` looks as following:

```json
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

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
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
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| ecs.version | ECS version | keyword |  |  |
| error.message | Error message. | text |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| service.address | Service address | keyword |  |  |
| service.type | Service type | keyword |  |  |

