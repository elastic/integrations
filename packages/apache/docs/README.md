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

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| apache.access.identity | The client's identity, as specified in RFC 1413, determined by the identd on the client's machine. | keyword |  |
| apache.access.remote_addresses | An array of remote addresses. It is a list because it is common to include, besides the client IP address, IP addresses from headers like `X-Forwarded-For`. | keyword |  |
| apache.access.response_time | Time to serve the request in microseconds. | long | micros |
| apache.access.ssl.cipher | SSL cipher name. - name: nginx.access | keyword |  |
| apache.access.ssl.protocol | SSL protocol version. | keyword |  |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |  |
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
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |  |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |  |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |  |
| destination.port | Port of the destination. | long |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |
| error.message | Error message. | match_only_text |  |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |  |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |  |
| event.dataset | Event dataset | constant_keyword |  |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |  |
| event.module | Event module | constant_keyword |  |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |  |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |  |
| file.path.text | Multi-field of `file.path`. | match_only_text |  |
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
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |  |
| http.request.referrer | Referrer for this HTTP request. | keyword |  |
| http.response.body.bytes | Size in bytes of the response body. | long |  |
| http.response.status_code | HTTP response status code. | long |  |
| http.version | HTTP version. | keyword |  |
| input.type | Input type | keyword |  |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |  |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |  |
| log.offset | Log offset | long |  |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |  |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |  |
| process.pid | Process id. | long |  |
| process.thread.id | Thread ID. | long |  |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |  |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |  |
| source.as.organization.name | Organization name. | keyword |  |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |  |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |  |
| source.geo.city_name | City name. | keyword |  |
| source.geo.continent_name | Name of the continent. | keyword |  |
| source.geo.country_iso_code | Country ISO code. | keyword |  |
| source.geo.country_name | Country name. | keyword |  |
| source.geo.location | Longitude and latitude. | geo_point |  |
| source.geo.region_iso_code | Region ISO code. | keyword |  |
| source.geo.region_name | Region name. | keyword |  |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |  |
| source.port | Port of the source. | long |  |
| tags | List of keywords used to tag each event. | keyword |  |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |  |
| tls.version | Numeric part of the version parsed from the original string. | keyword |  |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |  |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |  |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |  |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |  |
| url.original.text | Multi-field of `url.original`. | match_only_text |  |
| url.path | Path of the request, such as "/search". | wildcard |  |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |  |
| user.name | Short name or login of the user. | keyword |  |
| user.name.text | Multi-field of `user.name`. | match_only_text |  |
| user_agent.device.name | Name of the device. | keyword |  |
| user_agent.name | Name of the user agent. | keyword |  |
| user_agent.original | Unparsed user_agent string. | keyword |  |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |  |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |  |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |  |
| user_agent.os.name | Operating system name, without the version. | keyword |  |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |  |
| user_agent.os.version | Operating system version as a raw string. | keyword |  |
| user_agent.version | Version of the user agent. | keyword |  |


Supported format for the access logs are:

- [Common Log Format](https://en.wikipedia.org/wiki/Common_Log_Format)
  - Defined in apache `LogFormat` by : 
    >```%h %l %u %t \"%r\" %>s %b```
  - Example:
    > `127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326`
- Combined Log Format
  - Defined in apache `LogFormat` by:
    >```%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"```
  - Example:
    >```127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://datawarehouse.us.oracle.com/datamining/contents.htm" "Mozilla/4.7 [en] (WinNT; I)"```
- Combined Log Format + X-Forwarded-For header
  - Defined in apache `LogFormat` by:
    >```%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" X-Forwarded-For=\"%{X-Forwarded-For}i\"```
  - Example:
    >```127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://datawarehouse.us.oracle.com/datamining/contents.htm" "Mozilla/4.7 [en] (WinNT; I)" X-Forwarded-For="10.225.192.17, 10.2.2.121"```
- Combined Log Format + X-Forwarded-For header + Response time
  - Defined in apache `LogFormat` by:
    >```%h %l %u %t \"%r\" %>s %b %D \"%{Referer}i\" \"%{User-Agent}i\" X-Forwarded-For=\"%{X-Forwarded-For}i\"```
  - Example:
    >```127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 3413 "http://datawarehouse.us.oracle.com/datamining/contents.htm" "Mozilla/4.7 [en] (WinNT; I)" X-Forwarded-For="10.225.192.17, 10.2.2.121"```

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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
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
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
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
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |


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
        "version": "8.0.0"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| error.message | Error message. | match_only_text |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |


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
