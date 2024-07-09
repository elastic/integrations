# IIS (Internet Information Services) integration

The IIS (Internet Information Services) integration allows you to monitor your IIS Web servers.
IIS is a secure, reliable, and scalable Web server that provides an easy to manage platform for developing and hosting Web applications and services.

Use the IIS integration to collect data. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics and logs when troubleshooting an issue.

For example, you could:

* Use IIS System/Process counters like the overall server and CPU usage for the IIS Worker Process and memory to understand how much memory is currently being used and how much is available.
* Use IIS performance counters like _Web Service: Bytes Received/Sec_ and _Web Service: Bytes Sent/Sec_ to track to identify potential spikes in traffic.
* Use IIS Web Service Cache counters to monitor user mode cache and output cache.

## Data streams

The IIS integration collects two types of data streams: logs and metrics.

**Logs** help you keep a record of events happening on your IIS Web servers.
Log data streams collected by the IIS integration include `access` and `error`.
Find more details in [Logs](#logs-reference).

**Metrics** give you insight into the state of your IIS Web servers.
Metric data streams collected by the IIS integration include `webserver`, `website`, and `application_pool`.
Find more details in [Metrics](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

For more information on configuring IIS logging, refer to the [Microsoft documentation](https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis).

## Logs

### Compatibility

The IIS module has been tested with logs from version 7.5, 8 and version 10.

### access

This data stream will collect and parse access IIS logs. The supported log format is W3C. The W3C log format is customizable with different fields.

The IIS ships logs with few fields by default and if the user is interested in customizing the selection, the IIS Manager provides ability to add new fields for logging.

IIS integration automatically ships certain field combinations into Elasticsearch using ingest pipelines.
Please ensure that the IIS log format configuration matches one of the formats below:

#### Default Logging

    - Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken

#### Custom Logging

    - Fields: date time s-sitename cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(cookie) cs(Referer) cs-host sc-status sc-substatus sc-win32-status time-taken

    - Fields: date time s-sitename s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs-version cs(User-Agent) cs(cookie) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes, cs-bytes time-taken

    - Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs-version cs(User-Agent) cs(cookie) cs(Referer) cs-host sc-status sc-substatus sc-win32-status sc-bytes, cs-bytes time-taken

    - Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken

    - Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status sc-bytes, cs-bytes time-taken

    - Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(cookie) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes, cs-bytes time-taken

    - Fields: date time s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status sc-bytes, cs-bytes time-taken

`X-Forwarded-For` is an optional field which can be added with the above log formats.

>Note: If the provided log format doesn't match with any of the above formats, then create a custom ingest pipeline processor in Kibana to process the logs.

An example event for `access` looks as following:

```json
{
    "@timestamp": "2018-11-19T15:24:54.000Z",
    "agent": {
        "ephemeral_id": "3f65b650-b6a3-4694-83b3-0c324a60809d",
        "id": "db17f9fb-5bcb-4116-a009-79a1bb7d4820",
        "name": "DESKTOP-RFOOE09",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "destination": {
        "address": "127.0.0.1",
        "ip": "127.0.0.1",
        "port": 80
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "web",
            "network"
        ],
        "created": "2020-07-08T11:40:14.112Z",
        "duration": 725000000,
        "kind": "event",
        "outcome": "failure",
        "type": [
            "connection"
        ]
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 401
        }
    },
    "iis": {
        "access": {
            "sub_status": 3,
            "win32_status": 5
        }
    },
    "related": {
        "ip": [
            "127.0.0.1",
            "127.0.0.1"
        ]
    },
    "source": {
        "address": "127.0.0.1",
        "ip": "127.0.0.1"
    },
    "temp": {},
    "url": {
        "path": "/"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36",
        "os": {
            "full": "Windows 10",
            "name": "Windows",
            "version": "10"
        },
        "version": "70.0.3538.102"
    }
}
```

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| iis.access.cookie | The content of the cookie sent or received, if any. | keyword |
| iis.access.server_name | The name of the server on which the log file entry was generated. | keyword |
| iis.access.site_name | The site name and instance number. | keyword |
| iis.access.sub_status | The HTTP substatus code. | long |
| iis.access.win32_status | The Windows status code. | long |


### error

This data stream will collect and parse error IIS logs.

An example event for `error` looks as following:

```json
{
    "@timestamp": "2020-06-30T13:56:46.000Z",
    "agent": {
        "ephemeral_id": "3f65b650-b6a3-4694-83b3-0c324a60809d",
        "id": "db17f9fb-5bcb-4116-a009-79a1bb7d4820",
        "name": "DESKTOP-RFOOE09",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "destination": {
        "address": "::1%0",
        "ip": "::1",
        "port": 80
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "web",
            "network"
        ],
        "created": "2020-07-08T11:40:13.768Z",
        "kind": "event",
        "type": [
            "connection"
        ]
    },
    "iis": {
        "error": {
            "reason_phrase": "Timer_ConnectionIdle"
        }
    },
    "related": {
        "ip": [
            "::1",
            "::1"
        ]
    },
    "source": {
        "address": "::1%0",
        "ip": "::1",
        "port": 59827
    }
}
```

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| iis.error.queue_name | The IIS application pool name. | keyword |
| iis.error.reason_phrase | The HTTP reason phrase. | keyword |



## Metrics

### webserver

The `webserver` data stream allows users to retrieve aggregated metrics for the entire web server.

An example event for `webserver` looks as following:

```json
{
    "@timestamp": "2020-07-08T11:42:12.102Z",
    "agent": {
        "ephemeral_id": "8ade3582-e6ab-4664-ba27-52b3d46953e3",
        "id": "3b73ebb6-c6ea-4354-b1f3-240ac1aa072c",
        "name": "DESKTOP-RFOOE09",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "iis.webserver",
        "duration": 1205854900,
        "module": "iis"
    },
    "iis": {
        "webserver": {
            "asp_net": {
                "application_restarts": 0,
                "request_wait_time": 0
            },
            "asp_net_application": {
                "pipeline_instance_count": 2,
                "requests_executing": 0,
                "requests_in_application_queue": 0
            },
            "cache": {
                "current_file_cache_memory_usage": 696,
                "current_files_cached": 2,
                "current_uris_cached": 1,
                "file_cache_hits": 18,
                "file_cache_misses": 70,
                "maximum_file_cache_memory_usage": 99453,
                "output_cache_current_items": 0,
                "output_cache_current_memory_usage": 0,
                "output_cache_total_hits": 0,
                "output_cache_total_misses": 76,
                "total_files_cached": 15,
                "total_uris_cached": 10,
                "uri_cache_hits": 14,
                "uri_cache_misses": 62
            },
            "network": {
                "anonymous_users_per_sec": 0,
                "bytes_received_per_sec": 0,
                "bytes_sent_per_sec": 0,
                "current_anonymous_users": 0,
                "current_connections": 2,
                "current_non_anonymous_users": 0,
                "delete_requests_per_sec": 0,
                "get_requests_per_sec": 0,
                "maximum_connections": 6,
                "post_requests_per_sec": 0,
                "service_uptime": 1721919,
                "total_anonymous_users": 52,
                "total_bytes_received": 33151,
                "total_bytes_sent": 903338,
                "total_connection_attempts": 23,
                "total_delete_requests": 0,
                "total_get_requests": 52,
                "total_non_anonymous_users": 0,
                "total_post_requests": 0
            },
            "process": {
                "io_read_operations_per_sec": 5.7271735422265,
                "io_write_operations_per_sec": 5.7271735422265,
                "page_faults_per_sec": 1.0738450391674688,
                "private_bytes": 106692608,
                "virtual_bytes": 2222663852032,
                "worker_process_count": 2
            }
        }
    },
    "metricset": {
        "name": "webserver",
        "period": 10000
    },
    "service": {
        "type": "iis"
    }
}
```

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id |  | keyword |  |  |
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
| iis.webserver.asp_net.application_restarts | Number of applications restarts. | float |  | gauge |
| iis.webserver.asp_net.request_wait_time | Request wait time. | long |  |  |
| iis.webserver.asp_net_application.errors_total_per_sec | Total number of errors per sec. | float |  | gauge |
| iis.webserver.asp_net_application.pipeline_instance_count | The pipeline instance count. | float |  | gauge |
| iis.webserver.asp_net_application.requests_executing | Number of requests executing. | float |  | gauge |
| iis.webserver.asp_net_application.requests_in_application_queue | Number of requests in the application queue. | float |  |  |
| iis.webserver.asp_net_application.requests_per_sec | Number of requests per sec. | float |  | gauge |
| iis.webserver.cache.current_file_cache_memory_usage | The current file cache memory usage size. | float |  |  |
| iis.webserver.cache.current_files_cached | The number of current files cached. | float |  |  |
| iis.webserver.cache.current_uris_cached | The number of current uris cached. | float |  |  |
| iis.webserver.cache.file_cache_hits | The number of file cache hits. | float |  |  |
| iis.webserver.cache.file_cache_misses | The number of file cache misses. | float |  |  |
| iis.webserver.cache.maximum_file_cache_memory_usage | The max file cache size. | float |  |  |
| iis.webserver.cache.output_cache_current_items | The number of output cache current items. | float |  |  |
| iis.webserver.cache.output_cache_current_memory_usage | The output cache memory usage size. | float |  |  |
| iis.webserver.cache.output_cache_total_hits | The output cache total hits count. | float |  |  |
| iis.webserver.cache.output_cache_total_misses | The output cache total misses count. | float |  |  |
| iis.webserver.cache.total_files_cached | the total number of files cached. | float |  |  |
| iis.webserver.cache.total_uris_cached | The total number of URIs cached. | float |  |  |
| iis.webserver.cache.uri_cache_hits | The number of URIs cached hits. | float |  |  |
| iis.webserver.cache.uri_cache_misses | The number of URIs cache misses. | float |  |  |
| iis.webserver.network.anonymous_users_per_sec | The number of anonymous users per sec. | float |  | gauge |
| iis.webserver.network.bytes_received_per_sec | The size of bytes received per sec. | float | byte | gauge |
| iis.webserver.network.bytes_sent_per_sec | The size of bytes sent per sec. | float | byte | gauge |
| iis.webserver.network.current_anonymous_users | The number of current anonymous users. | float |  |  |
| iis.webserver.network.current_connections | The number of current connections. | float |  |  |
| iis.webserver.network.current_non_anonymous_users | The number of current non anonymous users. | float |  |  |
| iis.webserver.network.delete_requests_per_sec | Number of DELETE requests per sec. | float |  | gauge |
| iis.webserver.network.get_requests_per_sec | Number of GET requests per sec. | float |  | gauge |
| iis.webserver.network.maximum_connections | Number of maximum connections. | float |  | counter |
| iis.webserver.network.post_requests_per_sec | Number of POST requests per sec. | float |  | gauge |
| iis.webserver.network.service_uptime | Service uptime. | float |  |  |
| iis.webserver.network.total_anonymous_users | Total number of anonymous users. | float |  | counter |
| iis.webserver.network.total_bytes_received | Total size of bytes received. | float | byte | counter |
| iis.webserver.network.total_bytes_sent | Total size of bytes sent. | float | byte | counter |
| iis.webserver.network.total_connection_attempts | The total number of connection attempts. | float |  |  |
| iis.webserver.network.total_delete_requests | The total number of DELETE requests. | float |  | counter |
| iis.webserver.network.total_get_requests | The total number of GET requests. | float |  | counter |
| iis.webserver.network.total_non_anonymous_users | The total number of non anonymous users. | float |  | counter |
| iis.webserver.network.total_post_requests | The total number of POST requests. | float |  | counter |
| iis.webserver.process.cpu_usage_perc | The CPU usage percentage. | float |  | gauge |
| iis.webserver.process.handle_count | The number of handles. | float |  |  |
| iis.webserver.process.io_read_operations_per_sec | IO read operations per sec. | float |  | gauge |
| iis.webserver.process.io_write_operations_per_sec | IO write operations per sec. | float |  | gauge |
| iis.webserver.process.page_faults_per_sec | Memory page faults. | float |  | gauge |
| iis.webserver.process.private_bytes | Memory private bytes. | float | byte | gauge |
| iis.webserver.process.thread_count | The number of threads. | long |  |  |
| iis.webserver.process.virtual_bytes | Memory virtual bytes. | float | byte | gauge |
| iis.webserver.process.worker_process_count | Number of worker processes running. | float |  |  |
| iis.webserver.process.working_set | Memory working set. | float |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |


### website

This data stream will collect metrics of specific sites, users can configure which websites they want to monitor, else, all are considered.

An example event for `website` looks as following:

```json
{
    "@timestamp": "2020-07-08T11:40:22.114Z",
    "agent": {
        "ephemeral_id": "8ade3582-e6ab-4664-ba27-52b3d46953e3",
        "id": "3b73ebb6-c6ea-4354-b1f3-240ac1aa072c",
        "name": "DESKTOP-RFOOE09",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "iis.website",
        "duration": 5008200,
        "module": "iis"
    },
    "iis": {
        "website": {
            "name": "test2.local",
            "network": {
                "current_connections": 0,
                "maximum_connections": 4,
                "service_uptime": 1721807,
                "total_bytes_received": 4250,
                "total_bytes_sent": 135739,
                "total_connection_attempts": 7,
                "total_delete_requests": 0,
                "total_get_requests": 11,
                "total_post_requests": 0,
                "total_put_requests": 0
            }
        }
    },
    "metricset": {
        "name": "website",
        "period": 10000
    },
    "service": {
        "type": "iis"
    }
}
```

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id |  | keyword |  |  |
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
| iis.website.name | website name | keyword |  |  |
| iis.website.network.bytes_received_per_sec | The bytes received per sec size. | float | byte | gauge |
| iis.website.network.bytes_sent_per_sec | The bytes sent per sec size. | float | byte | gauge |
| iis.website.network.current_connections | The number of current connections. | float |  |  |
| iis.website.network.delete_requests_per_sec | The number of DELETE requests per sec. | float |  | gauge |
| iis.website.network.get_requests_per_sec | The number of GET requests per sec. | float |  | gauge |
| iis.website.network.maximum_connections | The number of maximum connections. | float |  |  |
| iis.website.network.post_requests_per_sec | The number of POST requests per sec. | float |  | gauge |
| iis.website.network.put_requests_per_sec | The number of PUT requests per sec. | float |  | gauge |
| iis.website.network.service_uptime | The service uptime. | float |  |  |
| iis.website.network.total_bytes_received | The total number of bytes received. | float | byte | counter |
| iis.website.network.total_bytes_sent | The  total number of bytes sent. | float | byte | counter |
| iis.website.network.total_connection_attempts | The total number of connection attempts. | float |  | counter |
| iis.website.network.total_delete_requests | The total number of DELETE requests. | float |  | counter |
| iis.website.network.total_get_requests | The total number of GET requests. | float |  | counter |
| iis.website.network.total_post_requests | The total number of POST requests. | float |  | counter |
| iis.website.network.total_put_requests | The total number of PUT requests. | float |  | counter |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |


### application_pool

This data stream will collect metrics of specific application pools, users can configure which websites they want to monitor, else, all are considered.

An example event for `application_pool` looks as following:

```json
{
    "@timestamp": "2020-07-08T11:41:31.048Z",
    "agent": {
        "ephemeral_id": "8ade3582-e6ab-4664-ba27-52b3d46953e3",
        "id": "3b73ebb6-c6ea-4354-b1f3-240ac1aa072c",
        "name": "DESKTOP-RFOOE09",
        "type": "metricbeat",
        "version": "8.0.0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "dataset": "iis.application_pool",
        "duration": 397142600,
        "module": "iis"
    },
    "iis": {
        "application_pool": {
            "name": "DefaultAppPool",
            "net_clr": {
                "total_exceptions_thrown": 0
            },
            "process": {
                "handle_count": 466,
                "private_bytes": 71516160,
                "thread_count": 30
            }
        }
    },
    "metricset": {
        "name": "application_pool",
        "period": 10000
    },
    "service": {
        "type": "iis"
    }
}
```

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| agent.id |  | keyword |  |  |
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
| iis.application_pool.name | application pool name | keyword |  |  |
| iis.application_pool.net_clr.filters_per_sec | Number of filters per sec. | float |  | gauge |
| iis.application_pool.net_clr.finallys_per_sec | The number of finallys per sec. | float |  | gauge |
| iis.application_pool.net_clr.throw_to_catch_depth_per_sec | Throw to catch depth count per sec. | float |  | gauge |
| iis.application_pool.net_clr.total_exceptions_thrown | Total number of exceptions thrown. | long |  | counter |
| iis.application_pool.process.cpu_usage_perc | The CPU usage percentage. | float | s | gauge |
| iis.application_pool.process.handle_count | The number of handles. | long |  |  |
| iis.application_pool.process.io_read_operations_per_sec | IO read operations per sec. | float |  | gauge |
| iis.application_pool.process.io_write_operations_per_sec | IO write operations per sec. | float |  | gauge |
| iis.application_pool.process.page_faults_per_sec | Memory page faults. | float |  | gauge |
| iis.application_pool.process.private_bytes | Memory private bytes. | float | byte | gauge |
| iis.application_pool.process.thread_count | The number of threads. | long |  | counter |
| iis.application_pool.process.virtual_bytes | Memory virtual bytes. | float | byte | gauge |
| iis.application_pool.process.working_set | Memory working set. | float |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
