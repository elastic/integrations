# HAProxy Integration

This integration periodically fetches logs and metrics from [HAProxy](https://www.haproxy.org/) servers.

## Compatibility

The `log` dataset was tested with logs from HAProxy 1.8, 1.9 and 2.0 running on a Debian. It is not available on Windows.

The `info` and `stat` datasets were tested with tested with HAProxy versions from 1.6, 1.7, 1.8 to 2.0. 

## Logs

### log

The `log` dataset collects the HAProxy application logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2018-07-30T09:03:52.726Z",
    "agent": {
        "ephemeral_id": "7eccbe53-c1e3-424d-8a1b-c290b8c2ca88",
        "id": "25ee0259-10b8-4a16-9f80-d18ce8ad6442",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "data_stream": {
        "dataset": "haproxy.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "25ee0259-10b8-4a16-9f80-d18ce8ad6442",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "haproxy.log",
        "duration": 2000000,
        "ingested": "2022-01-11T00:35:53Z",
        "kind": "event",
        "outcome": "success",
        "timezone": "+00:00"
    },
    "haproxy": {
        "backend_name": "docs_microservice",
        "backend_queue": 0,
        "bytes_read": 168,
        "connection_wait_time_ms": 1,
        "connections": {
            "active": 6,
            "backend": 0,
            "frontend": 6,
            "retries": 0,
            "server": 0
        },
        "frontend_name": "incoming~",
        "http": {
            "request": {
                "captured_cookie": "-",
                "captured_headers": [
                    "docs.example.internal"
                ],
                "raw_request_line": "GET /component---src-pages-index-js-4b15624544f97cf0bb8f.js HTTP/1.1",
                "time_wait_ms": 0,
                "time_wait_without_data_ms": 0
            },
            "response": {
                "captured_cookie": "-",
                "captured_headers": []
            }
        },
        "server_name": "docs",
        "server_queue": 0,
        "termination_state": "----",
        "total_waiting_time_ms": 0
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "4ccba669f0df47fa3f57a9e4169ae7f1",
        "ip": [
            "172.18.0.7"
        ],
        "mac": [
            "02:42:ac:12:00:07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "Core",
            "family": "redhat",
            "kernel": "5.11.0-43-generic",
            "name": "CentOS Linux",
            "platform": "centos",
            "type": "linux",
            "version": "7 (Core)"
        }
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "bytes": 168,
            "status_code": 304
        },
        "version": "1.1"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/haproxy.log"
        },
        "offset": 0
    },
    "process": {
        "name": "haproxy",
        "pid": 32450
    },
    "related": {
        "ip": [
            "67.43.156.13"
        ]
    },
    "source": {
        "address": "67.43.156.13",
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.13",
        "port": 38862
    },
    "tags": [
        "haproxy-log"
    ],
    "temp": {},
    "url": {
        "extension": "js",
        "original": "/component---src-pages-index-js-4b15624544f97cf0bb8f.js",
        "path": "/component---src-pages-index-js-4b15624544f97cf0bb8f.js"
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
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| haproxy.backend_name | Name of the backend (or listener) which was selected to manage the connection to the server. | keyword |
| haproxy.backend_queue | Total number of requests which were processed before this one in the backend's global queue. | long |
| haproxy.bind_name | Name of the listening address which received the connection. | keyword |
| haproxy.bytes_read | Total number of bytes transmitted to the client when the log is emitted. | long |
| haproxy.connection_wait_time_ms | Total time in milliseconds spent waiting for the connection to establish to the final server | long |
| haproxy.connections.active | Total number of concurrent connections on the process when the session was logged. | long |
| haproxy.connections.backend | Total number of concurrent connections handled by the backend when the session was logged. | long |
| haproxy.connections.frontend | Total number of concurrent connections on the frontend when the session was logged. | long |
| haproxy.connections.retries | Number of connection retries experienced by this session when trying to connect to the server. | long |
| haproxy.connections.server | Total number of concurrent connections still active on the server when the session was logged. | long |
| haproxy.error_message | Error message logged by HAProxy in case of error. | text |
| haproxy.frontend_name | Name of the frontend (or listener) which received and processed the connection. | keyword |
| haproxy.http.request.captured_cookie | Optional "name=value" entry indicating that the server has returned a cookie with its request. | keyword |
| haproxy.http.request.captured_headers | List of headers captured in the request due to the presence of the "capture request header" statement in the frontend. | keyword |
| haproxy.http.request.raw_request_line | Complete HTTP request line, including the method, request and HTTP version string. | keyword |
| haproxy.http.request.time_wait_ms | Total time in milliseconds spent waiting for a full HTTP request from the client (not counting body) after the first byte was received. | long |
| haproxy.http.request.time_wait_without_data_ms | Total time in milliseconds spent waiting for the server to send a full HTTP response, not counting data. | long |
| haproxy.http.response.captured_cookie | Optional "name=value" entry indicating that the client had this cookie in the response. | keyword |
| haproxy.http.response.captured_headers | List of headers captured in the response due to the presence of the "capture response header" statement in the frontend. | keyword |
| haproxy.mode | mode that the frontend is operating (TCP or HTTP) | keyword |
| haproxy.server_name | Name of the last server to which the connection was sent. | keyword |
| haproxy.server_queue | Total number of requests which were processed before this one in the server queue. | long |
| haproxy.source | The HAProxy source of the log | keyword |
| haproxy.tcp.connection_waiting_time_ms | Total time in milliseconds elapsed between the accept and the last close | long |
| haproxy.termination_state | Condition the session was in when the session ended. | keyword |
| haproxy.time_backend_connect | Total time in milliseconds spent waiting for the connection to establish to the final server, including retries. | long |
| haproxy.time_queue | Total time in milliseconds spent waiting in the various queues. | long |
| haproxy.total_waiting_time_ms | Total time in milliseconds spent waiting in the various queues | long |
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
| http.request.body.bytes | Size in bytes of the request body. | long |
| http.request.body.content | The full HTTP request body. | wildcard |
| http.request.body.content.text | Multi-field of `http.request.body.content`. | match_only_text |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.body.content | The full HTTP response body. | wildcard |
| http.response.body.content.text | Multi-field of `http.response.body.content`. | match_only_text |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| related.ip | All of the IPs seen on your event. | ip |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
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
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| url.username | Username of the request. | keyword |


## Metrics

### info

The HAProxy `info` dataset collects general information about HAProxy processes.

An example event for `info` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "agent": {
        "hostname": "host.example.com",
        "name": "host.example.com"
    },
    "event": {
        "dataset": "haproxy.info",
        "duration": 115000,
        "module": "haproxy"
    },
    "haproxy": {
        "info": {
            "compress": {
                "bps": {
                    "in": 0,
                    "out": 0,
                    "rate_limit": 0
                }
            },
            "connection": {
                "current": 0,
                "hard_max": 4000,
                "max": 4000,
                "rate": {
                    "limit": 0,
                    "max": 0,
                    "value": 0
                },
                "ssl": {
                    "current": 0,
                    "max": 0,
                    "total": 0
                },
                "total": 30
            },
            "idle": {
                "pct": 1
            },
            "memory": {
                "max": {
                    "bytes": 0
                }
            },
            "pipes": {
                "free": 0,
                "max": 0,
                "used": 0
            },
            "process_num": 1,
            "processes": 1,
            "requests": {
                "total": 30
            },
            "run_queue": 0,
            "session": {
                "rate": {
                    "limit": 0,
                    "max": 0,
                    "value": 0
                }
            },
            "sockets": {
                "max": 8034
            },
            "ssl": {
                "backend": {
                    "key_rate": {
                        "max": 0,
                        "value": 0
                    }
                },
                "cache_misses": 0,
                "cached_lookups": 0,
                "frontend": {
                    "key_rate": {
                        "max": 0,
                        "value": 0
                    },
                    "session_reuse": {
                        "pct": 0
                    }
                },
                "rate": {
                    "limit": 0,
                    "max": 0,
                    "value": 0
                }
            },
            "tasks": 7,
            "ulimit_n": 8034,
            "uptime": {
                "sec": 30
            },
            "zlib_mem_usage": {
                "max": 0,
                "value": 0
            }
        }
    },
    "metricset": {
        "name": "info"
    },
    "process": {
        "pid": 7
    },
    "service": {
        "address": "127.0.0.1:14567",
        "type": "haproxy"
    }
}
```

The fields reported are:

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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| haproxy.info.busy_polling | Number of busy polling. | long |
| haproxy.info.bytes.out.rate | Average bytes output rate. | long |
| haproxy.info.bytes.out.total | Number of bytes sent out. | long |
| haproxy.info.compress.bps.in | Incoming compressed data in bits per second. | long |
| haproxy.info.compress.bps.out | Outgoing compressed data in bits per second. | long |
| haproxy.info.compress.bps.rate_limit | Rate limit of compressed data in bits per second. | long |
| haproxy.info.connection.current | Current connections. | long |
| haproxy.info.connection.hard_max |  | long |
| haproxy.info.connection.max | Maximum connections. | long |
| haproxy.info.connection.rate.limit | Rate limit of connections. | long |
| haproxy.info.connection.rate.max | Maximum rate of connections. | long |
| haproxy.info.connection.rate.value | Number of connections in the last second. | long |
| haproxy.info.connection.ssl.current | Current SSL connections. | long |
| haproxy.info.connection.ssl.max | Maximum SSL connections. | long |
| haproxy.info.connection.ssl.total | Total SSL connections. | long |
| haproxy.info.connection.total | Total connections. | long |
| haproxy.info.dropped_logs | Number of dropped logs. | long |
| haproxy.info.failed_resolutions | Number of failed resolutions. | long |
| haproxy.info.idle.pct | Percentage of idle time. | scaled_float |
| haproxy.info.jobs | Number of all jobs. | long |
| haproxy.info.listeners | Number of listeners. | long |
| haproxy.info.memory.max.bytes | Maximum amount of memory usage in bytes (the 'Memmax_MB' value converted to bytes). | long |
| haproxy.info.peers.active | Number of active peers. | long |
| haproxy.info.peers.connected | Number of connected peers. | long |
| haproxy.info.pipes.free | Number of free pipes. | integer |
| haproxy.info.pipes.max | Maximum number of used pipes. | integer |
| haproxy.info.pipes.used | Number of used pipes during kernel-based tcp splicing. | integer |
| haproxy.info.pool.allocated | Size of the allocated pool. | long |
| haproxy.info.pool.failed | Number of failed connections to pool members. | long |
| haproxy.info.pool.used | Number of members used from the allocated pool. | long |
| haproxy.info.process_num | Process number. | long |
| haproxy.info.processes | Number of processes. | long |
| haproxy.info.requests.max | Maximum number of requests. | long |
| haproxy.info.requests.total | Total number of requests. | long |
| haproxy.info.run_queue |  | long |
| haproxy.info.session.rate.limit | Rate limit of sessions. | integer |
| haproxy.info.session.rate.max | Maximum rate of sessions. | integer |
| haproxy.info.session.rate.value | Rate of session per seconds. | integer |
| haproxy.info.sockets.max | Maximum number of sockets. | long |
| haproxy.info.ssl.backend.key_rate.max | Maximum key rate of SSL backend sessions. | integer |
| haproxy.info.ssl.backend.key_rate.value | Key rate of SSL backend sessions. | integer |
| haproxy.info.ssl.cache_misses | Number of SSL cache misses. | long |
| haproxy.info.ssl.cached_lookups | Number of SSL cache lookups. | long |
| haproxy.info.ssl.frontend.key_rate.max | Maximum key rate of SSL frontend. | integer |
| haproxy.info.ssl.frontend.key_rate.value | Key rate of SSL frontend. | integer |
| haproxy.info.ssl.frontend.session_reuse.pct | Rate of reuse of SSL frontend sessions. | scaled_float |
| haproxy.info.ssl.rate.limit | Rate limit of SSL requests. | integer |
| haproxy.info.ssl.rate.max | Maximum rate of SSL requests. | integer |
| haproxy.info.ssl.rate.value | Rate of SSL requests. | integer |
| haproxy.info.stopping | Number of stopping jobs. | long |
| haproxy.info.tasks |  | long |
| haproxy.info.threads | Number of threads. | long |
| haproxy.info.ulimit_n | Maximum number of open files for the process. | long |
| haproxy.info.unstoppable_jobs | Number of unstoppable jobs. | long |
| haproxy.info.uptime.sec | Current uptime in seconds. | long |
| haproxy.info.zlib_mem_usage.max | Maximum memory usage of zlib. | integer |
| haproxy.info.zlib_mem_usage.value | Memory usage of zlib. | integer |
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
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.code_signature.digest_algorithm | The hashing algorithm used to sign the process. This value can distinguish signatures when a file is signed multiple times by the same signer but with a different digest algorithm. | keyword |
| process.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| process.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.code_signature.subject_name | Subject name of the code signer | keyword |
| process.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.code_signature.timestamp | Date and time when the code signature was generated and signed. | date |
| process.code_signature.trusted | Stores the trust status of the certificate chain. Validating the trust of the certificate chain may be complicated, and this field should only be populated by tools that actively check the status. | boolean |
| process.code_signature.valid | Boolean to capture if the digital signature is verified against the binary content. Leave unpopulated if a certificate was unchecked. | boolean |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.elf.architecture | Machine architecture of the ELF file. | keyword |
| process.elf.byte_order | Byte sequence of ELF file. | keyword |
| process.elf.cpu_type | CPU type of the ELF file. | keyword |
| process.elf.creation_date | Extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. | date |
| process.elf.exports | List of exported element names and types. | flattened |
| process.elf.header.abi_version | Version of the ELF Application Binary Interface (ABI). | keyword |
| process.elf.header.class | Header class of the ELF file. | keyword |
| process.elf.header.data | Data table of the ELF header. | keyword |
| process.elf.header.entrypoint | Header entrypoint of the ELF file. | long |
| process.elf.header.object_version | "0x1" for original ELF files. | keyword |
| process.elf.header.os_abi | Application Binary Interface (ABI) of the Linux OS. | keyword |
| process.elf.header.type | Header type of the ELF file. | keyword |
| process.elf.header.version | Version of the ELF header. | keyword |
| process.elf.imports | List of imported element names and types. | flattened |
| process.elf.sections | An array containing an object for each section of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.sections.\*`. | nested |
| process.elf.sections.chi2 | Chi-square probability distribution of the section. | long |
| process.elf.sections.entropy | Shannon entropy calculation from the section. | long |
| process.elf.sections.flags | ELF Section List flags. | keyword |
| process.elf.sections.name | ELF Section List name. | keyword |
| process.elf.sections.physical_offset | ELF Section List offset. | keyword |
| process.elf.sections.physical_size | ELF Section List physical size. | long |
| process.elf.sections.type | ELF Section List type. | keyword |
| process.elf.sections.virtual_address | ELF Section List virtual address. | long |
| process.elf.sections.virtual_size | ELF Section List virtual size. | long |
| process.elf.segments | An array containing an object for each segment of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.segments.\*`. | nested |
| process.elf.segments.sections | ELF object segment sections. | keyword |
| process.elf.segments.type | ELF object segment type. | keyword |
| process.elf.shared_libraries | List of shared libraries used by this ELF object. | keyword |
| process.elf.telfhash | telfhash symbol hash for ELF file. | keyword |
| process.end | The time the process ended. | date |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.hash.sha512 | SHA512 hash. | keyword |
| process.hash.ssdeep | SSDEEP hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.parent.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.parent.code_signature.digest_algorithm | The hashing algorithm used to sign the process. This value can distinguish signatures when a file is signed multiple times by the same signer but with a different digest algorithm. | keyword |
| process.parent.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| process.parent.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.parent.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.parent.code_signature.subject_name | Subject name of the code signer | keyword |
| process.parent.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.parent.code_signature.timestamp | Date and time when the code signature was generated and signed. | date |
| process.parent.code_signature.trusted | Stores the trust status of the certificate chain. Validating the trust of the certificate chain may be complicated, and this field should only be populated by tools that actively check the status. | boolean |
| process.parent.code_signature.valid | Boolean to capture if the digital signature is verified against the binary content. Leave unpopulated if a certificate was unchecked. | boolean |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.elf.architecture | Machine architecture of the ELF file. | keyword |
| process.parent.elf.byte_order | Byte sequence of ELF file. | keyword |
| process.parent.elf.cpu_type | CPU type of the ELF file. | keyword |
| process.parent.elf.creation_date | Extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. | date |
| process.parent.elf.exports | List of exported element names and types. | flattened |
| process.parent.elf.header.abi_version | Version of the ELF Application Binary Interface (ABI). | keyword |
| process.parent.elf.header.class | Header class of the ELF file. | keyword |
| process.parent.elf.header.data | Data table of the ELF header. | keyword |
| process.parent.elf.header.entrypoint | Header entrypoint of the ELF file. | long |
| process.parent.elf.header.object_version | "0x1" for original ELF files. | keyword |
| process.parent.elf.header.os_abi | Application Binary Interface (ABI) of the Linux OS. | keyword |
| process.parent.elf.header.type | Header type of the ELF file. | keyword |
| process.parent.elf.header.version | Version of the ELF header. | keyword |
| process.parent.elf.imports | List of imported element names and types. | flattened |
| process.parent.elf.sections | An array containing an object for each section of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.sections.\*`. | nested |
| process.parent.elf.sections.chi2 | Chi-square probability distribution of the section. | long |
| process.parent.elf.sections.entropy | Shannon entropy calculation from the section. | long |
| process.parent.elf.sections.flags | ELF Section List flags. | keyword |
| process.parent.elf.sections.name | ELF Section List name. | keyword |
| process.parent.elf.sections.physical_offset | ELF Section List offset. | keyword |
| process.parent.elf.sections.physical_size | ELF Section List physical size. | long |
| process.parent.elf.sections.type | ELF Section List type. | keyword |
| process.parent.elf.sections.virtual_address | ELF Section List virtual address. | long |
| process.parent.elf.sections.virtual_size | ELF Section List virtual size. | long |
| process.parent.elf.segments | An array containing an object for each segment of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.segments.\*`. | nested |
| process.parent.elf.segments.sections | ELF object segment sections. | keyword |
| process.parent.elf.segments.type | ELF object segment type. | keyword |
| process.parent.elf.shared_libraries | List of shared libraries used by this ELF object. | keyword |
| process.parent.elf.telfhash | telfhash symbol hash for ELF file. | keyword |
| process.parent.end | The time the process ended. | date |
| process.parent.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.parent.hash.md5 | MD5 hash. | keyword |
| process.parent.hash.sha1 | SHA1 hash. | keyword |
| process.parent.hash.sha256 | SHA256 hash. | keyword |
| process.parent.hash.sha512 | SHA512 hash. | keyword |
| process.parent.hash.ssdeep | SSDEEP hash. | keyword |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pe.architecture | CPU architecture target for the file. | keyword |
| process.parent.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| process.parent.pe.description | Internal description of the file, provided at compile-time. | keyword |
| process.parent.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| process.parent.pe.imphash | A hash of the imports in a PE file. An imphash -- or import hash -- can be used to fingerprint binaries even after recompilation or other code-level transformations have occurred, which would change more traditional hash values. Learn more at https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html. | keyword |
| process.parent.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| process.parent.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| process.parent.pgid | Identifier of the group of processes the process belongs to. | long |
| process.parent.pid | Process id. | long |
| process.parent.start | The time the process started. | date |
| process.parent.thread.id | Thread ID. | long |
| process.parent.thread.name | Thread name. | keyword |
| process.parent.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.parent.title.text | Multi-field of `process.parent.title`. | match_only_text |
| process.parent.uptime | Seconds the process has been up. | long |
| process.parent.working_directory | The working directory of the process. | keyword |
| process.parent.working_directory.text | Multi-field of `process.parent.working_directory`. | match_only_text |
| process.pe.architecture | CPU architecture target for the file. | keyword |
| process.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| process.pe.description | Internal description of the file, provided at compile-time. | keyword |
| process.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| process.pe.imphash | A hash of the imports in a PE file. An imphash -- or import hash -- can be used to fingerprint binaries even after recompilation or other code-level transformations have occurred, which would change more traditional hash values. Learn more at https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html. | keyword |
| process.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| process.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| process.pgid | Identifier of the group of processes the process belongs to. | long |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| process.thread.id | Thread ID. | long |
| process.thread.name | Thread name. | keyword |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| process.uptime | Seconds the process has been up. | long |
| process.working_directory | The working directory of the process. | keyword |
| process.working_directory.text | Multi-field of `process.working_directory`. | match_only_text |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |


### stat

The HAProxy `stat` metricset collects stat fields from HAProxy processes.

See section "9.1. CSV format" of the official [HAProxy Management Guide](http://www.haproxy.org/download/2.0/doc/management.txt) for a full list of stat fields.

An example event for `stat` looks as following:

```json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "agent": {
        "hostname": "host.example.com",
        "name": "host.example.com"
    },
    "event": {
        "dataset": "haproxy.stat",
        "duration": 115000,
        "module": "haproxy"
    },
    "haproxy": {
        "stat": {
            "check": {
                "agent.last": "",
                "health.last": "",
                "status": ""
            },
            "component_type": 0,
            "compressor": {
                "bypassed.bytes": 0,
                "in.bytes": 0,
                "out.bytes": 0,
                "response.bytes": 0
            },
            "connection": {
                "total": 0
            },
            "in.bytes": 0,
            "out.bytes": 0,
            "proxy": {
                "id": 2,
                "name": "stat"
            },
            "queue": {},
            "request": {
                "denied": 0,
                "errors": 0,
                "rate": {
                    "max": 0,
                    "value": 0
                },
                "total": 0
            },
            "response": {
                "denied": 0,
                "http": {
                    "1xx": 0,
                    "2xx": 0,
                    "3xx": 0,
                    "4xx": 0,
                    "5xx": 0,
                    "other": 0
                }
            },
            "server": {
                "id": 0
            },
            "service_name": "FRONTEND",
            "session": {
                "current": 0,
                "limit": 25000,
                "max": 0,
                "rate": {
                    "limit": 0,
                    "max": 0,
                    "value": 0
                }
            },
            "status": "OPEN"
        }
    },
    "metricset": {
        "name": "stat"
    },
    "process": {
        "pid": 1
    },
    "service": {
        "address": "127.0.0.1:14567",
        "type": "haproxy"
    }
}
```

The fields reported are:

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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| haproxy.stat.agent.check.description | Human readable version of check. | keyword |
| haproxy.stat.agent.check.fall | Fall value of server. | integer |
| haproxy.stat.agent.check.health | Health parameter of server. Between 0 and `agent.check.rise`+`agent.check.fall`-1. | integer |
| haproxy.stat.agent.check.rise | Rise value of server. | integer |
| haproxy.stat.agent.code | Value reported by agent. | integer |
| haproxy.stat.agent.description | Human readable version of agent.status. | keyword |
| haproxy.stat.agent.duration | Duration of the last check in ms. | integer |
| haproxy.stat.agent.fall | Fall value of agent. | integer |
| haproxy.stat.agent.health | Health parameter of agent. Between 0 and `agent.rise`+`agent.fall`-1. | integer |
| haproxy.stat.agent.rise | Rise value of agent. | integer |
| haproxy.stat.agent.status | Status of the last health check. One of:    UNK     -\> unknown   INI     -\> initializing   SOCKERR -\> socket error   L4OK    -\> check passed on layer 4, no upper layers enabled   L4TOUT  -\> layer 1-4 timeout   L4CON   -\> layer 1-4 connection problem, for example             "Connection refused" (tcp rst) or "No route to host" (icmp)   L7OK    -\> agent reported "up"   L7STS   -\> agent reported "fail", "stop" or "down" | keyword |
| haproxy.stat.check.agent.last |  | integer |
| haproxy.stat.check.code | Layer 5-7 code, if available. | long |
| haproxy.stat.check.down | Number of UP-\>DOWN transitions. For backends, this value is the number of transitions to the whole backend being down, rather than the sum of the transitions for each server. | long |
| haproxy.stat.check.duration | Time in ms that it took to finish the last health check. | long |
| haproxy.stat.check.failed | Number of checks that failed while the server was up. | long |
| haproxy.stat.check.health.fail | Number of failed checks. | long |
| haproxy.stat.check.health.last | The result of the last health check. | keyword |
| haproxy.stat.check.status | Status of the last health check. One of:    UNK     -\> unknown   INI     -\> initializing   SOCKERR -\> socket error   L4OK    -\> check passed on layer 4, no upper layers testing enabled   L4TOUT  -\> layer 1-4 timeout   L4CON   -\> layer 1-4 connection problem, for example             "Connection refused" (tcp rst) or "No route to host" (icmp)   L6OK    -\> check passed on layer 6   L6TOUT  -\> layer 6 (SSL) timeout   L6RSP   -\> layer 6 invalid response - protocol error   L7OK    -\> check passed on layer 7   L7OKC   -\> check conditionally passed on layer 7, for example 404 with             disable-on-404   L7TOUT  -\> layer 7 (HTTP/SMTP) timeout   L7RSP   -\> layer 7 invalid response - protocol error   L7STS   -\> layer 7 response error, for example HTTP 5xx | keyword |
| haproxy.stat.client.aborted | Number of data transfers aborted by the client. | integer |
| haproxy.stat.component_type | Component type (0=frontend, 1=backend, 2=server, or 3=socket/listener). | integer |
| haproxy.stat.compressor.bypassed.bytes | Number of bytes that bypassed the HTTP compressor (CPU/BW limit). | long |
| haproxy.stat.compressor.in.bytes | Number of HTTP response bytes fed to the compressor. | long |
| haproxy.stat.compressor.out.bytes | Number of HTTP response bytes emitted by the compressor. | integer |
| haproxy.stat.compressor.response.bytes | Number of HTTP responses that were compressed. | long |
| haproxy.stat.connection.attempt.total | Number of connection establishment attempts. | long |
| haproxy.stat.connection.cache.hits | Number of cache hits. | long |
| haproxy.stat.connection.cache.lookup.total | Number of cache lookups. | long |
| haproxy.stat.connection.idle.limit | Limit on idle connections available for reuse. | long |
| haproxy.stat.connection.idle.total | Number of idle connections available for reuse. | long |
| haproxy.stat.connection.rate | Number of connections over the last second. | long |
| haproxy.stat.connection.rate_max | Highest value of connection.rate. | long |
| haproxy.stat.connection.retried | Number of times a connection to a server was retried. | long |
| haproxy.stat.connection.reuse.total | Number of connection reuses. | long |
| haproxy.stat.connection.time.avg | Average connect time in ms over the last 1024 requests. | long |
| haproxy.stat.connection.total | Cumulative number of connections. | long |
| haproxy.stat.cookie | Cookie value of the server or the name of the cookie of the backend. | keyword |
| haproxy.stat.downtime | Total downtime (in seconds). For backends, this value is the downtime for the whole backend, not the sum of the downtime for the servers. | long |
| haproxy.stat.header.rewrite.failed.total | Number of failed header rewrite warnings. | long |
| haproxy.stat.in.bytes | Bytes in. | long |
| haproxy.stat.last_change | Number of seconds since the last UP-\>DOWN or DOWN-\>UP transition. | integer |
| haproxy.stat.load_balancing_algorithm | Load balancing algorithm. | keyword |
| haproxy.stat.out.bytes | Bytes out. | long |
| haproxy.stat.proxy.id | Unique proxy ID. | integer |
| haproxy.stat.proxy.mode | Proxy mode (tcp, http, health, unknown). | keyword |
| haproxy.stat.proxy.name | Proxy name. | keyword |
| haproxy.stat.queue.limit | Configured queue limit (maxqueue) for the server, or nothing if the value of maxqueue is 0 (meaning no limit). | integer |
| haproxy.stat.queue.time.avg | The average queue time in ms over the last 1024 requests. | integer |
| haproxy.stat.request.connection.errors | Number of requests that encountered an error trying to connect to a server. For backends, this field reports the sum of the stat for all backend servers, plus any connection errors not associated with a particular server (such as the backend having no active servers). | long |
| haproxy.stat.request.denied | Requests denied because of security concerns.    \* For TCP this is because of a matched tcp-request content rule.   \* For HTTP this is because of a matched http-request or tarpit rule. | long |
| haproxy.stat.request.denied_by_connection_rules | Requests denied because of TCP request connection rules. | long |
| haproxy.stat.request.denied_by_session_rules | Requests denied because of TCP request session rules. | long |
| haproxy.stat.request.errors | Request errors. Some of the possible causes are:    \* early termination from the client, before the request has been sent   \* read error from the client   \* client timeout   \* client closed connection   \* various bad requests from the client.   \* request was tarpitted. | long |
| haproxy.stat.request.intercepted | Number of intercepted requests. | long |
| haproxy.stat.request.queued.current | Current queued requests. For backends, this field reports the number of requests queued without a server assigned. | long |
| haproxy.stat.request.queued.max | Maximum value of queued.current. | long |
| haproxy.stat.request.rate.max | Maximum number of HTTP requests per second. | long |
| haproxy.stat.request.rate.value | Number of HTTP requests per second over the last elapsed second. | long |
| haproxy.stat.request.redispatched | Number of times a request was redispatched to another server. For servers, this field reports the number of times the server was switched away from. | long |
| haproxy.stat.request.total | Total number of HTTP requests received. | long |
| haproxy.stat.response.denied | Responses denied because of security concerns. For HTTP this is because of a matched http-request rule, or "option checkcache". | integer |
| haproxy.stat.response.errors | Number of response errors. This value includes the number of data transfers aborted by the server (haproxy.stat.server.aborted). Some other errors are: \* write errors on the client socket (won't be counted for the server stat) \* failure applying filters to the response | long |
| haproxy.stat.response.http.1xx | HTTP responses with 1xx code. | long |
| haproxy.stat.response.http.2xx | HTTP responses with 2xx code. | long |
| haproxy.stat.response.http.3xx | HTTP responses with 3xx code. | long |
| haproxy.stat.response.http.4xx | HTTP responses with 4xx code. | long |
| haproxy.stat.response.http.5xx | HTTP responses with 5xx code. | long |
| haproxy.stat.response.http.other | HTTP responses with other codes (protocol error). | long |
| haproxy.stat.response.time.avg | Average response time in ms over the last 1024 requests (0 for TCP). | long |
| haproxy.stat.selected.total | Total number of times a server was selected, either for new sessions, or when re-dispatching. For servers, this field reports the the number of times the server was selected. | long |
| haproxy.stat.server.aborted | Number of data transfers aborted by the server. This value is included in haproxy.stat.response.errors. | integer |
| haproxy.stat.server.active | Number of backend servers that are active, meaning that they are healthy and can receive requests from the load balancer. | integer |
| haproxy.stat.server.backup | Number of backend servers that are backup servers. | integer |
| haproxy.stat.server.id | Server ID (unique inside a proxy). | integer |
| haproxy.stat.service_name | Service name (FRONTEND for frontend, BACKEND for backend, or any name for server/listener). | keyword |
| haproxy.stat.session.current | Number of current sessions. | long |
| haproxy.stat.session.limit | Configured session limit. | long |
| haproxy.stat.session.max | Maximum number of sessions. | long |
| haproxy.stat.session.rate.limit | Configured limit on new sessions per second. | integer |
| haproxy.stat.session.rate.max | Maximum number of new sessions per second. | integer |
| haproxy.stat.session.rate.value | Number of sessions per second over the last elapsed second. | integer |
| haproxy.stat.session.total | Number of all sessions. | long |
| haproxy.stat.source.address | Address of the source. | text |
| haproxy.stat.status | Status (UP, DOWN, NOLB, MAINT, or MAINT(via)...). | keyword |
| haproxy.stat.throttle.pct | Current throttle percentage for the server when slowstart is active, or no value if slowstart is inactive. | scaled_float |
| haproxy.stat.tracked.id | ID of the proxy/server if tracking is enabled. | long |
| haproxy.stat.weight | Total weight (for backends), or server weight (for servers). | long |
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
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.code_signature.digest_algorithm | The hashing algorithm used to sign the process. This value can distinguish signatures when a file is signed multiple times by the same signer but with a different digest algorithm. | keyword |
| process.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| process.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.code_signature.subject_name | Subject name of the code signer | keyword |
| process.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.code_signature.timestamp | Date and time when the code signature was generated and signed. | date |
| process.code_signature.trusted | Stores the trust status of the certificate chain. Validating the trust of the certificate chain may be complicated, and this field should only be populated by tools that actively check the status. | boolean |
| process.code_signature.valid | Boolean to capture if the digital signature is verified against the binary content. Leave unpopulated if a certificate was unchecked. | boolean |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.elf.architecture | Machine architecture of the ELF file. | keyword |
| process.elf.byte_order | Byte sequence of ELF file. | keyword |
| process.elf.cpu_type | CPU type of the ELF file. | keyword |
| process.elf.creation_date | Extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. | date |
| process.elf.exports | List of exported element names and types. | flattened |
| process.elf.header.abi_version | Version of the ELF Application Binary Interface (ABI). | keyword |
| process.elf.header.class | Header class of the ELF file. | keyword |
| process.elf.header.data | Data table of the ELF header. | keyword |
| process.elf.header.entrypoint | Header entrypoint of the ELF file. | long |
| process.elf.header.object_version | "0x1" for original ELF files. | keyword |
| process.elf.header.os_abi | Application Binary Interface (ABI) of the Linux OS. | keyword |
| process.elf.header.type | Header type of the ELF file. | keyword |
| process.elf.header.version | Version of the ELF header. | keyword |
| process.elf.imports | List of imported element names and types. | flattened |
| process.elf.sections | An array containing an object for each section of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.sections.\*`. | nested |
| process.elf.sections.chi2 | Chi-square probability distribution of the section. | long |
| process.elf.sections.entropy | Shannon entropy calculation from the section. | long |
| process.elf.sections.flags | ELF Section List flags. | keyword |
| process.elf.sections.name | ELF Section List name. | keyword |
| process.elf.sections.physical_offset | ELF Section List offset. | keyword |
| process.elf.sections.physical_size | ELF Section List physical size. | long |
| process.elf.sections.type | ELF Section List type. | keyword |
| process.elf.sections.virtual_address | ELF Section List virtual address. | long |
| process.elf.sections.virtual_size | ELF Section List virtual size. | long |
| process.elf.segments | An array containing an object for each segment of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.segments.\*`. | nested |
| process.elf.segments.sections | ELF object segment sections. | keyword |
| process.elf.segments.type | ELF object segment type. | keyword |
| process.elf.shared_libraries | List of shared libraries used by this ELF object. | keyword |
| process.elf.telfhash | telfhash symbol hash for ELF file. | keyword |
| process.end | The time the process ended. | date |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.hash.sha512 | SHA512 hash. | keyword |
| process.hash.ssdeep | SSDEEP hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.parent.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.parent.code_signature.digest_algorithm | The hashing algorithm used to sign the process. This value can distinguish signatures when a file is signed multiple times by the same signer but with a different digest algorithm. | keyword |
| process.parent.code_signature.exists | Boolean to capture if a signature is present. | boolean |
| process.parent.code_signature.signing_id | The identifier used to sign the process. This is used to identify the application manufactured by a software vendor. The field is relevant to Apple \*OS only. | keyword |
| process.parent.code_signature.status | Additional information about the certificate status. This is useful for logging cryptographic errors with the certificate validity or trust status. Leave unpopulated if the validity or trust of the certificate was unchecked. | keyword |
| process.parent.code_signature.subject_name | Subject name of the code signer | keyword |
| process.parent.code_signature.team_id | The team identifier used to sign the process. This is used to identify the team or vendor of a software product. The field is relevant to Apple \*OS only. | keyword |
| process.parent.code_signature.timestamp | Date and time when the code signature was generated and signed. | date |
| process.parent.code_signature.trusted | Stores the trust status of the certificate chain. Validating the trust of the certificate chain may be complicated, and this field should only be populated by tools that actively check the status. | boolean |
| process.parent.code_signature.valid | Boolean to capture if the digital signature is verified against the binary content. Leave unpopulated if a certificate was unchecked. | boolean |
| process.parent.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.parent.command_line.text | Multi-field of `process.parent.command_line`. | match_only_text |
| process.parent.elf.architecture | Machine architecture of the ELF file. | keyword |
| process.parent.elf.byte_order | Byte sequence of ELF file. | keyword |
| process.parent.elf.cpu_type | CPU type of the ELF file. | keyword |
| process.parent.elf.creation_date | Extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. | date |
| process.parent.elf.exports | List of exported element names and types. | flattened |
| process.parent.elf.header.abi_version | Version of the ELF Application Binary Interface (ABI). | keyword |
| process.parent.elf.header.class | Header class of the ELF file. | keyword |
| process.parent.elf.header.data | Data table of the ELF header. | keyword |
| process.parent.elf.header.entrypoint | Header entrypoint of the ELF file. | long |
| process.parent.elf.header.object_version | "0x1" for original ELF files. | keyword |
| process.parent.elf.header.os_abi | Application Binary Interface (ABI) of the Linux OS. | keyword |
| process.parent.elf.header.type | Header type of the ELF file. | keyword |
| process.parent.elf.header.version | Version of the ELF header. | keyword |
| process.parent.elf.imports | List of imported element names and types. | flattened |
| process.parent.elf.sections | An array containing an object for each section of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.sections.\*`. | nested |
| process.parent.elf.sections.chi2 | Chi-square probability distribution of the section. | long |
| process.parent.elf.sections.entropy | Shannon entropy calculation from the section. | long |
| process.parent.elf.sections.flags | ELF Section List flags. | keyword |
| process.parent.elf.sections.name | ELF Section List name. | keyword |
| process.parent.elf.sections.physical_offset | ELF Section List offset. | keyword |
| process.parent.elf.sections.physical_size | ELF Section List physical size. | long |
| process.parent.elf.sections.type | ELF Section List type. | keyword |
| process.parent.elf.sections.virtual_address | ELF Section List virtual address. | long |
| process.parent.elf.sections.virtual_size | ELF Section List virtual size. | long |
| process.parent.elf.segments | An array containing an object for each segment of the ELF file. The keys that should be present in these objects are defined by sub-fields underneath `elf.segments.\*`. | nested |
| process.parent.elf.segments.sections | ELF object segment sections. | keyword |
| process.parent.elf.segments.type | ELF object segment type. | keyword |
| process.parent.elf.shared_libraries | List of shared libraries used by this ELF object. | keyword |
| process.parent.elf.telfhash | telfhash symbol hash for ELF file. | keyword |
| process.parent.end | The time the process ended. | date |
| process.parent.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.parent.executable | Absolute path to the process executable. | keyword |
| process.parent.executable.text | Multi-field of `process.parent.executable`. | match_only_text |
| process.parent.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.parent.hash.md5 | MD5 hash. | keyword |
| process.parent.hash.sha1 | SHA1 hash. | keyword |
| process.parent.hash.sha256 | SHA256 hash. | keyword |
| process.parent.hash.sha512 | SHA512 hash. | keyword |
| process.parent.hash.ssdeep | SSDEEP hash. | keyword |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.parent.pe.architecture | CPU architecture target for the file. | keyword |
| process.parent.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| process.parent.pe.description | Internal description of the file, provided at compile-time. | keyword |
| process.parent.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| process.parent.pe.imphash | A hash of the imports in a PE file. An imphash -- or import hash -- can be used to fingerprint binaries even after recompilation or other code-level transformations have occurred, which would change more traditional hash values. Learn more at https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html. | keyword |
| process.parent.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| process.parent.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| process.parent.pgid | Identifier of the group of processes the process belongs to. | long |
| process.parent.pid | Process id. | long |
| process.parent.start | The time the process started. | date |
| process.parent.thread.id | Thread ID. | long |
| process.parent.thread.name | Thread name. | keyword |
| process.parent.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.parent.title.text | Multi-field of `process.parent.title`. | match_only_text |
| process.parent.uptime | Seconds the process has been up. | long |
| process.parent.working_directory | The working directory of the process. | keyword |
| process.parent.working_directory.text | Multi-field of `process.parent.working_directory`. | match_only_text |
| process.pe.architecture | CPU architecture target for the file. | keyword |
| process.pe.company | Internal company name of the file, provided at compile-time. | keyword |
| process.pe.description | Internal description of the file, provided at compile-time. | keyword |
| process.pe.file_version | Internal version of the file, provided at compile-time. | keyword |
| process.pe.imphash | A hash of the imports in a PE file. An imphash -- or import hash -- can be used to fingerprint binaries even after recompilation or other code-level transformations have occurred, which would change more traditional hash values. Learn more at https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html. | keyword |
| process.pe.original_file_name | Internal name of the file, provided at compile-time. | keyword |
| process.pe.product | Internal product name of the file, provided at compile-time. | keyword |
| process.pgid | Identifier of the group of processes the process belongs to. | long |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| process.thread.id | Thread ID. | long |
| process.thread.name | Thread name. | keyword |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| process.uptime | Seconds the process has been up. | long |
| process.working_directory | The working directory of the process. | keyword |
| process.working_directory.text | Multi-field of `process.working_directory`. | match_only_text |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |

