# HAProxy Integration

This integration periodically fetches logs and metrics from [HAProxy](https://www.haproxy.org/) servers.

The Integration can collect metrics in three datastreams from HAProxy: `info`, `stat` and `metrics`. `info` is not available when using the stats page. For more information, refer to the [HAProxy module](https://www.elastic.co/docs/reference/beats/metricbeat/metricbeat-module-haproxy).

## Compatibility

The `log` dataset was tested with logs from HAProxy `1.8`, `1.9` and `2.0`, `2.6`, `3.2` running on a Debian. It is not available on Windows. 
The integration supports the following default log patterns:
* [Default log format](https://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.1)
* [TCP log format](https://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.2)
* [HTTP log format](https://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.3)
* [HTTPS log format](https://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.4)
* [Error log format](https://cbonte.github.io/haproxy-dconv/2.6/configuration.html#8.2.5)

The `info` and `stat` datasets were tested with HAProxy versions from `1.6`, `1.7`, `1.8` to `3.2`.  
The `metrics` dataset collects metrics from Prometheus metrics. It was tested with HAProxy `2.8` and `3.2`. In Haproxy it was introduced in `2.0`. For configuration instructions, refer to the [HAProxy documentation](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/alerts-and-monitoring/prometheus/).

## Troubleshooting

If `source.address` is shown conflicted under ``metrics-*`` data view, then this issue can be solved by [reindexing](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds-reindex.html) the `stat` data stream indices.

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
        "version": "8.11.0"
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
            "02-42-AC-1F-00-07"
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

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| haproxy.backend_name | Name of the backend (or listener) which was selected to manage the connection to the server. | keyword |
| haproxy.backend_queue | Total number of requests which were processed before this one in the backend's global queue. | long |
| haproxy.bind_name | Name of the listening address which received the connection. | keyword |
| haproxy.bytes_read | Total number of bytes transmitted to the client when the log is emitted. | long |
| haproxy.connection_wait_time_ms | Total time in milliseconds spent waiting for the connection to establish to the final server | long |
| haproxy.connections.active | Total number of concurrent connections on the process when the session was logged. | long |
| haproxy.connections.backend | Total number of concurrent connections handled by the backend when the session was logged. | long |
| haproxy.connections.fc_err | Returns the ID of the error that might have occurred on the current connection. Any strictly positive value of this fetch indicates that the connection did not succeed and would result in an error log being output | long |
| haproxy.connections.frontend | Total number of concurrent connections on the frontend when the session was logged. | long |
| haproxy.connections.retries | Number of connection retries experienced by this session when trying to connect to the server. | long |
| haproxy.connections.server | Total number of concurrent connections still active on the server when the session was logged. | long |
| haproxy.connections.ssl_c_ca_err | When the incoming connection was made over an SSL/TLS transport layer, returns the ID of the first error detected during verification of the client certificate at depth \> 0, or 0 if no error was encountered during this verification process. | long |
| haproxy.connections.ssl_c_err | When the incoming connection was made over an SSL/TLS transport layer, returns the ID of the first error detected during verification at depth 0, or 0 if no error was encountered during this verification process. | long |
| haproxy.connections.ssl_fc_err | When the incoming connection was made over an SSL/TLS transport layer, returns the ID of the last error of the first error stack raised on the frontend side, or 0 if no error was encountered. It can be used to identify handshake related errors other than verify ones (such as cipher mismatch), as well as other read or write errors occurring during the connection's lifetime. | long |
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
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |



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

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| haproxy.info.busy_polling | Number of busy polling. | long | gauge |
| haproxy.info.bytes.out.rate | Average bytes output rate. | long | gauge |
| haproxy.info.bytes.out.total | Number of bytes sent out. | long | gauge |
| haproxy.info.compress.bps.in | Incoming compressed data in bits per second. | long | gauge |
| haproxy.info.compress.bps.out | Outgoing compressed data in bits per second. | long | gauge |
| haproxy.info.compress.bps.rate_limit | Rate limit of compressed data in bits per second. | long | gauge |
| haproxy.info.connection.current | Current connections. | long | gauge |
| haproxy.info.connection.hard_max |  | long | gauge |
| haproxy.info.connection.max | Maximum connections. | long | gauge |
| haproxy.info.connection.rate.limit | Rate limit of connections. | long | gauge |
| haproxy.info.connection.rate.max | Maximum rate of connections. | long | gauge |
| haproxy.info.connection.rate.value | Number of connections in the last second. | long | gauge |
| haproxy.info.connection.ssl.current | Current SSL connections. | long | gauge |
| haproxy.info.connection.ssl.max | Maximum SSL connections. | long | gauge |
| haproxy.info.connection.ssl.total | Total SSL connections. | long | counter |
| haproxy.info.connection.total | Total connections. | long | counter |
| haproxy.info.dropped_logs | Number of dropped logs. | long | gauge |
| haproxy.info.failed_resolutions | Number of failed resolutions. | long | gauge |
| haproxy.info.idle.pct | Percentage of idle time. | scaled_float | gauge |
| haproxy.info.jobs | Number of all jobs. | long | gauge |
| haproxy.info.listeners | Number of listeners. | long | gauge |
| haproxy.info.memory.max.bytes | Maximum amount of memory usage in bytes (the 'Memmax_MB' value converted to bytes). | long | gauge |
| haproxy.info.peers.active | Number of active peers. | long | gauge |
| haproxy.info.peers.connected | Number of connected peers. | long | gauge |
| haproxy.info.pipes.free | Number of free pipes. | integer | gauge |
| haproxy.info.pipes.max | Maximum number of used pipes. | integer | gauge |
| haproxy.info.pipes.used | Number of used pipes during kernel-based tcp splicing. | integer | gauge |
| haproxy.info.pool.allocated | Size of the allocated pool. | long | gauge |
| haproxy.info.pool.failed | Number of failed connections to pool members. | long | counter |
| haproxy.info.pool.used | Number of members used from the allocated pool. | long | gauge |
| haproxy.info.process_num | Process number. | long | gauge |
| haproxy.info.processes | Number of processes. | long | gauge |
| haproxy.info.requests.max | Maximum number of requests. | long | gauge |
| haproxy.info.requests.total | Total number of requests. | long | counter |
| haproxy.info.run_queue |  | long | gauge |
| haproxy.info.session.rate.limit | Rate limit of sessions. | integer | gauge |
| haproxy.info.session.rate.max | Maximum rate of sessions. | integer | gauge |
| haproxy.info.session.rate.value | Rate of session per seconds. | integer | gauge |
| haproxy.info.sockets.max | Maximum number of sockets. | long | gauge |
| haproxy.info.ssl.backend.key_rate.max | Maximum key rate of SSL backend sessions. | integer | gauge |
| haproxy.info.ssl.backend.key_rate.value | Key rate of SSL backend sessions. | integer | gauge |
| haproxy.info.ssl.cache_misses | Number of SSL cache misses. | long | counter |
| haproxy.info.ssl.cached_lookups | Number of SSL cache lookups. | long | counter |
| haproxy.info.ssl.frontend.key_rate.max | Maximum key rate of SSL frontend. | integer | gauge |
| haproxy.info.ssl.frontend.key_rate.value | Key rate of SSL frontend. | integer | gauge |
| haproxy.info.ssl.frontend.session_reuse.pct | Rate of reuse of SSL frontend sessions. | scaled_float | gauge |
| haproxy.info.ssl.rate.limit | Rate limit of SSL requests. | integer | gauge |
| haproxy.info.ssl.rate.max | Maximum rate of SSL requests. | integer | gauge |
| haproxy.info.ssl.rate.value | Rate of SSL requests. | integer | gauge |
| haproxy.info.stopping | Number of stopping jobs. | long | gauge |
| haproxy.info.tasks |  | long | gauge |
| haproxy.info.threads | Number of threads. | long | gauge |
| haproxy.info.ulimit_n | Maximum number of open files for the process. | long | gauge |
| haproxy.info.unstoppable_jobs | Number of unstoppable jobs. | long | gauge |
| haproxy.info.uptime.sec | Current uptime in seconds. | long | gauge |
| haproxy.info.zlib_mem_usage.max | Maximum memory usage of zlib. | integer | gauge |
| haproxy.info.zlib_mem_usage.value | Memory usage of zlib. | integer | gauge |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| process.pid | Process id. | long |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


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

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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
| haproxy.stat.agent.check.description | Human readable version of check. | keyword |  |
| haproxy.stat.agent.check.fall | Fall value of server. | integer |  |
| haproxy.stat.agent.check.health | Health parameter of server. Between 0 and `agent.check.rise`+`agent.check.fall`-1. | integer |  |
| haproxy.stat.agent.check.rise | Rise value of server. | integer |  |
| haproxy.stat.agent.code | Value reported by agent. | integer |  |
| haproxy.stat.agent.description | Human readable version of agent.status. | keyword |  |
| haproxy.stat.agent.duration | Duration of the last check in ms. | integer |  |
| haproxy.stat.agent.fall | Fall value of agent. | integer |  |
| haproxy.stat.agent.health | Health parameter of agent. Between 0 and `agent.rise`+`agent.fall`-1. | integer |  |
| haproxy.stat.agent.rise | Rise value of agent. | integer |  |
| haproxy.stat.agent.status | Status of the last health check. One of:    UNK     -\> unknown   INI     -\> initializing   SOCKERR -\> socket error   L4OK    -\> check passed on layer 4, no upper layers enabled   L4TOUT  -\> layer 1-4 timeout   L4CON   -\> layer 1-4 connection problem, for example             "Connection refused" (tcp rst) or "No route to host" (icmp)   L7OK    -\> agent reported "up"   L7STS   -\> agent reported "fail", "stop" or "down" | keyword |  |
| haproxy.stat.check.agent.last |  | integer |  |
| haproxy.stat.check.code | Layer 5-7 code, if available. | long |  |
| haproxy.stat.check.down | Number of UP-\>DOWN transitions. For backends, this value is the number of transitions to the whole backend being down, rather than the sum of the transitions for each server. | long | counter |
| haproxy.stat.check.duration | Time in ms that it took to finish the last health check. | long | gauge |
| haproxy.stat.check.failed | Number of checks that failed while the server was up. | long | counter |
| haproxy.stat.check.health.fail | Number of failed checks. | long |  |
| haproxy.stat.check.health.last | The result of the last health check. | keyword |  |
| haproxy.stat.check.status | Status of the last health check. One of:    UNK     -\> unknown   INI     -\> initializing   SOCKERR -\> socket error   L4OK    -\> check passed on layer 4, no upper layers testing enabled   L4TOUT  -\> layer 1-4 timeout   L4CON   -\> layer 1-4 connection problem, for example             "Connection refused" (tcp rst) or "No route to host" (icmp)   L6OK    -\> check passed on layer 6   L6TOUT  -\> layer 6 (SSL) timeout   L6RSP   -\> layer 6 invalid response - protocol error   L7OK    -\> check passed on layer 7   L7OKC   -\> check conditionally passed on layer 7, for example 404 with             disable-on-404   L7TOUT  -\> layer 7 (HTTP/SMTP) timeout   L7RSP   -\> layer 7 invalid response - protocol error   L7STS   -\> layer 7 response error, for example HTTP 5xx | keyword |  |
| haproxy.stat.client.aborted | Number of data transfers aborted by the client. | integer | counter |
| haproxy.stat.component_type | Component type (0=frontend, 1=backend, 2=server, or 3=socket/listener). | integer |  |
| haproxy.stat.compressor.bypassed.bytes | Number of bytes that bypassed the HTTP compressor (CPU/BW limit). | long | counter |
| haproxy.stat.compressor.in.bytes | Number of HTTP response bytes fed to the compressor. | long | counter |
| haproxy.stat.compressor.out.bytes | Number of HTTP response bytes emitted by the compressor. | integer | counter |
| haproxy.stat.compressor.response.bytes | Number of HTTP responses that were compressed. | long | counter |
| haproxy.stat.connection.attempt.total | Number of connection establishment attempts. | long | counter |
| haproxy.stat.connection.cache.hits | Number of cache hits. | long | counter |
| haproxy.stat.connection.cache.lookup.total | Number of cache lookups. | long | counter |
| haproxy.stat.connection.idle.limit | Limit on idle connections available for reuse. | long | gauge |
| haproxy.stat.connection.idle.total | Number of idle connections available for reuse. | long | gauge |
| haproxy.stat.connection.rate | Number of connections over the last second. | long | gauge |
| haproxy.stat.connection.rate_max | Highest value of connection.rate. | long | gauge |
| haproxy.stat.connection.retried | Number of times a connection to a server was retried. | long | counter |
| haproxy.stat.connection.reuse.total | Number of connection reuses. | long | counter |
| haproxy.stat.connection.time.avg | Average connect time in ms over the last 1024 requests. | long | gauge |
| haproxy.stat.connection.total | Cumulative number of frontend connections. | long | counter |
| haproxy.stat.cookie | Cookie value of the server or the name of the cookie of the backend. | keyword |  |
| haproxy.stat.downtime | Total downtime (in seconds). For backends, this value is the downtime for the whole backend, not the sum of the downtime for the servers. | long | counter |
| haproxy.stat.header.rewrite.failed.total | Number of failed header rewrite warnings. | long | counter |
| haproxy.stat.in.bytes | Bytes in. | long | counter |
| haproxy.stat.last_change | Number of seconds since the last UP-\>DOWN or DOWN-\>UP transition. | integer | gauge |
| haproxy.stat.load_balancing_algorithm | Load balancing algorithm. | keyword |  |
| haproxy.stat.out.bytes | Bytes out. | long | counter |
| haproxy.stat.proxy.id | Unique proxy ID. | integer |  |
| haproxy.stat.proxy.mode | Proxy mode (tcp, http, health, unknown). | keyword |  |
| haproxy.stat.proxy.name | Proxy name. | keyword |  |
| haproxy.stat.queue.limit | Configured queue limit (maxqueue) for the server, or nothing if the value of maxqueue is 0 (meaning no limit). | integer |  |
| haproxy.stat.queue.time.avg | The average queue time in ms over the last 1024 requests. | integer | gauge |
| haproxy.stat.request.connection.errors | Number of requests that encountered an error trying to connect to a server. For backends, this field reports the sum of the stat for all backend servers, plus any connection errors not associated with a particular server (such as the backend having no active servers). | long | counter |
| haproxy.stat.request.denied | Requests denied because of security concerns.    \* For TCP this is because of a matched tcp-request content rule.   \* For HTTP this is because of a matched http-request or tarpit rule. | long | counter |
| haproxy.stat.request.denied_by_connection_rules | Requests denied because of TCP request connection rules. | long | counter |
| haproxy.stat.request.denied_by_session_rules | Requests denied because of TCP request session rules. | long | counter |
| haproxy.stat.request.errors | Request errors. Some of the possible causes are:    \* early termination from the client, before the request has been sent   \* read error from the client   \* client timeout   \* client closed connection   \* various bad requests from the client.   \* request was tarpitted. | long | counter |
| haproxy.stat.request.intercepted | Number of intercepted requests. | long | counter |
| haproxy.stat.request.queued.current | Current queued requests. For backends, this field reports the number of requests queued without a server assigned. | long | gauge |
| haproxy.stat.request.queued.max | Maximum value of queued.current. | long | gauge |
| haproxy.stat.request.rate.max | Maximum number of HTTP requests per second. | long | gauge |
| haproxy.stat.request.rate.value | Number of HTTP requests per second over the last elapsed second. | long | gauge |
| haproxy.stat.request.redispatched | Number of times a request was redispatched to another server. For servers, this field reports the number of times the server was switched away from. | long | counter |
| haproxy.stat.request.total | Total number of HTTP requests received. | long | counter |
| haproxy.stat.response.denied | Responses denied because of security concerns. For HTTP this is because of a matched http-request rule, or "option checkcache". | integer | counter |
| haproxy.stat.response.errors | Number of response errors. This value includes the number of data transfers aborted by the server (haproxy.stat.server.aborted). Some other errors are: \* write errors on the client socket (won't be counted for the server stat) \* failure applying filters to the response | long | counter |
| haproxy.stat.response.http.1xx | HTTP responses with 1xx code. | long | counter |
| haproxy.stat.response.http.2xx | HTTP responses with 2xx code. | long | counter |
| haproxy.stat.response.http.3xx | HTTP responses with 3xx code. | long | counter |
| haproxy.stat.response.http.4xx | HTTP responses with 4xx code. | long | counter |
| haproxy.stat.response.http.5xx | HTTP responses with 5xx code. | long | counter |
| haproxy.stat.response.http.other | HTTP responses with other codes (protocol error). | long | counter |
| haproxy.stat.response.time.avg | Average response time in ms over the last 1024 requests (0 for TCP). | long | gauge |
| haproxy.stat.selected.total | Total number of times a server was selected, either for new sessions, or when re-dispatching. For servers, this field reports the the number of times the server was selected. | long | counter |
| haproxy.stat.server.aborted | Number of data transfers aborted by the server. This value is included in haproxy.stat.response.errors. | integer | counter |
| haproxy.stat.server.active | Number of backend servers that are active, meaning that they are healthy and can receive requests from the load balancer. | integer | gauge |
| haproxy.stat.server.backup | Number of backend servers that are backup servers. | integer | gauge |
| haproxy.stat.server.id | Server ID (unique inside a proxy). | integer |  |
| haproxy.stat.service_name | Service name (FRONTEND for frontend, BACKEND for backend, or any name for server/listener). | keyword |  |
| haproxy.stat.session.current | Number of current sessions. | long | gauge |
| haproxy.stat.session.limit | Configured session limit. | long | gauge |
| haproxy.stat.session.max | Maximum number of sessions. | long | gauge |
| haproxy.stat.session.rate.limit | Configured limit on new sessions per second. | integer | gauge |
| haproxy.stat.session.rate.max | Maximum number of new sessions per second. | integer | gauge |
| haproxy.stat.session.rate.value | Number of sessions per second over the last elapsed second. | integer | gauge |
| haproxy.stat.session.total | Number of all sessions. | long | counter |
| haproxy.stat.source.address | Address of the source. | keyword |  |
| haproxy.stat.status | Status (UP, DOWN, NOLB, MAINT, or MAINT(via)...). | keyword |  |
| haproxy.stat.throttle.pct | Current throttle percentage for the server when slowstart is active, or no value if slowstart is inactive. | scaled_float | gauge |
| haproxy.stat.tracked.id | ID of the proxy/server if tracking is enabled. | long |  |
| haproxy.stat.weight | Total weight (for backends), or server weight (for servers). | long | gauge |
| host.containerized | If the host is a container. | boolean |  |
| host.name | Name of the host.  It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| process.pid | Process id. | long |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |


### metrics

The HAProxy `metrics` metricset collects metric fields from HAProxy Prometheus metrics.

An example event for `metrics` looks as following:

```json
{
    "@timestamp": "2026-03-24T00:27:13.407Z",
    "agent": {
        "ephemeral_id": "70c712a8-e9ce-4360-ad68-a47aad61bc02",
        "id": "bdfe958f-242b-4f40-8cc5-93f6388e5345",
        "name": "EPGETBIW05AD",
        "type": "metricbeat",
        "version": "9.3.1"
    },
    "data_stream": {
        "dataset": "haproxy.metrics",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "bdfe958f-242b-4f40-8cc5-93f6388e5345",
        "snapshot": false,
        "version": "9.3.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "haproxy.metrics",
        "duration": 10873000,
        "ingested": "2026-03-24T00:27:13Z",
        "module": "prometheus"
    },
    "haproxy": {
        "metrics": {
            "haproxy_frontend_bytes_in_total": 17229,
            "haproxy_frontend_bytes_out_total": 2084777,
            "haproxy_frontend_connections_rate_max": 6,
            "haproxy_frontend_connections_total": 46,
            "haproxy_frontend_current_session_rate": 1,
            "haproxy_frontend_current_sessions": 1,
            "haproxy_frontend_denied_connections_total": 0,
            "haproxy_frontend_denied_sessions_total": 0,
            "haproxy_frontend_failed_header_rewriting_total": 0,
            "haproxy_frontend_http_cache_hits_total": 0,
            "haproxy_frontend_http_cache_lookups_total": 0,
            "haproxy_frontend_http_comp_bytes_bypassed_total": 0,
            "haproxy_frontend_http_comp_bytes_in_total": 0,
            "haproxy_frontend_http_comp_bytes_out_total": 0,
            "haproxy_frontend_http_comp_responses_total": 0,
            "haproxy_frontend_http_requests_rate_max": 6,
            "haproxy_frontend_http_requests_total": 46,
            "haproxy_frontend_intercepted_requests_total": 31,
            "haproxy_frontend_internal_errors_total": 0,
            "haproxy_frontend_limit_session_rate": 0,
            "haproxy_frontend_limit_sessions": 25000,
            "haproxy_frontend_max_session_rate": 6,
            "haproxy_frontend_max_sessions": 2,
            "haproxy_frontend_request_errors_total": 0,
            "haproxy_frontend_requests_denied_total": 0,
            "haproxy_frontend_responses_denied_total": 0,
            "haproxy_frontend_sessions_total": 46
        }
    },
    "host": {
        "architecture": "arm64",
        "hostname": "EPGETBIW05AD",
        "id": "EA0EF0A6-3698-566E-93AD-49EC580C1969",
        "ip": [
            "192.168.8.247",
            "fe80::432:f789:5d89:8418",
            "fe80::4e2:681:a281:2d4d",
            "fe80::1036:28ff:fe7c:649e",
            "fe80::a2a5:e63d:cc82:b7ef",
            "fe80::ce81:b1c:bd2c:69e",
            "fe80::ed2d:e501:f5f3:db4f"
        ],
        "mac": [
            "12-36-28-7C-64-9E",
            "1A-52-43-7C-F8-C2",
            "36-BD-64-BA-FB-00",
            "36-BD-64-BA-FB-04",
            "36-BD-64-BA-FB-08",
            "42-29-38-E4-A3-AA",
            "42-29-38-E4-A3-AB",
            "42-29-38-E4-A3-AC",
            "42-29-38-E4-A3-CA",
            "42-29-38-E4-A3-CB",
            "42-29-38-E4-A3-CC",
            "A6-51-3F-B3-70-0A"
        ],
        "name": "epgetbiw05ad",
        "os": {
            "build": "25D2128",
            "family": "darwin",
            "kernel": "25.3.0",
            "name": "macOS",
            "platform": "darwin",
            "type": "macos",
            "version": "26.3.1"
        }
    },
    "metricset": {
        "name": "collector",
        "period": 10000
    },
    "service": {
        "address": "http://localhost:8405/metrics",
        "type": "prometheus"
    }
}
```

The fields reported are:

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| container.id | Unique container id. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| haproxy.metrics.haproxy_backend_active_servers | Total number of active UP servers with a non-zero weight | double | gauge |
| haproxy.metrics.haproxy_backend_agg_check_status | Backend's aggregated gauge of servers' state check status | double | gauge |
| haproxy.metrics.haproxy_backend_agg_server_check_status | [DEPRECATED] Backend's aggregated gauge of servers' status | double | gauge |
| haproxy.metrics.haproxy_backend_agg_server_status | Backend's aggregated gauge of servers' status | double | gauge |
| haproxy.metrics.haproxy_backend_backup_servers | Total number of backup UP servers with a non-zero weight | double | gauge |
| haproxy.metrics.haproxy_backend_bytes_in_total | Total number of request bytes since process started | long | counter |
| haproxy.metrics.haproxy_backend_bytes_out_total | Total number of response bytes since process started | long | counter |
| haproxy.metrics.haproxy_backend_check_last_change_seconds | How long ago the last server state changed, in seconds | double | gauge |
| haproxy.metrics.haproxy_backend_check_up_down_total | Total number of failed checks causing UP to DOWN server transitions, per server/backend, since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_client_aborts_total | Total number of requests or connections aborted by the client since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_connect_time_average_seconds | Avg. connect time for last 1024 successful connections. | double | gauge |
| haproxy.metrics.haproxy_backend_connection_attempts_total | Total number of outgoing connection attempts on this backend/server since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_connection_errors_total | Total number of failed connections to server since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_connection_reuses_total | Total number of reused connection on this backend/server since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_current_queue | Number of current queued connections | double | gauge |
| haproxy.metrics.haproxy_backend_current_session_rate | Total number of sessions processed by this object over the last second (sessions for listeners/frontends, requests for backends/servers) | double | gauge |
| haproxy.metrics.haproxy_backend_current_sessions | Number of current sessions on the frontend, backend or server | double | gauge |
| haproxy.metrics.haproxy_backend_downtime_seconds_total | Total time spent in DOWN state, for server or backend | double | gauge |
| haproxy.metrics.haproxy_backend_failed_header_rewriting_total | Total number of failed HTTP header rewrites since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_http_cache_hits_total | Total number of HTTP requests not found in the cache on this frontend/backend since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_http_cache_lookups_total | Total number of HTTP requests looked up in the cache on this frontend/backend since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_http_comp_bytes_bypassed_total | Total number of bytes that bypassed HTTP compression for this object since the worker process started (CPU/memory/bandwidth limitation) | long | counter |
| haproxy.metrics.haproxy_backend_http_comp_bytes_in_total | Total number of bytes submitted to the HTTP compressor for this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_http_comp_bytes_out_total | Total number of bytes emitted by the HTTP compressor for this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_http_comp_responses_total | Total number of HTTP responses that were compressed for this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_http_requests_total | Total number of HTTP requests processed by this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_http_responses_total | Total number of HTTP responses with status 100-199 returned by this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_internal_errors_total | Total number of internal errors since process started | long | counter |
| haproxy.metrics.haproxy_backend_last_session_seconds | How long ago some traffic was seen on this object on this worker process, in seconds | double | gauge |
| haproxy.metrics.haproxy_backend_limit_sessions | Frontend/listener/server's maxconn, backend's fullconn | double | gauge |
| haproxy.metrics.haproxy_backend_loadbalanced_total | Total number of requests routed by load balancing since the worker process started (ignores queue pop and stickiness) | long | counter |
| haproxy.metrics.haproxy_backend_max_connect_time_seconds | Maximum observed time spent waiting for a connection to complete | double | gauge |
| haproxy.metrics.haproxy_backend_max_queue | Highest value of queued connections encountered since process started | double | gauge |
| haproxy.metrics.haproxy_backend_max_queue_time_seconds | Maximum observed time spent in the queue | double | gauge |
| haproxy.metrics.haproxy_backend_max_response_time_seconds | Maximum observed time spent waiting for a server response | double | gauge |
| haproxy.metrics.haproxy_backend_max_session_rate | Highest value of sessions per second observed since the worker process started | double | gauge |
| haproxy.metrics.haproxy_backend_max_sessions | Highest value of current sessions encountered since process started | double | gauge |
| haproxy.metrics.haproxy_backend_max_total_time_seconds | Maximum observed total request+response time (request+queue+connect+response+processing) | double | gauge |
| haproxy.metrics.haproxy_backend_queue_time_average_seconds | Avg. queue time for last 1024 successful connections. | double | gauge |
| haproxy.metrics.haproxy_backend_redispatch_warnings_total | Total number of server redispatches due to connection failures since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_requests_denied_total | Total number of denied requests since process started | long | counter |
| haproxy.metrics.haproxy_backend_response_errors_total | Total number of invalid responses since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_response_time_average_seconds | Avg. response time for last 1024 successful connections. | double | gauge |
| haproxy.metrics.haproxy_backend_responses_denied_total | Total number of denied responses since process started | long | counter |
| haproxy.metrics.haproxy_backend_retry_warnings_total | Total number of server connection retries since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_server_aborts_total | Total number of requests or connections aborted by the server since the worker process started | long | counter |
| haproxy.metrics.haproxy_backend_sessions_total | Total number of sessions since process started | long | counter |
| haproxy.metrics.haproxy_backend_status | Current status of the service, per state label value. | double | gauge |
| haproxy.metrics.haproxy_backend_total_time_average_seconds | Avg. total time for last 1024 successful connections. | double | gauge |
| haproxy.metrics.haproxy_backend_uweight | Server's user weight, or sum of active servers' user weights for a backend | double | gauge |
| haproxy.metrics.haproxy_backend_weight | Server's effective weight, or sum of active servers' effective weights for a backend | double | gauge |
| haproxy.metrics.haproxy_frontend_bytes_in_total | Total number of request bytes since process started | long | counter |
| haproxy.metrics.haproxy_frontend_bytes_out_total | Total number of response bytes since process started | long | counter |
| haproxy.metrics.haproxy_frontend_connections_rate_max | Highest value of connections per second observed since the worker process started | double | gauge |
| haproxy.metrics.haproxy_frontend_connections_total | Total number of new connections accepted on this frontend since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_current_session_rate | Total number of sessions processed by this object over the last second (sessions for listeners/frontends, requests for backends/servers) | double | gauge |
| haproxy.metrics.haproxy_frontend_current_sessions | Number of current sessions on the frontend, backend or server | double | gauge |
| haproxy.metrics.haproxy_frontend_denied_connections_total | Total number of incoming connections blocked on a listener/frontend by a tcp-request connection rule since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_denied_sessions_total | Total number of incoming sessions blocked on a listener/frontend by a tcp-request connection rule since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_failed_header_rewriting_total | Total number of failed HTTP header rewrites since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_http_cache_hits_total | Total number of HTTP requests not found in the cache on this frontend/backend since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_http_cache_lookups_total | Total number of HTTP requests looked up in the cache on this frontend/backend since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_http_comp_bytes_bypassed_total | Total number of bytes that bypassed HTTP compression for this object since the worker process started (CPU/memory/bandwidth limitation) | long | counter |
| haproxy.metrics.haproxy_frontend_http_comp_bytes_in_total | Total number of bytes submitted to the HTTP compressor for this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_http_comp_bytes_out_total | Total number of bytes emitted by the HTTP compressor for this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_http_comp_responses_total | Total number of HTTP responses that were compressed for this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_http_requests_rate_max | Highest value of http requests observed since the worker process started | double | gauge |
| haproxy.metrics.haproxy_frontend_http_requests_total | Total number of HTTP requests processed by this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_http_responses_total | Total number of HTTP responses with status 100-199 returned by this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_intercepted_requests_total | Total number of HTTP requests intercepted on the frontend (redirects/stats/services) since the worker process started | long | counter |
| haproxy.metrics.haproxy_frontend_internal_errors_total | Total number of internal errors since process started | long | counter |
| haproxy.metrics.haproxy_frontend_limit_session_rate | Limit on the number of sessions accepted in a second (frontend only, 'rate-limit sessions' setting) | double | gauge |
| haproxy.metrics.haproxy_frontend_limit_sessions | Frontend/listener/server's maxconn, backend's fullconn | double | gauge |
| haproxy.metrics.haproxy_frontend_max_session_rate | Highest value of sessions per second observed since the worker process started | double | gauge |
| haproxy.metrics.haproxy_frontend_max_sessions | Highest value of current sessions encountered since process started | double | gauge |
| haproxy.metrics.haproxy_frontend_request_errors_total | Total number of invalid requests since process started | long | counter |
| haproxy.metrics.haproxy_frontend_requests_denied_total | Total number of denied requests since process started | long | counter |
| haproxy.metrics.haproxy_frontend_responses_denied_total | Total number of denied responses since process started | long | counter |
| haproxy.metrics.haproxy_frontend_sessions_total | Total number of sessions since process started | long | counter |
| haproxy.metrics.haproxy_frontend_status | Current status of the service, per state label value. | double | gauge |
| haproxy.metrics.haproxy_process_active_peers | Current number of verified active peers connections on the current worker process | double | gauge |
| haproxy.metrics.haproxy_process_build_info | Build info | double | gauge |
| haproxy.metrics.haproxy_process_busy_polling_enabled | 1 if busy-polling is currently in use on the worker process, otherwise zero (config.busy-polling) | double | gauge |
| haproxy.metrics.haproxy_process_bytes_out_rate | Number of bytes emitted by current worker process over the last second | double | gauge |
| haproxy.metrics.haproxy_process_bytes_out_total | Total number of bytes emitted by current worker process since started | long | counter |
| haproxy.metrics.haproxy_process_connected_peers | Current number of peers having passed the connection step on the current worker process | double | gauge |
| haproxy.metrics.haproxy_process_connections_total | Total number of connections on this worker process since started | long | counter |
| haproxy.metrics.haproxy_process_current_backend_ssl_key_rate | Number of SSL keys created on backends in this worker process over the last second | double | gauge |
| haproxy.metrics.haproxy_process_current_connection_rate | Number of front connections created on this worker process over the last second | double | gauge |
| haproxy.metrics.haproxy_process_current_connections | Current number of connections on this worker process | double | gauge |
| haproxy.metrics.haproxy_process_current_frontend_ssl_key_rate | Number of SSL keys created on frontends in this worker process over the last second | double | gauge |
| haproxy.metrics.haproxy_process_current_run_queue | Total number of active tasks+tasklets in the current worker process | double | gauge |
| haproxy.metrics.haproxy_process_current_session_rate | Number of sessions created on this worker process over the last second | double | gauge |
| haproxy.metrics.haproxy_process_current_ssl_connections | Current number of SSL endpoints on this worker process (front+back) | double | gauge |
| haproxy.metrics.haproxy_process_current_ssl_rate | Number of SSL connections created on this worker process over the last second | double | gauge |
| haproxy.metrics.haproxy_process_current_tasks | Total number of tasks in the current worker process (active + sleeping) | double | gauge |
| haproxy.metrics.haproxy_process_current_zlib_memory | Amount of memory currently used by HTTP compression on the current worker process (in bytes) | double | gauge |
| haproxy.metrics.haproxy_process_dropped_logs_total | Total number of dropped logs for current worker process since started | long | counter |
| haproxy.metrics.haproxy_process_failed_resolutions | Total number of failed DNS resolutions in current worker process since started | long | counter |
| haproxy.metrics.haproxy_process_frontend_ssl_reuse | Percent of frontend SSL connections which did not require a new key | double | gauge |
| haproxy.metrics.haproxy_process_hard_max_connections | Hard limit on the number of per-process connections (imposed by Memmax_MB or Ulimit-n) | double | gauge |
| haproxy.metrics.haproxy_process_http_comp_bytes_in_total | Number of bytes submitted to the HTTP compressor in this worker process over the last second | long | counter |
| haproxy.metrics.haproxy_process_http_comp_bytes_out_total | Number of bytes emitted by the HTTP compressor in this worker process over the last second | long | counter |
| haproxy.metrics.haproxy_process_idle_time_percent | Percentage of last second spent waiting in the current worker thread | double | gauge |
| haproxy.metrics.haproxy_process_jobs | Current number of active jobs on the current worker process (frontend connections, master connections, listeners) | double | gauge |
| haproxy.metrics.haproxy_process_limit_connection_rate | Hard limit for ConnRate (global.maxconnrate) | double | gauge |
| haproxy.metrics.haproxy_process_limit_http_comp | Limit of CompressBpsOut beyond which HTTP compression is automatically disabled | double | gauge |
| haproxy.metrics.haproxy_process_limit_session_rate | Hard limit for SessRate (global.maxsessrate) | double | gauge |
| haproxy.metrics.haproxy_process_limit_ssl_rate | Hard limit for SslRate (global.maxsslrate) | double | gauge |
| haproxy.metrics.haproxy_process_listeners | Current number of active listeners on the current worker process | double | gauge |
| haproxy.metrics.haproxy_process_max_backend_ssl_key_rate | Highest SslBackendKeyRate reached on this worker process since started (in SSL keys per second) | double | gauge |
| haproxy.metrics.haproxy_process_max_connection_rate | Highest ConnRate reached on this worker process since started (in connections per second) | double | gauge |
| haproxy.metrics.haproxy_process_max_connections | Hard limit on the number of per-process connections (configured or imposed by Ulimit-n) | double | gauge |
| haproxy.metrics.haproxy_process_max_fds | Hard limit on the number of per-process file descriptors | double | gauge |
| haproxy.metrics.haproxy_process_max_frontend_ssl_key_rate | Highest SslFrontendKeyRate reached on this worker process since started (in SSL keys per second) | double | gauge |
| haproxy.metrics.haproxy_process_max_memory_bytes | Worker process's hard limit on memory usage in byes (-m on command line) | double | gauge |
| haproxy.metrics.haproxy_process_max_pipes | Hard limit on the number of pipes for splicing, 0=unlimited | double | gauge |
| haproxy.metrics.haproxy_process_max_session_rate | Highest SessRate reached on this worker process since started (in sessions per second) | double | gauge |
| haproxy.metrics.haproxy_process_max_sockets | Hard limit on the number of per-process sockets | double | gauge |
| haproxy.metrics.haproxy_process_max_ssl_connections | Hard limit on the number of per-process SSL endpoints (front+back), 0=unlimited | double | gauge |
| haproxy.metrics.haproxy_process_max_ssl_rate | Highest SslRate reached on this worker process since started (in connections per second) | double | gauge |
| haproxy.metrics.haproxy_process_max_zlib_memory | Limit on the amount of memory used by HTTP compression above which it is automatically disabled (in bytes, see global.maxzlibmem) | double | gauge |
| haproxy.metrics.haproxy_process_nbproc | Number of started worker processes (historical, always 1) | double | gauge |
| haproxy.metrics.haproxy_process_nbthread | Number of started threads (global.nbthread) | double | gauge |
| haproxy.metrics.haproxy_process_node | Node name (global.node) | double | gauge |
| haproxy.metrics.haproxy_process_pipes_free_total | Current number of allocated and available pipes in this worker process | long | counter |
| haproxy.metrics.haproxy_process_pipes_used_total | Current number of pipes in use in this worker process | long | counter |
| haproxy.metrics.haproxy_process_pool_allocated_bytes | Amount of memory allocated in pools (in bytes) | double | gauge |
| haproxy.metrics.haproxy_process_pool_failures_total | Number of failed pool allocations since this worker was started | long | counter |
| haproxy.metrics.haproxy_process_pool_used_bytes | Amount of pool memory currently used (in bytes) | double | gauge |
| haproxy.metrics.haproxy_process_recv_logs_total | Total number of log messages received by log-forwarding listeners on this worker process since started | long | counter |
| haproxy.metrics.haproxy_process_relative_process_id | Relative worker process number (1) | double | gauge |
| haproxy.metrics.haproxy_process_requests_total | Total number of requests on this worker process since started | long | counter |
| haproxy.metrics.haproxy_process_spliced_bytes_out_total | Total number of bytes emitted by current worker process through a kernel pipe since started | long | counter |
| haproxy.metrics.haproxy_process_ssl_cache_lookups_total | Total number of SSL session ID lookups in the SSL session cache on this worker since started | long | counter |
| haproxy.metrics.haproxy_process_ssl_cache_misses_total | Total number of SSL session ID lookups that didn't find a session in the SSL session cache on this worker since started | long | counter |
| haproxy.metrics.haproxy_process_ssl_connections_total | Total number of SSL endpoints on this worker process since started (front+back) | long | counter |
| haproxy.metrics.haproxy_process_start_time_seconds | Start time in seconds | double | gauge |
| haproxy.metrics.haproxy_process_stopping | 1 if the worker process is currently stopping, otherwise zero | double | gauge |
| haproxy.metrics.haproxy_process_total_warnings | Total warnings issued | long | counter |
| haproxy.metrics.haproxy_process_unstoppable_jobs | Current number of unstoppable jobs on the current worker process (master connections) | double | gauge |
| haproxy.metrics.haproxy_process_uptime_seconds | How long ago this worker process was started (seconds) | double | gauge |
| haproxy.metrics.haproxy_resolver_any_err | Any errors | double | gauge |
| haproxy.metrics.haproxy_resolver_cname | CNAME | double | gauge |
| haproxy.metrics.haproxy_resolver_cname_error | CNAME error | double | gauge |
| haproxy.metrics.haproxy_resolver_invalid | Invalid | double | gauge |
| haproxy.metrics.haproxy_resolver_nx | NX | double | gauge |
| haproxy.metrics.haproxy_resolver_other | Other | double | gauge |
| haproxy.metrics.haproxy_resolver_outdated | Outdated | double | gauge |
| haproxy.metrics.haproxy_resolver_refused | Refused | double | gauge |
| haproxy.metrics.haproxy_resolver_send_error | Send error | double | gauge |
| haproxy.metrics.haproxy_resolver_sent | Sent | double | gauge |
| haproxy.metrics.haproxy_resolver_timeout | Timeout | double | gauge |
| haproxy.metrics.haproxy_resolver_too_big | Too big | double | gauge |
| haproxy.metrics.haproxy_resolver_truncated | Truncated | double | gauge |
| haproxy.metrics.haproxy_resolver_update | Update | double | gauge |
| haproxy.metrics.haproxy_resolver_valid | Valid | double | gauge |
| haproxy.metrics.haproxy_server_active | Total number of active UP servers with a non-zero weight | double | gauge |
| haproxy.metrics.haproxy_server_backup | Total number of backup UP servers with a non-zero weight | double | gauge |
| haproxy.metrics.haproxy_server_bytes_in_total | Total number of request bytes since process started | long | counter |
| haproxy.metrics.haproxy_server_bytes_out_total | Total number of response bytes since process started | long | counter |
| haproxy.metrics.haproxy_server_check_code | layer5-7 code, if available of the last health check. | double | gauge |
| haproxy.metrics.haproxy_server_check_duration_seconds | Total duration of the latest server health check, in seconds. | double | gauge |
| haproxy.metrics.haproxy_server_check_failures_total | Total number of failed individual health checks per server/backend, since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_check_last_change_seconds | How long ago the last server state changed, in seconds | double | gauge |
| haproxy.metrics.haproxy_server_check_status | Status of last health check, per state label value. | double | gauge |
| haproxy.metrics.haproxy_server_check_up_down_total | Total number of failed checks causing UP to DOWN server transitions, per server/backend, since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_client_aborts_total | Total number of requests or connections aborted by the client since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_connect_time_average_seconds | Avg. connect time for last 1024 successful connections. | double | gauge |
| haproxy.metrics.haproxy_server_connection_attempts_total | Total number of outgoing connection attempts on this backend/server since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_connection_errors_total | Total number of failed connections to server since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_connection_reuses_total | Total number of reused connection on this backend/server since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_current_queue | Number of current queued connections | double | gauge |
| haproxy.metrics.haproxy_server_current_session_rate | Total number of sessions processed by this object over the last second (sessions for listeners/frontends, requests for backends/servers) | double | gauge |
| haproxy.metrics.haproxy_server_current_sessions | Number of current sessions on the frontend, backend or server | double | gauge |
| haproxy.metrics.haproxy_server_current_throttle | Throttling ratio applied to a server's maxconn and weight during the slowstart period (0 to 100%) | double | gauge |
| haproxy.metrics.haproxy_server_downtime_seconds_total | Total time spent in DOWN state, for server or backend | long | counter |
| haproxy.metrics.haproxy_server_failed_header_rewriting_total | Total number of failed HTTP header rewrites since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_http_requests_total | Total number of HTTP requests processed by this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_http_responses_total | Total number of HTTP responses with status 100-199 returned by this object since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_idle_connections_current | Current number of idle connections available for reuse on this server | double | gauge |
| haproxy.metrics.haproxy_server_idle_connections_limit | Limit on the number of available idle connections on this server (server 'pool_max_conn' directive) | double | gauge |
| haproxy.metrics.haproxy_server_internal_errors_total | Total number of internal errors since process started | long | counter |
| haproxy.metrics.haproxy_server_last_session_seconds | How long ago some traffic was seen on this object on this worker process, in seconds | double | gauge |
| haproxy.metrics.haproxy_server_limit_sessions | Frontend/listener/server's maxconn, backend's fullconn | double | gauge |
| haproxy.metrics.haproxy_server_loadbalanced_total | Total number of requests routed by load balancing since the worker process started (ignores queue pop and stickiness) | long | counter |
| haproxy.metrics.haproxy_server_max_connect_time_seconds | Maximum observed time spent waiting for a connection to complete | double | gauge |
| haproxy.metrics.haproxy_server_max_queue | Highest value of queued connections encountered since process started | double | gauge |
| haproxy.metrics.haproxy_server_max_queue_time_seconds | Maximum observed time spent in the queue | double | gauge |
| haproxy.metrics.haproxy_server_max_response_time_seconds | Maximum observed time spent waiting for a server response | double | gauge |
| haproxy.metrics.haproxy_server_max_session_rate | Highest value of sessions per second observed since the worker process started | double | gauge |
| haproxy.metrics.haproxy_server_max_sessions | Highest value of current sessions encountered since process started | double | gauge |
| haproxy.metrics.haproxy_server_max_total_time_seconds | Maximum observed total request+response time (request+queue+connect+response+processing) | double | gauge |
| haproxy.metrics.haproxy_server_need_connections_current | Estimated needed number of connections | double | gauge |
| haproxy.metrics.haproxy_server_queue_limit | Limit on the number of connections in queue, for servers only (maxqueue argument) | double | gauge |
| haproxy.metrics.haproxy_server_queue_time_average_seconds | Avg. queue time for last 1024 successful connections. | double | gauge |
| haproxy.metrics.haproxy_server_redispatch_warnings_total | Total number of server redispatches due to connection failures since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_response_errors_total | Total number of invalid responses since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_response_time_average_seconds | Avg. response time for last 1024 successful connections. | double | gauge |
| haproxy.metrics.haproxy_server_responses_denied_total | Total number of denied responses since process started | long | counter |
| haproxy.metrics.haproxy_server_retry_warnings_total | Total number of server connection retries since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_safe_idle_connections_current | Current number of safe idle connections | double | gauge |
| haproxy.metrics.haproxy_server_server_aborts_total | Total number of requests or connections aborted by the server since the worker process started | long | counter |
| haproxy.metrics.haproxy_server_sessions_total | Total number of sessions since process started | long | counter |
| haproxy.metrics.haproxy_server_status | Current status of the service, per state label value. | double | gauge |
| haproxy.metrics.haproxy_server_total_time_average_seconds | Avg. total time for last 1024 successful connections. | double | gauge |
| haproxy.metrics.haproxy_server_unsafe_idle_connections_current | Current number of unsafe idle connections | double | gauge |
| haproxy.metrics.haproxy_server_used_connections_current | Current number of connections in use | double | gauge |
| haproxy.metrics.haproxy_server_uweight | Server's user weight, or sum of active servers' user weights for a backend | double | gauge |
| haproxy.metrics.haproxy_server_weight | Server's effective weight, or sum of active servers' effective weights for a backend | double | gauge |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |  |
| prometheus.labels.instance | Prometheus target instance label. | keyword |  |
| prometheus.labels.job | Prometheus target job label. | keyword |  |
| prometheus.labels.proxy | HAProxy proxy label exported with metrics. | keyword |  |
| prometheus.labels.state | HAProxy state label exported with metrics. | keyword |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |

