# HAProxy Integration

This integration periodically fetches logs and metrics from [HAProxy](https://www.haproxy.org/) servers.

## Compatibility

The `log` dataset was tested with logs from HAProxy 1.8, 1.9 and 2.0 running on a Debian. It is not available on Windows.

The `info` and `stat` datasets were tested with tested with HAProxy versions from 1.6, 1.7, 1.8 to 2.0. 

## Logs

### log

The `log` dataset collects the HAProxy application logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
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
| http.response.status_code | HTTP response status code. | long |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.pid | Process id. | long |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.port | Port of the source. | long |


## Metrics

### info

The HAProxy `info` dataset collects general information about HAProxy processes.

An example event for `info` looks as following:

```$json
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
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
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
| process.pid | Process id. | long |


### stat

The HAProxy `stat` metricset collects stat fields from HAProxy processes.

See section "9.1. CSV format" of the official [HAProxy Management Guide](http://www.haproxy.org/download/2.0/doc/management.txt) for a full list of stat fields.

An example event for `stat` looks as following:

```$json
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
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
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
| haproxy.stat.agent.status | Status of the last health check. One of:    UNK     -> unknown   INI     -> initializing   SOCKERR -> socket error   L4OK    -> check passed on layer 4, no upper layers enabled   L4TOUT  -> layer 1-4 timeout   L4CON   -> layer 1-4 connection problem, for example             "Connection refused" (tcp rst) or "No route to host" (icmp)   L7OK    -> agent reported "up"   L7STS   -> agent reported "fail", "stop" or "down" | keyword |
| haproxy.stat.check.agent.last |  | integer |
| haproxy.stat.check.code | Layer 5-7 code, if available. | long |
| haproxy.stat.check.down | Number of UP->DOWN transitions. For backends, this value is the number of transitions to the whole backend being down, rather than the sum of the transitions for each server. | long |
| haproxy.stat.check.duration | Time in ms that it took to finish the last health check. | long |
| haproxy.stat.check.failed | Number of checks that failed while the server was up. | long |
| haproxy.stat.check.health.fail | Number of failed checks. | long |
| haproxy.stat.check.health.last | The result of the last health check. | keyword |
| haproxy.stat.check.status | Status of the last health check. One of:    UNK     -> unknown   INI     -> initializing   SOCKERR -> socket error   L4OK    -> check passed on layer 4, no upper layers testing enabled   L4TOUT  -> layer 1-4 timeout   L4CON   -> layer 1-4 connection problem, for example             "Connection refused" (tcp rst) or "No route to host" (icmp)   L6OK    -> check passed on layer 6   L6TOUT  -> layer 6 (SSL) timeout   L6RSP   -> layer 6 invalid response - protocol error   L7OK    -> check passed on layer 7   L7OKC   -> check conditionally passed on layer 7, for example 404 with             disable-on-404   L7TOUT  -> layer 7 (HTTP/SMTP) timeout   L7RSP   -> layer 7 invalid response - protocol error   L7STS   -> layer 7 response error, for example HTTP 5xx | keyword |
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
| haproxy.stat.last_change | Number of seconds since the last UP->DOWN or DOWN->UP transition. | integer |
| haproxy.stat.load_balancing_algorithm | Load balancing algorithm. | keyword |
| haproxy.stat.out.bytes | Bytes out. | long |
| haproxy.stat.proxy.id | Unique proxy ID. | integer |
| haproxy.stat.proxy.mode | Proxy mode (tcp, http, health, unknown). | keyword |
| haproxy.stat.proxy.name | Proxy name. | keyword |
| haproxy.stat.queue.limit | Configured queue limit (maxqueue) for the server, or nothing if the value of maxqueue is 0 (meaning no limit). | integer |
| haproxy.stat.queue.time.avg | The average queue time in ms over the last 1024 requests. | integer |
| haproxy.stat.request.connection.errors | Number of requests that encountered an error trying to connect to a server. For backends, this field reports the sum of the stat for all backend servers, plus any connection errors not associated with a particular server (such as the backend having no active servers). | long |
| haproxy.stat.request.denied | Requests denied because of security concerns.    * For TCP this is because of a matched tcp-request content rule.   * For HTTP this is because of a matched http-request or tarpit rule. | long |
| haproxy.stat.request.denied_by_connection_rules | Requests denied because of TCP request connection rules. | long |
| haproxy.stat.request.denied_by_session_rules | Requests denied because of TCP request session rules. | long |
| haproxy.stat.request.errors | Request errors. Some of the possible causes are:    * early termination from the client, before the request has been sent   * read error from the client   * client timeout   * client closed connection   * various bad requests from the client.   * request was tarpitted. | long |
| haproxy.stat.request.intercepted | Number of intercepted requests. | long |
| haproxy.stat.request.queued.current | Current queued requests. For backends, this field reports the number of requests queued without a server assigned. | long |
| haproxy.stat.request.queued.max | Maximum value of queued.current. | long |
| haproxy.stat.request.rate.max | Maximum number of HTTP requests per second. | long |
| haproxy.stat.request.rate.value | Number of HTTP requests per second over the last elapsed second. | long |
| haproxy.stat.request.redispatched | Number of times a request was redispatched to another server. For servers, this field reports the number of times the server was switched away from. | long |
| haproxy.stat.request.total | Total number of HTTP requests received. | long |
| haproxy.stat.response.denied | Responses denied because of security concerns. For HTTP this is because of a matched http-request rule, or "option checkcache". | integer |
| haproxy.stat.response.errors | Number of response errors. This value includes the number of data transfers aborted by the server (haproxy.stat.server.aborted). Some other errors are: * write errors on the client socket (won't be counted for the server stat) * failure applying filters to the response | long |
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
| process.pid | Process id. | long |

