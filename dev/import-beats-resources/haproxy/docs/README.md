# MySQL Integration

This integration periodically fetches logs and metrics from [HAProxy](https://www.haproxy.com/) servers.

## Compatibility

The `log` dataset was tested with logs from HAProxy 1.8, 1.9 and 2.0 running on a Debian. It is not available on Windows.

The `info` and `stats` datasets were tested with tested with HAProxy versions from 1.6, 1.7, 1.8 to 2.0. 

## Logs

### log

The `log` dataset collects the MySQL error logs.

{{fields "log"}}

## Metrics

### info

The `info` dataset periodically fetches metrics from [Galera](http://galeracluster.com/)-MySQL cluster servers.

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

{{fields "info"}}

### stats

The MySQL `stats` dataset collects data from MySQL by running a `SHOW GLOBAL stats;` SQL query. This query returns a large number of metrics.

An example event for `stats` looks as following:

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

{{fields "stats"}}
