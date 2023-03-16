# Beat

The `beat` package collects metrics and logs of Beats and APM server.

## Metrics

### Usage for Stack Monitoring

The `beat` package can be used to collect metrics shown in our Stack Monitoring
UI in Kibana.

### Stats

An example event for `stats` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "67d0c20f-d474-43b0-8977-a0e99cc78ec6",
        "type": "metricbeat",
        "ephemeral_id": "11e58ae8-8629-4a35-962b-3970fbd154f3",
        "version": "8.7.0"
    },
    "@timestamp": "2023-03-16T14:27:28.408Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "beats.stack_monitoring.stats"
    },
    "service": {
        "address": "http://elastic-package-service_beat_1:5066/stats",
        "name": "beat",
        "type": "beat"
    },
    "beat": {
        "elasticsearch": {
            "cluster": {
                "id": "RMRLbVsRQFGRM5p2cu3rLw"
            }
        },
        "stats": {
            "handles": {
                "limit": {
                    "hard": 1048576,
                    "soft": 1048576
                },
                "open": 16
            },
            "apm_server": {
                "server": {
                    "request": {
                        "count": 173
                    },
                    "response": {
                        "valid": {
                            "notmodified": 0,
                            "count": 173,
                            "accepted": 173,
                            "ok": 0
                        },
                        "count": 173,
                        "errors": {
                            "ratelimit": 0,
                            "internal": 0,
                            "toolarge": 0,
                            "method": 0,
                            "unavailable": 0,
                            "forbidden": 0,
                            "count": 0,
                            "decode": 0,
                            "timeout": 0,
                            "unauthorized": 0,
                            "notfound": 0,
                            "closed": 0,
                            "invalidquery": 0,
                            "queue": 0,
                            "validate": 0
                        }
                    },
                    "unset": 0
                },
                "profiling": {
                    "ilm": {
                        "custom_ilm": {
                            "skipped_for_time_constraints": {
                                "count": 0
                            },
                            "execution": {
                                "count": 0
                            },
                            "failed": {
                                "count": 0
                            },
                            "undeleted_index": {
                                "count": 0
                            }
                        }
                    },
                    "indexer": {
                        "document": {
                            "stacktraces": {
                                "total": {
                                    "count": 0
                                },
                                "failure": {
                                    "count": 0
                                },
                                "duplicate": {
                                    "count": 0
                                }
                            },
                            "executables": {
                                "total": {
                                    "count": 0
                                },
                                "failure": {
                                    "count": 0
                                }
                            },
                            "stackframes": {
                                "total": {
                                    "count": 0
                                },
                                "failure": {
                                    "count": 0
                                },
                                "duplicate": {
                                    "count": 0
                                }
                            },
                            "events": {
                                "total": {
                                    "count": 0
                                },
                                "failure": {
                                    "count": 0
                                }
                            }
                        }
                    },
                    "unrecoverable_error": {
                        "count": 0
                    },
                    "grpc": {
                        "collect": {
                            "request": {
                                "count": 0
                            },
                            "response": {
                                "valid": {
                                    "count": 0
                                },
                                "count": 0,
                                "errors": {
                                    "ratelimit": 0,
                                    "unauthorized": 0,
                                    "count": 0,
                                    "timeout": 0
                                }
                            }
                        }
                    }
                },
                "sampling": {
                    "transactions_dropped": 0
                },
                "root": {
                    "request": {
                        "count": 1
                    },
                    "response": {
                        "valid": {
                            "notmodified": 0,
                            "count": 1,
                            "accepted": 0,
                            "ok": 1
                        },
                        "count": 1,
                        "errors": {
                            "ratelimit": 0,
                            "toolarge": 0,
                            "internal": 0,
                            "method": 0,
                            "unavailable": 0,
                            "forbidden": 0,
                            "count": 0,
                            "decode": 0,
                            "timeout": 0,
                            "unauthorized": 0,
                            "notfound": 0,
                            "closed": 0,
                            "invalidquery": 0,
                            "queue": 0,
                            "validate": 0
                        }
                    },
                    "unset": 0
                },
                "acm": {
                    "request": {
                        "count": 0
                    },
                    "response": {
                        "valid": {
                            "notmodified": 0,
                            "count": 0,
                            "accepted": 0,
                            "ok": 0
                        },
                        "count": 0,
                        "errors": {
                            "ratelimit": 0,
                            "internal": 0,
                            "toolarge": 0,
                            "method": 0,
                            "unavailable": 0,
                            "forbidden": 0,
                            "count": 0,
                            "decode": 0,
                            "timeout": 0,
                            "unauthorized": 0,
                            "notfound": 0,
                            "closed": 0,
                            "invalidquery": 0,
                            "queue": 0,
                            "validate": 0
                        }
                    },
                    "unset": 0
                },
                "aggregation": {
                    "txmetrics": {
                        "active_groups": 1,
                        "overflowed": {
                            "total": 0,
                            "txn_groups": 0,
                            "per_service_txn_groups": 0,
                            "services": 0
                        }
                    },
                    "servicetxmetrics": {
                        "overflowed.total": 0,
                        "active_groups": 0
                    },
                    "servicesummarymetrics": {
                        "overflowed.total": 0,
                        "active_groups": 0
                    },
                    "spanmetrics": {
                        "active_groups": 0,
                        "overflowed.total": 0
                    }
                },
                "otlp": {
                    "http": {
                        "traces": {
                            "request": {
                                "count": 0
                            },
                            "response": {
                                "valid": {
                                    "count": 0
                                },
                                "count": 0,
                                "errors": {
                                    "ratelimit": 0,
                                    "unauthorized": 0,
                                    "count": 0,
                                    "timeout": 0
                                }
                            }
                        },
                        "metrics": {
                            "request": {
                                "count": 0
                            },
                            "response": {
                                "valid": {
                                    "count": 0
                                },
                                "count": 0,
                                "errors": {
                                    "ratelimit": 0,
                                    "unauthorized": 0,
                                    "count": 0,
                                    "timeout": 0
                                }
                            },
                            "consumer": {
                                "unsupported_dropped": 0
                            }
                        },
                        "logs": {
                            "request": {
                                "count": 0
                            },
                            "response": {
                                "valid": {
                                    "count": 0
                                },
                                "count": 0,
                                "errors": {
                                    "ratelimit": 0,
                                    "unauthorized": 0,
                                    "count": 0,
                                    "timeout": 0
                                }
                            }
                        }
                    },
                    "grpc": {
                        "traces": {
                            "request": {
                                "count": 0
                            },
                            "response": {
                                "valid": {
                                    "count": 0
                                },
                                "count": 0,
                                "errors": {
                                    "ratelimit": 0,
                                    "unauthorized": 0,
                                    "count": 0,
                                    "timeout": 0
                                }
                            }
                        },
                        "metrics": {
                            "request": {
                                "count": 0
                            },
                            "response": {
                                "valid": {
                                    "count": 0
                                },
                                "count": 0,
                                "errors": {
                                    "ratelimit": 0,
                                    "unauthorized": 0,
                                    "count": 0,
                                    "timeout": 0
                                }
                            },
                            "consumer": {
                                "unsupported_dropped": 0
                            }
                        },
                        "logs": {
                            "request": {
                                "count": 0
                            },
                            "response": {
                                "valid": {
                                    "count": 0
                                },
                                "count": 0,
                                "errors": {
                                    "ratelimit": 0,
                                    "unauthorized": 0,
                                    "count": 0,
                                    "timeout": 0
                                }
                            }
                        }
                    }
                },
                "processor": {
                    "metric": {
                        "transformations": 178
                    },
                    "stream": {
                        "accepted": 692,
                        "errors": {
                            "toolarge": 0,
                            "invalid": 0
                        }
                    },
                    "error": {
                        "transformations": 173
                    },
                    "transaction": {
                        "transformations": 173
                    },
                    "span": {
                        "transformations": 173
                    }
                },
                "agentcfg": {
                    "elasticsearch": {
                        "fetch.es": 0,
                        "cache.refresh.failures": 3,
                        "fetch.unavailable": 0,
                        "fetch.invalid": 0,
                        "fetch.fallback": 0,
                        "cache.entries.count": 0,
                        "cache.refresh.successes": 0
                    }
                },
                "jaeger": {
                    "grpc": {
                        "sampling": {
                            "request": {
                                "count": 0
                            },
                            "response": {
                                "valid": {
                                    "count": 0
                                },
                                "count": 0,
                                "errors": {
                                    "count": 0
                                }
                            },
                            "event": {
                                "received": {
                                    "count": 0
                                }
                            }
                        },
                        "collect": {
                            "request": {
                                "count": 0
                            },
                            "response": {
                                "valid": {
                                    "count": 0
                                },
                                "count": 0,
                                "errors": {
                                    "ratelimit": 0,
                                    "unauthorized": 0,
                                    "count": 0,
                                    "timeout": 0
                                }
                            }
                        }
                    }
                }
            },
            "system": {
                "load": {
                    "1": 0.59,
                    "5": 0.48,
                    "15": 0.48,
                    "norm": {
                        "1": 0.0738,
                        "5": 0.06,
                        "15": 0.06
                    }
                },
                "cpu": {
                    "cores": 8
                }
            },
            "beat": {
                "name": "893a3c04ecfe",
                "host": "893a3c04ecfe",
                "type": "apm-server",
                "uuid": "5ad4fb6a-0ab1-42e2-a2fe-db955257649f",
                "version": "8.7.0"
            },
            "cpu": {
                "total": {
                    "ticks": 960,
                    "time": {
                        "ms": 960
                    },
                    "value": 960
                },
                "system": {
                    "ticks": 370,
                    "time": {
                        "ms": 370
                    }
                },
                "user": {
                    "ticks": 590,
                    "time": {
                        "ms": 590
                    }
                }
            },
            "runtime": {
                "goroutines": 55
            },
            "memstats": {
                "rss": 122343424,
                "memory": {
                    "total": 311294872,
                    "alloc": 299154104
                },
                "gc_next": 484823864
            },
            "libbeat": {
                "output": {
                    "type": "elasticsearch",
                    "write": {
                        "bytes": 0
                    },
                    "events": {
                        "batches": 0,
                        "total": 697,
                        "toomany": 0,
                        "active": 697,
                        "failed": 0,
                        "acked": 0
                    }
                },
                "pipeline": {
                    "events": {
                        "total": 697
                    }
                }
            },
            "cgroup": {
                "memory": {
                    "mem": {
                        "usage": {
                            "bytes": 94502912
                        }
                    },
                    "id": "/"
                },
                "cpu": {
                    "stats": {
                        "periods": 0,
                        "throttled": {
                            "ns": 0,
                            "periods": 0
                        }
                    },
                    "id": "/"
                }
            },
            "info": {
                "name": "apm-server",
                "ephemeral_id": "ff280956-08d9-42df-a300-2ae04beed234",
                "version": "8.7.0",
                "uptime": {
                    "ms": 84247
                }
            },
            "uptime": {
                "ms": 84247
            }
        },
        "id": "5ad4fb6a-0ab1-42e2-a2fe-db955257649f",
        "type": "apm-server"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "family": "debian",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "ip": [
            "172.24.0.7"
        ],
        "containerized": false,
        "name": "docker-fleet-agent",
        "id": "0d9a72390807443bbe4884110c6a0495",
        "mac": [
            "02-42-AC-18-00-07"
        ],
        "architecture": "x86_64"
    },
    "elastic_agent": {
        "id": "67d0c20f-d474-43b0-8977-a0e99cc78ec6",
        "version": "8.7.0",
        "snapshot": true
    },
    "metricset": {
        "period": 10000,
        "name": "stats"
    },
    "event": {
        "duration": 5179163,
        "agent_id_status": "verified",
        "ingested": "2023-03-16T14:27:29Z",
        "module": "beat",
        "dataset": "beats.stack_monitoring.stats"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| beat.elasticsearch.cluster.id |  | keyword |
| beat.id | Beat ID. | keyword |
| beat.stats.apm_server.acm.request.count |  | long |
| beat.stats.apm_server.acm.response.count |  | long |
| beat.stats.apm_server.acm.response.errors.closed |  | long |
| beat.stats.apm_server.acm.response.errors.count |  | long |
| beat.stats.apm_server.acm.response.errors.decode |  | long |
| beat.stats.apm_server.acm.response.errors.forbidden |  | long |
| beat.stats.apm_server.acm.response.errors.internal |  | long |
| beat.stats.apm_server.acm.response.errors.invalidquery |  | long |
| beat.stats.apm_server.acm.response.errors.method |  | long |
| beat.stats.apm_server.acm.response.errors.notfound |  | long |
| beat.stats.apm_server.acm.response.errors.queue |  | long |
| beat.stats.apm_server.acm.response.errors.ratelimit |  | long |
| beat.stats.apm_server.acm.response.errors.timeout |  | long |
| beat.stats.apm_server.acm.response.errors.toolarge |  | long |
| beat.stats.apm_server.acm.response.errors.unauthorized |  | long |
| beat.stats.apm_server.acm.response.errors.unavailable |  | long |
| beat.stats.apm_server.acm.response.errors.validate |  | long |
| beat.stats.apm_server.acm.response.request.count |  | long |
| beat.stats.apm_server.acm.response.unset |  | long |
| beat.stats.apm_server.acm.response.valid.accepted |  | long |
| beat.stats.apm_server.acm.response.valid.count |  | long |
| beat.stats.apm_server.acm.response.valid.notmodified |  | long |
| beat.stats.apm_server.acm.response.valid.ok |  | long |
| beat.stats.apm_server.acm.unset |  | long |
| beat.stats.apm_server.agentcfg.elasticsearch.cache.entries.count |  | long |
| beat.stats.apm_server.agentcfg.elasticsearch.cache.refresh.failures |  | long |
| beat.stats.apm_server.agentcfg.elasticsearch.cache.refresh.successes |  | long |
| beat.stats.apm_server.agentcfg.elasticsearch.fetch.es |  | long |
| beat.stats.apm_server.agentcfg.elasticsearch.fetch.fallback |  | long |
| beat.stats.apm_server.agentcfg.elasticsearch.fetch.invalid |  | long |
| beat.stats.apm_server.agentcfg.elasticsearch.fetch.unavailable |  | long |
| beat.stats.apm_server.aggregation |  | object |
| beat.stats.apm_server.decoder.deflate.content-length |  | long |
| beat.stats.apm_server.decoder.deflate.count |  | long |
| beat.stats.apm_server.decoder.gzip.content-length |  | long |
| beat.stats.apm_server.decoder.gzip.count |  | long |
| beat.stats.apm_server.decoder.missing-content-length.count |  | long |
| beat.stats.apm_server.decoder.reader.count |  | long |
| beat.stats.apm_server.decoder.reader.size |  | long |
| beat.stats.apm_server.decoder.uncompressed.content-length |  | long |
| beat.stats.apm_server.decoder.uncompressed.count |  | long |
| beat.stats.apm_server.jaeger.grpc.collect.request.count |  | long |
| beat.stats.apm_server.jaeger.grpc.collect.response.count |  | long |
| beat.stats.apm_server.jaeger.grpc.collect.response.errors.count |  | long |
| beat.stats.apm_server.jaeger.grpc.collect.response.errors.ratelimit |  | long |
| beat.stats.apm_server.jaeger.grpc.collect.response.errors.timeout |  | long |
| beat.stats.apm_server.jaeger.grpc.collect.response.errors.unauthorized |  | long |
| beat.stats.apm_server.jaeger.grpc.collect.response.valid.count |  | long |
| beat.stats.apm_server.jaeger.grpc.logs.request.count |  | long |
| beat.stats.apm_server.jaeger.grpc.logs.response.count |  | long |
| beat.stats.apm_server.jaeger.grpc.logs.response.errors.count |  | long |
| beat.stats.apm_server.jaeger.grpc.logs.response.errors.ratelimit |  | long |
| beat.stats.apm_server.jaeger.grpc.logs.response.errors.timeout |  | long |
| beat.stats.apm_server.jaeger.grpc.logs.response.errors.unauthorized |  | long |
| beat.stats.apm_server.jaeger.grpc.logs.response.valid.count |  | long |
| beat.stats.apm_server.jaeger.grpc.sampling.event.received.count |  | long |
| beat.stats.apm_server.jaeger.grpc.sampling.request.count |  | long |
| beat.stats.apm_server.jaeger.grpc.sampling.response.count |  | long |
| beat.stats.apm_server.jaeger.grpc.sampling.response.errors.count |  | long |
| beat.stats.apm_server.jaeger.grpc.sampling.response.valid.count |  | long |
| beat.stats.apm_server.otlp.grpc.logs.request.count |  | long |
| beat.stats.apm_server.otlp.grpc.logs.response.count |  | long |
| beat.stats.apm_server.otlp.grpc.logs.response.errors.count |  | long |
| beat.stats.apm_server.otlp.grpc.logs.response.errors.ratelimit |  | long |
| beat.stats.apm_server.otlp.grpc.logs.response.errors.timeout |  | long |
| beat.stats.apm_server.otlp.grpc.logs.response.errors.unauthorized |  | long |
| beat.stats.apm_server.otlp.grpc.logs.response.valid.count |  | long |
| beat.stats.apm_server.otlp.grpc.metrics.consumer.unsupported_dropped |  | long |
| beat.stats.apm_server.otlp.grpc.metrics.request.count |  | long |
| beat.stats.apm_server.otlp.grpc.metrics.response.count |  | long |
| beat.stats.apm_server.otlp.grpc.metrics.response.errors.count |  | long |
| beat.stats.apm_server.otlp.grpc.metrics.response.errors.ratelimit |  | long |
| beat.stats.apm_server.otlp.grpc.metrics.response.errors.timeout |  | long |
| beat.stats.apm_server.otlp.grpc.metrics.response.errors.unauthorized |  | long |
| beat.stats.apm_server.otlp.grpc.metrics.response.valid.count |  | long |
| beat.stats.apm_server.otlp.grpc.traces.request.count |  | long |
| beat.stats.apm_server.otlp.grpc.traces.response.count |  | long |
| beat.stats.apm_server.otlp.grpc.traces.response.errors.count |  | long |
| beat.stats.apm_server.otlp.grpc.traces.response.errors.ratelimit |  | long |
| beat.stats.apm_server.otlp.grpc.traces.response.errors.timeout |  | long |
| beat.stats.apm_server.otlp.grpc.traces.response.errors.unauthorized |  | long |
| beat.stats.apm_server.otlp.grpc.traces.response.valid.count |  | long |
| beat.stats.apm_server.otlp.http.logs.request.count |  | long |
| beat.stats.apm_server.otlp.http.logs.response.count |  | long |
| beat.stats.apm_server.otlp.http.logs.response.errors.count |  | long |
| beat.stats.apm_server.otlp.http.logs.response.errors.ratelimit |  | long |
| beat.stats.apm_server.otlp.http.logs.response.errors.timeout |  | long |
| beat.stats.apm_server.otlp.http.logs.response.errors.unauthorized |  | long |
| beat.stats.apm_server.otlp.http.logs.response.valid.count |  | long |
| beat.stats.apm_server.otlp.http.metrics.consumer.unsupported_dropped |  | long |
| beat.stats.apm_server.otlp.http.metrics.request.count |  | long |
| beat.stats.apm_server.otlp.http.metrics.response.count |  | long |
| beat.stats.apm_server.otlp.http.metrics.response.errors.count |  | long |
| beat.stats.apm_server.otlp.http.metrics.response.errors.ratelimit |  | long |
| beat.stats.apm_server.otlp.http.metrics.response.errors.timeout |  | long |
| beat.stats.apm_server.otlp.http.metrics.response.errors.unauthorized |  | long |
| beat.stats.apm_server.otlp.http.metrics.response.valid.count |  | long |
| beat.stats.apm_server.otlp.http.traces.request.count |  | long |
| beat.stats.apm_server.otlp.http.traces.response.count |  | long |
| beat.stats.apm_server.otlp.http.traces.response.errors.count |  | long |
| beat.stats.apm_server.otlp.http.traces.response.errors.ratelimit |  | long |
| beat.stats.apm_server.otlp.http.traces.response.errors.timeout |  | long |
| beat.stats.apm_server.otlp.http.traces.response.errors.unauthorized |  | long |
| beat.stats.apm_server.otlp.http.traces.response.valid.count |  | long |
| beat.stats.apm_server.processor.error.decoding.count |  | long |
| beat.stats.apm_server.processor.error.decoding.errors |  | long |
| beat.stats.apm_server.processor.error.frames |  | long |
| beat.stats.apm_server.processor.error.spans |  | long |
| beat.stats.apm_server.processor.error.stacktraces |  | long |
| beat.stats.apm_server.processor.error.transformations |  | long |
| beat.stats.apm_server.processor.error.validation.count |  | long |
| beat.stats.apm_server.processor.error.validation.errors |  | long |
| beat.stats.apm_server.processor.metric.decoding.count |  | long |
| beat.stats.apm_server.processor.metric.decoding.errors |  | long |
| beat.stats.apm_server.processor.metric.transformations |  | long |
| beat.stats.apm_server.processor.metric.validation.count |  | long |
| beat.stats.apm_server.processor.metric.validation.errors |  | long |
| beat.stats.apm_server.processor.sourcemap.counter |  | long |
| beat.stats.apm_server.processor.sourcemap.decoding.count |  | long |
| beat.stats.apm_server.processor.sourcemap.decoding.errors |  | long |
| beat.stats.apm_server.processor.sourcemap.validation.count |  | long |
| beat.stats.apm_server.processor.sourcemap.validation.errors |  | long |
| beat.stats.apm_server.processor.span.transformations |  | long |
| beat.stats.apm_server.processor.stream.accepted |  | long |
| beat.stats.apm_server.processor.stream.errors.invalid |  | long |
| beat.stats.apm_server.processor.stream.errors.toolarge |  | long |
| beat.stats.apm_server.processor.transaction.decoding.count |  | long |
| beat.stats.apm_server.processor.transaction.decoding.errors |  | long |
| beat.stats.apm_server.processor.transaction.frames |  | long |
| beat.stats.apm_server.processor.transaction.spans |  | long |
| beat.stats.apm_server.processor.transaction.stacktraces |  | long |
| beat.stats.apm_server.processor.transaction.transactions |  | long |
| beat.stats.apm_server.processor.transaction.transformations |  | long |
| beat.stats.apm_server.processor.transaction.validation.count |  | long |
| beat.stats.apm_server.processor.transaction.validation.errors |  | long |
| beat.stats.apm_server.profiling.grpc.collect.request.count |  | long |
| beat.stats.apm_server.profiling.grpc.collect.response.count |  | long |
| beat.stats.apm_server.profiling.grpc.collect.response.errors.count |  | long |
| beat.stats.apm_server.profiling.grpc.collect.response.errors.ratelimit |  | long |
| beat.stats.apm_server.profiling.grpc.collect.response.errors.timeout |  | long |
| beat.stats.apm_server.profiling.grpc.collect.response.errors.unauthorized |  | long |
| beat.stats.apm_server.profiling.grpc.collect.response.valid.count |  | long |
| beat.stats.apm_server.profiling.ilm.custom_ilm.execution.count |  | long |
| beat.stats.apm_server.profiling.ilm.custom_ilm.failed.count |  | long |
| beat.stats.apm_server.profiling.ilm.custom_ilm.skipped_for_time_constraints.count |  | long |
| beat.stats.apm_server.profiling.ilm.custom_ilm.undeleted_index.count |  | long |
| beat.stats.apm_server.profiling.indexer.document.events.failure.count |  | long |
| beat.stats.apm_server.profiling.indexer.document.events.total.count |  | long |
| beat.stats.apm_server.profiling.indexer.document.executables.failure.count |  | long |
| beat.stats.apm_server.profiling.indexer.document.executables.total.count |  | long |
| beat.stats.apm_server.profiling.indexer.document.stackframes.duplicate.count |  | long |
| beat.stats.apm_server.profiling.indexer.document.stackframes.failure.count |  | long |
| beat.stats.apm_server.profiling.indexer.document.stackframes.total.count |  | long |
| beat.stats.apm_server.profiling.indexer.document.stacktraces.duplicate.count |  | long |
| beat.stats.apm_server.profiling.indexer.document.stacktraces.failure.count |  | long |
| beat.stats.apm_server.profiling.indexer.document.stacktraces.total.count |  | long |
| beat.stats.apm_server.profiling.unrecoverable_error.count |  | long |
| beat.stats.apm_server.root.request.count |  | long |
| beat.stats.apm_server.root.response.count |  | long |
| beat.stats.apm_server.root.response.errors.closed |  | long |
| beat.stats.apm_server.root.response.errors.count |  | long |
| beat.stats.apm_server.root.response.errors.decode |  | long |
| beat.stats.apm_server.root.response.errors.forbidden |  | long |
| beat.stats.apm_server.root.response.errors.internal |  | long |
| beat.stats.apm_server.root.response.errors.invalidquery |  | long |
| beat.stats.apm_server.root.response.errors.method |  | long |
| beat.stats.apm_server.root.response.errors.notfound |  | long |
| beat.stats.apm_server.root.response.errors.queue |  | long |
| beat.stats.apm_server.root.response.errors.ratelimit |  | long |
| beat.stats.apm_server.root.response.errors.timeout |  | long |
| beat.stats.apm_server.root.response.errors.toolarge |  | long |
| beat.stats.apm_server.root.response.errors.unauthorized |  | long |
| beat.stats.apm_server.root.response.errors.unavailable |  | long |
| beat.stats.apm_server.root.response.errors.validate |  | long |
| beat.stats.apm_server.root.response.valid.accepted |  | long |
| beat.stats.apm_server.root.response.valid.count |  | long |
| beat.stats.apm_server.root.response.valid.notmodified |  | long |
| beat.stats.apm_server.root.response.valid.ok |  | long |
| beat.stats.apm_server.root.unset |  | long |
| beat.stats.apm_server.sampling.transactions_dropped |  | long |
| beat.stats.apm_server.server.concurrent.wait.ms |  | long |
| beat.stats.apm_server.server.request.count |  | long |
| beat.stats.apm_server.server.response.count |  | long |
| beat.stats.apm_server.server.response.errors.closed |  | long |
| beat.stats.apm_server.server.response.errors.concurrency |  | long |
| beat.stats.apm_server.server.response.errors.count |  | long |
| beat.stats.apm_server.server.response.errors.decode |  | long |
| beat.stats.apm_server.server.response.errors.forbidden |  | long |
| beat.stats.apm_server.server.response.errors.internal |  | long |
| beat.stats.apm_server.server.response.errors.invalidquery |  | long |
| beat.stats.apm_server.server.response.errors.method |  | long |
| beat.stats.apm_server.server.response.errors.notfound |  | long |
| beat.stats.apm_server.server.response.errors.queue |  | long |
| beat.stats.apm_server.server.response.errors.ratelimit |  | long |
| beat.stats.apm_server.server.response.errors.timeout |  | long |
| beat.stats.apm_server.server.response.errors.toolarge |  | long |
| beat.stats.apm_server.server.response.errors.unauthorized |  | long |
| beat.stats.apm_server.server.response.errors.unavailable |  | long |
| beat.stats.apm_server.server.response.errors.validate |  | long |
| beat.stats.apm_server.server.response.valid.accepted |  | long |
| beat.stats.apm_server.server.response.valid.count |  | long |
| beat.stats.apm_server.server.response.valid.notmodified |  | long |
| beat.stats.apm_server.server.response.valid.ok |  | long |
| beat.stats.apm_server.server.unset |  | long |
| beat.stats.beat.host |  | keyword |
| beat.stats.beat.name |  | keyword |
| beat.stats.beat.type |  | keyword |
| beat.stats.beat.uuid |  | keyword |
| beat.stats.beat.version |  | keyword |
| beat.stats.cgroup.cpu.cfs.period.us |  | long |
| beat.stats.cgroup.cpu.cfs.quota.us |  | long |
| beat.stats.cgroup.cpu.id |  | keyword |
| beat.stats.cgroup.cpu.stats.periods |  | long |
| beat.stats.cgroup.cpu.stats.throttled.ns |  | long |
| beat.stats.cgroup.cpu.stats.throttled.periods |  | long |
| beat.stats.cgroup.cpuacct.id |  | keyword |
| beat.stats.cgroup.cpuacct.total.ns |  | long |
| beat.stats.cgroup.memory.id |  | keyword |
| beat.stats.cgroup.memory.mem.limit.bytes |  | long |
| beat.stats.cgroup.memory.mem.usage.bytes |  | long |
| beat.stats.cpu.system.ticks |  | long |
| beat.stats.cpu.system.time.ms |  | long |
| beat.stats.cpu.total.ticks |  | long |
| beat.stats.cpu.total.time.ms |  | long |
| beat.stats.cpu.total.value |  | long |
| beat.stats.cpu.user.ticks |  | long |
| beat.stats.cpu.user.time.ms |  | long |
| beat.stats.handles.limit.hard |  | long |
| beat.stats.handles.limit.soft |  | long |
| beat.stats.handles.open |  | long |
| beat.stats.info.ephemeral_id |  | keyword |
| beat.stats.info.host |  | keyword |
| beat.stats.info.name |  | keyword |
| beat.stats.info.type |  | keyword |
| beat.stats.info.uptime.ms |  | long |
| beat.stats.info.uuid |  | keyword |
| beat.stats.info.version |  | keyword |
| beat.stats.libbeat.config.reloads |  | long |
| beat.stats.libbeat.config.running |  | long |
| beat.stats.libbeat.config.starts |  | long |
| beat.stats.libbeat.config.stops |  | long |
| beat.stats.libbeat.output.events.acked | Number of events acknowledged | long |
| beat.stats.libbeat.output.events.active | Number of active events | long |
| beat.stats.libbeat.output.events.batches | Number of event batches | long |
| beat.stats.libbeat.output.events.dropped | Number of events dropped | long |
| beat.stats.libbeat.output.events.duplicates | Number of events duplicated | long |
| beat.stats.libbeat.output.events.failed | Number of events failed | long |
| beat.stats.libbeat.output.events.toomany | Number of too many events | long |
| beat.stats.libbeat.output.events.total | Total number of events | long |
| beat.stats.libbeat.output.read.bytes | Number of bytes read | long |
| beat.stats.libbeat.output.read.errors | Number of read errors | long |
| beat.stats.libbeat.output.type | Type of output | keyword |
| beat.stats.libbeat.output.write.bytes | Number of bytes written | long |
| beat.stats.libbeat.output.write.errors | Number of write errors | long |
| beat.stats.libbeat.pipeline.clients |  | long |
| beat.stats.libbeat.pipeline.events.active |  | long |
| beat.stats.libbeat.pipeline.events.dropped |  | long |
| beat.stats.libbeat.pipeline.events.failed |  | long |
| beat.stats.libbeat.pipeline.events.filtered |  | long |
| beat.stats.libbeat.pipeline.events.published |  | long |
| beat.stats.libbeat.pipeline.events.retry |  | long |
| beat.stats.libbeat.pipeline.events.total |  | long |
| beat.stats.libbeat.pipeline.queue.acked |  | long |
| beat.stats.memstats.gc_next |  | long |
| beat.stats.memstats.memory.alloc |  | long |
| beat.stats.memstats.memory.total |  | long |
| beat.stats.memstats.rss |  | long |
| beat.stats.runtime.goroutines | Number of goroutines running in Beat | long |
| beat.stats.state.events |  | long |
| beat.stats.state.failures |  | long |
| beat.stats.state.success |  | long |
| beat.stats.system.cpu.cores |  | long |
| beat.stats.system.load.1 |  | double |
| beat.stats.system.load.15 |  | double |
| beat.stats.system.load.5 |  | double |
| beat.stats.system.load.norm.1 |  | double |
| beat.stats.system.load.norm.15 |  | double |
| beat.stats.system.load.norm.5 |  | double |
| beat.stats.uptime.ms | Beat uptime | long |
| beat.type | Beat type. | keyword |
| beats_state.beat.host |  | alias |
| beats_state.beat.name |  | alias |
| beats_state.beat.type |  | alias |
| beats_state.beat.uuid |  | alias |
| beats_state.beat.version |  | alias |
| beats_state.state.beat.name |  | alias |
| beats_state.state.host.os.platform |  | alias |
| beats_state.state.host.os.version |  | alias |
| beats_state.state.input.count |  | alias |
| beats_state.state.input.names |  | alias |
| beats_state.state.module.count |  | alias |
| beats_state.state.module.names |  | alias |
| beats_state.state.output.name |  | alias |
| beats_state.state.service.id |  | alias |
| beats_state.state.service.name |  | alias |
| beats_state.state.service.version |  | alias |
| beats_stats.beat.host |  | alias |
| beats_stats.beat.name |  | alias |
| beats_stats.beat.type |  | alias |
| beats_stats.beat.uuid |  | alias |
| beats_stats.beat.version |  | alias |
| beats_stats.metrics.apm-server.acm.request.count |  | alias |
| beats_stats.metrics.apm-server.acm.response.count |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.closed |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.count |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.decode |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.forbidden |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.internal |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.invalidquery |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.method |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.notfound |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.queue |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.ratelimit |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.toolarge |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.unauthorized |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.unavailable |  | alias |
| beats_stats.metrics.apm-server.acm.response.errors.validate |  | alias |
| beats_stats.metrics.apm-server.acm.response.request.count |  | alias |
| beats_stats.metrics.apm-server.acm.response.unset |  | alias |
| beats_stats.metrics.apm-server.acm.response.valid.accepted |  | alias |
| beats_stats.metrics.apm-server.acm.response.valid.count |  | alias |
| beats_stats.metrics.apm-server.acm.response.valid.notmodified |  | alias |
| beats_stats.metrics.apm-server.acm.response.valid.ok |  | alias |
| beats_stats.metrics.apm-server.decoder.deflate.content-length |  | alias |
| beats_stats.metrics.apm-server.decoder.deflate.count |  | alias |
| beats_stats.metrics.apm-server.decoder.gzip.content-length |  | alias |
| beats_stats.metrics.apm-server.decoder.gzip.count |  | alias |
| beats_stats.metrics.apm-server.decoder.missing-content-length.count |  | alias |
| beats_stats.metrics.apm-server.decoder.reader.count |  | alias |
| beats_stats.metrics.apm-server.decoder.reader.size |  | alias |
| beats_stats.metrics.apm-server.decoder.uncompressed.content-length |  | alias |
| beats_stats.metrics.apm-server.decoder.uncompressed.count |  | alias |
| beats_stats.metrics.apm-server.processor.error.decoding.count |  | alias |
| beats_stats.metrics.apm-server.processor.error.decoding.errors |  | alias |
| beats_stats.metrics.apm-server.processor.error.frames |  | alias |
| beats_stats.metrics.apm-server.processor.error.spans |  | alias |
| beats_stats.metrics.apm-server.processor.error.stacktraces |  | alias |
| beats_stats.metrics.apm-server.processor.error.transformations |  | alias |
| beats_stats.metrics.apm-server.processor.error.validation.count |  | alias |
| beats_stats.metrics.apm-server.processor.error.validation.errors |  | alias |
| beats_stats.metrics.apm-server.processor.metric.decoding.count |  | alias |
| beats_stats.metrics.apm-server.processor.metric.decoding.errors |  | alias |
| beats_stats.metrics.apm-server.processor.metric.transformations |  | alias |
| beats_stats.metrics.apm-server.processor.metric.validation.count |  | alias |
| beats_stats.metrics.apm-server.processor.metric.validation.errors |  | alias |
| beats_stats.metrics.apm-server.processor.sourcemap.counter |  | alias |
| beats_stats.metrics.apm-server.processor.sourcemap.decoding.count |  | alias |
| beats_stats.metrics.apm-server.processor.sourcemap.decoding.errors |  | alias |
| beats_stats.metrics.apm-server.processor.sourcemap.validation.count |  | alias |
| beats_stats.metrics.apm-server.processor.sourcemap.validation.errors |  | alias |
| beats_stats.metrics.apm-server.processor.span.transformations |  | alias |
| beats_stats.metrics.apm-server.processor.transaction.decoding.count |  | alias |
| beats_stats.metrics.apm-server.processor.transaction.decoding.errors |  | alias |
| beats_stats.metrics.apm-server.processor.transaction.frames |  | alias |
| beats_stats.metrics.apm-server.processor.transaction.spans |  | alias |
| beats_stats.metrics.apm-server.processor.transaction.stacktraces |  | alias |
| beats_stats.metrics.apm-server.processor.transaction.transactions |  | alias |
| beats_stats.metrics.apm-server.processor.transaction.transformations |  | alias |
| beats_stats.metrics.apm-server.processor.transaction.validation.count |  | alias |
| beats_stats.metrics.apm-server.processor.transaction.validation.errors |  | alias |
| beats_stats.metrics.apm-server.server.concurrent.wait.ms |  | alias |
| beats_stats.metrics.apm-server.server.request.count |  | alias |
| beats_stats.metrics.apm-server.server.response.count |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.closed |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.concurrency |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.count |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.decode |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.forbidden |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.internal |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.method |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.queue |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.ratelimit |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.toolarge |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.unauthorized |  | alias |
| beats_stats.metrics.apm-server.server.response.errors.validate |  | alias |
| beats_stats.metrics.apm-server.server.response.valid.accepted |  | alias |
| beats_stats.metrics.apm-server.server.response.valid.count |  | alias |
| beats_stats.metrics.apm-server.server.response.valid.ok |  | alias |
| beats_stats.metrics.beat.cgroup.cpu.cfs.period.us |  | alias |
| beats_stats.metrics.beat.cgroup.cpu.cfs.quota.us |  | alias |
| beats_stats.metrics.beat.cgroup.cpu.id |  | alias |
| beats_stats.metrics.beat.cgroup.cpu.stats.periods |  | alias |
| beats_stats.metrics.beat.cgroup.cpu.stats.throttled.ns |  | alias |
| beats_stats.metrics.beat.cgroup.cpu.stats.throttled.periods |  | alias |
| beats_stats.metrics.beat.cgroup.cpuacct.id |  | alias |
| beats_stats.metrics.beat.cgroup.cpuacct.total.ns |  | alias |
| beats_stats.metrics.beat.cgroup.mem.limit.bytes |  | alias |
| beats_stats.metrics.beat.cgroup.mem.usage.bytes |  | alias |
| beats_stats.metrics.beat.cgroup.memory.id |  | alias |
| beats_stats.metrics.beat.cpu.system.ticks |  | alias |
| beats_stats.metrics.beat.cpu.system.time.ms |  | alias |
| beats_stats.metrics.beat.cpu.total.ticks |  | alias |
| beats_stats.metrics.beat.cpu.total.time.ms |  | alias |
| beats_stats.metrics.beat.cpu.total.value |  | alias |
| beats_stats.metrics.beat.cpu.user.ticks |  | alias |
| beats_stats.metrics.beat.cpu.user.time.ms |  | alias |
| beats_stats.metrics.beat.handles.limit.hard |  | alias |
| beats_stats.metrics.beat.handles.limit.soft |  | alias |
| beats_stats.metrics.beat.handles.open |  | alias |
| beats_stats.metrics.beat.info.ephemeral_id |  | alias |
| beats_stats.metrics.beat.info.uptime.ms |  | alias |
| beats_stats.metrics.beat.memstats.gc_next |  | alias |
| beats_stats.metrics.beat.memstats.memory_alloc |  | alias |
| beats_stats.metrics.beat.memstats.memory_total |  | alias |
| beats_stats.metrics.beat.memstats.rss |  | alias |
| beats_stats.metrics.libbeat.config.module.running |  | alias |
| beats_stats.metrics.libbeat.config.module.starts |  | alias |
| beats_stats.metrics.libbeat.config.module.stops |  | alias |
| beats_stats.metrics.libbeat.output.events.acked |  | alias |
| beats_stats.metrics.libbeat.output.events.active |  | alias |
| beats_stats.metrics.libbeat.output.events.batches |  | alias |
| beats_stats.metrics.libbeat.output.events.dropped |  | alias |
| beats_stats.metrics.libbeat.output.events.duplicated |  | alias |
| beats_stats.metrics.libbeat.output.events.failed |  | alias |
| beats_stats.metrics.libbeat.output.events.toomany |  | alias |
| beats_stats.metrics.libbeat.output.events.total |  | alias |
| beats_stats.metrics.libbeat.output.read.bytes |  | alias |
| beats_stats.metrics.libbeat.output.read.errors |  | alias |
| beats_stats.metrics.libbeat.output.type |  | alias |
| beats_stats.metrics.libbeat.output.write.bytes |  | alias |
| beats_stats.metrics.libbeat.output.write.errors |  | alias |
| beats_stats.metrics.libbeat.pipeline.clients |  | alias |
| beats_stats.metrics.libbeat.pipeline.events.active |  | alias |
| beats_stats.metrics.libbeat.pipeline.events.dropped |  | alias |
| beats_stats.metrics.libbeat.pipeline.events.failed |  | alias |
| beats_stats.metrics.libbeat.pipeline.events.filtered |  | alias |
| beats_stats.metrics.libbeat.pipeline.events.published |  | alias |
| beats_stats.metrics.libbeat.pipeline.events.retry |  | alias |
| beats_stats.metrics.libbeat.pipeline.events.total |  | alias |
| beats_stats.metrics.libbeat.pipeline.queue.acked |  | alias |
| beats_stats.metrics.system.cpu.cores |  | alias |
| beats_stats.metrics.system.load.1 |  | alias |
| beats_stats.metrics.system.load.15 |  | alias |
| beats_stats.metrics.system.load.5 |  | alias |
| beats_stats.metrics.system.load.norm.1 |  | alias |
| beats_stats.metrics.system.load.norm.15 |  | alias |
| beats_stats.metrics.system.load.norm.5 |  | alias |
| beats_stats.timestamp |  | alias |
| cluster_uuid |  | alias |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| timestamp |  | alias |


### State

An example event for `state` looks as following:

```json
{
    "@timestamp": "2022-11-23T17:08:54.575Z",
    "agent": {
        "ephemeral_id": "552bd946-18b1-44bd-9cab-f6baa2dffe3d",
        "id": "de291921-7d38-4a60-89ca-cb6080ca6aa7",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.5.0"
    },
    "beat": {
        "elasticsearch": {
            "cluster": {
                "id": "TtFsAyBvS-GP8YnmKAaCgg"
            }
        },
        "state": {
            "beat": {
                "host": "7db5d44ab310",
                "name": "7db5d44ab310",
                "type": "metricbeat",
                "uuid": "8bf6384a-5ade-4097-b270-fa7acec60ed0",
                "version": "8.5.0"
            },
            "cluster": {
                "uuid": "TtFsAyBvS-GP8YnmKAaCgg"
            },
            "host": {
                "containerized": "containerized",
                "os": {
                    "kernel": "5.10.47-linuxkit",
                    "name": "Ubuntu",
                    "platform": "ubuntu",
                    "version": "20.04.5 LTS (Focal Fossa)"
                }
            },
            "management": {
                "enabled": false
            },
            "module": {
                "count": 2
            },
            "output": {
                "name": "elasticsearch"
            },
            "queue": {
                "name": "mem"
            },
            "service": {
                "id": "8bf6384a-5ade-4097-b270-fa7acec60ed0",
                "name": "metricbeat",
                "version": "8.5.0"
            }
        }
    },
    "data_stream": {
        "dataset": "beats.stack_monitoring.state",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "de291921-7d38-4a60-89ca-cb6080ca6aa7",
        "snapshot": false,
        "version": "8.5.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "beats.stack_monitoring.state",
        "duration": 3815000,
        "ingested": "2022-11-23T17:08:55Z",
        "module": "beat"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "id": "66392b0697b84641af8006d87aeb89f1",
        "ip": [
            "192.168.192.7"
        ],
        "mac": [
            "02-42-C0-A8-C0-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "5.10.47-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.5 LTS (Focal Fossa)"
        }
    },
    "metricset": {
        "name": "state",
        "period": 10000
    },
    "service": {
        "address": "http://elastic-package-service_beat_1:5066/state",
        "type": "beat"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| beat.elasticsearch.cluster.id |  | keyword |
| beat.id | Beat ID. | keyword |
| beat.state.beat.host |  | keyword |
| beat.state.beat.name |  | keyword |
| beat.state.beat.type |  | keyword |
| beat.state.beat.uuid |  | keyword |
| beat.state.beat.version |  | keyword |
| beat.state.cluster.uuid |  | keyword |
| beat.state.host.containerized |  | keyword |
| beat.state.host.os.kernel |  | keyword |
| beat.state.host.os.name |  | keyword |
| beat.state.host.os.platform |  | keyword |
| beat.state.host.os.version |  | keyword |
| beat.state.input.count |  | long |
| beat.state.input.names |  | keyword |
| beat.state.management.enabled | Is central management enabled? | boolean |
| beat.state.module.count | Number of modules enabled | integer |
| beat.state.module.names |  | keyword |
| beat.state.output.name | Name of output used by Beat | keyword |
| beat.state.queue.name | Name of queue being used by Beat | keyword |
| beat.state.service.id |  | keyword |
| beat.state.service.name |  | keyword |
| beat.state.service.version |  | keyword |
| beat.type | Beat type. | keyword |
| beats_state.beat.host |  | alias |
| beats_state.beat.name |  | alias |
| beats_state.beat.type |  | alias |
| beats_state.beat.uuid |  | alias |
| beats_state.beat.version |  | alias |
| beats_state.state.beat.name |  | alias |
| beats_state.state.host.os.platform |  | alias |
| beats_state.state.host.os.version |  | alias |
| beats_state.state.input.count |  | alias |
| beats_state.state.input.names |  | alias |
| beats_state.state.module.count |  | alias |
| beats_state.state.module.names |  | alias |
| beats_state.state.output.name |  | alias |
| beats_state.state.service.id |  | alias |
| beats_state.state.service.name |  | alias |
| beats_state.state.service.version |  | alias |
| cluster_uuid |  | alias |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| timestamp |  | alias |

