# Aerospike Integration

This Elastic Agent integration collects core Aerospike metrics, giving visibility into the performance and health of your Aerospike clusters. Aerospike is a high-performance NoSQL database designed for real-time applications. The integration uses the official Aerospike Go client to connect directly to the server and retrieve metrics.

## Data Streams

### Namespace Metrics

Namespace metrics collect the Aerospike Namespace Metrics.

An example event for the `namespace` data stream looks as following:

```json
{
    "@timestamp": "2025-09-14T16:48:55.940Z",
    "aerospike": {
        "namespace": {
            "client": {
                "delete": {
                    "error": 0,
                    "not_found": 1076,
                    "success": 2179,
                    "timeout": 0
                },
                "read": {
                    "error": 0,
                    "not_found": 1061,
                    "success": 2143,
                    "timeout": 0
                },
                "write": {
                    "error": 0,
                    "success": 6624,
                    "timeout": 0
                }
            },
            "device": {
                "available": {
                    "pct": 99
                },
                "free": {
                    "pct": 99
                },
                "total": {
                    "bytes": 4294967296
                },
                "used": {
                    "bytes": 3920
                }
            },
            "hwm_breached": false,
            "memory": {
                "free": {
                    "pct": 99
                },
                "used": {
                    "data": {
                        "bytes": 0
                    },
                    "index": {
                        "bytes": 2240
                    },
                    "sindex": {
                        "bytes": 0
                    },
                    "total": {
                        "bytes": 2240
                    }
                }
            },
            "name": "test",
            "node": {
                "host": "172.23.0.4:3000",
                "name": "BB93EB596170552"
            },
            "objects": {
                "master": 35,
                "total": 35
            },
            "stop_writes": false
        }
    },
    "agent": {
        "ephemeral_id": "cd020f09-a67c-4891-9303-9b8a7bcaa66e",
        "id": "2b51df07-4a2b-4f59-8863-e5c0a1ff074e",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "9.1.0"
    },
    "data_stream": {
        "dataset": "aerospike.namespace",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "2b51df07-4a2b-4f59-8863-e5c0a1ff074e",
        "snapshot": false,
        "version": "9.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "aerospike.namespace",
        "duration": 7919750,
        "ingested": "2025-09-14T16:48:56Z",
        "module": "aerospike"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "ip": "172.23.0.10",
        "mac": "92-FD-0D-1F-A5-29",
        "name": "docker-fleet-agent",
        "os": {
            "family": "",
            "kernel": "6.10.14-linuxkit",
            "name": "Wolfi",
            "platform": "wolfi",
            "type": "linux",
            "version": "20230201"
        }
    },
    "metricset": {
        "name": "namespace",
        "period": 10000
    },
    "service": {
        "type": "aerospike"
    }
}
```


### Known Issues / Limitations

In version 7.x, Aerospike [removed and renamed many metrics](https://aerospike.com/docs/database/release/7-0/#metrics-changes) used by this integration:

| Elastic Agent Metric                            | Aerospike Metric             | Availability    |
|-------------------------------------------------|------------------------------|-----------------|
| `aerospike.namespace.device.available.pct`      | `device_available_pct`       | Not available   |
| `aerospike.namespace.device.free.pct`           | `device_free_pct`            | Not available   |
| `aerospike.namespace.device.used.bytes`         | `device_used_bytes`          | Not available   |
| `aerospike.namespace.device.total.bytes`        | `device_total_bytes`         | Not available   |
| `aerospike.namespace.memory.free.pct`           | `memory_free_pct`            | Not available   |
| `aerospike.namespace.memory.used.data.bytes`    | `memory_used_data_bytes`     | Not available   |
| `aerospike.namespace.memory.used.index.bytes`   | `memory_used_index_bytes`    | Not available   |
| `aerospike.namespace.memory.used.sindex.bytes`  | `memory_used_sindex_bytes`   | Not available   |
| `aerospike.namespace.memory.used.total.bytes`   | `memory_used_bytes`          | Not available   |

These metrics are not collected in Aerospike 7.x and later. As a result, the Used vs Total Memory panel in the Aerospike Namespace 
Dashboard will remain empty until the Aerospike Metricbeat module is updated to support the new memory metrics.

#### Workarounds

- If you need these metrics on Aerospike 7.x and later, you can expose them via the 
[Aerospike Prometheus Exporter](https://github.com/aerospike/aerospike-prometheus-exporter). This requires installing 
the exporter on your Aerospike nodes and configuring Elastic Agent to scrape the Prometheus metrics.

- Alternatively, if you do not want to install an additional component on your Aerospike Server, you can build an 
[EDOT-Like Collector](https://www.elastic.co/docs/reference/opentelemetry/edot-collector/custom-collector) (or use OpenTelemetry Collector Contrib) to collect the data with the OpenTelemetry [Aerospike receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/aerospikereceiver). Refer to the official [Aerospike Documentation](https://aerospike.com/docs/database/observe/monitor/otel/).

## Compatibility

This integration has been tested with Aerospike Enterprise 7.2.0.1 and 6.4.0.2. It is expected to work with Aerospike versions 4.9 and later.