# System OpenTelemetry Assets

System OpenTelemetry Assets provides dashboards for vizualising OpenTelemetry hosts' metrics and logs. 

## Requirements

Collect and ingest OpenTelemetry data from the Collector's [`hostmetrics` receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.127.0/receiver/hostmetricsreceiver) through:

- the [Elastic Distributions of OpenTelemetry](https://www.elastic.co/docs/reference/opentelemetry/quickstart/)
- or using the vanilla / upstream OpenTelemetry Collector

Compatible `hostmetrics` receiver versions are all versions `>= v0.102.0`.

For full functionality of the dashboards included in this content pack, you will need to ensure the following metrics are enabled in the [`hostmetrics` receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.127.0/receiver/hostmetricsreceiver):

| Metric | Enabled by default in EDOT Collector | Enabled by default in upstream Contrib Collector |
|---|---|---|
|**[CPU](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.127.0/receiver/hostmetricsreceiver/internal/scraper/cpuscraper/documentation.md)**|||
| `system.cpu.time` | ✅ | ✅ |
| `system.cpu.utilization` | ✅ | ❌ |
| `system.cpu.logical.count` | ✅ | ❌ |
|**[Load](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.127.0/receiver/hostmetricsreceiver/internal/scraper/loadscraper/documentation.md)**|||
| `system.cpu.load_average.1m` | ✅ | ✅ |
| `system.cpu.load_average.5m` | ✅ | ✅ |
| `system.cpu.load_average.15m` | ✅ | ✅ |
|**[Memory](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.127.0/receiver/hostmetricsreceiver/internal/scraper/memoryscraper/documentation.md)**|||
| `system.memory.usage` | ✅ | ✅ |
| `system.memory.utilization` | ✅ | ❌ |
|**[Network](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/internal/scraper/networkscraper/documentation.md)**|||
| `system.network.connections` | ✅ | ✅ |
| `system.network.dropped` | ✅ | ✅ |
| `system.network.errors` | ✅ | ✅ |
| `system.network.io` | ✅ | ✅ |
| `system.network.packets` | ✅ | ✅ |
|**[Disk](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/internal/scraper/diskscraper/documentation.md)**|||
| `system.disk.io` | ✅ | ✅ |
| `system.disk.io_time` | ✅ | ✅ |
| `system.disk.operations` | ✅ | ✅ |
|**[File System](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/internal/scraper/filesystemscraper/documentation.md)**|||
| `system.filesystem.usage` | ✅ | ✅ |
|**[Processes](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/internal/scraper/processesscraper/documentation.md)**|||
| `system.processes.count` | ✅ | ✅ |
| `system.processes.created` | ✅ | ✅ |

For step-by-step instructions on how to ingest OpenTelemetry data using Elastic's distribution of the OpenTelemetry Collector, see the
[quickstart guide](https://www.elastic.co/docs/reference/opentelemetry/quickstart/).

Also, it's recommended to enable the [`resourcedetection` processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/resourcedetectionprocessor/README.md) with detection of the following resource attributes explicitly enabled:

- `host.name`
- `host.id`
- `host.arch`
- `host.ip`
- `host.mac`
- `host.cpu.vendor.id`
- `host.cpu.family`
- `host.cpu.model.id`
- `host.cpu.model.name`
- `host.cpu.stepping`
- `host.cpu.cache.l2.size`
- `os.description`
- `os.type`

## Troubleshooting

If individual widgets in the dashboard show errors that certain fields are not evailable, that might be an indicator of one of the following:

- For your use case the missing data is not relevant (e.g. you are only running plain, local VMs, no `Cloud` metadata will be available)
- You are using the OpenTelemetry upstream Contrib Collector (or any other, non-EDOT Collector) and some of the above-mentioned requirements are not met

See also:

- [Scraper limitations](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.129.0/receiver/hostmetricsreceiver#host-metrics-receiver) with the `hostmetrics` receiver for certain systems
- [Related EDOT Collector limitations](https://www.elastic.co/docs/reference/opentelemetry/compatibility/limitations#infrastructure-and-host-metrics) for host metrics 
