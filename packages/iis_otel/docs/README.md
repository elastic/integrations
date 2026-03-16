# IIS OpenTelemetry Assets

Internet Information Services (IIS) is Microsoft's extensible web server for Windows, used to host websites, web applications, and services such as ASP.NET, WCF, and static content. It is the primary HTTP server on the Windows platform.

This content pack provides dashboards, alert rules, and SLO templates that use metrics from the OpenTelemetry IIS receiver. The assets cover application pool health, request handling capacity, traffic patterns, and resource utilization.

## Compatibility

The IIS OpenTelemetry assets have been tested with OpenTelemetry IIS receiver v0.146.1.

IIS tested against:

- IIS 10.0 (Windows Server 2016/2019/2022)

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

### Prerequisites

IIS must be running on the Windows host where you deploy the OpenTelemetry Collector. The collector uses Windows Performance Counters to gather IIS metrics, so the counters must be accessible.

To verify IIS is running:

```powershell
Get-Service W3SVC
```

To list available web service counters:

```powershell
Get-Counter -ListSet "Web Service"
```

If counters are corrupted or missing, rebuild them:

```powershell
lodctr /r
```

### Configuration

Add the following configuration to your OpenTelemetry Collector or Elastic Observability Distribution of OpenTelemetry (EDOT) Collector. The IIS receiver runs on the Windows host that runs IIS; it collects metrics from local performance counters and exports them to Elasticsearch.

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `<ES_ENDPOINT>` | Your Elasticsearch endpoint URL | `https://my-cluster.es.us-central1.gcp.cloud.es.io:443` |
| `<ES_API_KEY>` | Elasticsearch API key with privileges to ingest metrics | Set via `ES_API_KEY` environment variable |

```yaml
receivers:
  iis:
    collection_interval: 30s

processors:
  resourcedetection/system:
    detectors: ["system"]
    system:
      hostname_sources: ["os"]

exporters:
  elasticsearch/otel:
    endpoints: [ '<ES_ENDPOINT>' ]
    api_key: '${env:ES_API_KEY}'
    mapping:
      mode: otel

service:
  pipelines:
    metrics:
      receivers: [ iis ]
      processors: [ resourcedetection/system ]
      exporters: [ elasticsearch/otel ]
```

> **Note**: Run the collector on the same Windows host as IIS so it can read local performance counters. The receiver has no remote collection capability.

The `resourcedetection/system` processor is required to populate host information (`resource.attributes.host.name`) used by the dashboards. Without it, host-level fields will be empty.

## Reference

### Metrics

Refer to the [metadata.yaml](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/iisreceiver/metadata.yaml) of the OpenTelemetry IIS receiver for details on available metrics.

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| **[IIS OTel] Overview** | Key metrics for IIS web server health — application pool state, request handling, traffic, and resource utilization. |
| **[IIS OTel] Sites & Pools** | Per-site and per-application-pool breakdown of request handling, traffic, and resource utilization. |

## Alert rules

| Alert | Trigger | Severity |
|-------|---------|----------|
| **[IIS OTel] Application pool not running** | Application pool state is not Running (3) | Critical |
| **[IIS OTel] Request rejections detected** | One or more requests rejected in the evaluation window | High |
| **[IIS OTel] Request queue depth elevated** | Request queue depth exceeds 10 | High |
| **[IIS OTel] Request queue age elevated** | Oldest queued request age exceeds 5000 ms | Medium |
| **[IIS OTel] Bandwidth throttling detected** | Bytes blocked by bandwidth throttling in the evaluation window | Warning |

## SLO templates

> **Note**: SLO templates require Elastic Stack version 9.4.0 or later.

| SLO | Target | Window | Description |
|-----|--------|--------|-------------|
| **[IIS OTel] Zero request rejections 99.5% rolling 30 days** | 99.5% | 30-day rolling | Proportion of 1-minute intervals with zero request rejections; non-zero rejections indicate the server failed to serve clients. |
| **[IIS OTel] Request queue age 99.5% rolling 30 days** | 99.5% | 30-day rolling | Proportion of 1-minute intervals where the oldest queued request age stays below 1000 ms; queue age is the primary latency proxy. |
