# Influxdb Integration

This integration is for ingesting task, storage, golang, performance related metrics from Influxdb OSS 2.x databases. This integration provides  out-of-the-box dashboards named Status Metrics, Advanced Status Metrics.


## Requirements

This integration depends on prometheus endpoint (default: `http://<influxdbhost>:<port>/metrics`) of Influxdb for collecting status and advanced status metrics. 


## Compatibility

This integration has been tested against Influxdb OSS 2.4, Influxdb OSS 2.0


## Metrics

### Status Metrics

Status metrics include details of memory usage, OS thread usage, query statistics, organization & users statistics, tasks & task workers, WAL size etc.


{{fields "status"}}

{{event "status"}}

### Advanced Status Metrics

Advanced status metric include details of query execution statistics, compaction levels, retention details, errors & partial writes, latency etc.

{{fields "advstatus"}}

{{event "advstatus"}}


