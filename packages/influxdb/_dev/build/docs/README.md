# InfluxDB Integration

This integration is for ingesting task, storage, golang, performance related metrics from InfluxDB OSS 2.x databases. This integration provides out-of-the-box dashboards named Status Metrics, Advanced Status Metrics.


## Requirements

This integration depends on prometheus endpoint (default: `http://<InfluxDBhost>:<port>/metrics`) of InfluxDB for collecting status and advanced status metrics. 


## Compatibility

This integration has been tested against InfluxDB OSS 2.4, InfluxDB OSS 2.0


## Metrics

### Status Metrics

Status metrics include details of memory usage, OS thread usage, query statistics, organization & users statistics, tasks & task workers, WAL size etc.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "status"}}

{{event "status"}}

### Advanced Status Metrics

Advanced status metric include details of query execution statistics, compaction levels, retention details, errors & partial writes, latency etc.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "advstatus"}}

{{event "advstatus"}}
