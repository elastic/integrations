# Kibana

The Kibana integration collects events from your {{ url "kibana-introduction" "Kibana" }} instance.

## Configuration parameters

If the Kibana instance is using a basepath in its URL, you must set the `basepath` setting for this integration with the same value.

## Compatibility

The `kibana` package works with Kibana 8.10.0 and later.

## Usage for Stack Monitoring

The `kibana` package can be used to collect metrics shown in our Stack Monitoring
UI in Kibana.

**Note**: Using this integration package will require elasticsearch to be monitored as well in order to see the data in Stack Monitoring UI. If the elasticsearch data is not collected and only Kibana is monitored the Stack monitoring UI won't show the Kibana data.

## Logs

### Audit

{{fields "audit"}}

### Log

{{fields "log"}}

## HTTP Metrics

### Background task utilization

This data stream uses the `/api/task_manager/_background_task_utilization` API of Kibana, which is available starting in 8.9.

{{fields "background_task_utilization"}}

{{event "background_task_utilization"}}

### Task manager metrics

This data stream uses the `/api/task_manager/metrics` API of Kibana, which is available starting in 8.10.

{{fields "task_manager_metrics"}}

{{event "task_manager_metrics"}}

## Metrics

### Stats

Stats data stream uses the stats endpoint of Kibana, which is available in 6.4 by default.

{{fields "stats"}}

{{event "stats"}}

### Status

This status endpoint is available in 6.0 by default and can be enabled in Kibana >= 5.4 with the config option `status.v6ApiFormat: true`.

{{fields "status"}}

{{event "status"}}

### Cluster actions

Cluster actions metrics documentation

{{fields "cluster_actions"}}

{{event "cluster_actions"}}

### Cluster rules

Cluster rules metrics

{{fields "cluster_rules"}}

{{event "cluster_rules"}}

### Node actions

Node actions metrics

{{fields "node_actions"}}

{{event "node_actions"}}

### Node rules

Node rules metrics

{{fields "node_rules"}}

{{event "node_rules"}}
