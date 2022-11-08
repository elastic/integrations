# Kibana

The Kibana integration collects events from your {{ url "kibana-introduction" "Kibana" }} instance.

## Configuration parameters

If the Kibana instance is using a basepath in its URL, you must set the `basepath` setting for this integration with the same value.

## Compatibility

The `kibana` package works with Kibana 8.5.0 and later.

## Usage for Stack Monitoring

The `kibana` package can be used to collect metrics shown in our Stack Monitoring
UI in Kibana. To enable this usage, set `xpack.enabled: true` on the package config.

## Logs

### Audit

{{fields "audit"}}

### Log

{{fields "log"}}

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
