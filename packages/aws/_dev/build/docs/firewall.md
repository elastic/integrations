# AWS Network Firewall

This integration is used to fetch logs and metrics from [AWS Network Firewall](https://aws.amazon.com/network-firewall/).

## Logs

The `firewall_logs` dataset collects AWS Network Firewall logs. Users can use these logs to
monitor network activity.

{{event "firewall_logs" }}

{{fields "firewall_logs"}}

## Metrics

The `firewall_metrics` dataset collects AWS Network Firewall metrics.

{{event "firewall_metrics" }}

{{fields "firewall_metrics"}}
