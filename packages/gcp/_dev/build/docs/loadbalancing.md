# Load Balancing

## Logs

The `loadbalancing_logs` dataset collects logs of the requests sent to and handled by GCP Load Balancers.

{{event "loadbalancing_logs"}}

{{fields "loadbalancing_logs"}}

## Metrics

The `loadbalancing_metrics` dataset fetches HTTPS, HTTP, and Layer 3 metrics from [Load Balancing](https://cloud.google.com/load-balancing/) in Google Cloud Platform. It contains all metrics exported from the [GCP Load Balancing Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-loadbalancing).

{{event "loadbalancing_metrics"}}

{{fields "loadbalancing_metrics"}}