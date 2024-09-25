# Load Balancing

## Logs

The `loadbalancing_logs` dataset collects logs of the requests sent to and handled by GCP Load Balancers.

{{event "loadbalancing_logs"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "loadbalancing_logs"}}

## Metrics

The `loadbalancing_metrics` dataset fetches HTTPS, HTTP, and Layer 3 metrics from [Load Balancing](https://cloud.google.com/load-balancing/) in Google Cloud Platform. It contains all metrics exported from the [GCP Load Balancing Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-loadbalancing).

{{event "loadbalancing_metrics"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "loadbalancing_metrics"}}