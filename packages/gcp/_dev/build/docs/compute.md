# Compute

## Metrics

The `compute` dataset is designed to fetch metrics for [Compute Engine](https://cloud.google.com/compute/) Virtual Machines in Google Cloud Platform. It contains all metrics exported from the [GCP Cloud Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-compute).

Extra labels and metadata are also extracted using the [Compute API](https://cloud.google.com/compute/docs/reference/rest/v1/instances/get). This is enough to get most of the info associated with a metric like Compute labels and metadata and metric specific Labels.

## Sample Event

{{event "compute"}}

## Exported fields

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "compute"}}