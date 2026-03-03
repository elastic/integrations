# Dataproc

## Metrics

The `dataproc` dataset fetches metrics from [Dataproc](https://cloud.google.com/dataproc/) in Google Cloud Platform. It contains all metrics exported from the [GCP Dataproc Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-dataproc).

You can specify a single region to fetch metrics like `us-central1`. Be aware that GCP Dataproc is a regional service. If no region is specified, it will return metrics from all buckets.

## Sample Event
    
{{event "dataproc"}}

## Exported fields

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "dataproc"}}