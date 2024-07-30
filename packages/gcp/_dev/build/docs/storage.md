# Storage

## Metrics

The `storage` dataset fetches metrics from [Storage](https://cloud.google.com/storage/) in Google Cloud Platform. It contains all metrics exported from the [GCP Storage Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-storage).

You can specify a single region to fetch metrics like `us-central1`. Be aware that GCP Storage does not use zones so `us-central1-a` will return nothing. If no region is specified, it will return metrics from all buckets.

## Sample Event
    
{{event "storage"}}

## Exported fields

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "storage"}}