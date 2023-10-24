# Storage

## Metrics

The `storage` dataset fetches metrics from [Storage](https://cloud.google.com/storage/) in Google Cloud Platform. It contains all metrics exported from the [GCP Storage Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-storage).

You can specify a single region to fetch metrics like `us-central1`. Be aware that GCP Storage does not use zones so `us-central1-a` will return nothing. If no region is specified, it will return metrics from all buckets.

## Sample Event
    
{{event "storage"}}

## Exported fields

{{fields "storage"}}