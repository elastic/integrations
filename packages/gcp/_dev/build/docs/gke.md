# GKE

## Metrics

The `gke` dataset fetches metrics from [GKE](https://cloud.google.com/kubernetes-engine) in Google Cloud Platform. It contains all GA metrics exported from the [GCP GKE Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-container).

You can specify a single region to fetch metrics like `us-central1`. Be aware that GCP GKE does not use zones so `us-central1-a` will return nothing. If no region is specified, it will return metrics from all regions.

## Sample Event
    
{{event "gke"}}

## Exported fields

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "gke"}}