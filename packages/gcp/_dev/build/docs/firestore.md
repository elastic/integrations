# Firestore

## Metrics

The `firestore` dataset fetches metrics from [Firestore](https://cloud.google.com/firestore/) in Google Cloud Platform. It contains all metrics exported from the [GCP Firestore Monitoring API](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-firestore).

You can specify a single region to fetch metrics like `us-central1`. Be aware that GCP Storage does not use zones so `us-central1-a` will return nothing. If no region is specified, it will return metrics from all buckets.

## Sample Event
    
{{event "firestore"}}

## Exported fields

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "firestore"}}