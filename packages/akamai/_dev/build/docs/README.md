# Akamai Integration

The Akamai integration collects events from the Akamai API, specifically reading from the [Akamai SIEM API](https://techdocs.akamai.com/siem-integration/reference/api).

## Logs

### SIEM

The Security Information and Event Management API allows you to capture security events generated on the Akamai platform in your SIEM application.

Use this API to get security event data generated on the Akamai platform and correlate it with data from other sources in your SIEM solution. Capture security event data incrementally, or replay missed security events from the past 12 hours. You can store, query, and analyze the data delivered through this API on your end, then go back and adjust your Akamai security settings. If you’re coding your own SIEM connector, it needs to adhere to these specifications in order to pull in security events from Akamai Security Events Collector (ASEC) and process them properly.

See [Akamai API get started](https://techdocs.akamai.com/siem-integration/reference/api-get-started) to set up your Akamai account and get your credentials.

### To collect data from GCS Bucket, follow the below steps:
- Configure the [Data Forwarder](https://techdocs.akamai.com/datastream2/docs/stream-google-cloud/) to ingest data into a GCS bucket.
- Configure the GCS bucket names and credentials along with the required configs under the "Collect Akamai SIEM logs via Google Cloud Storage" section. 
- Make sure the service account and authentication being used, has proper levels of access to the GCS bucket [Manage Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys/)

**Note**:
- The GCS input currently does not support fetching of buckets using bucket prefixes, so the bucket names have to be configured manually for each data stream.
- The GCS input currently only accepts a service account JSON key or a service account JSON file for authentication.
- The GCS input currently only supports JSON data.

### To collect data via the OpenTelemetry receiver (Technical Preview), follow the below steps:

This collection mode uses the native OpenTelemetry `akamai_siem` receiver embedded in the Elastic Agent's EDOT collector instead of the CEL input. It polls the same [Akamai SIEM API](https://techdocs.akamai.com/siem-integration/reference/api) using the same EdgeGrid credentials.

- Requires Elastic Stack (Kibana, Elastic Agent) version 9.5.0 or later.
- Configure the API Host, Security Configuration IDs and the EdgeGrid credentials (Client Token, Client Secret, Access Token) under the "Collect Akamai SIEM logs via OpenTelemetry receiver" section.
- Events are routed to the `akamai.siem` dataset, processed by the same ingest pipeline as the CEL input, and stored in `logs-akamai.siem-<namespace>`.
- If the integration policy uses a namespace other than `default`, set the "Data Stream Namespace" option to the same value so that the `data_stream.namespace` field written into each event matches the target data stream.

**Note**:
- The receiver supports persisting its poll cursor through an OpenTelemetry storage extension (equivalent to the CEL input's registry-based cursor), but Fleet cannot yet wire storage extensions into receiver configurations, so cursor persistence is not available in Fleet-managed deployments. After an agent restart the receiver re-fetches the configured Initial Lookback window; replayed events are deduplicated by the ingest pipeline's `event.original` fingerprint within the same backing index.
- Unlike the CEL input, events collected via the OTel receiver are not tagged with `akamai-siem`/`forwarded` tags.

{{fields "siem"}}

{{event "siem"}}