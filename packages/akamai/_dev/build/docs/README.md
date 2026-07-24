# Akamai Integration

The Akamai integration collects events from the Akamai API, specifically reading from the [Akamai SIEM API](https://techdocs.akamai.com/siem-integration/reference/api).

> **Breaking change in 4.0.0**: The backend used to collect Akamai SIEM logs from the API has changed. After upgrading, existing agent policies that collect Akamai SIEM logs via the API must be reconfigured for data collection to resume. Collection from Google Cloud Storage is unaffected.

## Logs

### SIEM

The Security Information and Event Management API allows you to capture security events generated on the Akamai platform in your SIEM application.

Use this API to get security event data generated on the Akamai platform and correlate it with data from other sources in your SIEM solution. Capture security event data incrementally, or replay missed security events from the past 12 hours. You can store, query, and analyze the data delivered through this API on your end, then go back and adjust your Akamai security settings. If you’re coding your own SIEM connector, it needs to adhere to these specifications in order to pull in security events from Akamai Security Events Collector (ASEC) and process them properly.

See [Akamai API get started](https://techdocs.akamai.com/siem-integration/reference/api-get-started) to set up your Akamai account and get your credentials.

### To collect data via API, follow the steps below:
- Configure the API Host, Security Configuration IDs and the EdgeGrid credentials (Client Token, Client Secret, Access Token) under the "Collect Akamai SIEM logs via API" section.
- If the integration policy uses a namespace other than `default`, set the "Data Stream Namespace" option to the same value.

API collection uses the native OpenTelemetry `akamai_siem` receiver behind the scenes. This is an internal backend detail and does not change the data you collect.

**Note**:
- Cursor persistence is enabled by default, so collection resumes from where it left off after an Elastic Agent restart. It can be turned off via the "Enable Cursor Persistence" advanced option; when disabled, after a restart the integration re-fetches the configured Initial Interval window, and any duplicate events are removed during ingestion. Cursor persistence is not guaranteed across stack upgrades and breaking changes; in those cases the integration re-fetches the configured Initial Interval window, and any duplicate events are removed during ingestion.

### To collect data from GCS Bucket, follow the steps below:
- Configure the [Data Forwarder](https://techdocs.akamai.com/datastream2/docs/stream-google-cloud/) to ingest data into a GCS bucket.
- Configure the GCS bucket names and credentials along with the required configs under the "Collect Akamai SIEM logs via Google Cloud Storage" section. 
- Make sure the service account and authentication being used, has proper levels of access to the GCS bucket [Manage Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys/)

**Note**:
- The GCS input currently does not support fetching of buckets using bucket prefixes, so the bucket names have to be configured manually for each data stream.
- The GCS input currently only accepts a service account JSON key or a service account JSON file for authentication.
- The GCS input currently only supports JSON data.

{{fields "siem"}}

{{event "siem"}}