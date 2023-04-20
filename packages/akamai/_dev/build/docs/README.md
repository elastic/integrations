# Akamai Integration

The Akamai integration collects events from the Akamai API, specifically reading from the [Akamai SIEM API](https://techdocs.akamai.com/siem-integration/reference/api).

## Logs

### SIEM

The Security Information and Event Management API allows you to capture security events generated on the ​Akamai​ platform in your SIEM application.

Use this API to get security event data generated on the ​Akamai​ platform and correlate it with data from other sources in your SIEM solution. Capture security event data incrementally, or replay missed security events from the past 12 hours. You can store, query, and analyze the data delivered through this API on your end, then go back and adjust your Akamai security settings. If you’re coding your own SIEM connector, it needs to adhere to these specifications in order to pull in security events from Akamai Security Events Collector (ASEC) and process them properly.

See [Akamai API get started](https://techdocs.akamai.com/siem-integration/reference/api-get-started) to set up your Akamai account and get your credentials.

### To collect data from GCS Bucket [Beta], follow the below steps:
- Configure the [Data Forwarder](https://techdocs.akamai.com/datastream2/docs/stream-google-cloud/) to ingest data into a GCS bucket.
- Configure the GCS bucket names and credentials along with the required configs under the "Collect Akamai SIEM logs via Google Cloud Storage" section. 
- Make sure the service account and authentication being used, has proper levels of access to the GCS bucket [Manage Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys/)

**Note**:
- The GCS input currently does not support fetching of buckets using bucket prefixes, so the bucket names have to be configured manually for each data stream.
- The GCS input currently only accepts a service account JSON key or a service account JSON file for authentication.
- The GCS input currently only supports JSON data.
- This input is still in beta.

{{fields "siem"}}

{{event "siem"}}