<img width="1093" height="503" alt="image" src="https://github.com/user-attachments/assets/c47ab648-6d7a-4bcb-878c-ea86257ec76f" /># Akamai Integration

The Akamai integration collects events from the Akamai API, specifically reading from the [Akamai SIEM API](https://techdocs.akamai.com/siem-integration/reference/api).

>**Breaking change in 4.0.0 — CEL to OpenTelemetry migration**

Starting with version 4.0.0, Akamai SIEM API collection uses the OpenTelemetry receiver instead of CEL and requires Elastic Stack 9.5.0 or later.

When upgrading from a CEL-based integration, compatible API settings and credentials can be preserved through automatic input migration.

**Before upgrading, review the following settings:**

- **Initial Interval:** Ensure this value is `12h` or less. The previous CEL input accepted larger values and automatically limited requests to 12 hours. The OpenTelemetry receiver rejects values exceeding `12h`, preventing collection from starting.
- **SSL Configuration:** Existing Beats SSL settings such as `certificate_authorities`, `verification_mode`, and `supported_protocols` are not automatically converted to the OpenTelemetry TLS schema. Review and rewrite custom SSL configurations using the supported options (`ca_file`, `ca_pem`, `cert_file`, `cert_pem`, `key_file`, `key_pem`, `insecure_skip_verify`, `min_version`, and `max_version`).
- **Custom Processors**: Custom CEL/Beats processors are not migrated to the OpenTelemetry input. Any filtering, enrichment, or transformations implemented through these processors will no longer be applied. Review and reimplement the required processing before upgrading, for example using an Elasticsearch custom ingest pipeline (logs-akamai.siem@custom). Note that Elasticsearch ingest pipelines process events after they are transmitted from Elastic Agent, rather than filtering them at the source.

The Akamai SIEM API provides access to only the previous 12 hours of events. Verify that data collection resumes promptly after upgrading to avoid permanent gaps. Collection from Google Cloud Storage is unaffected.

## Logs

### SIEM

The Security Information and Event Management API allows you to capture security events generated on the Akamai platform in your SIEM application.

Use this API to get security event data generated on the Akamai platform and correlate it with data from other sources in your SIEM solution. Capture security event data incrementally, or replay missed security events from the past 12 hours. You can store, query, and analyze the data delivered through this API on your end, then go back and adjust your Akamai security settings. If you’re coding your own SIEM connector, it needs to adhere to these specifications in order to pull in security events from Akamai Security Events Collector (ASEC) and process them properly.

See [Akamai API get started](https://techdocs.akamai.com/siem-integration/reference/api-get-started) to set up your Akamai account and get your credentials.

### To collect data via API, follow the steps below:
- Enable the "Collect Akamai SIEM logs via API" toggle; it is disabled by default.
- Configure the API Host, Zone IDs and the EdgeGrid credentials (Client Token, Client Secret, Access Token) under the "Collect Akamai SIEM logs via API" section.
- If the integration policy uses a namespace other than `default`, set the "Data Stream Namespace" option to the same value.

API collection uses the native OpenTelemetry `akamai_siem` receiver behind the scenes. This is an internal backend detail and does not change the Akamai event data you collect.

**Note**:
- Events collected via the API carry fewer agent fields than events collected by the earlier Beats-based input. `agent.name` is the host name of the Elastic Agent (or the `ELASTIC_AGENT_HOSTNAME` override), and `input.type` is `otelcol` (the CEL input used `cel`). `agent.type`, `agent.id`, `agent.version`, `agent.ephemeral_id` and the `elastic_agent.*` fields are not set, so `event.agent_id_status` is `missing`.
- Cursor persistence is enabled by default, so collection resumes from where it left off after an Elastic Agent restart. It can be turned off via the "Persist Cursor" advanced option. Cursor persistence is also not guaranteed across stack upgrades and breaking changes. Whenever the cursor is unavailable, the integration re-fetches the configured Initial Interval window; replayed events are deduplicated by the ingest pipeline's `event.original` fingerprint as long as the data stream is still writing to the same backing index.

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
