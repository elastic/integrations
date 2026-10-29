# Akamai Integration

The Akamai integration collects events from the Akamai API, specifically reading from the [Akamai SIEM API](https://techdocs.akamai.com/siem-integration/reference/api).

> **Breaking change in 4.0.0 — CEL to OpenTelemetry migration**

Starting with version 4.0.0, Akamai SIEM API collection uses the OpenTelemetry receiver instead of CEL and requires Elastic Stack 9.5.0 or later.

When upgrading from a CEL-based integration, compatible API settings and credentials can be preserved through automatic input migration.

**Before upgrading, review the following settings:**

- **Initial Interval:** Ensure this value is `12h` or less. The previous CEL input accepted larger values and automatically limited requests to 12 hours. The OpenTelemetry receiver rejects values exceeding `12h`, preventing collection from starting.
- **SSL Configuration:** Existing Beats SSL settings such as `certificate_authorities`, `verification_mode`, and `supported_protocols` are not automatically converted to the OpenTelemetry TLS schema. Review and rewrite custom SSL configurations using the supported options (`ca_file`, `ca_pem`, `cert_file`, `cert_pem`, `key_file`, `key_pem`, `insecure_skip_verify`, `min_version`, and `max_version`).
- **Custom Processors:** Custom CEL/Beats processors are not migrated to the OpenTelemetry input. Any filtering, enrichment, or transformations implemented through these processors will no longer be applied. Review and reimplement the required processing before upgrading, for example using an Elasticsearch custom ingest pipeline (`logs-akamai.siem@custom`). Note that Elasticsearch ingest pipelines process events after they are transmitted from Elastic Agent, rather than filtering them at the source.

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

### To collect data from Amazon S3

Akamai [DataStream 2 security logs](https://techdocs.akamai.com/datastream2/docs/security-logs) can be delivered to an [Amazon S3 destination](https://techdocs.akamai.com/datastream2/docs/stream-amazon-s3). The Akamai integration can collect these files using the `aws-s3` input, either by consuming S3 object notifications from Amazon SQS (recommended) or by directly polling an S3 bucket. Both methods use the existing `akamai.siem` data stream and ingest pipeline.

#### Configure native Akamai delivery to Amazon S3

1. In Akamai DataStream 2, create a security logs (SIEM) stream and select the relevant security configurations. See [Create a security log stream](https://techdocs.akamai.com/datastream2/docs/create-a-security-log-stream).
2. Select **Amazon S3** as the delivery destination and configure the bucket name, region, optional folder path, and AWS access credentials. Follow [Akamai's Amazon S3 destination instructions](https://techdocs.akamai.com/datastream2/docs/stream-amazon-s3).
3. Choose JSON security logs. Akamai DataStream 2 delivers log files gzip-compressed by default. The AWS S3 input reads supported compressed objects and processes newline-delimited JSON records individually.
4. Verify that files are arriving in the intended S3 bucket and prefix. Note that Akamai might also create a small access-verification file while validating the destination. Use a dedicated prefix or filtering where appropriate to avoid ingesting non-log files.

#### Collect data from AWS SQS (recommended)

1. Create a **Standard** SQS queue in the same AWS region as the S3 bucket. Do not use a FIFO queue for native S3 event notifications.
2. Configure the queue's resource-based access policy to allow the `s3.amazonaws.com` service principal to perform `sqs:SendMessage`, restricted to the intended bucket ARN (`aws:SourceArn`) and AWS account (`aws:SourceAccount`). See [AWS S3 event notification permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/grant-destinations-permissions-to-s3.html).
3. On the S3 bucket, create an event notification for **All object create events** (`s3:ObjectCreated:*`) with the SQS queue as the destination. Set an optional prefix or suffix filter if only Akamai log objects should generate notifications.
4. Grant the Elastic Agent's AWS identity `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:ChangeMessageVisibility`, and `sqs:GetQueueAttributes` on the queue, plus `s3:GetObject` on the relevant S3 objects. If a customer-managed AWS KMS key protects the resources, include the required KMS permissions.
5. In Fleet, enable **Collect Akamai SIEM logs via AWS S3 / SQS**, leave **Collect via direct S3 bucket polling** disabled, and set **SQS Queue URL**. Configure the AWS region and authentication. Prefer an IAM role or the standard AWS credential chain to long-lived access keys where available.
6. Adjust **SQS Visibility Timeout**, **SQS API Timeout**, and **Workers** for the expected object sizes and traffic. The API timeout must not exceed half the visibility timeout.

SQS messages must contain standard S3 event notifications. Nonstandard wrappers, such as messages produced through SNS or EventBridge, might require custom notification parsing and are not configured by this integration's default input template. For a shared queue, use file selectors carefully. Do not have multiple independent consumers compete for the same messages.

#### Collect data by direct S3 bucket polling

1. In Fleet, enable **Collect Akamai SIEM logs via AWS S3 / SQS** and turn on **Collect via direct S3 bucket polling**.
2. Enter the **S3 Bucket ARN** (`arn:aws:s3:::your-bucket`). Optionally set **S3 Bucket Prefix** and **S3 Bucket List Interval**.
3. Grant the Elastic Agent's AWS identity `s3:ListBucket` and `s3:GetObject`, and `s3:GetBucketLocation` if required by your environment. Configure AWS credentials and region, and save the policy.

Use either SQS notifications or direct bucket polling for a given input, not both. SQS is preferred for ongoing collection because it avoids repeated bucket listing. Avoid collecting the same objects through multiple inputs, which can result in duplicate processing.

**Note**:
- These instructions cover **Amazon S3**. Although Akamai also supports [S3-compatible destinations](https://techdocs.akamai.com/datastream2/docs/stream-s3-compatible), this input currently exposes an Amazon S3 bucket ARN or an AWS SQS queue URL, not the `non_aws_bucket_name` configuration required for generic S3-compatible storage.
- This integration supports Akamai DataStream 2 [Security Logs (SIEM)](https://techdocs.akamai.com/datastream2/docs/security-logs) exported in JSON format to Amazon S3. Other DataStream 2 log types are not supported by the `akamai.siem` ingest pipeline.

{{fields "siem"}}

{{event "siem"}}
