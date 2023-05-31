# SentinelOne Cloud Funnel

The [SentinelOne Cloud Funnel](https://assets.sentinelone.com/training/sentinelone_cloud_fu#page=1) integration allows you to monitor logs of various event types. SentinelOne Singularity XDR autonomously protects modern organizations across their expanding ecosystems by providing real-time endpoint protection, detection, and response capabilities. This process creates a growing wealth of XDR data. Singularity XDR stores this valuable information within its XDR DataLake for threat hunting and correlation. However, some enterprises prefer to store a copy of their XDR data in their own data lake, requiring an efficient solution to stream data to an outside source.
Cloud Funnel enables your security team to securely stream XDR data to Amazon S3 for data storage, integration with SIEM and SOAR tools, correlation with outside data sources, and other security workflows.

The SentinelOne Cloud Funnel integration can be used in two different modes to collect data:
- AWS S3 polling mode: SentinelOne Cloud Funnel writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode: SentinelOne Cloud Funnel writes data to S3, S3 sends a notification of a new object to SQS, the Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple agents can be used in this mode.

## Compatibility

This module has been tested against the latest SentinelOne Cloud Funnel version **v2**.

## Data streams

The SentinelOne Cloud Funnel integration collects logs for the following thirteen events:

| Event Type                    |
|-------------------------------|
| Command Script                |
| Cross Process                 |
| DNS                           |
| File                          |
| Indicator                     |
| Login                         |
| Module                        |
| Network Action                |
| Process                       |
| Registry                      |
| Scheduled Task                |
| Threat Intelligence Indicator |
| URL                           |

**NOTE**: The SentinelOne Cloud Funnel integration collects logs for the above mentioned events, but we have combined all of those in one data stream named `event`.

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).
The minimum **kibana.version** required is **8.3.0**.

## Setup

### To collect data from an AWS S3 bucket, follow the below steps:
- Considering you already have an AWS S3 bucket setup, to configure it with SentinelOne Cloud Funnel, follow the steps mentioned here: ```[Your Login URL]/docs/en/how-to-configure-your-amazon-s3-bucket.html```.
- Enable the Cloud Funnel Streaming as mentioned here: ```[Your Login URL]/docs/en/how-to-enable-cloud-funnel-streaming.html#how-to-enable-cloud-funnel-streaming```.
- The default value of the field `Bucket List Prefix` is s1/cloud_funnel.

**NOTE**:
- SentinelOne Cloud Funnel sends logs to the following destination: ```s1/ > cloud_funnel/ > yyyy/ > mm/ > dd/ > account_id={account_id}```.

- You must have SentinelOne Admin Account Credentials along with the Login URL.

### To collect data from AWS SQS, follow the below steps:
1. Assuming you've already set up a connection to push data into the AWS bucket; if not, see the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" mentioned in the [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
- While creating an access policy, use the bucket name configured to create a connection for AWS S3 in SentinelOne Cloud Funnel.
3. Configure event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue, and select the queue name created in Step 2.

## Logs reference

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}

