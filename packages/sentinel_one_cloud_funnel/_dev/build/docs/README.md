# SentinelOne Cloud Funnel

This [SentinelOne Cloud Funnel](https://assets.sentinelone.com/training/sentinelone_cloud_fu#page=1) integration enables your security team to securely stream XDR data to Elastic Security, via Amazon S3. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for threat protection, detection, and incident response.

The SentinelOne Cloud Funnel integration can be used in three different modes to collect data:
- AWS S3 polling mode: SentinelOne Cloud Funnel writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode: SentinelOne Cloud Funnel writes data to S3, S3 sends a notification of a new object to SQS, the Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple agents can be used in this mode.
- GCS polling mode: SentinelOne Cloud Funnel writes data to GCS bucket, and Elastic Agent polls the GCS bucket by listing its contents and reading new files.

## Compatibility

This module has been tested against the latest SentinelOne Cloud Funnel version **v2**.

## Data streams

The SentinelOne Cloud Funnel integration collects logs for the following thirteen events:

| Event Type                    |
|-------------------------------|
| Command Script                |
| Cross Process                 |
| DNS                           |
| File                          |
| Indicator                     |
| Login                         |
| Module                        |
| Network Action                |
| Process                       |
| Registry                      |
| Scheduled Task                |
| Threat Intelligence Indicator |
| URL                           |

**NOTE**: The SentinelOne Cloud Funnel integration collects logs for the above mentioned events, but we have combined all of those in one data stream named `event`.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the S3 bucket and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### To collect data from an AWS S3 bucket, follow the below steps:

- Considering you already have an AWS S3 bucket setup, to configure it with SentinelOne Cloud Funnel, follow the steps mentioned here: `[Your Login URL]/docs/en/how-to-configure-your-amazon-s3-bucket.html`.
- Enable the Cloud Funnel Streaming as mentioned here: `[Your Login URL]/docs/en/how-to-enable-cloud-funnel-streaming.html#how-to-enable-cloud-funnel-streaming`.
- The default value of the field `Bucket List Prefix` is s1/cloud_funnel.

### To collect data from a GCS bucket, follow the below steps:

- Considering you already have a GCS bucket setup, configure it with SentinelOne Cloud Funnel.
- Enable the Cloud Funnel Streaming as mentioned here: `[Your Login URL]/docs/en/how-to-enable-cloud-funnel-streaming.html#how-to-enable-cloud-funnel-streaming`.
- The default value of the field `File Selectors` is `- regex: "s1/cloud_funnel"`. It is commented out by default and resides in the advanced settings section.
- Configure the integration with your GCS project ID and JSON Credentials key.

## The GCS credentials key file:
This is a one-time download JSON key file that you get after adding a key to a GCP service account. 
If you are just starting out creating your GCS bucket, do the following: 

1) Make sure you have a service account available, if not follow the steps below:
   - Navigate to 'APIs & Services' > 'Credentials'
   - Click on 'Create credentials' > 'Service account'
2) Once the service account is created, you can navigate to the 'Keys' section and attach/generate your service account key.
3) Make sure to download the JSON key file once prompted.
4) Use this JSON key file either inline (JSON string object), or by specifying the path to the file on the host machine, where the agent is running.

A sample JSON Credentials file looks as follows: 
```json
{
  "type": "dummy_service_account",
  "project_id": "dummy-project",
  "private_key_id": "dummy-private-key-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\nDummyPrivateKey\n-----END PRIVATE KEY-----\n",
  "client_email": "dummy-service-account@example.com",
  "client_id": "12345678901234567890",
  "auth_uri": "https://dummy-auth-uri.com",
  "token_uri": "https://dummy-token-uri.com",
  "auth_provider_x509_cert_url": "https://dummy-auth-provider-cert-url.com",
  "client_x509_cert_url": "https://dummy-client-cert-url.com",
  "universe_domain": "dummy-universe-domain.com"
}
```

**NOTE**:

- SentinelOne Cloud Funnel sends logs to the following destination: `s1/ > cloud_funnel/ > yyyy/ > mm/ > dd/ > account_id={account_id}`.

- You must have SentinelOne Admin Account Credentials along with the Login URL.

- When using the GCS input, if you are using JSON Credentials inline, then you must specify the entire JSON object within single quotes i.e `'{GCS_CREDS_JSON_OBJECT}'`

### To collect data from AWS SQS, follow the below steps:

1. Assuming you've already set up a connection to push data into the AWS bucket; if not, see the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" mentioned in the [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
   - While creating an access policy, use the bucket name configured to create a connection for AWS S3 in SentinelOne Cloud Funnel.
3. Configure event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
   - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue, and select the queue name created in Step 2.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type SentinelOne Cloud Funnel
3. Click on the "SentinelOne Cloud Funnel" integration from the search results.
4. Click on the Add SentinelOne Cloud Funnel Integration button to add the integration.
5. While adding the integration, if you want to collect logs via AWS S3, then you have to put the following details:
   - access key id
   - secret access key
   - bucket arn
   - collect logs via S3 Bucket toggled on

   or if you want to collect logs via AWS SQS, then you have to put the following details:
   - access key id
   - secret access key
   - queue url
   - collect logs via S3 Bucket toggled off

**NOTE**: There are other input combination options available, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

## Logs reference

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}

