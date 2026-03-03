# SentinelOne Cloud Funnel

This [SentinelOne Cloud Funnel](https://assets.sentinelone.com/training/sentinelone_cloud_fu#page=1) integration enables your security team to securely stream XDR data to Elastic Security, via Amazon S3. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for threat protection, detection, and incident response.

The SentinelOne Cloud Funnel integration can be used in four different modes to collect data:
- AWS S3 polling mode: SentinelOne Cloud Funnel writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode: SentinelOne Cloud Funnel writes data to S3, S3 sends a notification of a new object to SQS, the Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple agents can be used in this mode.
- GCS polling mode: SentinelOne Cloud Funnel writes data to GCS bucket, and Elastic Agent polls the GCS bucket by listing its contents and reading new files.
- Azure Blob Storage mode: SentinelOne Cloud Funnel writes data to Azure Blob containers, and Elastic Agent polls the data from containers by listing its contents and reading new files.

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

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

### Collect data from an AWS S3 bucket

1. Assuming that you already have an AWS S3 bucket setup, configure it with SentinelOne Cloud Funnel by following these steps: `[Your Login URL]/docs/en/how-to-configure-your-amazon-s3-bucket.html`.
2. Enable the Cloud Funnel Streaming as mentioned here: `[Your Login URL]/docs/en/how-to-enable-cloud-funnel-streaming.html#how-to-enable-cloud-funnel-streaming`.
The default value of the field **Bucket List Prefix** is `s1/cloud_funnel`.

### Collect data from a GCS bucket

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

**NOTE**

- SentinelOne Cloud Funnel sends logs to the following destination: `s1/ > cloud_funnel/ > yyyy/ > mm/ > dd/ > account_id={account_id}`.

- You must have SentinelOne Admin Account Credentials along with the Login URL.

- When using the GCS input, if you are using JSON Credentials inline, then you must specify the entire JSON object within single quotes i.e `'{GCS_CREDS_JSON_OBJECT}'`

### Collect data from AWS SQS

1. Assuming you've already set up a connection to push data into the AWS bucket; if not, check the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" mentioned in the [this guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
   - While creating an access policy, use the bucket name configured to create a connection for AWS S3 in SentinelOne Cloud Funnel.
3. To configure event notifications for an S3 bucket, check [this guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
   - While creating `event notification` select the event type as `s3:ObjectCreated:*`, destination type `SQS Queue`, and select the queue name created in Step 2.

### Collect data from an Azure Blob Storage

- Considering you already have an Blob Storage setup, to configure it with SentinelOne Cloud Funnel, follow the steps mentioned here: `[Your Login URL]/docs/en/how-to-configure-your-amazon-s3-bucket.html`.
- Enable the Cloud Funnel Streaming as mentioned here: `[Your Login URL]/docs/en/how-to-enable-cloud-funnel-streaming.html#how-to-enable-cloud-funnel-streaming`.
- Configure the integration using either Service Account Credentials or Microsoft Entra ID RBAC with OAuth2 options.For OAuth2 (Entra ID RBAC), you'll need the Client ID, Client Secret, and Tenant ID. For Service Account Credentials, you'll need either the Service Account Key or the URI to access the data.
- How to setup the `auth.oauth2` credentials can be found in the Azure documentation https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app[here]

Note:
- The service principal must be granted the appropriate permissions to read blobs. Ensure that the necessary role assignments are in place for the service principal to access the storage resources. For more information, please refer to the [Azure Role-Based Access Control (RBAC) documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage).
- We recommend assigning either the Storage Blob Data Reader or BlobOwner role. The Storage Blob Data Reader role provides read-only access to blob data and is aligned with the principle of least privilege, making it suitable for most use cases. The Storage Blob Data Owner role grants full administrative access — including read, write, and delete permissions — and should be used only when such elevated access is explicitly required.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **SentinelOne Cloud Funnel**.
3. Select the **SentinelOne Cloud Funnel** integration and add it.
4. While adding the integration, if you want to collect logs via AWS S3, then you have to put the following details:
   - access key id
   - secret access key
   - bucket arn
   - collect logs via S3 Bucket toggled on

   or if you want to collect logs via AWS SQS, then you have to put the following details:
   - access key id
   - secret access key
   - queue url
   - collect logs via S3 Bucket toggled off
5. To collect logs from Azure Blob Storage, you'll need to provide the following details:
   For OAuth2 (Microsoft Entra ID RBAC):
   - Account Name
   - Client ID
   - Client Secret
   - Tenant ID
   - Container Details.

   For Service Account Credentials:
   - Service Account Key or the URI
   - Account Name
   - Container Details
6. To collect logs from Google Cloud Storage, you'll need to provide the following details:
   - Project ID
   - Either the JSON credential key or the path to the JSON credential file
7. Save the integration.

**NOTE**: There are other input combination options available, check the [AWS documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

## Logs reference

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}

