# Netskope

This integration is for Netskope. It can be used to receive logs sent by [Netskope Cloud Log Shipper](https://docs.netskope.com/en/cloud-exchange-feature-lists.html#UUID-e7c43f4b-8aad-679e-eea0-59ce19f16e29_section-idm4547044691454432680066508785) and [Netskope Log Streaming](https://docs.netskope.com/en/log-streaming/). To receive log from Netskope Cloud Log Shipper use the TCP input, and for Netskope Log Streaming use any of the Cloud based inputs (AWS, GCS, or Azure Blob Storage).



The log message is expected to be in JSON format. The data is mapped to
ECS fields where applicable and the remaining fields are written under
`netskope.<data-stream-name>.*`.

## Setup steps

### For receiving log from Netskope Cloud Shipper
1. Configure this integration with the TCP input in Kibana.
2. For all Netskope Cloud Exchange configurations refer to the [Log Shipper](https://docs.netskope.com/en/cloud-exchange-feature-lists.html#UUID-e7c43f4b-8aad-679e-eea0-59ce19f16e29_section-idm4547044691454432680066508785).
3. In Netskope Cloud Exchange please enable Log Shipper, add your Netskope Tenant.
4. Configure input connectors:
    1. First with all Event types, and
    2. Second with all Alerts type.
    For detailed steps refer to [Configure the Netskope Plugin for Log Shipper](https://docs.netskope.com/en/configure-the-netskope-plugin-for-log-shipper.html).
5. Configure output connectors:
    1. Navigate to Settings -> Plugins.
    2. Add separate output connector **Elastic CLS** for both Alerts and Events and select mapping **"Elastic Default Mappings (Recommended)"** for both.
6. Create business rules:
    1. Navigate to Home Page > Log Shipper > Business Rules.
    2. Create business rules with Netskope Alerts.
    3. Create business rules with Netskope Events.
    For detailed steps refer to [Manage Log Shipper Business Rules](https://docs.netskope.com/en/manage-log-shipper-business-rules.html).
7. Adding SIEM mappings:
    1. Navigate to Home Page > Log Shipper > SIEM Mappings
    2. Add SIEM mapping for events:
        * Add **Rule** put rule created in step 6.
        * Add **Source Configuration** put input created for Events in step 4.
        * Add **Destination Configuration**, put output created for Events in step 5.

> Note: For detailed steps refer to [Configure Log Shipper SIEM Mappings](https://docs.netskope.com/en/configure-log-shipper-siem-mappings.html).
Please make sure to use the given response formats.

### For receiving log from Netskope Log Streaming
1. To configure Log streaming please refer to the [Log Streaming Configuration](https://docs.netskope.com/en/configuring-streams). Ensure that compression is set to GZIP when configuring the stream as other compression types are not supported.


#### Collect data from an AWS S3 bucket

Considering you already have an AWS S3 bucket setup, to configure it with Netskope, follow [these steps](https://docs.netskope.com/en/stream-logs-to-amazon-s3) to enable the log streaming.

#### Collect data from Azure Blob Storage

1. If you already have an Azure storage container setup, configure it with Netskope via log streaming.
2. Enable the Netskope log streaming by following [these instructions](https://docs.netskope.com/en/stream-logs-to-azure-blob).
3. Configure the integration using either Service Account Credentials or Microsoft Entra ID RBAC with OAuth2 options. For OAuth2 (Entra ID RBAC), you will need the Client ID, Client Secret, and Tenant ID. For Service Account Credentials, you will need either the Service Account Key or the URI to access the data.


- How to setup the `auth.oauth2` credentials can be found in the Azure documentation [here]( https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
- For more details about the Azure Blob Storage input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-blob-storage.html).

Note:
- The service principal must be granted the appropriate permissions to read blobs. Ensure that the necessary role assignments are in place for the service principal to access the storage resources. For more information, please refer to the [Azure Role-Based Access Control (RBAC) documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage).
- We recommend assigning either the **Storage Blob Data Reader** or **Storage Blob Data Owner** role. The **Storage Blob Data Reader** role provides read-only access to blob data and is aligned with the principle of least privilege, making it suitable for most use cases. The **Storage Blob Data Owner** role grants full administrative access — including read, write, and delete permissions — and should be used only when such elevated access is explicitly required.

#### Collect data from a GCS bucket

1. If you already have a GCS bucket setup, configure it with Netskope via log streaming.
2. Enable the Netskope log streaming by following [these instructions](https://docs.netskope.com/en/stream-logs-to-gcp-cloud-storage).
3. Configure the integration with your GCS project ID, Bucket name and Service Account Key/Service Account Credentials File.

For more details about the GCS input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-gcs.html).

#### The GCS credentials key file:

Once you have added a key to GCP service account, you will get a JSON key file that can only be downloaded once.
If you're new to GCS bucket creation, follow these steps:

1. Make sure you have a service account available, if not follow the steps below:
   - Navigate to 'APIs & Services' > 'Credentials'
   - Click on 'Create credentials' > 'Service account'
2. Once the service account is created, you can navigate to the 'Keys' section and attach/generate your service account key.
3. Make sure to download the JSON key file once prompted.
4. Use this JSON key file either inline (JSON string object), or by specifying the path to the file on the host machine, where the agent is running.

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


#### Collect data from AWS SQS

1. If you have already set up a connection to push data into the AWS bucket; if not, refer to the section above.

2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" mentioned in the [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
   - While creating an access policy, use the bucket name configured to create a connection for AWS S3 in Netskope.
3. Configure event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
   - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue, and select the queue name created in Step 2.

For more details about the AWS-S3 input settings, check this [documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

### Enable the integration in Elastic

1. In Kibana go to **Management** > **Integrations**.
2. In "Search for integrations" top bar, search for `Netskope`.
3. Select the **Netskope** integration from the search results.
4. Select "Add Netskope" to add the integration.
5. While adding the integration, there are different options to collect logs; 
    
    To collect logs via AWS S3 when adding the integration, you must provide the following details::
    - Collect logs via S3 Bucket toggled on
    - Access Key ID
    - Secret Access Key
    - Bucket ARN
    - Session Token

    To collect logs via AWS SQS when adding the integration, you must provide the following details:
    - Collect logs via S3 Bucket toggled off
    - Queue URL
    - Secret Access Key
    - Access Key ID

    To collect logs via GCS when adding the integration, you must provide the following details:
    - Project ID
    - Buckets
    - Service Account Key/Service Account Credentials File

    To collect logs via Azure Blob Storage when adding the integration, you must provide the following details:

    - For OAuth2 (Microsoft Entra ID RBAC):
        - Toggle on **Collect logs using OAuth2 authentication**
        - Account Name
        - Client ID
        - Client Secret
        - Tenant ID
        - Container Details.

    - For Service Account Credentials:
        - Service Account Key or the URI
        - Account Name
        - Container Details
        

    To collect logs via TCP when adding the integration, you must provide the following details:
    - Listen Address
    - Listen Port
6. Save the integration.

## Compatibility

This package has been tested against `Netskope version 95.1.0.645` and `Netskope Cloud Exchange version 3.4.0`.

## Documentation and configuration

### Alerts

Default port: _9020_

### Events

Default port: _9021_

## Fields and Sample event

### Alerts

{{fields "alerts"}}

{{event "alerts"}}

### Alerts V2

{{fields "alerts_v2"}}

{{event "alerts_v2"}}

### Events

{{fields "events"}}

{{event "events"}}