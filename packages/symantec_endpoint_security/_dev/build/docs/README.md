# Symantec Endpoint Security

This Symantec Endpoint Security integration enables your security team to securely stream event data to Elastic Security, via AWS S3, AWS SQS or GCS. When integrated with Elastic Security, this valuable data can be leveraged within Elastic.
Symantec Endpoint Security (SES) delivers comprehensive protection for all your traditional and mobile devices across the entire attack chain. Symantec endpoint innovations include behavioral isolation, Active Directory security, and Threat Hunter technologies to protect your endpoints against sophisticated threats and targeted attacks.

The Symantec Endpoint Security integration can be used in three different modes to collect data:
- AWS S3 polling mode: Symantec Endpoint Security writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode: Symantec Endpoint Security writes data to S3, S3 sends a notification of a new object to SQS, the Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple agents can be used in this mode.
- GCS polling mode: Symantec Endpoint Security writes data to GCS bucket, and Elastic Agent polls the GCS bucket by listing its contents and reading new files.

## Data streams

The Symantec Endpoint Security integration collects logs for different events that Integrated Cyber Defense Schema organizes into following categories:

**Security [1]**

| Event Type                                         |
|----------------------------------------------------|
| 8020 - Scan                                        |
| 8025 - Boot Record Detection                       |
| 8026 - User Session Detection                      |
| 8027 - Process Detection                           |
| 8028 - Module Detection                            |
| 8030 - Kernel Detection                            |
| 8031 - File Detection                              |
| 8032 - Registry Key Detection                      |
| 8033 - Registry Value Detection                    |
| 8038 - Peripheral Device Detection                 |
| 8040 - Host Network Detection                      |
| 8061 - Entity Change                               |
| 8070 - Compliance Scan                             |
| 8071 - Compliance                                  |
| 8075 - Incident Creation                           |
| 8076 - Incident Update                             |
| 8077 - Incident Closure                            |
| 8078 - Incident Associate                          |

**License [2]**

| Event Type                                         |
|----------------------------------------------------|
| 30 - License Lifecycle                             |
| 31 - License Expiry                                |

**Application Activity [3]**

| Event Type                                         |
|----------------------------------------------------|
| 2 - Application Lifecycle                          |
| 3 - Update                                         |
| 4 - Policy Change                                  |
| 5 - File Reputation                                |
| 11 - Command Activity                              |
| 12 - Action Request                                |
| 13 - Action Response                               |
| 42 - URL Reputation                                |

**Audit [4]**

| Event Type                                         |
|----------------------------------------------------|
| 20 - User Session Audit                            |
| 21 - Entity Audit                                  |
| 22 - Policy Override Audit                         |

**System Activity [5]**

| Event Type                                         |
|----------------------------------------------------|
| 8000 - User Session Activity                       |
| 8001 - Process Activity                            |
| 8002 - Module Activity                             |
| 8003 - File Activity                               |
| 8004 - Directory Activity                          |
| 8005 - Registry Key Activity                       |
| 8006 - Registry Value Activity                     |
| 8007 - Host Network Activity                       |
| 8009 - Kernel Activity                             |
| 8011 - Email Activity                              |
| 8015 - Monitored Source                            |
| 8016 - Startup Application Configuration Change    |
| 8018 - AMSI Activity                               |

**Diagnostic [6]**

| Event Type                                         |
|----------------------------------------------------|
| 1000 - Status                                      |

**NOTE**: The Symantec Endpoint Security integration collects logs for the above mentioned events, but we have combined all of those in one data stream named `event`.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the S3 bucket or GCS and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.12.0**.

## Setup

### To collect data from an AWS S3 bucket, follow the below steps:

- Considering you already have an AWS S3 bucket setup, to configure it with Symantec Endpoint Security, follow the steps mentioned [here](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-security/sescloud/Integrations/Event-streaming-using-EDR.html) to enable the Symantec Endpoint Streaming.

### To collect data from a GCS bucket, follow the below steps:

- Considering you already have a GCS bucket setup, configure it with Symantec Endpoint Security.
- Enable the Symantec Endpoint Streaming as mentioned [here](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-security/sescloud/Integrations/Event-streaming-using-EDR.html).
- Configure the integration with your GCS project ID, Bucket name and Service Account Key/Service Account Credentials File.

### The GCS credentials key file:
Once you have added a key to GCP service account, you will get a JSON key file that can only be downloaded once.
If you're new to GCS bucket creation, follow the following steps:

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

- You must have Symantec Account Credentials to configure event stream. Refer [here](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-security/sescloud/Integrations/Event-streaming-using-EDR.html) for more details.


### To collect data from AWS SQS, follow the below steps:

1. Assuming you've already set up a connection to push data into the AWS bucket; if not, see the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" mentioned in the [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
   - While creating an access policy, use the bucket name configured to create a connection for AWS S3 in Symantec.
3. Configure event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
   - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue, and select the queue name created in Step 2.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Symantec Endpoint Security
3. Click on the "Symantec Endpoint Security" integration from the search results.
4. Click on the Add Symantec Endpoint Security Integration button to add the integration.
5. While adding the integration, if you want to collect logs via AWS S3, then you have to put the following details:
   - Collect logs via S3 Bucket toggled on
   - Access Key ID
   - Secret Access Key
   - Bucket ARN
   - Session Token

   or if you want to collect logs via AWS SQS, then you have to put the following details:
   - Collect logs via S3 Bucket toggled off
   - Queue URL
   - Secret Access Key
   - Access Key ID

   or if you want to collect logs via GCS, then you have to put the following details:
   - Project ID
   - Buckets
   - Service Account Key/Service Account Credentials File
6. Save the integration.

**NOTE**:

1. There are other input combination options available for the AWS S3 and AWS SQS, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).
2. There are other input combination options available for the GCS, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-gcs.html).

## Logs reference

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}
