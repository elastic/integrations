# Symantec Endpoint Security

Symantec Endpoint Security (SES), is fully cloud-managed version of the on-premises Symantec Endpoint Protection (SEP), which delivers multilayer protection to stop threats regardless of how they attack your endpoints. You manage SES through a unified cloud console that provides threat visibility across your endpoints and uses multiple technologies to manage the security of your organization.

This SES Integration enables user to stream Events and EDR incidents data to Elastic, via Data Storage(AWS S3, AWS SQS or GCS) and API endpoint respectively.

## Compatibility

This module has been tested against **Symantec Integrated Cyber Defense Exchange 1.4.7** for events, and **Symantec Endpoint Security API Version v1** for EDR Incidents. 

## Data streams

The Symantec Endpoint Security integration collects logs via Amazon S3 and SQS, and Google GCP for different events that The Integrated Cyber Defense Schema organizes into following categories:

**Security [1]**

- **8020 - Scan**                     
- **8025 - Boot Record Detection**       
- **8026 - User Session Detection**      
- **8027 - Process Detection**           
- **8028 - Module Detection**            
- **8030 - Kernel Detection**            
- **8031 - File Detection**              
- **8032 - Registry Key Detection**      
- **8033 - Registry Value Detection**    
- **8038 - Peripheral Device Detection** 
- **8040 - Host Network Detection**      
- **8061 - Entity Change**               
- **8070 - Compliance Scan**             
- **8071 - Compliance**                  
- **8075 - Incident Creation**           
- **8076 - Incident Update**             
- **8077 - Incident Closure**            
- **8078 - Incident Associate**          

**License [2]**


- **30 - License Lifecycle**                            
- **31 - License Expiry**                               

**Application Activity [3]**


- **2 - Application Lifecycle**                   
- **3 - Update**                                  
- **4 - Policy Change**                           
- **5 - File Reputation**                         
- **11 - Command Activity**                       
- **12 - Action Request**                         
- **13 - Action Response**                        
- **42 - URL Reputation**                         

**Audit [4]**

- **20 - User Session Audit**                         
- **21 - Entity Audit**                                
- **22 - Policy Override Audit**                       

**System Activity [5]**

- **8000 - User Session Activity**           
- **8001 - Process Activity**                
- **8002 - Module Activity**                 
- **8003 - File Activity**                   
- **8004 - Directory Activity**              
- **8005 - Registry Key Activity**           
- **8006 - Registry Value Activity**         
- **8007 - Host Network Activity**           
- **8009 - Kernel Activity**                 
- **8011 - Email Activity**                  
- **8015 - Monitored Source**                
- **8016 - Startup Application Configuration Change** 
- **8018 - AMSI Activity**                   

**Diagnostic [6]**

- **1000 - Status**                                      

The Symantec Endpoint Security integration can also retrieve **EDR incidents** via a REST API. See more details in the API documentation [here](https://apidocs.securitycloud.symantec.com/#/doc?id=edr_incidents).

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).  

## Setup

### Collect data from an AWS S3 bucket

Considering you already have an AWS S3 bucket setup, to configure it with Symantec Endpoint Security, follow [these steps](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-security/sescloud/Integrations/Event-streaming-using-EDR.html) to enable the Symantec Endpoint Streaming.

### Collect data from Azure Blob Storage

1. If you already have an Azure storage container setup, configure it with Symantec Endpoint Security.
2. Enable the Symantec Endpoint Streaming by following [these instructions](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-security/sescloud/Integrations/Event-streaming-using-EDR.html).
3. Configure the integration with your Azure Storage account name, Container name and Service Account Key/Service Account URI.

For more details about the Azure Blob Storage input settings, check the  [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-blob-storage.html).

### Collect data from a GCS bucket

1. If you already have a GCS bucket setup, configure it with Symantec Endpoint Security.
2. Enable the Symantec Endpoint Streaming by following [these instructions](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-security/sescloud/Integrations/Event-streaming-using-EDR.html).
3. Configure the integration with your GCS project ID, Bucket name and Service Account Key/Service Account Credentials File.

For more details about the GCS input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-gcs.html).

### The GCS credentials key file:

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

**NOTE**:
You must have Symantec Account Credentials to configure event stream. Check [this documentation](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-security/sescloud/Integrations/Event-streaming-using-EDR.html) for more details.


### Collect data from AWS SQS

1. If you've already set up a connection to push data into the AWS bucket; if not, refer to the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" mentioned in the [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
   - While creating an access policy, use the bucket name configured to create a connection for AWS S3 in Symantec.
3. Configure event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
   - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue, and select the queue name created in Step 2.

For more details about the AWS-S3 input settings, check this [documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

### Steps to obtain Client ID and Client Secret to collect data from EDR Incident API

1. Login to your [Symantec EDR Cloud console](https://sep.securitycloud.symantec.com/v2/landing).
2. Click Integration > Client Applications.
3. Click Add for adding Client Application.
4. Enter Client Application Name and press the Add button.
5. Select Client Secret from the top.
6. Copy the Client ID and Client Secret.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Symantec Endpoint Security**.
3. Select the **Symantec Endpoint Security** integration and add it.
4. While adding the integration, if you want to collect logs via AWS S3, then you have to put the following details:
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

   or if you want to collect logs via the REST API, then you have to put the following details:
   - Client ID
   - Client Secret
   - URL
   - Token URL

5. Save the integration.

**NOTE**:

1. There are other input combination options available for the AWS S3 and AWS SQS, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).
2. There are other input combination options available for the GCS, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-gcs.html).

### Troubleshooting

If the user stops integration and starts integration again after 30 days, then user will not be able to collect data and will get an error as Symantec EDR Cloud only collects data for the last 30 days. To avoid this issue, create a new integration instead of restarting it after 30 days.

## Logs reference

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}

### Incident

This is the `Incident` dataset.

#### Example

{{event "incident"}}

{{fields "incident"}}
