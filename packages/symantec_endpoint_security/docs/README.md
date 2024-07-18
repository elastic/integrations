# Symantec Endpoint Security

Symantec Endpoint Security (SES), is fully cloud-managed version of the on-premises Symantec Endpoint Protection (SEP), which delivers multilayer protection to stop threats regardless of how they attack your endpoints. You manage SES through a unified cloud console that provides threat visibility across your endpoints and uses multiple technologies to manage the security of your organization.

This SES Integration enables user to stream Events and EDR incidents data to Elastic, via Data Storage(AWS S3, AWS SQS or GCS) and API endpoint respectively.

## Data streams

The Symantec Endpoint Security integration collects logs via AWS S3, SQS and GCP configuration for different events which are mapped with Integrated Cyber Defense Schema organizes into following categories:

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

The Symantec Endpoint Security integration also retrieve **EDR incidents** via API configuration. See more details in the API documentation [here](https://apidocs.securitycloud.symantec.com/#/doc?id=edr_incidents).

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
 
This module has been tested against the **Symantec Integrated Cyber Defense Exchange 1.4.7** for events.  
This module has been tested against the **Symantec Endpoint Security API Version v1** for EDR Incidents.  

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


### Steps to obtain Client ID and Client Secret to collect data from EDR Incident API:

1. Login to your [Symantec EDR Cloud console](https://sep.securitycloud.symantec.com/v2/landing).
2. Click Integration > Client Applications.
3. Click Add for adding Client Application.
4. Enter Client Application Name and press the Add button.
5. Select Client Secret from the top.
6. Copy the Client ID and Client Secret.

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

   or if you want to collect logs via API, then you have to put the following details:
   - Client ID
   - Client Secret
   - URL
   - Token URL

6. Save the integration.

**NOTE**:

1. There are other input combination options available for the AWS S3 and AWS SQS, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).
2. There are other input combination options available for the GCS, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-gcs.html).

### Troubleshooting

If the user stops integration and starts integration again after 30 days, then user will not be able to collect data and will get an error as Symantec EDR Cloud only collects data for the last 30 days. To avoid this issue, create a new integration instead of restarting it after 30 days.

## Logs reference

### Event

This is the `Event` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2024-02-29T02:00:00.000Z",
    "agent": {
        "ephemeral_id": "8dda9355-8ed9-46d6-996f-2b0563b3b1e3",
        "id": "8d5f9e50-329d-42d2-af28-c8823fcbb3c4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "aws": {
        "s3": {
            "bucket": {
                "arn": "arn:aws:s3:::elastic-package-symantec-endpoint-security-bucket-78927",
                "name": "elastic-package-symantec-endpoint-security-bucket-78927"
            },
            "object": {
                "key": "events.log"
            }
        }
    },
    "client": {
        "domain": "device.domain.internal.somecompany.com",
        "geo": {
            "country_iso_code": "IN"
        }
    },
    "cloud": {
        "region": "us-east-1"
    },
    "data_stream": {
        "dataset": "symantec_endpoint_security.event",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "175.16.199.0"
    },
    "device": {
        "id": [
            "Device_UID"
        ],
        "manufacturer": [
            "LENOVO"
        ]
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8d5f9e50-329d-42d2-af28-c8823fcbb3c4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "direction": [
            "inbound",
            "unknown"
        ],
        "from": {
            "address": [
                "abc@example.com"
            ]
        },
        "subject": [
            "Cybox-Emails-Header_Subject 1",
            "Cybox-Emails-Header_Subject 2"
        ],
        "to": {
            "address": [
                "Cybox-Emails-Header_To 1",
                "Cybox-Emails-Header_Tos 1",
                "Cybox-Emails-Header_To 2",
                "Cybox-Emails-Header_Tos 2"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2021-02-11T05:30:04.000Z",
        "dataset": "symantec_endpoint_security.event",
        "end": [
            "2021-02-11T05:30:04.000Z"
        ],
        "id": "SR-1565234545",
        "ingested": "2024-06-25T12:39:12Z",
        "kind": "event",
        "original": "{\"category_id\":3,\"collector_device_ip\":\"175.16.199.0\",\"collector_device_name\":\"Collector_Device_Name\",\"collector_name\":\"Collection12\",\"collector_uid\":\"TT1456\",\"composite\":1,\"container\":{\"host_name\":\"azure-us.local\",\"image_name\":\"Image-sp2133\",\"image_uid\":\"SH4322323\",\"name\":\"User12345\",\"networks\":[{\"bssid\":\"Container-Networks-BSSID 1\",\"gateway_ip\":\"89.160.20.112\",\"gateway_mac\":\"00:B0:D0:63:C2:01\",\"ipv4\":\"81.2.69.144\",\"ipv6\":\"2a02:cf40::\",\"is_public\":true,\"mac\":\"00:B0:D0:63:C2:02\",\"rep_score_id\":0,\"ssid\":\"SSID-4326451\",\"type_id\":0},{\"bssid\":\"HN0845435\",\"gateway_ip\":\"81.2.69.142\",\"gateway_mac\":\"00:B0:D0:63:C2:03\",\"ipv4\":\"81.2.69.144\",\"ipv6\":\"2a02:cf40::\",\"is_public\":true,\"mac\":\"00:B0:D0:63:C2:04\",\"rep_score_id\":1,\"ssid\":\"Container-Networks-SSID 2\",\"type_id\":1}],\"os_name\":\"Windows\",\"uid\":\"UU35r3454\"},\"correlation_uid\":\"DD78666\",\"count\":563,\"customer_registry_uid\":\"CP45254\",\"customer_uid\":\"CH32534\",\"cybox\":{\"domains\":[\"example.com\",\"abc.com\"],\"emails\":[{\"direction_id\":0,\"header_from\":\"abc@example.com\",\"header_message_id\":\"Cybox-Emails-Header_Message_ID 1\",\"header_reply_to\":\"Cybox-Emails-Header_Reply_To 1\",\"header_subject\":\"Cybox-Emails-Header_Subject 1\",\"header_to\":[\"Cybox-Emails-Header_To 1\",\"Cybox-Emails-Header_Tos 1\"],\"sender_ip\":\"81.2.69.144\",\"size\":12345678901,\"smtp_from\":\"Cybox-Emails-SMTP_From 1\",\"smtp_hello\":\"Cybox-Emails-SMTP_Hello 1\",\"smtp_to\":\"Cybox-Emails-SMTP_To 1\"},{\"direction_id\":1,\"header_from\":\"abc@example.com\",\"header_message_id\":\"Cybox-Emails-Header_Message_ID 2\",\"header_reply_to\":\"Cybox-Emails-Header_Reply_To 2\",\"header_subject\":\"Cybox-Emails-Header_Subject 2\",\"header_to\":[\"Cybox-Emails-Header_To 2\",\"Cybox-Emails-Header_Tos 2\"],\"sender_ip\":\"81.2.69.144\",\"size\":12345678902,\"smtp_from\":\"Cybox-Emails-SMTP_From 2\",\"smtp_hello\":\"Cybox-Emails-SMTP_Hello 2\",\"smtp_to\":\"Cybox-Emails-SMTP_To 2\"}],\"files\":[{\"accessed\":1613021404000,\"accessor\":\"Cybox-Files-Accessor 1\",\"attribute_ids\":[1,2,3,4,5,6,7,8,9,10],\"attributes\":12345678901,\"company_name\":\"Microsoft Corporation\",\"confidentiality_id\":0,\"content_type\":{\"family_id\":0,\"subtype\":\"SubType 1\",\"type_id\":0},\"created\":1613021404000,\"creator\":\"Creator 1\",\"creator_process\":\"Cybox-Files-Creator_Process 1\",\"desc\":\"Cybox-Files-Desc 1\",\"folder\":\"c:\\\\windows\\\\system32\\\\cybox\\files\\folder\\\\1\",\"folder_uid\":\"Cybox-Files-Folder_UID 1\",\"is_system\":true,\"md5\":\"HFDajsdf3254345436\",\"mime_type\":\"Cybox-Files-MIME_Type 1\",\"modified\":1613021404000,\"modifier\":\"Cybox-Files-Modifier 1\",\"name\":\"cybox_files_name_1.exe\",\"normalized_path\":\"CSIDL_SYSTEM\\\\cybox_files_normalized_path_1.exe\",\"original_name\":\"Cybox-Files-Original_Name 1\",\"owner\":\"Cybox-Files-Owner 1\",\"parent_name\":\"Cybox-Files-Parent_Name 1\",\"parent_sha2\":\"Cybox-Files-Parent_SHA2 1\",\"path\":\"c:\\\\windows\\\\system32\\\\cybox_files_path_1.exe\",\"product_name\":\"Windows Internet Explorer 1\",\"product_path\":\"Cybox-Files-Product_Path 1\",\"rep_discovered_band\":0,\"rep_discovered_date\":1613021404000,\"rep_prevalence\":12345678901,\"rep_prevalence_band\":0,\"rep_score\":12345678901,\"rep_score_band\":0,\"security_descriptor\":\"Cybox-Files-Security_Descriptor 1\",\"sha1\":\"Cybox-Files-SHA1 1\",\"sha2\":\"Cybox-Files-SHA2 1\",\"signature_company_name\":\"Cybox-Files-Signature_Company_Name 1\",\"signature_created_date\":1613021404000,\"signature_developer_uid\":\"Cybox-Files-Signature_Developer_UID 1\",\"signature_fingerprints\":[{\"algorithm\":\"Cybox-Files-Signature_Fingerprints-Algorithm 1\",\"value\":\"Cybox-Files-Signature_Fingerprints-Value 1\"},{\"algorithm\":\"Cybox-Files-Signature_Fingerprints-Algorithms 1\",\"value\":\"Cybox-Files-Signature_Fingerprints-Values 1\"}],\"signature_issuer\":\"Cybox-Files-Signature_Issuer 1\",\"signature_level_id\":0,\"signature_serial_number\":\"Cybox-Files-Signature_Serial_Number 1\",\"signature_value\":12345678901,\"signature_value_ids\":[0,1,2,3,4,5,6,7,8,9,10],\"size\":12345678901,\"size_compressed\":12345678901,\"src_ip\":\"81.2.69.142\",\"src_name\":\"Cybox-Files-SRC_Name 1\",\"type_id\":1,\"uid\":\"Cybox-Files-UID 1\",\"url\":{\"categories\":[\"Cybox-Files-URL-Category 1\",\"Cybox-Files-URL-Categories 1\"],\"category_ids\":[1,3,4,5,6,7,9,11,14,15,16,17,18,20,21,22,23,24,25,26,27,29,30,31,32,33,34,35,36,37,38,40,43,44,45,46,47,49,50,51,52,53,54,55,56,57,58,59,60,61,63,64,65,66,67,68,71,83,84,85,86,87,88,89,90,92,93,95,96,97,98],\"extension\":\"Cybox-Files-URL-Extension 1\",\"host\":\"www.files-url-host-1.com\",\"method\":\"Cybox-Files-URL-Method 1\",\"parent_categories\":[\"Cybox-Files-URL-Parent_Category 1\",\"Cybox-Files-URL-Parent_Categories 1\"],\"path\":\"/download/trouble/cybox/files/url/path/1\",\"port\":80,\"provider\":\"Cybox-Files-URL-Provider 1\",\"query\":\"q=bad&sort=date_1\",\"referrer\":\"Cybox-Files-URL-Referrer 1\",\"referrer_categories\":[\"Cybox-Files-URL-Referrer_Category 1\",\"Cybox-Files-URL-Referrer_Categories 1\"],\"referrer_category_ids\":[12345678901,67890123451],\"rep_score_id\":0,\"scheme\":\"Cybox-Files-URL-Scheme 1\",\"text\":\"www.files-url-text-1.com/download/trouble\"},\"version\":\"Cybox-Files-Version 1\",\"xattributes\":{\"ads_name\":\"Cybox-Files-XAttributes-ADS_Name 1\",\"ads_size\":\"Cybox-Files-XAttributes-ADS_Size 1\",\"dacl\":\"Cybox-Files-XAttributes-DACL 1\",\"owner\":\"Cybox-Files-XAttributes-Owner 1\",\"primary_group\":\"Cybox-Files-XAttributes-Primary_Group 1\",\"link_name\":\"Cybox-Files-XAttributes-Link_Name 1\",\"hard_link_count\":\"Cybox-Files-XAttributes-Hard_Link_Count 1\",\"Unix_permissions\":\"Cybox-Files-XAttributes-Unix_Permissions 1\"}},{\"accessed\":1613021404000,\"accessor\":\"Cybox-Files-Accessor 2\",\"attribute_ids\":[11,12,13,14,15,16,17],\"attributes\":12345678902,\"company_name\":\"Microsoft Corporation 2\",\"confidentiality_id\":1,\"content_type\":{\"family_id\":1,\"subtype\":\"Cybox-Files-Content_Type-SubType 2\",\"type_id\":1},\"created\":1613021404000,\"creator\":\"Cybox-Files-Creator 2\",\"creator_process\":\"Cybox-Files-Creator_Process 2\",\"desc\":\"Cybox-Files-Desc 2\",\"folder\":\"c:\\\\windows\\\\system32\\\\cybox\\files\\folder\\\\2\",\"folder_uid\":\"Cybox-Files-Folder_UID 2\",\"is_system\":true,\"md5\":\"Cybox-Files-MD5 2\",\"mime_type\":\"Cybox-Files-MIME_Type 2\",\"modified\":1613021404000,\"modifier\":\"Cybox-Files-Modifier 2\",\"name\":\"cybox_files_name_2.exe\",\"normalized_path\":\"CSIDL_SYSTEM\\\\cybox_files_normalized_path_2.exe\",\"original_name\":\"Cybox-Files-Original_Name 2\",\"owner\":\"Cybox-Files-Owner 2\",\"parent_name\":\"Cybox-Files-Parent_Name 2\",\"parent_sha2\":\"Cybox-Files-Parent_SHA2 2\",\"path\":\"c:\\\\windows\\\\system32\\\\cybox_files_path_2.exe\",\"product_name\":\"Windows Internet Explorer 2\",\"product_path\":\"Cybox-Files-Product_Path 2\",\"rep_discovered_band\":1,\"rep_discovered_date\":1613021404000,\"rep_prevalence\":12345678902,\"rep_prevalence_band\":1,\"rep_score\":12345678902,\"rep_score_band\":1,\"security_descriptor\":\"Cybox-Files-Security_Descriptor 2\",\"sha1\":\"Cybox-Files-SHA1 2\",\"sha2\":\"Cybox-Files-SHA2 2\",\"signature_company_name\":\"Cybox-Files-Signature_Company_Name 2\",\"signature_created_date\":1613021404000,\"signature_developer_uid\":\"Cybox-Files-Signature_Developer_UID 2\",\"signature_fingerprints\":[{\"algorithm\":\"Cybox-Files-Signature_Fingerprints-Algorithm 2\",\"value\":\"Cybox-Files-Signature_Fingerprints-Value 2\"},{\"algorithm\":\"Cybox-Files-Signature_Fingerprints-Algorithms 2\",\"value\":\"Cybox-Files-Signature_Fingerprints-Values 2\"}],\"signature_issuer\":\"Cybox-Files-Signature_Issuer 2\",\"signature_level_id\":1,\"signature_serial_number\":\"Cybox-Files-Signature_Serial_Number 2\",\"signature_value\":12345678902,\"signature_value_ids\":[11,12,13,14,15,16,17,18,19,20,21,22,23,24,25],\"size\":12345678902,\"size_compressed\":12345678902,\"src_ip\":\"81.2.69.144\",\"src_name\":\"Cybox-Files-SRC_Name 2\",\"type_id\":1,\"uid\":\"Cybox-Files-UID 2\",\"url\":{\"categories\":[\"Cybox-Files-URL-Category 2\",\"Cybox-Files-URL-Categories 2\"],\"category_ids\":[101,102,103,104,105,106,107,108,109,110,111,112,113,114,116,117,118,121,124],\"extension\":\"Cybox-Files-URL-Extension 2\",\"host\":\"www.files-url-host-2.com\",\"method\":\"Cybox-Files-URL-Method 2\",\"parent_categories\":[\"Cybox-Files-URL-Parent_Category 2\",\"Cybox-Files-URL-Parent_Categories 2\"],\"path\":\"/download/trouble/cybox/files/url/path/2\",\"port\":81,\"provider\":\"Cybox-Files-URL-Provider 2\",\"query\":\"q=bad&sort=date_2\",\"referrer\":\"Cybox-Files-URL-Referrer 2\",\"referrer_categories\":[\"Cybox-Files-URL-Referrer_Category 2\",\"Cybox-Files-URL-Referrer_Categories 2\"],\"referrer_category_ids\":[12345678902,67890123452],\"rep_score_id\":1,\"scheme\":\"Cybox-Files-URL-Scheme 2\",\"text\":\"www.files-url-text-2.com/download/trouble\"},\"version\":\"Cybox-Files-Version 2\",\"xattributes\":{\"ads_name\":\"Cybox-Files-XAttributes-ADS_Name 2\",\"ads_size\":\"Cybox-Files-XAttributes-ADS_Size 2\",\"dacl\":\"Cybox-Files-XAttributes-DACL 2\",\"owner\":\"Cybox-Files-XAttributes-Owner 2\",\"primary_group\":\"Cybox-Files-XAttributes-Primary_Group 2\",\"link_name\":\"Cybox-Files-XAttributes-Link_Name 2\",\"hard_link_count\":\"Cybox-Files-XAttributes-Hard_Link_Count 2\",\"Unix_permissions\":\"Cybox-Files-XAttributes-Unix_Permissions 2\"}}],\"hostnames\":[\"Cybox-Hostname 1\",\"Cybox-Hostnames 1\"],\"icap_reqmod\":[{\"metadata\":{\"field1_keyword\":\"Cybox-ICAP_ReqMod-field1_Keyword\",\"field1_number\":12345678901,\"field1_boolean\":true,\"field1_ip\":\"175.16.199.0\"},\"service\":\"Cybox-ICAP_ReqMod-Service 1\",\"status\":\"Cybox-ICAP_ReqMod-Status 1\",\"status_detail\":\"Cybox-ICAP_ReqMod-Status_Detail 1\"},{\"metadata\":{\"field2_keyword\":\"Cybox-ICAP_ReqMod-field2_Keyword\",\"field2_number\":12345678902,\"field2_boolean\":true,\"field2_ip\":\"175.16.199.0\"},\"service\":\"Cybox-ICAP_ReqMod-Service 2\",\"status\":\"Cybox-ICAP_ReqMod-Status 2\",\"status_detail\":\"Cybox-ICAP_ReqMod-Status_Detail 2\"}],\"icap_respmod\":[{\"metadata\":{\"field1_keyword\":\"Cybox-ICAP_RespMod-field1_Keyword\",\"field1_number\":12345678901,\"field1_boolean\":true,\"field1_ip\":\"175.16.199.0\"},\"service\":\"Cybox-ICAP_RespMod-Service 1\",\"status\":\"Cybox-ICAP_RespMod-Status 1\",\"status_detail\":\"Cybox-ICAP_RespMod-Status_Detail 1\"},{\"metadata\":{\"field2_keyword\":\"Cybox-ICAP_RespMod-field2_Keyword\",\"field2_number\":12345678902,\"field2_boolean\":true,\"field2_ip\":\"175.16.199.0\"},\"service\":\"Cybox-ICAP_RespMod-Service 2\",\"status\":\"Cybox-ICAP_RespMod-Status 2\",\"status_detail\":\"Cybox-ICAP_RespMod-Status_Detail 2\"}],\"ipv4s\":[\"175.16.199.0\",\"175.16.199.0\"],\"ipv6s\":[\"2a02:cf40::\",\"2a02:cf40::\"],\"macs\":[\"00:B0:D0:63:C2:05\",\"00:B0:D0:63:C2:06\"],\"urls\":[{\"categories\":[\"Cybox-URLs-Category 1\",\"Cybox-URLs-Categories 1\"],\"category_ids\":[1,3,4,5,6,7,9,11,14,15,16,17,18,20,21,22,23,24,25,26,27,29,30,31,32,33,34,35,36,37,38,40,43,44,45,46,47,49,50,51,52,53,54,55,56,57,58,59,60,61,63,64,65,66,67,68,71,83,84,85,86,87,88,89,90,92,93,95,96,97,98],\"extension\":\"Cybox-URLs-Extension 1\",\"host\":\"www.urls-host-1.com\",\"method\":\"Cybox-URLs-Method 1\",\"parent_categories\":[\"Cybox-URLs-Parent_Category 1\",\"Cybox-URLs-Parent_Categories 1\"],\"path\":\"/download/trouble/cybox/urls/path/1\",\"port\":80,\"provider\":\"Cybox-URLs-Provider 1\",\"query\":\"q=bad&sort=date_1\",\"referrer\":\"Cybox-URLs-Referrer 1\",\"referrer_categories\":[\"Cybox-URLs-Referrer_Category 1\",\"Cybox-URLs-Referrer_Categories 1\"],\"referrer_category_ids\":[12345678901,67890123451],\"rep_score_id\":0,\"scheme\":\"Cybox-URLs-Scheme 1\",\"text\":\"www.urls-text-1.com/download/trouble\"},{\"categories\":[\"Cybox-URLs-Category 2\",\"Cybox-URLs-Categories 2\"],\"category_ids\":[101,102,103,104,105,106,107,108,109,110,111,112,113,114,116,117,118,121,124],\"extension\":\"Cybox-URLs-Extension 2\",\"host\":\"www.urls-host-2.com\",\"method\":\"Cybox-URLs-Method 2\",\"parent_categories\":[\"Cybox-URLs-Parent_Category 2\",\"Cybox-URLs-Parent_Categories 2\"],\"path\":\"/download/trouble/cybox/urls/path/2\",\"port\":81,\"provider\":\"Cybox-URLs-Provider 2\",\"query\":\"q=bad&sort=date_2\",\"referrer\":\"Cybox-URLs-Referrer 2\",\"referrer_categories\":[\"Cybox-URLs-Referrer_Category 2\",\"Cybox-URLs-Referrer_Categories 2\"],\"referrer_category_ids\":[12345678902,67890123452],\"rep_score_id\":1,\"scheme\":\"Cybox-URLs-Scheme 2\",\"text\":\"www.urls-text-2.com/download/trouble\"}]},\"device_alias_name\":\"Device_Alias_Name\",\"device_cap\":\"Device_Cap\",\"device_cloud_vm\":{\"autoscale_uid\":\"Device_Cloud_VM-Autoscale_UID\",\"dc_region\":\"Device_Cloud_VM-DC_Region\",\"instance_uid\":\"Device_Cloud_VM-Instance_UID\",\"subnet_uid\":\"Device_Cloud_VM-Subnet_UID\",\"vpc_uid\":\"Device_Cloud_VM-VPC_UID\"},\"device_desc\":\"Device_Desc\",\"device_domain\":\"device.domain.internal.somecompany.com\",\"device_domain_uid\":\"Device_Domain_UID\",\"device_end_time\":1613021404000,\"device_gateway\":\"175.16.199.0\",\"device_group\":\"Device_Group\",\"device_group_name\":\"Device_Group_Name\",\"device_hw_bios_date\":\"03/31/16\",\"device_hw_bios_manufacturer\":\"LENOVO\",\"device_hw_bios_ver\":\"LENOVO G5ETA2WW (2.62)\",\"device_hw_cpu_type\":\"x86 Family 6 Model 37 Stepping 5\",\"device_imei\":\"Device_IMEI\",\"device_ip\":\"175.16.199.0\",\"device_is_compliant\":true,\"device_is_personal\":true,\"device_is_trusted\":true,\"device_is_unmanaged\":true,\"device_location\":{\"city\":\"Device_Location-City\",\"continent\":\"Device_Location-Continent\",\"coordinates\":[-12.345,56.789],\"country\":\"US\",\"desc\":\"Device_Location-Desc\",\"isp\":\"Device_Location-ISP\",\"on_premises\":true,\"region\":\"US-CA\"},\"device_mac\":\"00:B0:D0:63:C2:07\",\"device_name\":\"device.name.computer.domain\",\"device_name_md5\":\"4ED962DDBF17E2BBA7B14EBC00F3162E\",\"device_networks\":[{\"bssid\":\"Device_Networks-BSSID 1\",\"gateway_ip\":\"175.16.199.0\",\"gateway_mac\":\"00:B0:D0:63:C2:08\",\"ipv4\":\"175.16.199.0\",\"ipv6\":\"2a02:cf40::\",\"is_public\":true,\"mac\":\"00:B0:D0:63:C2:09\",\"rep_score_id\":0,\"ssid\":\"Device_Networks-SSID 1\",\"type_id\":0},{\"bssid\":\"Device_Networks-BSSID 2\",\"gateway_ip\":\"89.160.20.112\",\"gateway_mac\":\"00:B0:D0:63:C2:10\",\"ipv4\":\"89.160.20.112\",\"ipv6\":\"2a02:cf40::\",\"is_public\":true,\"mac\":\"00:B0:D0:63:C2:11\",\"rep_score_id\":1,\"ssid\":\"Device_Networks-SSID 2\",\"type_id\":1}],\"device_org_unit\":\"Device_Org_Unit\",\"device_os_bits\":12345678901,\"device_os_build\":\"Device_OS_Build\",\"device_os_country\":\"IN\",\"device_os_edition\":\"Professional\",\"device_os_lang\":\"en\",\"device_os_name\":\"Windows Server 2019 Standard Edition\",\"device_os_sp_name\":\"Device_OS_SP_Name\",\"device_os_sp_ver\":\"Device_OS_SP_Ver\",\"device_os_type_id\":0,\"device_os_ver\":\"Windows 10\",\"device_proxy_ip\":\"89.160.20.112\",\"device_proxy_name\":\"Device_Proxy_Name\",\"device_public_ip\":\"89.160.20.112\",\"device_ref_uid\":\"Device_Ref_UID\",\"device_site\":\"Device_Site\",\"device_subnet\":\"81.2.69.144\",\"device_time\":1613021404000,\"device_type\":\"server\",\"device_uid\":\"Device_UID\",\"device_vhost\":\"Device_VHost\",\"device_vhost_id\":0,\"domain_uid\":\"Domain_UID\",\"end_time\":\"2024-02-29T01:00:00.000Z\",\"entity\":{\"data\":{\"field1_keyword\":\"Entity-Data-field1_Keyword\",\"field1_number\":12345678901,\"field1_boolean\":true},\"name\":\"Entity-Name\",\"type\":\"Entity-Type\",\"uid\":\"Entity-UID\",\"version\":\"Entity-Version\"},\"event_id\":2001,\"events\":[{\"connection\":{\"direction_id\":1,\"dst_service\":\"C:\\\\Windows\\\\system32\\\\NTOSKRNL.EXE\",\"src_ip\":\"159.19.163.218\"},\"count\":1,\"device_end_time\":1709225074618,\"device_time\":1709225074618}],\"feature_name\":\"Feature_Name\",\"feature_path\":\"Feature_Path\",\"feature_type\":\"Feature_Type\",\"feature_uid\":\"Feature_UID\",\"feature_ver\":\"2014.1.4.25\",\"id\":12345678901,\"impersonator_customer_uid\":\"Impersonator_Customer_UID\",\"impersonator_domain_uid\":\"Impersonator_Domain_UID\",\"impersonator_user_uid\":\"Impersonator_User_UID\",\"is_user_present\":true,\"log_level\":\"Log Level\",\"log_name\":\"Log_Name\",\"log_time\":\"2024-02-29T01:00:00.000Z\",\"logging_device_ip\":\"89.160.20.112\",\"logging_device_name\":\"Logging_Device_Name\",\"logging_device_post_time\":1613021404000,\"logging_device_ref_uid\":\"Logging_Device_Ref_UID\",\"message\":\"Message\",\"message_code\":\"Message_Code\",\"message_id\":0,\"org_unit_uid\":\"Org_Unit_UID\",\"orig_data\":\"Orig_Data\",\"product_data\":{\"sep_domain_uid\":\"Product_Data-Sep_Domain_UID\",\"sep_hw_uid\":\"Product_Data-Sep_HW_UID\"},\"product_lang\":\"en\",\"product_name\":\"Symantec Endpoint Security\",\"product_uid\":\"Product_UID\",\"product_ver\":\"2014.1.4.25-beta\",\"proxy_device_ip\":\"89.160.20.112\",\"proxy_device_name\":\"Proxy_Device_Name\",\"raw_data\":{\"assetID\":\"vc9DagprQYyLZ23SEY1APw\",\"assetOpstateDTO\":{\"productUuid\":\"31B0C880-0229-49E8-94C5-48D56B1BD7B9\",\"features\":[{\"uuid\":\"1DF0351C-146D-4F07-B155-BF5C7077FF40\",\"featureStatus\":\"SECURE\",\"opstate\":{\"EDRContentSequence\":\"20231128005\",\"EDREngineVersion\":\"4.11.0.10\",\"EDRFramworkVersion\":\"4.10.0.59\",\"FDRStatus\":true,\"LowDiskSpace\":false,\"MaxDBSizeHonored\":true,\"applied_policy\":{\"effective_date\":1709219437080,\"sha2\":\"ee6b0bebbc4575b507ac616d2c362f2c54d462b92cf4068cb6681ae3187d4de3\",\"uid\":\"7dc29d40-f303-477a-9012-287ef252a391\",\"version\":\"16\"},\"disk_usage_mb\":1546,\"fdr_first_event_date\":\"20240227\",\"fdr_state\":1},\"state\":\"ENABLED\",\"statusReason\":[\"-107\",\"0\"],\"prevention_state\":\"1\"}],\"products_active\":0,\"blades\":0}},\"ref_log_name\":\"Ref_Log_Name\",\"ref_log_time\":\"2024-02-29T01:00:00.000Z\",\"ref_orig_uid\":\"Ref_Orig_UID\",\"ref_uid\":\"Ref_UID\",\"remediated\":true,\"remediation\":\"Remediation\",\"remediation_ref\":\"Remediation_Ref\",\"remediation_uid\":0,\"seq_num\":12345678901,\"sessions\":[{\"auth_protocol_id\":0,\"cleartext_credentials\":true,\"direction_id\":0,\"id\":12345678901,\"is_admin\":true,\"logon_type_id\":1,\"port\":80,\"previous_users\":[\"Sessions-Previous_User 1\",\"Sessions-Previous_Users 1\"],\"remote\":true,\"remote_host\":\"Sessions-Remote_Host 1\",\"remote_ip\":\"89.160.20.112\",\"user\":{\"account_disabled\":true,\"cloud_resource_uid\":\"Sessions-User-Cloud_Resource_UID 1\",\"domain\":\"Sessions-User-Domain 1\",\"external_account_uid\":\"Sessions-User-External_Account_UID 1\",\"external_uid\":\"Sessions-User-External_UID 1\",\"full_name\":\"Sessions-User-Full_Name 1\",\"groups\":[\"Sessions-User-Group 1\",\"Sessions-User-Groups 1\"],\"home\":\"Sessions-User-Home 1\",\"is_admin\":true,\"logon_name\":\"Sessions-User-Logon_Name 1\",\"name\":\"session-User-Name 1\",\"password_expires\":true,\"shell\":\"Sessions-User-Shell 1\",\"sid\":\"Sessions-User-SID 1\",\"uid\":\"Sessions-User-UID 1\"}},{\"auth_protocol_id\":1,\"cleartext_credentials\":true,\"direction_id\":1,\"id\":67890123451,\"is_admin\":true,\"logon_type_id\":2,\"port\":81,\"previous_users\":[\"Sessions-Previous_User 2\",\"Sessions-Previous_Users 2\"],\"remote\":true,\"remote_host\":\"Sessions-Remote_Host 2\",\"remote_ip\":\"89.160.20.112\",\"user\":{\"account_disabled\":true,\"cloud_resource_uid\":\"Sessions-User-Cloud_Resource_UID 2\",\"domain\":\"Sessions-User-Domain 2\",\"external_account_uid\":\"Sessions-User-External_Account_UID 2\",\"external_uid\":\"Sessions-User-External_UID 2\",\"full_name\":\"Sessions-User-Full_Name 2\",\"groups\":[\"Sessions-User-Group 2\",\"Sessions-User-Groups 2\"],\"home\":\"Sessions-User-Home 2\",\"is_admin\":true,\"logon_name\":\"Sessions-User-Logon_Name 2\",\"name\":\"session-User-Name 2\",\"password_expires\":true,\"shell\":\"Sessions-User-Shell 2\",\"sid\":\"Sessions-User-SID 2\",\"uid\":\"Sessions-User-UID 2\"}}],\"severity_id\":0,\"source\":{\"facility\":\"Source-Facility\",\"facility_detail\":\"Source-Facility_Detail\",\"facility_uid\":\"Source-Facility_UID\",\"type_id\":1},\"status_detail\":\"Status_Detail\",\"status_id\":0,\"status_os\":\"Status_OS\",\"status_os_src\":12345678901,\"status_stack_trace\":\"Status_Stack_Trace\",\"status_thread_name\":\"Status_Thread_Name\",\"stic_has_pii\":true,\"stic_hw_uid\":\"STIC_HW_UID\",\"stic_ip_hash\":\"STIC_IP_Hash\",\"stic_legacy_ent_uids\":[\"STIC_Legacy_Ent_UIDs 1\",\"STIC_Legacy_Ent_UIDs 2\"],\"stic_legacy_hw_uids\":[\"STIC_Legacy_HW_UIDs 1\",\"STIC_Legacy_HW_UIDs 2\"],\"stic_legacy_uids\":[\"STIC_Legacy_UIDs 1\",\"STIC_Legacy_UIDs 2\"],\"stic_schema_id\":\"STIC_Schema_ID\",\"stic_uid\":\"STIC_UID\",\"stic_version\":\"STIC_Version\",\"subfeature_name\":\"Subfeature_Name\",\"time\":\"2024-02-29T02:00:00Z\",\"timezone\":12345678901,\"type\":\"Type\",\"type_id\":2,\"user\":{\"account_disabled\":true,\"cloud_resource_uid\":\"User-Cloud_Resource_UID\",\"domain\":\"User-Domain\",\"external_account_uid\":\"User-External_Account_UID\",\"external_uid\":\"User-External_UID\",\"full_name\":\"User-Full_Name\",\"groups\":[\"User-Group 1\",\"User-Groups 1\"],\"home\":\"User-Home\",\"is_admin\":true,\"logon_name\":\"User-Logon_Name\",\"name\":\"User123\",\"password_expires\":true,\"shell\":\"User-Shell\",\"sid\":\"TT23009\",\"uid\":\"UU34899825\"},\"user_name\":\"Mohit\",\"user_uid\":\"AB45698\",\"uuid\":\"SR-1565234545\",\"version\":\"1.4\"}",
        "sequence": [
            12345678901
        ],
        "severity": 0
    },
    "file": {
        "accessed": [
            "2021-02-11T05:30:04.000Z"
        ],
        "attributes": [
            "system",
            "encrypted",
            "hidden",
            "readonly",
            "archive",
            "compressed",
            "directory",
            "execute"
        ],
        "created": [
            "2021-02-11T05:30:04.000Z"
        ],
        "hash": {
            "md5": [
                "HFDajsdf3254345436",
                "Cybox-Files-MD5 2"
            ],
            "sha1": [
                "Cybox-Files-SHA1 1",
                "Cybox-Files-SHA1 2"
            ]
        },
        "mime_type": [
            "Cybox-Files-MIME_Type 1",
            "Cybox-Files-MIME_Type 2"
        ],
        "name": [
            "cybox_files_name_1.exe",
            "cybox_files_name_2.exe"
        ],
        "path": [
            "c:\\windows\\system32\\cybox_files_path_1.exe",
            "c:\\windows\\system32\\cybox_files_path_2.exe"
        ],
        "size": [
            12345678901,
            12345678902
        ],
        "type": [
            "file"
        ],
        "x509": {
            "issuer": {
                "distinguished_name": [
                    "Cybox-Files-Signature_Issuer 1",
                    "Cybox-Files-Signature_Issuer 2"
                ]
            },
            "serial_number": [
                "Cybox-Files-Signature_Serial_Number 1",
                "Cybox-Files-Signature_Serial_Number 2"
            ]
        }
    },
    "host": {
        "architecture": "x86 Family 6 Model 37 Stepping 5",
        "geo": {
            "city_name": "Device_Location-City",
            "continent_name": "Device_Location-Continent",
            "country_iso_code": "US",
            "region_name": "US-CA"
        },
        "os": {
            "name": "Windows Server 2019 Standard Edition",
            "version": [
                "Device_OS_Build",
                "Windows 10"
            ]
        },
        "type": [
            "server"
        ]
    },
    "input": {
        "type": "aws-s3"
    },
    "log": {
        "file": {
            "path": "https://elastic-package-symantec-endpoint-security-bucket-78927.s3.us-east-1.amazonaws.com/events.log"
        },
        "level": [
            "Log Level"
        ],
        "logger": "Log_Name",
        "offset": 0
    },
    "message": "Message",
    "process": {
        "thread": {
            "name": [
                "Status_Thread_Name"
            ]
        }
    },
    "related": {
        "hash": [
            "4ED962DDBF17E2BBA7B14EBC00F3162E",
            "STIC_IP_Hash",
            "HFDajsdf3254345436",
            "Cybox-Files-MD5 2",
            "Cybox-Files-SHA1 1",
            "Cybox-Files-SHA1 2",
            "Cybox-Files-SHA2 1",
            "Cybox-Files-SHA2 2",
            "Cybox-Files-Parent_SHA2 1",
            "Cybox-Files-Parent_SHA2 2"
        ],
        "hosts": [
            "Cybox-Files-SRC_Name 1",
            "Cybox-Files-SRC_Name 2"
        ],
        "ip": [
            "175.16.199.0",
            "89.160.20.112",
            "81.2.69.144",
            "81.2.69.142",
            "2a02:cf40::"
        ],
        "user": [
            "Impersonator_User_UID",
            "AB45698",
            "Mohit",
            "Sessions-User-UID 1",
            "Sessions-User-UID 2",
            "session-User-Name 1",
            "session-User-Name 2",
            "UU34899825",
            "User123"
        ]
    },
    "ses": {
        "category_id": "3",
        "category_name": "Application Activity",
        "collector_device_name": "Collector_Device_Name",
        "collector_name": "Collection12",
        "collector_uid": "TT1456",
        "composite": 1,
        "container": {
            "host_name": "azure-us.local",
            "image_name": "Image-sp2133",
            "image_uid": "SH4322323",
            "name": "User12345",
            "networks": [
                {
                    "bssid": "Container-Networks-BSSID 1",
                    "gateway_ip": "89.160.20.112",
                    "gateway_mac": "00:B0:D0:63:C2:01",
                    "ipv4": "81.2.69.144",
                    "ipv6": "2a02:cf40::",
                    "is_public": true,
                    "mac": "00:B0:D0:63:C2:02",
                    "rep_score_id": "0",
                    "ssid": "SSID-4326451",
                    "type_id": "0"
                },
                {
                    "bssid": "HN0845435",
                    "gateway_ip": "81.2.69.142",
                    "gateway_mac": "00:B0:D0:63:C2:03",
                    "ipv4": "81.2.69.144",
                    "ipv6": "2a02:cf40::",
                    "is_public": true,
                    "mac": "00:B0:D0:63:C2:04",
                    "rep_score_id": "1",
                    "ssid": "Container-Networks-SSID 2",
                    "type_id": "1"
                }
            ],
            "os_name": "Windows",
            "uid": "UU35r3454"
        },
        "correlation_uid": "DD78666",
        "count": 563,
        "customer_registry_uid": "CP45254",
        "customer_uid": "CH32534",
        "cybox": {
            "domains": [
                "example.com",
                "abc.com"
            ],
            "emails": [
                {
                    "direction_id": "0",
                    "header_message_id": "Cybox-Emails-Header_Message_ID 1",
                    "header_reply_to": "Cybox-Emails-Header_Reply_To 1",
                    "sender_ip": "81.2.69.144",
                    "size": 12345678901,
                    "smtp_from": "Cybox-Emails-SMTP_From 1",
                    "smtp_hello": "Cybox-Emails-SMTP_Hello 1",
                    "smtp_to": "Cybox-Emails-SMTP_To 1"
                },
                {
                    "direction_id": "1",
                    "header_message_id": "Cybox-Emails-Header_Message_ID 2",
                    "header_reply_to": "Cybox-Emails-Header_Reply_To 2",
                    "sender_ip": "81.2.69.144",
                    "size": 12345678902,
                    "smtp_from": "Cybox-Emails-SMTP_From 2",
                    "smtp_hello": "Cybox-Emails-SMTP_Hello 2",
                    "smtp_to": "Cybox-Emails-SMTP_To 2"
                }
            ],
            "files": [
                {
                    "accessor": "Cybox-Files-Accessor 1",
                    "attribute_ids": [
                        "1",
                        "2",
                        "3",
                        "4",
                        "5",
                        "6",
                        "7",
                        "8",
                        "9",
                        "10"
                    ],
                    "attributes": 12345678901,
                    "company_name": "Microsoft Corporation",
                    "confidentiality_id": "0",
                    "content_type": {
                        "family_id": "0",
                        "subtype": "SubType 1",
                        "type_id": "0"
                    },
                    "creator": "Creator 1",
                    "creator_process": "Cybox-Files-Creator_Process 1",
                    "desc": "Cybox-Files-Desc 1",
                    "folder": "c:\\windows\\system32\\cybox\files\folder\\1",
                    "folder_uid": "Cybox-Files-Folder_UID 1",
                    "is_system": true,
                    "modified": "2021-02-11T05:30:04.000Z",
                    "modifier": "Cybox-Files-Modifier 1",
                    "normalized_path": "CSIDL_SYSTEM\\cybox_files_normalized_path_1.exe",
                    "original_name": "Cybox-Files-Original_Name 1",
                    "owner": "Cybox-Files-Owner 1",
                    "parent_name": "Cybox-Files-Parent_Name 1",
                    "parent_sha2": "Cybox-Files-Parent_SHA2 1",
                    "product_name": "Windows Internet Explorer 1",
                    "product_path": "Cybox-Files-Product_Path 1",
                    "rep_discovered_band": 0,
                    "rep_discovered_date": "2021-02-11T05:30:04.000Z",
                    "rep_prevalence": 12345678901,
                    "rep_prevalence_band": 0,
                    "rep_score": 12345678901,
                    "rep_score_band": 0,
                    "security_descriptor": "Cybox-Files-Security_Descriptor 1",
                    "sha2": "Cybox-Files-SHA2 1",
                    "signature_company_name": "Cybox-Files-Signature_Company_Name 1",
                    "signature_created_date": "2021-02-11T05:30:04.000Z",
                    "signature_developer_uid": "Cybox-Files-Signature_Developer_UID 1",
                    "signature_fingerprints": [
                        {
                            "algorithm": "Cybox-Files-Signature_Fingerprints-Algorithm 1",
                            "value": "Cybox-Files-Signature_Fingerprints-Value 1"
                        },
                        {
                            "algorithm": "Cybox-Files-Signature_Fingerprints-Algorithms 1",
                            "value": "Cybox-Files-Signature_Fingerprints-Values 1"
                        }
                    ],
                    "signature_level_id": "0",
                    "signature_value": 12345678901,
                    "signature_value_ids": [
                        "0",
                        "1",
                        "2",
                        "3",
                        "4",
                        "5",
                        "6",
                        "7",
                        "8",
                        "9",
                        "10"
                    ],
                    "size_compressed": 12345678901,
                    "src_ip": "81.2.69.142",
                    "src_name": "Cybox-Files-SRC_Name 1",
                    "type_id": "1",
                    "uid": "Cybox-Files-UID 1",
                    "url": {
                        "categories": [
                            "Cybox-Files-URL-Category 1",
                            "Cybox-Files-URL-Categories 1"
                        ],
                        "category_ids": [
                            "1",
                            "3",
                            "4",
                            "5",
                            "6",
                            "7",
                            "9",
                            "11",
                            "14",
                            "15",
                            "16",
                            "17",
                            "18",
                            "20",
                            "21",
                            "22",
                            "23",
                            "24",
                            "25",
                            "26",
                            "27",
                            "29",
                            "30",
                            "31",
                            "32",
                            "33",
                            "34",
                            "35",
                            "36",
                            "37",
                            "38",
                            "40",
                            "43",
                            "44",
                            "45",
                            "46",
                            "47",
                            "49",
                            "50",
                            "51",
                            "52",
                            "53",
                            "54",
                            "55",
                            "56",
                            "57",
                            "58",
                            "59",
                            "60",
                            "61",
                            "63",
                            "64",
                            "65",
                            "66",
                            "67",
                            "68",
                            "71",
                            "83",
                            "84",
                            "85",
                            "86",
                            "87",
                            "88",
                            "89",
                            "90",
                            "92",
                            "93",
                            "95",
                            "96",
                            "97",
                            "98"
                        ],
                        "extension": "Cybox-Files-URL-Extension 1",
                        "host": "www.files-url-host-1.com",
                        "method": "Cybox-Files-URL-Method 1",
                        "parent_categories": [
                            "Cybox-Files-URL-Parent_Category 1",
                            "Cybox-Files-URL-Parent_Categories 1"
                        ],
                        "path": "/download/trouble/cybox/files/url/path/1",
                        "port": 80,
                        "provider": "Cybox-Files-URL-Provider 1",
                        "query": "q=bad&sort=date_1",
                        "referrer": "Cybox-Files-URL-Referrer 1",
                        "referrer_categories": [
                            "Cybox-Files-URL-Referrer_Category 1",
                            "Cybox-Files-URL-Referrer_Categories 1"
                        ],
                        "referrer_category_ids": [
                            "12345678901",
                            "67890123451"
                        ],
                        "rep_score_id": "0",
                        "scheme": "Cybox-Files-URL-Scheme 1",
                        "text": "www.files-url-text-1.com/download/trouble"
                    },
                    "version": "Cybox-Files-Version 1",
                    "xattributes": {
                        "Unix_permissions": "Cybox-Files-XAttributes-Unix_Permissions 1",
                        "ads_name": "Cybox-Files-XAttributes-ADS_Name 1",
                        "ads_size": "Cybox-Files-XAttributes-ADS_Size 1",
                        "dacl": "Cybox-Files-XAttributes-DACL 1",
                        "hard_link_count": "Cybox-Files-XAttributes-Hard_Link_Count 1",
                        "link_name": "Cybox-Files-XAttributes-Link_Name 1",
                        "owner": "Cybox-Files-XAttributes-Owner 1",
                        "primary_group": "Cybox-Files-XAttributes-Primary_Group 1"
                    }
                },
                {
                    "accessor": "Cybox-Files-Accessor 2",
                    "attribute_ids": [
                        "11",
                        "12",
                        "13",
                        "14",
                        "15",
                        "16",
                        "17"
                    ],
                    "attributes": 12345678902,
                    "company_name": "Microsoft Corporation 2",
                    "confidentiality_id": "1",
                    "content_type": {
                        "family_id": "1",
                        "subtype": "Cybox-Files-Content_Type-SubType 2",
                        "type_id": "1"
                    },
                    "creator": "Cybox-Files-Creator 2",
                    "creator_process": "Cybox-Files-Creator_Process 2",
                    "desc": "Cybox-Files-Desc 2",
                    "folder": "c:\\windows\\system32\\cybox\files\folder\\2",
                    "folder_uid": "Cybox-Files-Folder_UID 2",
                    "is_system": true,
                    "modified": "2021-02-11T05:30:04.000Z",
                    "modifier": "Cybox-Files-Modifier 2",
                    "normalized_path": "CSIDL_SYSTEM\\cybox_files_normalized_path_2.exe",
                    "original_name": "Cybox-Files-Original_Name 2",
                    "owner": "Cybox-Files-Owner 2",
                    "parent_name": "Cybox-Files-Parent_Name 2",
                    "parent_sha2": "Cybox-Files-Parent_SHA2 2",
                    "product_name": "Windows Internet Explorer 2",
                    "product_path": "Cybox-Files-Product_Path 2",
                    "rep_discovered_band": 1,
                    "rep_discovered_date": "2021-02-11T05:30:04.000Z",
                    "rep_prevalence": 12345678902,
                    "rep_prevalence_band": 1,
                    "rep_score": 12345678902,
                    "rep_score_band": 1,
                    "security_descriptor": "Cybox-Files-Security_Descriptor 2",
                    "sha2": "Cybox-Files-SHA2 2",
                    "signature_company_name": "Cybox-Files-Signature_Company_Name 2",
                    "signature_created_date": "2021-02-11T05:30:04.000Z",
                    "signature_developer_uid": "Cybox-Files-Signature_Developer_UID 2",
                    "signature_fingerprints": [
                        {
                            "algorithm": "Cybox-Files-Signature_Fingerprints-Algorithm 2",
                            "value": "Cybox-Files-Signature_Fingerprints-Value 2"
                        },
                        {
                            "algorithm": "Cybox-Files-Signature_Fingerprints-Algorithms 2",
                            "value": "Cybox-Files-Signature_Fingerprints-Values 2"
                        }
                    ],
                    "signature_level_id": "1",
                    "signature_value": 12345678902,
                    "signature_value_ids": [
                        "11",
                        "12",
                        "13",
                        "14",
                        "15",
                        "16",
                        "17",
                        "18",
                        "19",
                        "20",
                        "21",
                        "22",
                        "23",
                        "24",
                        "25"
                    ],
                    "size_compressed": 12345678902,
                    "src_ip": "81.2.69.144",
                    "src_name": "Cybox-Files-SRC_Name 2",
                    "type_id": "1",
                    "uid": "Cybox-Files-UID 2",
                    "url": {
                        "categories": [
                            "Cybox-Files-URL-Category 2",
                            "Cybox-Files-URL-Categories 2"
                        ],
                        "category_ids": [
                            "101",
                            "102",
                            "103",
                            "104",
                            "105",
                            "106",
                            "107",
                            "108",
                            "109",
                            "110",
                            "111",
                            "112",
                            "113",
                            "114",
                            "116",
                            "117",
                            "118",
                            "121",
                            "124"
                        ],
                        "extension": "Cybox-Files-URL-Extension 2",
                        "host": "www.files-url-host-2.com",
                        "method": "Cybox-Files-URL-Method 2",
                        "parent_categories": [
                            "Cybox-Files-URL-Parent_Category 2",
                            "Cybox-Files-URL-Parent_Categories 2"
                        ],
                        "path": "/download/trouble/cybox/files/url/path/2",
                        "port": 81,
                        "provider": "Cybox-Files-URL-Provider 2",
                        "query": "q=bad&sort=date_2",
                        "referrer": "Cybox-Files-URL-Referrer 2",
                        "referrer_categories": [
                            "Cybox-Files-URL-Referrer_Category 2",
                            "Cybox-Files-URL-Referrer_Categories 2"
                        ],
                        "referrer_category_ids": [
                            "12345678902",
                            "67890123452"
                        ],
                        "rep_score_id": "1",
                        "scheme": "Cybox-Files-URL-Scheme 2",
                        "text": "www.files-url-text-2.com/download/trouble"
                    },
                    "version": "Cybox-Files-Version 2",
                    "xattributes": {
                        "Unix_permissions": "Cybox-Files-XAttributes-Unix_Permissions 2",
                        "ads_name": "Cybox-Files-XAttributes-ADS_Name 2",
                        "ads_size": "Cybox-Files-XAttributes-ADS_Size 2",
                        "dacl": "Cybox-Files-XAttributes-DACL 2",
                        "hard_link_count": "Cybox-Files-XAttributes-Hard_Link_Count 2",
                        "link_name": "Cybox-Files-XAttributes-Link_Name 2",
                        "owner": "Cybox-Files-XAttributes-Owner 2",
                        "primary_group": "Cybox-Files-XAttributes-Primary_Group 2"
                    }
                }
            ],
            "hostnames": [
                "Cybox-Hostname 1",
                "Cybox-Hostnames 1"
            ],
            "icap_reqmod": [
                {
                    "metadata": {
                        "field1_boolean": true,
                        "field1_ip": "175.16.199.0",
                        "field1_keyword": "Cybox-ICAP_ReqMod-field1_Keyword",
                        "field1_number": 12345678901
                    },
                    "service": "Cybox-ICAP_ReqMod-Service 1",
                    "status": "Cybox-ICAP_ReqMod-Status 1",
                    "status_detail": "Cybox-ICAP_ReqMod-Status_Detail 1"
                },
                {
                    "metadata": {
                        "field2_boolean": true,
                        "field2_ip": "175.16.199.0",
                        "field2_keyword": "Cybox-ICAP_ReqMod-field2_Keyword",
                        "field2_number": 12345678902
                    },
                    "service": "Cybox-ICAP_ReqMod-Service 2",
                    "status": "Cybox-ICAP_ReqMod-Status 2",
                    "status_detail": "Cybox-ICAP_ReqMod-Status_Detail 2"
                }
            ],
            "icap_respmod": [
                {
                    "metadata": {
                        "field1_boolean": true,
                        "field1_ip": "175.16.199.0",
                        "field1_keyword": "Cybox-ICAP_RespMod-field1_Keyword",
                        "field1_number": 12345678901
                    },
                    "service": "Cybox-ICAP_RespMod-Service 1",
                    "status": "Cybox-ICAP_RespMod-Status 1",
                    "status_detail": "Cybox-ICAP_RespMod-Status_Detail 1"
                },
                {
                    "metadata": {
                        "field2_boolean": true,
                        "field2_ip": "175.16.199.0",
                        "field2_keyword": "Cybox-ICAP_RespMod-field2_Keyword",
                        "field2_number": 12345678902
                    },
                    "service": "Cybox-ICAP_RespMod-Service 2",
                    "status": "Cybox-ICAP_RespMod-Status 2",
                    "status_detail": "Cybox-ICAP_RespMod-Status_Detail 2"
                }
            ],
            "ipv4s": [
                "175.16.199.0",
                "175.16.199.0"
            ],
            "ipv6s": [
                "2a02:cf40::",
                "2a02:cf40::"
            ],
            "macs": [
                "00:B0:D0:63:C2:05",
                "00:B0:D0:63:C2:06"
            ],
            "urls": [
                {
                    "categories": [
                        "Cybox-URLs-Category 1",
                        "Cybox-URLs-Categories 1"
                    ],
                    "category_ids": [
                        "1",
                        "3",
                        "4",
                        "5",
                        "6",
                        "7",
                        "9",
                        "11",
                        "14",
                        "15",
                        "16",
                        "17",
                        "18",
                        "20",
                        "21",
                        "22",
                        "23",
                        "24",
                        "25",
                        "26",
                        "27",
                        "29",
                        "30",
                        "31",
                        "32",
                        "33",
                        "34",
                        "35",
                        "36",
                        "37",
                        "38",
                        "40",
                        "43",
                        "44",
                        "45",
                        "46",
                        "47",
                        "49",
                        "50",
                        "51",
                        "52",
                        "53",
                        "54",
                        "55",
                        "56",
                        "57",
                        "58",
                        "59",
                        "60",
                        "61",
                        "63",
                        "64",
                        "65",
                        "66",
                        "67",
                        "68",
                        "71",
                        "83",
                        "84",
                        "85",
                        "86",
                        "87",
                        "88",
                        "89",
                        "90",
                        "92",
                        "93",
                        "95",
                        "96",
                        "97",
                        "98"
                    ],
                    "extension": "Cybox-URLs-Extension 1",
                    "host": "www.urls-host-1.com",
                    "method": "Cybox-URLs-Method 1",
                    "parent_categories": [
                        "Cybox-URLs-Parent_Category 1",
                        "Cybox-URLs-Parent_Categories 1"
                    ],
                    "provider": "Cybox-URLs-Provider 1",
                    "referrer": "Cybox-URLs-Referrer 1",
                    "referrer_categories": [
                        "Cybox-URLs-Referrer_Category 1",
                        "Cybox-URLs-Referrer_Categories 1"
                    ],
                    "referrer_category_ids": [
                        "12345678901",
                        "67890123451"
                    ],
                    "rep_score_id": "0"
                },
                {
                    "categories": [
                        "Cybox-URLs-Category 2",
                        "Cybox-URLs-Categories 2"
                    ],
                    "category_ids": [
                        "101",
                        "102",
                        "103",
                        "104",
                        "105",
                        "106",
                        "107",
                        "108",
                        "109",
                        "110",
                        "111",
                        "112",
                        "113",
                        "114",
                        "116",
                        "117",
                        "118",
                        "121",
                        "124"
                    ],
                    "extension": "Cybox-URLs-Extension 2",
                    "host": "www.urls-host-2.com",
                    "method": "Cybox-URLs-Method 2",
                    "parent_categories": [
                        "Cybox-URLs-Parent_Category 2",
                        "Cybox-URLs-Parent_Categories 2"
                    ],
                    "provider": "Cybox-URLs-Provider 2",
                    "referrer": "Cybox-URLs-Referrer 2",
                    "referrer_categories": [
                        "Cybox-URLs-Referrer_Category 2",
                        "Cybox-URLs-Referrer_Categories 2"
                    ],
                    "referrer_category_ids": [
                        "12345678902",
                        "67890123452"
                    ],
                    "rep_score_id": "1"
                }
            ]
        },
        "device_alias_name": "Device_Alias_Name",
        "device_cap": "Device_Cap",
        "device_cloud_vm": {
            "autoscale_uid": "Device_Cloud_VM-Autoscale_UID",
            "dc_region": "Device_Cloud_VM-DC_Region",
            "instance_uid": "Device_Cloud_VM-Instance_UID",
            "subnet_uid": "Device_Cloud_VM-Subnet_UID",
            "vpc_uid": "Device_Cloud_VM-VPC_UID"
        },
        "device_desc": "Device_Desc",
        "device_gateway": "175.16.199.0",
        "device_group": "Device_Group",
        "device_group_name": "Device_Group_Name",
        "device_hw_bios_date": "03/31/16",
        "device_hw_bios_ver": "LENOVO G5ETA2WW (2.62)",
        "device_imei": "Device_IMEI",
        "device_is_compliant": true,
        "device_is_personal": true,
        "device_is_trusted": true,
        "device_is_unmanaged": true,
        "device_location": {
            "coordinates": [
                -12.345,
                56.789
            ],
            "desc": "Device_Location-Desc",
            "isp": "Device_Location-ISP",
            "on_premises": true
        },
        "device_name_md5": "4ED962DDBF17E2BBA7B14EBC00F3162E",
        "device_networks": [
            {
                "bssid": "Device_Networks-BSSID 1",
                "gateway_ip": "175.16.199.0",
                "gateway_mac": "00:B0:D0:63:C2:08",
                "ipv4": "175.16.199.0",
                "ipv6": "2a02:cf40::",
                "is_public": true,
                "mac": "00:B0:D0:63:C2:09",
                "rep_score_id": "0",
                "ssid": "Device_Networks-SSID 1",
                "type_id": "0"
            },
            {
                "bssid": "Device_Networks-BSSID 2",
                "gateway_ip": "89.160.20.112",
                "gateway_mac": "00:B0:D0:63:C2:10",
                "ipv4": "89.160.20.112",
                "ipv6": "2a02:cf40::",
                "is_public": true,
                "mac": "00:B0:D0:63:C2:11",
                "rep_score_id": "1",
                "ssid": "Device_Networks-SSID 2",
                "type_id": "1"
            }
        ],
        "device_org_unit": "Device_Org_Unit",
        "device_os_bits": 12345678901,
        "device_os_edition": "Professional",
        "device_os_lang": "en",
        "device_os_sp_name": "Device_OS_SP_Name",
        "device_os_sp_ver": "Device_OS_SP_Ver",
        "device_os_type_id": "0",
        "device_os_type_value": "Unknown",
        "device_proxy_ip": "89.160.20.112",
        "device_proxy_name": "Device_Proxy_Name",
        "device_public_ip": "89.160.20.112",
        "device_ref_uid": "Device_Ref_UID",
        "device_site": "Device_Site",
        "device_subnet": "81.2.69.144",
        "device_vhost": "Device_VHost",
        "device_vhost_id": "0",
        "domain_uid": "Domain_UID",
        "end_time": "2024-02-29T01:00:00.000Z",
        "entity": {
            "data": {
                "field1_boolean": true,
                "field1_keyword": "Entity-Data-field1_Keyword",
                "field1_number": 12345678901
            },
            "name": "Entity-Name",
            "type": "Entity-Type",
            "uid": "Entity-UID",
            "version": "Entity-Version"
        },
        "event_id": "2001",
        "events": [
            {
                "connection": {
                    "direction_id": 1,
                    "dst_service": "C:\\Windows\\system32\\NTOSKRNL.EXE",
                    "src_ip": "159.19.163.218"
                },
                "count": 1,
                "device_end_time": 1709225074618,
                "device_time": 1709225074618
            }
        ],
        "feature_name": "Feature_Name",
        "feature_path": "Feature_Path",
        "feature_type": "Feature_Type",
        "feature_uid": "Feature_UID",
        "feature_ver": "2014.1.4.25",
        "id": 12345678901,
        "impersonator_customer_uid": "Impersonator_Customer_UID",
        "impersonator_domain_uid": "Impersonator_Domain_UID",
        "impersonator_user_uid": "Impersonator_User_UID",
        "is_user_present": true,
        "log_time": "2024-02-29T01:00:00.000Z",
        "logging_device_ip": "89.160.20.112",
        "logging_device_name": "Logging_Device_Name",
        "logging_device_post_time": "2021-02-11T05:30:04.000Z",
        "logging_device_ref_uid": "Logging_Device_Ref_UID",
        "message_code": "Message_Code",
        "message_id": "0",
        "org_unit_uid": "Org_Unit_UID",
        "orig_data": "Orig_Data",
        "product_data": {
            "sep_domain_uid": "Product_Data-Sep_Domain_UID",
            "sep_hw_uid": "Product_Data-Sep_HW_UID"
        },
        "product_lang": "en",
        "product_name": "Symantec Endpoint Security",
        "product_uid": "Product_UID",
        "product_ver": "2014.1.4.25-beta",
        "proxy_device_ip": "89.160.20.112",
        "proxy_device_name": "Proxy_Device_Name",
        "raw_data": {
            "assetID": "vc9DagprQYyLZ23SEY1APw",
            "assetOpstateDTO": {
                "blades": 0,
                "features": [
                    {
                        "featureStatus": "SECURE",
                        "opstate": {
                            "EDRContentSequence": "20231128005",
                            "EDREngineVersion": "4.11.0.10",
                            "EDRFramworkVersion": "4.10.0.59",
                            "FDRStatus": true,
                            "LowDiskSpace": false,
                            "MaxDBSizeHonored": true,
                            "applied_policy": {
                                "effective_date": 1709219437080,
                                "sha2": "ee6b0bebbc4575b507ac616d2c362f2c54d462b92cf4068cb6681ae3187d4de3",
                                "uid": "7dc29d40-f303-477a-9012-287ef252a391",
                                "version": "16"
                            },
                            "disk_usage_mb": 1546,
                            "fdr_first_event_date": "20240227",
                            "fdr_state": 1
                        },
                        "prevention_state": "1",
                        "state": "ENABLED",
                        "statusReason": [
                            "-107",
                            "0"
                        ],
                        "uuid": "1DF0351C-146D-4F07-B155-BF5C7077FF40"
                    }
                ],
                "productUuid": "31B0C880-0229-49E8-94C5-48D56B1BD7B9",
                "products_active": 0
            }
        },
        "ref_log_name": "Ref_Log_Name",
        "ref_log_time": "2024-02-29T01:00:00.000Z",
        "ref_orig_uid": "Ref_Orig_UID",
        "ref_uid": "Ref_UID",
        "remediated": true,
        "remediation": "Remediation",
        "remediation_ref": "Remediation_Ref",
        "remediation_uid": "0",
        "sessions": [
            {
                "auth_protocol_id": "0",
                "cleartext_credentials": true,
                "direction_id": "0",
                "id": 12345678901,
                "is_admin": true,
                "logon_type_id": "1",
                "port": 80,
                "previous_users": [
                    "Sessions-Previous_User 1",
                    "Sessions-Previous_Users 1"
                ],
                "remote": true,
                "remote_host": "Sessions-Remote_Host 1",
                "remote_ip": "89.160.20.112",
                "user": {
                    "account_disabled": true,
                    "cloud_resource_uid": "Sessions-User-Cloud_Resource_UID 1",
                    "domain": "Sessions-User-Domain 1",
                    "external_account_uid": "Sessions-User-External_Account_UID 1",
                    "external_uid": "Sessions-User-External_UID 1",
                    "full_name": "Sessions-User-Full_Name 1",
                    "groups": [
                        "Sessions-User-Group 1",
                        "Sessions-User-Groups 1"
                    ],
                    "home": "Sessions-User-Home 1",
                    "is_admin": true,
                    "logon_name": "Sessions-User-Logon_Name 1",
                    "name": "session-User-Name 1",
                    "password_expires": true,
                    "shell": "Sessions-User-Shell 1",
                    "sid": "Sessions-User-SID 1",
                    "uid": "Sessions-User-UID 1"
                }
            },
            {
                "auth_protocol_id": "1",
                "cleartext_credentials": true,
                "direction_id": "1",
                "id": 67890123451,
                "is_admin": true,
                "logon_type_id": "2",
                "port": 81,
                "previous_users": [
                    "Sessions-Previous_User 2",
                    "Sessions-Previous_Users 2"
                ],
                "remote": true,
                "remote_host": "Sessions-Remote_Host 2",
                "remote_ip": "89.160.20.112",
                "user": {
                    "account_disabled": true,
                    "cloud_resource_uid": "Sessions-User-Cloud_Resource_UID 2",
                    "domain": "Sessions-User-Domain 2",
                    "external_account_uid": "Sessions-User-External_Account_UID 2",
                    "external_uid": "Sessions-User-External_UID 2",
                    "full_name": "Sessions-User-Full_Name 2",
                    "groups": [
                        "Sessions-User-Group 2",
                        "Sessions-User-Groups 2"
                    ],
                    "home": "Sessions-User-Home 2",
                    "is_admin": true,
                    "logon_name": "Sessions-User-Logon_Name 2",
                    "name": "session-User-Name 2",
                    "password_expires": true,
                    "shell": "Sessions-User-Shell 2",
                    "sid": "Sessions-User-SID 2",
                    "uid": "Sessions-User-UID 2"
                }
            }
        ],
        "severity_value": "Unknown",
        "source": {
            "facility": "Source-Facility",
            "facility_detail": "Source-Facility_Detail",
            "facility_uid": "Source-Facility_UID",
            "type_id": "1"
        },
        "status_detail": "Status_Detail",
        "status_id": "0",
        "status_os": "Status_OS",
        "status_os_src": 12345678901,
        "status_stack_trace": "Status_Stack_Trace",
        "status_value": "Unknown",
        "stic_has_pii": true,
        "stic_hw_uid": "STIC_HW_UID",
        "stic_ip_hash": "STIC_IP_Hash",
        "stic_legacy_ent_uids": [
            "STIC_Legacy_Ent_UIDs 1",
            "STIC_Legacy_Ent_UIDs 2"
        ],
        "stic_legacy_hw_uids": [
            "STIC_Legacy_HW_UIDs 1",
            "STIC_Legacy_HW_UIDs 2"
        ],
        "stic_legacy_uids": [
            "STIC_Legacy_UIDs 1",
            "STIC_Legacy_UIDs 2"
        ],
        "stic_schema_id": "STIC_Schema_ID",
        "stic_uid": "STIC_UID",
        "stic_version": "STIC_Version",
        "subfeature_name": "Subfeature_Name",
        "timezone": 12345678901,
        "type": "Type",
        "type_id": "2",
        "user": {
            "account_disabled": true,
            "cloud_resource_uid": "User-Cloud_Resource_UID",
            "external_account_uid": "User-External_Account_UID",
            "external_uid": "User-External_UID",
            "full_name": "User-Full_Name",
            "groups": [
                "User-Group 1",
                "User-Groups 1"
            ],
            "home": "User-Home",
            "is_admin": true,
            "logon_name": "User-Logon_Name",
            "password_expires": true,
            "shell": "User-Shell",
            "sid": "TT23009"
        },
        "version": "1.4"
    },
    "source": {
        "address": "device.name.computer.domain",
        "domain": "Device_Domain_UID",
        "ip": "175.16.199.0",
        "mac": "00-B0-D0-63-C2-07"
    },
    "tags": [
        "collect_sqs_logs",
        "preserve_original_event",
        "forwarded",
        "symantec_endpoint_security-event"
    ],
    "url": {
        "full": [
            "www.urls-text-1.com/download/trouble",
            "www.urls-text-2.com/download/trouble"
        ],
        "path": [
            "/download/trouble/cybox/urls/path/1",
            "/download/trouble/cybox/urls/path/2"
        ],
        "port": [
            80,
            81
        ],
        "query": [
            "q=bad&sort=date_1",
            "q=bad&sort=date_2"
        ],
        "scheme": [
            "Cybox-URLs-Scheme 1",
            "Cybox-URLs-Scheme 2"
        ]
    },
    "user": {
        "domain": [
            "User-Domain"
        ],
        "id": "UU34899825",
        "name": "User123"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.s3.bucket.arn | The AWS S3 bucket ARN. | keyword |
| aws.s3.bucket.name | The AWS S3 bucket name. | keyword |
| aws.s3.object.key | The AWS S3 Object key. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| ses.access_mask | The access mask in platform-native format. | long |
| ses.access_mask_ids | The access mask values. | keyword |
| ses.access_scope_id | The scope of the requested access. | keyword |
| ses.activity_id | The process activity. | keyword |
| ses.actor.app_name | A label that may be associated with this process, for example, the name of the containment sandbox assigned to the process or, for login detection events, the login application (ssh, telnet, sql server, etc.). | keyword |
| ses.actor.app_uid | The identifier of the application that may be associated with this process. | keyword |
| ses.actor.app_ver | The version of the application that may be associated with this process. | keyword |
| ses.actor.cmd_line | The command line used to launch the startup application, service, process or job. | keyword |
| ses.actor.file.accessed | The time that the file was last accessed. | date |
| ses.actor.file.accessor | The name of the user who last accessed the object. | keyword |
| ses.actor.file.attribute_ids | The array of file attributes. | keyword |
| ses.actor.file.attributes | The bitmask value that represents the file attributes. | long |
| ses.actor.file.company_name | The name of the company that published the file. | keyword |
| ses.actor.file.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.actor.file.content_type.family_id | The top level file classification. | keyword |
| ses.actor.file.content_type.subtype | The specific format for the type of data. | keyword |
| ses.actor.file.content_type.type_id | The general type of a file. | keyword |
| ses.actor.file.created | The time that the file was created. | date |
| ses.actor.file.creator | The name of the user who created the file. | keyword |
| ses.actor.file.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.actor.file.desc | The description of the file, as returned by file system. | keyword |
| ses.actor.file.folder | The parent folder in which the file resides. | keyword |
| ses.actor.file.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.actor.file.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.actor.file.md5 | The MD5 checksum of the object content. | keyword |
| ses.actor.file.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.actor.file.modified | The time when the file was last modified. | date |
| ses.actor.file.modifier | The name of the user who last modified the file. | keyword |
| ses.actor.file.name | The name of the file. | keyword |
| ses.actor.file.normalized_path | The CSIDL normalized path name. | keyword |
| ses.actor.file.original_name | The original name of the file. | keyword |
| ses.actor.file.owner | The owner of the file. | keyword |
| ses.actor.file.parent_name | The name of the file that contains this file. | keyword |
| ses.actor.file.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.actor.file.path | The full path to the file. | keyword |
| ses.actor.file.product_name | The name of the product that includes the file. | keyword |
| ses.actor.file.product_path | The path to the product that includes the file. | keyword |
| ses.actor.file.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.actor.file.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.actor.file.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.actor.file.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.actor.file.rep_score | The reputation score of the file. | long |
| ses.actor.file.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.actor.file.security_descriptor | The object security descriptor. | keyword |
| ses.actor.file.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.actor.file.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.actor.file.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.actor.file.signature_created_date | The date and time when the signature was created. | date |
| ses.actor.file.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.actor.file.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.actor.file.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.actor.file.signature_issuer | The issuer of the object signature. | keyword |
| ses.actor.file.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.actor.file.signature_serial_number | The object serial number. | keyword |
| ses.actor.file.signature_value | The digital signature bitmask. | long |
| ses.actor.file.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.actor.file.size | The size of the object, in bytes. | long |
| ses.actor.file.size_compressed | The compressed size of the object, in bytes. | long |
| ses.actor.file.src_ip | The IP address of the host where the file resides. | ip |
| ses.actor.file.src_name | The name of the host where the file resides. | keyword |
| ses.actor.file.type_id | The file type. | keyword |
| ses.actor.file.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.actor.file.url.categories | The array of URL categories. | keyword |
| ses.actor.file.url.category_ids | The array of URL categories. | keyword |
| ses.actor.file.url.extension | Document extension from the original URL requested. | keyword |
| ses.actor.file.url.host | The URL host as extracted from the URL. | keyword |
| ses.actor.file.url.method | The HTTP method used in the URL request. | keyword |
| ses.actor.file.url.parent_categories | The array of parent URL categories. | keyword |
| ses.actor.file.url.path | The URL path as extracted from the URL. | keyword |
| ses.actor.file.url.port | The URL port. | long |
| ses.actor.file.url.provider | The origin of the reputation and category information. | keyword |
| ses.actor.file.url.query | The query portion of the URL. | keyword |
| ses.actor.file.url.referrer | The address accessed prior to this one. | keyword |
| ses.actor.file.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.actor.file.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.actor.file.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.actor.file.url.scheme | The scheme portion of the URL. | keyword |
| ses.actor.file.url.text | The URL. | keyword |
| ses.actor.file.version | The file version. | keyword |
| ses.actor.file.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.actor.integrity_id | The process integrity level (Windows only). | keyword |
| ses.actor.lineage | The lineage of the actor process. | keyword |
| ses.actor.loaded_modules | The list of loaded module names. | keyword |
| ses.actor.module.accessed | The time that the file was last accessed. | date |
| ses.actor.module.accessor | The name of the user who last accessed the object. | keyword |
| ses.actor.module.attribute_ids | The array of file attributes. | keyword |
| ses.actor.module.attributes | The bitmask value that represents the file attributes. | long |
| ses.actor.module.base_address | The memory address where the module was loaded. | keyword |
| ses.actor.module.company_name | The name of the company that published the file. | keyword |
| ses.actor.module.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.actor.module.content_type.family_id | The top level file classification. | keyword |
| ses.actor.module.content_type.subtype | The specific format for the type of data. | keyword |
| ses.actor.module.content_type.type_id | The general type of a file. | keyword |
| ses.actor.module.created | The time that the module was created. | date |
| ses.actor.module.creator | The name of the user who created the module. | keyword |
| ses.actor.module.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.actor.module.desc | The description of the file, as returned by file system. | keyword |
| ses.actor.module.folder | The parent folder in which the file resides. | keyword |
| ses.actor.module.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.actor.module.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.actor.module.load_type | The load type describes how the module was loaded in memory. | keyword |
| ses.actor.module.load_type_id | The load type identifies how the module was loaded in memory. | keyword |
| ses.actor.module.md5 | The MD5 checksum of the object content. | keyword |
| ses.actor.module.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.actor.module.modified | The time when the module was last modified. | date |
| ses.actor.module.modifier | The name of the user who last modified the module. | keyword |
| ses.actor.module.name | The name of the file. | keyword |
| ses.actor.module.normalized_path | The CSIDL normalized path name. | keyword |
| ses.actor.module.original_name | The original name of the file. | keyword |
| ses.actor.module.owner | The owner of the file. | keyword |
| ses.actor.module.parent_name | The name of the file that contains this file. | keyword |
| ses.actor.module.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.actor.module.path | The full path to the file. | keyword |
| ses.actor.module.product_name | The name of the product that includes the file. | keyword |
| ses.actor.module.product_path | The path to the product that includes the file. | keyword |
| ses.actor.module.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.actor.module.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.actor.module.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.actor.module.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.actor.module.rep_score | The reputation score of the file. | long |
| ses.actor.module.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.actor.module.security_descriptor | The object security descriptor. | keyword |
| ses.actor.module.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.actor.module.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.actor.module.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.actor.module.signature_created_date | The date and time when the signature was created. | date |
| ses.actor.module.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.actor.module.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.actor.module.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.actor.module.signature_issuer | The issuer of the object signature. | keyword |
| ses.actor.module.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.actor.module.signature_serial_number | The object serial number. | keyword |
| ses.actor.module.signature_value | The digital signature bitmask. | long |
| ses.actor.module.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.actor.module.size | The size of the object, in bytes. | long |
| ses.actor.module.size_compressed | The compressed size of the object, in bytes. | long |
| ses.actor.module.src_ip | The IP address of the host where the file resides. | ip |
| ses.actor.module.src_name | The name of the host where the file resides. | keyword |
| ses.actor.module.type_id | The file type. | keyword |
| ses.actor.module.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.actor.module.url.categories | The array of URL categories. | keyword |
| ses.actor.module.url.category_ids | The array of URL categories. | keyword |
| ses.actor.module.url.extension | Document extension from the original URL requested. | keyword |
| ses.actor.module.url.host | The URL host as extracted from the URL. | keyword |
| ses.actor.module.url.method | The HTTP method used in the URL request. | keyword |
| ses.actor.module.url.parent_categories | The array of parent URL categories. | keyword |
| ses.actor.module.url.path | The URL path as extracted from the URL. | keyword |
| ses.actor.module.url.port | The URL port. | long |
| ses.actor.module.url.provider | The origin of the reputation and category information. | keyword |
| ses.actor.module.url.query | The query portion of the URL. | keyword |
| ses.actor.module.url.referrer | The address accessed prior to this one. | keyword |
| ses.actor.module.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.actor.module.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.actor.module.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.actor.module.url.scheme | The scheme portion of the URL. | keyword |
| ses.actor.module.url.text | The URL. | keyword |
| ses.actor.module.version | The file version. | keyword |
| ses.actor.module.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.actor.normalized_cmd_line | The CSIDL normalized command line used to launch the startup application, service, process or job (Windows only). | keyword |
| ses.actor.pid | The process identifier, as reported by the operating system. | long |
| ses.actor.sandbox_name | The name of the containment jail (sandbox) assigned by the policy to this process/module. | keyword |
| ses.actor.session.auth_protocol_id | The authentication protocol. | keyword |
| ses.actor.session.cleartext_credentials | Indicates whether the credentials were passed in clear text. | boolean |
| ses.actor.session.direction_id | The direction of the initiated traffic. | keyword |
| ses.actor.session.id | The unique session identifier, as reported by the operating system. | keyword |
| ses.actor.session.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.actor.session.logon_type_id | The type of session logon. | keyword |
| ses.actor.session.port | The port that the remote session connects to; applicable for remote sessions only. | long |
| ses.actor.session.previous_users | An ordered list of the previous user names used within the session, from latest to earliest. | keyword |
| ses.actor.session.remote | The indication of whether the session is remote. | boolean |
| ses.actor.session.remote_host | The host name of the device associated with the remote session. | keyword |
| ses.actor.session.remote_ip | The IP address of the device associated with the remote session. The format is either IPv4 or IPv6. | ip |
| ses.actor.session.user.account_disabled | The indication of whether the user's account is disabled. | boolean |
| ses.actor.session.user.cloud_resource_uid | The cloud resource unique identifier of this user. | keyword |
| ses.actor.session.user.domain | The domain where the user is defined. | keyword |
| ses.actor.session.user.external_account_uid | The user's external account unique identifier. | keyword |
| ses.actor.session.user.external_uid | The user's external unique identifier. | keyword |
| ses.actor.session.user.full_name | The full name of the user. | keyword |
| ses.actor.session.user.groups | The administrative groups to which the user belongs. | keyword |
| ses.actor.session.user.home | The user's home directory. | keyword |
| ses.actor.session.user.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.actor.session.user.logon_name | The name of the authenticated principal that is associated with the event. | keyword |
| ses.actor.session.user.name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.actor.session.user.password_expires | The indication of whether the user's password is configured to expire. | boolean |
| ses.actor.session.user.shell | The user's login shell. | keyword |
| ses.actor.session.user.sid | The user security identifier (SID). | keyword |
| ses.actor.session.user.uid | The unique identifier of the user associated with the event. | keyword |
| ses.actor.session_id | The user session ID from which the process was launched. | keyword |
| ses.actor.start_time | The time that the process started. | date |
| ses.actor.tid | The Identifier of the thread associated with the event, as returned by the operating system. | long |
| ses.actor.uid | The unique identifier of the process. | keyword |
| ses.actor.user.account_disabled | The indication of whether the user's account is disabled. | boolean |
| ses.actor.user.cloud_resource_uid | The cloud resource unique identifier of this user. | keyword |
| ses.actor.user.domain | The domain where the user is defined. | keyword |
| ses.actor.user.external_account_uid | The user's external account unique identifier. | keyword |
| ses.actor.user.external_uid | The user's external unique identifier. | keyword |
| ses.actor.user.full_name | The full name of the user. | keyword |
| ses.actor.user.groups | The administrative groups to which the user belongs. | keyword |
| ses.actor.user.home | The user's home directory. | keyword |
| ses.actor.user.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.actor.user.logon_name | The name of the authenticated principal that is associated with the event. | keyword |
| ses.actor.user.name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.actor.user.password_expires | The indication of whether the user's password is configured to expire. | boolean |
| ses.actor.user.shell | The user's login shell. | keyword |
| ses.actor.user.sid | The user security identifier (SID). | keyword |
| ses.actor.user.uid | The unique identifier of the user associated with the event. | keyword |
| ses.actor.xattributes | An unordered collection of zero or more name/value pairs that represent a process extended attribute. | flattened |
| ses.actual_permissions | The permissions that were granted to the process. | long |
| ses.analysis | The anti-malware emulation analysis. | keyword |
| ses.app_name | The name of the application that may be associated with the policy change. | keyword |
| ses.app_uid | The identifier of the application that may be associated with the policy change. | keyword |
| ses.app_ver | The version of the application that may be associated with the policy change. | keyword |
| ses.assignee | The name of the user who is assigned to the incident. | keyword |
| ses.attacker_ip | The IP address of the malicious network device. The format is either IPv4 or IPv6. | ip |
| ses.attacks.sub_technique_name | The name of the attack sub-technique, as defined by ATT&CK MatrixTM. | keyword |
| ses.attacks.sub_technique_uid | The unique identifier of the attack sub-technique, as defined by ATT&CK MatrixTM. | keyword |
| ses.attacks.tactic_ids | The tactics that are associated with the attack technique (To be deprecated, use tactic_uids). | keyword |
| ses.attacks.tactic_uids | The tactics that are associated with the attack technique, as defined by ATT&CK MatrixTM. | keyword |
| ses.attacks.technique_name | The name of the attack technique, as defined by ATT&CK MatrixTM. | keyword |
| ses.attacks.technique_uid | The unique identifier of the attack technique, as defined by ATT&CK MatrixTM. | keyword |
| ses.audit | The audit mode of the event. When true, no remediation actions were performed. | boolean |
| ses.category_id | The event type category. | keyword |
| ses.category_name | Category name of the event. | keyword |
| ses.change_type_id | The reason for the policy change. | keyword |
| ses.channel_id | The channel that was used to update the component. | keyword |
| ses.client_uid | The OAUTH 2.0 Client ID. | keyword |
| ses.collector_device_ip | The IP address of the collector device in either IPv4 or IPv6 format. | ip |
| ses.collector_device_name | The name of the collector device. | keyword |
| ses.collector_name | The name of the collector. | keyword |
| ses.collector_uid | The unique identifier of the collector. | keyword |
| ses.command_name | The command that pertains to the event or object. | keyword |
| ses.command_ref_uid | The command identifier that corresponds to the original command identifier. | keyword |
| ses.command_uid | The command identifier that is associated with this Scan event; required if the scan was initiated by a command. | keyword |
| ses.comment | The user-provided comment. | keyword |
| ses.compliance_rule.criteria_id | The criteria that is associated with the rule. | keyword |
| ses.compliance_rule.desc | The description of the rule. | keyword |
| ses.compliance_rule.name | The name given to the rule. | keyword |
| ses.compliance_rule.type_id | The type of the rule. | keyword |
| ses.compliance_rule.uid | The unique identifier of the rule. | keyword |
| ses.component | The name or relative pathname of a subcomponent of the  data object, if applicable. | keyword |
| ses.composite | The type of composite event. See the Event Logging API for more information. | long |
| ses.conclusion | The conclusive description of the events that are associated with the incident. | keyword |
| ses.config_path | The file or registry key that holds the startup application configuration. | keyword |
| ses.connection.bytes_download | The number of bytes downloaded from the source to the destination. | long |
| ses.connection.bytes_upload | The number of bytes uploaded from the source to the destination. | long |
| ses.connection.connection_direction_id | The direction of the initiated connection. | keyword |
| ses.connection.direction_id | The direction of the initiated traffic. | keyword |
| ses.connection.dst_ip | The IP address of the destination network connection device. The format is either IPv4 or IPv6. | ip |
| ses.connection.dst_location.city | The name of the city. | keyword |
| ses.connection.dst_location.continent | The name of the continent. | keyword |
| ses.connection.dst_location.coordinates | A two-element array, containing a longitude/latitude pair. The format conforms with GeoJSON. | float |
| ses.connection.dst_location.country | The ISO 3166-1 Alpha-2 country code. For the complete list of country codes see ISO 3166-1 alpha-2 codes.Note: The two letter country code should be capitalized. | keyword |
| ses.connection.dst_location.desc | The description of the location. | keyword |
| ses.connection.dst_location.isp | The name of the Internet Service Provider (ISP). | keyword |
| ses.connection.dst_location.on_premises | The indication of whether the location is on premises. | boolean |
| ses.connection.dst_location.region | The alphanumeric code that identifies the principal subdivision (e.g. province or state) of the country. Region codes are defined at ISO 3166-2 and have a limit of three characters. For examples, see the region codes for the US. | keyword |
| ses.connection.dst_mac | The MAC address of the destination network connection device. | keyword |
| ses.connection.dst_name | The host name of the destination network connection device. | keyword |
| ses.connection.dst_port | The port number of the destination network connection. | long |
| ses.connection.dst_service | The destination network connection service name. | keyword |
| ses.connection.ether_type | The EtherType indicates which protocol is encapsulated in the payload of an Ethernet frame. | long |
| ses.connection.http_status | The HTTP status code returned to the client. | long |
| ses.connection.http_user_agent | The request header that is used to identify the operating system and web browser. | keyword |
| ses.connection.local | The indication of whether the connection is between two endpoints on the same device. For example, if Source IP (src_ip) and Destination IP (dst_ip) could be the same. | boolean |
| ses.connection.protocol_id | The network protocol as defined by RFC1340. | keyword |
| ses.connection.protocol_version | The version of the network protocol. | long |
| ses.connection.request_headers | The additional information associated with HTTP request. | flattened |
| ses.connection.response_headers | The additional information associated with HTTP response. | flattened |
| ses.connection.rpc.binding | The remote procedure call protocol family, hostname, and endpoint connection. | keyword |
| ses.connection.rpc.interface_op | The remote procedure call interface operation number. | long |
| ses.connection.rpc.interface_uid | The unique identifier of the remote procedure call interface. | keyword |
| ses.connection.rpc.interface_ver | The remote procedure call interface version. | keyword |
| ses.connection.src_ip | The IP address of the device that initiated the network connection. | ip |
| ses.connection.src_location.city | The name of the city. | keyword |
| ses.connection.src_location.continent | The name of the continent. | keyword |
| ses.connection.src_location.coordinates | A two-element array, containing a longitude/latitude pair. The format conforms with GeoJSON. | float |
| ses.connection.src_location.country | The ISO 3166-1 Alpha-2 country code. For the complete list of country codes see ISO 3166-1 alpha-2 codes.Note: The two letter country code should be capitalized. | keyword |
| ses.connection.src_location.desc | The description of the location. | keyword |
| ses.connection.src_location.isp | The name of the Internet Service Provider (ISP). | keyword |
| ses.connection.src_location.on_premises | The indication of whether the location is on premises. | boolean |
| ses.connection.src_location.region | The alphanumeric code that identifies the principal subdivision (e.g. province or state) of the country. Region codes are defined at ISO 3166-2 and have a limit of three characters. | keyword |
| ses.connection.src_mac | The MAC address of the device that initiated the network connection. | keyword |
| ses.connection.src_name | The host name of the device that initiated the network connection. | keyword |
| ses.connection.src_port | The port number of the source device. | long |
| ses.connection.src_service | The source network connection service name. | keyword |
| ses.connection.svc_name | The service name as defined by the Internet Assigned Numbers Authority (IANA). See Service Name and Transport Protocol Port Number Registry. | keyword |
| ses.connection.tcp_flags | The network connection TCP header flags (i.e., control bits). | long |
| ses.connection.tls.cipher | The encryption algorithm. | keyword |
| ses.connection.tls.cipher_size | Cipher size of the OpenSSL cipher suite negotiated for the client or server connection. | long |
| ses.connection.tls.cipher_strength | Strength of the OpenSSL cipher suite negotiated for the client or server connection. | long |
| ses.connection.tls.client_certificate.end_time | The time at which the certificate becomes invalid. | date |
| ses.connection.tls.client_certificate.is_valid | The indication of whether the certificate is valid. | boolean |
| ses.connection.tls.client_certificate.issuer_name | The certificate issuer name. | keyword |
| ses.connection.tls.client_certificate.issuer_organization | The certificate issuer organization. | keyword |
| ses.connection.tls.client_certificate.serial | The certificate serial number. | keyword |
| ses.connection.tls.client_certificate.signature_statuses | The array of signature statuses. | keyword |
| ses.connection.tls.client_certificate.start_time | The time at which the certificate becomes valid. | date |
| ses.connection.tls.client_certificate.subject_city | The certificate subject city. | keyword |
| ses.connection.tls.client_certificate.subject_country | The certificate subject country. | keyword |
| ses.connection.tls.client_certificate.subject_email | The certificate subject email. | keyword |
| ses.connection.tls.client_certificate.subject_name | The certificate subject name. | keyword |
| ses.connection.tls.client_certificate.subject_org_unit | The certificate subject organizational unit. | keyword |
| ses.connection.tls.client_certificate.subject_organization | The certificate subject organization. | keyword |
| ses.connection.tls.client_certificate.subject_state | The certificate subject state. | keyword |
| ses.connection.tls.client_certificate.subject_street | The certificate subject street. | keyword |
| ses.connection.tls.client_certificate.version | The certificate version. | keyword |
| ses.connection.tls.is_advertised | The indication of whether the protocol is advertised by the server. | boolean |
| ses.connection.tls.is_used | The indication of whether the TLS is used. | boolean |
| ses.connection.tls.issuer_keyring | Issuer for forged certificates. | keyword |
| ses.connection.tls.issuer_keyring_alias | Key alias name in HSM issuer for forged certificates. | keyword |
| ses.connection.tls.key_length | The length of the encryption key. | long |
| ses.connection.tls.ocsp_status_detail | Errors observed during OCSP check of server certificate. | keyword |
| ses.connection.tls.server_certificate.end_time | The time at which the certificate becomes invalid. | date |
| ses.connection.tls.server_certificate.is_valid | The indication of whether the certificate is valid. | boolean |
| ses.connection.tls.server_certificate.issuer_name | The certificate issuer name. | keyword |
| ses.connection.tls.server_certificate.issuer_organization | The certificate issuer organization. | keyword |
| ses.connection.tls.server_certificate.serial | The certificate serial number. | keyword |
| ses.connection.tls.server_certificate.signature_statuses | The array of signature statuses. | keyword |
| ses.connection.tls.server_certificate.start_time | The time at which the certificate becomes valid. | date |
| ses.connection.tls.server_certificate.subject_city | The certificate subject city. | keyword |
| ses.connection.tls.server_certificate.subject_country | The certificate subject country. | keyword |
| ses.connection.tls.server_certificate.subject_email | The certificate subject email. | keyword |
| ses.connection.tls.server_certificate.subject_name | The certificate subject name. | keyword |
| ses.connection.tls.server_certificate.subject_org_unit | The certificate subject organizational unit. | keyword |
| ses.connection.tls.server_certificate.subject_organization | The certificate subject organization. | keyword |
| ses.connection.tls.server_certificate.subject_state | The certificate subject state. | keyword |
| ses.connection.tls.server_certificate.subject_street | The certificate subject street. | keyword |
| ses.connection.tls.server_certificate.version | The certificate version. | keyword |
| ses.connection.tls.tls_policy_id | The Transport Layer Security (TLS) policy. | keyword |
| ses.connection.tls.version | The protocol version. | keyword |
| ses.connection.uid | The unique identifier of the connection. | keyword |
| ses.connection.url.categories | The array of URL categories. | keyword |
| ses.connection.url.category_ids | The array of URL categories. | keyword |
| ses.connection.url.extension | Document extension from the original URL requested. | keyword |
| ses.connection.url.host | The URL host as extracted from the URL. | keyword |
| ses.connection.url.method | The HTTP method used in the URL request. | keyword |
| ses.connection.url.parent_categories | The array of parent URL categories. | keyword |
| ses.connection.url.path | The URL path as extracted from the URL. | keyword |
| ses.connection.url.port | The URL port. | long |
| ses.connection.url.provider | The origin of the reputation and category information. | keyword |
| ses.connection.url.query | The query portion of the URL. | keyword |
| ses.connection.url.referrer | The address accessed prior to this one. | keyword |
| ses.connection.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.connection.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.connection.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.connection.url.scheme | The scheme portion of the URL. | keyword |
| ses.connection.url.text | The URL. | keyword |
| ses.connection_ref_uid | The reference to the network connection object that pertains to the event. | keyword |
| ses.container.host_name | The container host name. | keyword |
| ses.container.image_name | The container image name. | keyword |
| ses.container.image_uid | The container unique image identifier. | keyword |
| ses.container.name | The container instance name. | keyword |
| ses.container.networks.bssid | The Basic Service Set Identifier (BSSID). | keyword |
| ses.container.networks.gateway_ip | The gateway IP address. | ip |
| ses.container.networks.gateway_mac | The gateway media access control (MAC) address. | keyword |
| ses.container.networks.ipv4 | The IPv4 address that is associated with the network interface. | ip |
| ses.container.networks.ipv6 | The IPv6 address that is associated with the network interface. | ip |
| ses.container.networks.is_public | The indication of whether the network interface is a public IP address. | boolean |
| ses.container.networks.mac | The MAC address that is associated with the network interface. | keyword |
| ses.container.networks.rep_score_id | The reputation of the network. | keyword |
| ses.container.networks.ssid | The Service Set Identifier (SSID). | keyword |
| ses.container.networks.type_id | The type of network. | keyword |
| ses.container.os_name | The container operating system name. | keyword |
| ses.container.uid | The container unique identifier. | keyword |
| ses.content_type_id | The type of the content to which the update pertains. | keyword |
| ses.content_ver | The version of the detection engine or signature content. | keyword |
| ses.correlation_uid | The unique identifier used to correlate events. | keyword |
| ses.count | For aggregated events, the number of times that the event occurred during the Device Time to Device End Time period. | long |
| ses.create_mask | The Windows setting needed when creating a file. | long |
| ses.create_mask_id | The Windows create file flag, applicable to System Activity File Create event. | keyword |
| ses.created | The time that the incident was created. | date |
| ses.creator | The name of the user who created the incident. | keyword |
| ses.curr_location.city | The name of the city. | keyword |
| ses.curr_location.continent | The name of the continent. | keyword |
| ses.curr_location.coordinates | A two-element array, containing a longitude/latitude pair. The format conforms with GeoJSON. | float |
| ses.curr_location.country | The ISO 3166-1 Alpha-2 country code. For the complete list of country codes see ISO 3166-1 alpha-2 codes.Note: The two letter country code should be capitalized. | keyword |
| ses.curr_location.desc | The description of the location. | keyword |
| ses.curr_location.isp | The name of the Internet Service Provider (ISP). | keyword |
| ses.curr_location.on_premises | The indication of whether the location is on premises. | boolean |
| ses.curr_location.region | The alphanumeric code that identifies the principal subdivision (e.g. province or state) of the country. Region codes are defined at ISO 3166-2 and have a limit of three characters. | keyword |
| ses.curr_security_level_id | The current security level of the entity. | keyword |
| ses.curr_security_level_value | The current security level of the entity in keyword. | keyword |
| ses.curr_security_state_ids | The type of the operating system. | keyword |
| ses.curr_ver | The updated version of the code, content, configuration or policy. | keyword |
| ses.customer_registry_uid | The unique Symantec customer registry identifier. | keyword |
| ses.customer_uid | The unique customer identifier. | keyword |
| ses.cve.desc | The description that pertains to the CVE. | keyword |
| ses.cve.name | The name of the CVE. | keyword |
| ses.cve.published | The date and time the CVE Record was first published in the CVE List. | date |
| ses.cve.reference_url | The URL associated with the CVE. | keyword |
| ses.cve.requires_device | True if there is a device associated with the CVE. | boolean |
| ses.cve.score | A CVE score used for prioritizing the severity of the vulnerability. | float |
| ses.cve.severity_id | The severity of the event. | keyword |
| ses.cve.title | The title associated with the CVE. | keyword |
| ses.cve.uid | The unique CVE identifier that this record pertains to. | keyword |
| ses.cvssv2.access_complexity_id | The access complexity Common Vulnerability Scoring System (CVSS) metric. | keyword |
| ses.cvssv2.attack_vector_id | The attack vector Common Vulnerability Scoring System (CVSS) metric. | keyword |
| ses.cvssv2.authentication_id | The authentication Common Vulnerability Scoring System (CVSS) metric. | keyword |
| ses.cvssv2.availability_impact_id | The availability impact Common Vulnerability Scoring System (CVSS) metric. | keyword |
| ses.cvssv2.confidentiality_impact_id | The confidentiality impact Common Vulnerability Scoring System (CVSS) metric. | keyword |
| ses.cvssv2.integrity_impact_id | The integrity impact Common Vulnerability Scoring System (CVSS) metric. | keyword |
| ses.cvssv2.risk | The Common Vulnerability Scoring System (CVSS) calculated risk. | float |
| ses.cybox.domains | The array of CybOXTM fully qualified domain names (FQDN). | keyword |
| ses.cybox.emails.direction_id | The direction of the email relative to the scanning host or organization. | keyword |
| ses.cybox.emails.header_from | The email header From values, as defined by RFC 5322. | keyword |
| ses.cybox.emails.header_message_id | The email header Message-Id value, as defined by RFC 5322. | keyword |
| ses.cybox.emails.header_reply_to | The email header Reply-To values, as defined by RFC 5322. | keyword |
| ses.cybox.emails.header_subject | The email header Subject value, as defined by RFC 5322. | keyword |
| ses.cybox.emails.header_to | The email header To values, as defined by RFC 5322. | keyword |
| ses.cybox.emails.sender_ip | The IP address of the sender, in either IPv4 or IPv6 format. | ip |
| ses.cybox.emails.size | The size in bytes of the email, including attachments. | long |
| ses.cybox.emails.smtp_from | The value of the SMTP MAIL FROM command. | keyword |
| ses.cybox.emails.smtp_hello | The value of the SMTP HELO or EHLO command. | keyword |
| ses.cybox.emails.smtp_to | The value of the SMTP envelope RCPT TO command. | keyword |
| ses.cybox.files.accessed | The time that the file was last accessed. | date |
| ses.cybox.files.accessor | The name of the user who last accessed the object. | keyword |
| ses.cybox.files.attribute_ids | The array of file attributes. | keyword |
| ses.cybox.files.attributes | The bitmask value that represents the file attributes. | long |
| ses.cybox.files.company_name | The name of the company that published the file. | keyword |
| ses.cybox.files.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.cybox.files.content_type.family_id | The top level file classification. | keyword |
| ses.cybox.files.content_type.subtype | The specific format for the type of data. | keyword |
| ses.cybox.files.content_type.type_id | The general type of a file. | keyword |
| ses.cybox.files.created | The time that the file was created. | date |
| ses.cybox.files.creator | The name of the user who created the file. | keyword |
| ses.cybox.files.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.cybox.files.desc | The description of the file, as returned by file system. | keyword |
| ses.cybox.files.folder | The parent folder in which the file resides. | keyword |
| ses.cybox.files.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.cybox.files.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.cybox.files.md5 | The MD5 checksum of the object content. | keyword |
| ses.cybox.files.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.cybox.files.modified | The time when the file was last modified. | date |
| ses.cybox.files.modifier | The name of the user who last modified the file. | keyword |
| ses.cybox.files.name | The name of the file. | keyword |
| ses.cybox.files.normalized_path | The CSIDL normalized path name. | keyword |
| ses.cybox.files.original_name | The original name of the file. | keyword |
| ses.cybox.files.owner | The owner of the file. | keyword |
| ses.cybox.files.parent_name | The name of the file that contains this file. | keyword |
| ses.cybox.files.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.cybox.files.path | The full path to the file. | keyword |
| ses.cybox.files.product_name | The name of the product that includes the file. | keyword |
| ses.cybox.files.product_path | The path to the product that includes the file. | keyword |
| ses.cybox.files.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.cybox.files.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.cybox.files.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.cybox.files.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.cybox.files.rep_score | The reputation score of the file. | long |
| ses.cybox.files.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.cybox.files.security_descriptor | The object security descriptor. | keyword |
| ses.cybox.files.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.cybox.files.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.cybox.files.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.cybox.files.signature_created_date | The date and time when the signature was created. | date |
| ses.cybox.files.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.cybox.files.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.cybox.files.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.cybox.files.signature_issuer | The issuer of the object signature. | keyword |
| ses.cybox.files.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.cybox.files.signature_serial_number | The object serial number. | keyword |
| ses.cybox.files.signature_value | The digital signature bitmask. | long |
| ses.cybox.files.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.cybox.files.size | The size of the object, in bytes. | long |
| ses.cybox.files.size_compressed | The compressed size of the object, in bytes. | long |
| ses.cybox.files.src_ip | The IP address of the host where the file resides. | ip |
| ses.cybox.files.src_name | The name of the host where the file resides. | keyword |
| ses.cybox.files.type_id | The file type. | keyword |
| ses.cybox.files.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.cybox.files.url.categories | The array of URL categories. | keyword |
| ses.cybox.files.url.category_ids | The array of URL categories. | keyword |
| ses.cybox.files.url.extension | Document extension from the original URL requested. | keyword |
| ses.cybox.files.url.host | The URL host as extracted from the URL. | keyword |
| ses.cybox.files.url.method | The HTTP method used in the URL request. | keyword |
| ses.cybox.files.url.parent_categories | The array of parent URL categories. | keyword |
| ses.cybox.files.url.path | The URL path as extracted from the URL. | keyword |
| ses.cybox.files.url.port | The URL port. | long |
| ses.cybox.files.url.provider | The origin of the reputation and category information. | keyword |
| ses.cybox.files.url.query | The query portion of the URL. | keyword |
| ses.cybox.files.url.referrer | The address accessed prior to this one. | keyword |
| ses.cybox.files.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.cybox.files.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.cybox.files.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.cybox.files.url.scheme | The scheme portion of the URL. | keyword |
| ses.cybox.files.url.text | The URL. | keyword |
| ses.cybox.files.version | The file version. | keyword |
| ses.cybox.files.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.cybox.hostnames | The array of CybOXTM hostnames. | keyword |
| ses.cybox.icap_reqmod.metadata | ICAP request modification header details. | flattened |
| ses.cybox.icap_reqmod.service | Name of the ICAP service. | keyword |
| ses.cybox.icap_reqmod.status | ICAP request modification status. | keyword |
| ses.cybox.icap_reqmod.status_detail | ICAP request modification error details. | keyword |
| ses.cybox.icap_respmod.metadata | ICAP response modification header details. | flattened |
| ses.cybox.icap_respmod.service | Name of the ICAP service. | keyword |
| ses.cybox.icap_respmod.status | ICAP response modification status. | keyword |
| ses.cybox.icap_respmod.status_detail | ICAP response modification error details. | keyword |
| ses.cybox.ipv4s | The array of CybOXTM IPv4 addresses. | ip |
| ses.cybox.ipv6s | The array of CybOXTM IPv6 addresses. | ip |
| ses.cybox.macs | The array of CybOXTM MAC addresses. | keyword |
| ses.cybox.urls.categories | The array of URL categories. | keyword |
| ses.cybox.urls.category_ids | The array of URL categories. | keyword |
| ses.cybox.urls.extension | Document extension from the original URL requested. | keyword |
| ses.cybox.urls.host | The URL host as extracted from the URL. | keyword |
| ses.cybox.urls.method | The HTTP method used in the URL request. | keyword |
| ses.cybox.urls.parent_categories | The array of parent URL categories. | keyword |
| ses.cybox.urls.path | The URL path as extracted from the URL. | keyword |
| ses.cybox.urls.port | The URL port. | long |
| ses.cybox.urls.provider | The origin of the reputation and category information. | keyword |
| ses.cybox.urls.query | The query portion of the URL. | keyword |
| ses.cybox.urls.referrer | The address accessed prior to this one. | keyword |
| ses.cybox.urls.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.cybox.urls.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.cybox.urls.rep_score_id | The reputation score of the URL. | keyword |
| ses.cybox.urls.scheme | The scheme portion of the URL. | keyword |
| ses.cybox.urls.text | The URL. | keyword |
| ses.data | The data that was scanned. | keyword |
| ses.data_size | The size of the data prior to truncation. | long |
| ses.days_left | The number of days left before license expiration. | long |
| ses.detection_type | The incident detection type. | keyword |
| ses.detection_uid | The associated unique detection event identifier. | keyword |
| ses.device_alias_name | The alternate device name, ordinarily as assigned by an administrator. | keyword |
| ses.device_cap | A short description or caption of the device. | keyword |
| ses.device_cloud_vm.autoscale_uid | The unique identifier of the cloud autoscale configuration. | keyword |
| ses.device_cloud_vm.dc_region | The data center region, as defined by the cloud vendor. | keyword |
| ses.device_cloud_vm.instance_uid | The unique identifier of the cloud hosted virtual machine instance. | keyword |
| ses.device_cloud_vm.subnet_uid | The unique identifier of the virtual subnet. | keyword |
| ses.device_cloud_vm.vpc_uid | The unique identifier of the Virtual Private Cloud (VPC). | keyword |
| ses.device_desc | The description of the device, ordinarily as reported by the operating system. | keyword |
| ses.device_domain | The network domain where the device resides. | keyword |
| ses.device_domain_uid | The unique identifier of the domain where the device resides. | keyword |
| ses.device_end_time | The time of the last aggregated event. | date |
| ses.device_gateway | The gateway IP address. | ip |
| ses.device_group | The full path of the group to which the device belongs. | keyword |
| ses.device_group_name | The name of the leaf group to which the device belongs. | keyword |
| ses.device_hw_bios_date | The BIOS date. | keyword |
| ses.device_hw_bios_manufacturer | The BIOS manufacturer. | keyword |
| ses.device_hw_bios_ver | The BIOS version. | keyword |
| ses.device_hw_cpu_type | The processor type. | keyword |
| ses.device_imei | The International Mobile Station Equipment Identifier that is associated with the device. | keyword |
| ses.device_ip | The IP address that pertains to the event, in either IPv4 or IPv6 format. | ip |
| ses.device_is_compliant | The event occurred on a compliant device. | boolean |
| ses.device_is_personal | The event occurred on a personal device. | boolean |
| ses.device_is_trusted | The event occurred on a trusted device. | boolean |
| ses.device_is_unmanaged | The event occurred on an unmanaged device. | boolean |
| ses.device_location.city | The name of the city. | keyword |
| ses.device_location.continent | The name of the continent. | keyword |
| ses.device_location.coordinates | A two-element array, containing a longitude/latitude pair. The format conforms with GeoJSON. | float |
| ses.device_location.country | The ISO 3166-1 Alpha-2 country code. For the complete list of country codes see ISO 3166-1 alpha-2 codes. | keyword |
| ses.device_location.desc | The description of the location. | keyword |
| ses.device_location.isp | The name of the Internet Service Provider (ISP). | keyword |
| ses.device_location.on_premises | The indication of whether the location is on premises. | boolean |
| ses.device_location.region | The alphanumeric code that identifies the principal subdivision (e.g. province or state) of the country. Region codes are defined at ISO 3166-2 and have a limit of three characters. | keyword |
| ses.device_mac | The Media Access Control (MAC) address that is associated with the device. | keyword |
| ses.device_name | The name of the device originating the event. | keyword |
| ses.device_name_md5 | The MD5 hash of the device name.Note: The hash must be of the lower-case device name. | keyword |
| ses.device_networks.bssid | The Basic Service Set Identifier (BSSID). | keyword |
| ses.device_networks.gateway_ip | The gateway IP address. | ip |
| ses.device_networks.gateway_mac | The gateway media access control (MAC) address. | keyword |
| ses.device_networks.ipv4 | The IPv4 address that is associated with the network interface. | ip |
| ses.device_networks.ipv6 | The IPv6 address that is associated with the network interface. | ip |
| ses.device_networks.is_public | The indication of whether the network interface is a public IP address. | boolean |
| ses.device_networks.mac | The MAC address that is associated with the network interface. | keyword |
| ses.device_networks.rep_score_id | The reputation of the network. | keyword |
| ses.device_networks.ssid | The Service Set Identifier (SSID). | keyword |
| ses.device_networks.type_id | The type of network. | keyword |
| ses.device_org_unit | The name of the org unit to which the device belongs. | keyword |
| ses.device_os_bits | The number of processor bits. | long |
| ses.device_os_build | The operating system build number. | keyword |
| ses.device_os_country | The operating system country code as defined by the ISO 3166-1 standard (Alpha-2 code). For the complete list of country codes, see ISO 3166-1 alpha-2 codes. | keyword |
| ses.device_os_edition | The operating system edition. | keyword |
| ses.device_os_lang | The lowercase two-letter ISO language code as defined by ISO 639-1. | keyword |
| ses.device_os_name | The name of the operating system running on the device from which the event originated. | keyword |
| ses.device_os_sp_name | The name of the latest Service Pack. | keyword |
| ses.device_os_sp_ver | The version number of the latest Service Pack. | keyword |
| ses.device_os_type_id | The type of the operating system. | keyword |
| ses.device_os_type_value | The type value of the operating system. | keyword |
| ses.device_os_ver | The version of the OS running on the device that originated the event. | keyword |
| ses.device_proxy_ip | The proxy IP address. | ip |
| ses.device_proxy_name | The proxy host name. | keyword |
| ses.device_public_ip | The public IP address. | ip |
| ses.device_ref_uid | The unique reference identifier of the device. | keyword |
| ses.device_site | The name of the site to which the device belongs. | keyword |
| ses.device_subnet | The subnet IP address. | ip |
| ses.device_time | The time that the event occurred at the device. | date |
| ses.device_type | The type of device originating the event. | keyword |
| ses.device_uid | The unique identifier of the device. | keyword |
| ses.device_vhost | The device virtual host type string. | keyword |
| ses.device_vhost_id | The device virtual host type. | keyword |
| ses.directory.accessed | The time that the file was last accessed. | date |
| ses.directory.accessor | The name of the user who last accessed the object. | keyword |
| ses.directory.attribute_ids | The array of file attributes. | keyword |
| ses.directory.attributes | The bitmask value that represents the file attributes. | long |
| ses.directory.company_name | The name of the company that published the file. | keyword |
| ses.directory.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.directory.content_type.family_id | The top level file classification. | keyword |
| ses.directory.content_type.subtype | The specific format for the type of data. | keyword |
| ses.directory.content_type.type_id | The general type of a file. | keyword |
| ses.directory.created | The time that the file was created. | date |
| ses.directory.creator | The name of the user who created the file. | keyword |
| ses.directory.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.directory.desc | The description of the file, as returned by file system. | keyword |
| ses.directory.folder | The parent folder in which the file resides. | keyword |
| ses.directory.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.directory.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.directory.md5 | The MD5 checksum of the object content. | keyword |
| ses.directory.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.directory.modified | The time when the file was last modified. | date |
| ses.directory.modifier | The name of the user who last modified the file. | keyword |
| ses.directory.name | The name of the file. | keyword |
| ses.directory.normalized_path | The CSIDL normalized path name. | keyword |
| ses.directory.original_name | The original name of the file. | keyword |
| ses.directory.owner | The owner of the file. | keyword |
| ses.directory.parent_name | The name of the file that contains this file. | keyword |
| ses.directory.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.directory.path | The full path to the file. | keyword |
| ses.directory.product_name | The name of the product that includes the file. | keyword |
| ses.directory.product_path | The path to the product that includes the file. | keyword |
| ses.directory.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.directory.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.directory.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.directory.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.directory.rep_score | The reputation score of the file. | long |
| ses.directory.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.directory.security_descriptor | The object security descriptor. | keyword |
| ses.directory.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.directory.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.directory.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.directory.signature_created_date | The date and time when the signature was created. | date |
| ses.directory.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.directory.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.directory.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.directory.signature_issuer | The issuer of the object signature. | keyword |
| ses.directory.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.directory.signature_serial_number | The object serial number. | keyword |
| ses.directory.signature_value | The digital signature bitmask. | long |
| ses.directory.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.directory.size | The size of the object, in bytes. | long |
| ses.directory.size_compressed | The compressed size of the object, in bytes. | long |
| ses.directory.src_ip | The IP address of the host where the file resides. | ip |
| ses.directory.src_name | The name of the host where the file resides. | keyword |
| ses.directory.type_id | The file type. | keyword |
| ses.directory.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.directory.url.categories | The array of URL categories. | keyword |
| ses.directory.url.category_ids | The array of URL categories. | keyword |
| ses.directory.url.extension | Document extension from the original URL requested. | keyword |
| ses.directory.url.host | The URL host as extracted from the URL. | keyword |
| ses.directory.url.method | The HTTP method used in the URL request. | keyword |
| ses.directory.url.parent_categories | The array of parent URL categories. | keyword |
| ses.directory.url.path | The URL path as extracted from the URL. | keyword |
| ses.directory.url.port | The URL port. | long |
| ses.directory.url.provider | The origin of the reputation and category information. | keyword |
| ses.directory.url.query | The query portion of the URL. | keyword |
| ses.directory.url.referrer | The address accessed prior to this one. | keyword |
| ses.directory.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.directory.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.directory.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.directory.url.scheme | The scheme portion of the URL. | keyword |
| ses.directory.url.text | The URL. | keyword |
| ses.directory.version | The file version. | keyword |
| ses.directory.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.directory_result.accessed | The time that the file was last accessed. | date |
| ses.directory_result.accessor | The name of the user who last accessed the object. | keyword |
| ses.directory_result.attribute_ids | The array of file attributes. | keyword |
| ses.directory_result.attributes | The bitmask value that represents the file attributes. | long |
| ses.directory_result.company_name | The name of the company that published the file. | keyword |
| ses.directory_result.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.directory_result.content_type.family_id | The top level file classification. | keyword |
| ses.directory_result.content_type.subtype | The specific format for the type of data. | keyword |
| ses.directory_result.content_type.type_id | The general type of a file. | keyword |
| ses.directory_result.created | The time that the file was created. | date |
| ses.directory_result.creator | The name of the user who created the file. | keyword |
| ses.directory_result.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.directory_result.desc | The description of the file, as returned by file system. | keyword |
| ses.directory_result.folder | The parent folder in which the file resides. | keyword |
| ses.directory_result.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.directory_result.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.directory_result.md5 | The MD5 checksum of the object content. | keyword |
| ses.directory_result.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.directory_result.modified | The time when the file was last modified. | date |
| ses.directory_result.modifier | The name of the user who last modified the file. | keyword |
| ses.directory_result.name | The name of the file. | keyword |
| ses.directory_result.normalized_path | The CSIDL normalized path name. | keyword |
| ses.directory_result.original_name | The original name of the file. | keyword |
| ses.directory_result.owner | The owner of the file. | keyword |
| ses.directory_result.parent_name | The name of the file that contains this file. | keyword |
| ses.directory_result.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.directory_result.path | The full path to the file. | keyword |
| ses.directory_result.product_name | The name of the product that includes the file. | keyword |
| ses.directory_result.product_path | The path to the product that includes the file. | keyword |
| ses.directory_result.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.directory_result.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.directory_result.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.directory_result.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.directory_result.rep_score | The reputation score of the file. | long |
| ses.directory_result.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.directory_result.security_descriptor | The object security descriptor. | keyword |
| ses.directory_result.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.directory_result.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.directory_result.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.directory_result.signature_created_date | The date and time when the signature was created. | date |
| ses.directory_result.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.directory_result.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.directory_result.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.directory_result.signature_issuer | The issuer of the object signature. | keyword |
| ses.directory_result.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.directory_result.signature_serial_number | The object serial number. | keyword |
| ses.directory_result.signature_value | The digital signature bitmask. | long |
| ses.directory_result.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.directory_result.size | The size of the object, in bytes. | long |
| ses.directory_result.size_compressed | The compressed size of the object, in bytes. | long |
| ses.directory_result.src_ip | The IP address of the host where the file resides. | ip |
| ses.directory_result.src_name | The name of the host where the file resides. | keyword |
| ses.directory_result.type_id | The file type. | keyword |
| ses.directory_result.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.directory_result.url.categories | The array of URL categories. | keyword |
| ses.directory_result.url.category_ids | The array of URL categories. | keyword |
| ses.directory_result.url.extension | Document extension from the original URL requested. | keyword |
| ses.directory_result.url.host | The URL host as extracted from the URL. | keyword |
| ses.directory_result.url.method | The HTTP method used in the URL request. | keyword |
| ses.directory_result.url.parent_categories | The array of parent URL categories. | keyword |
| ses.directory_result.url.path | The URL path as extracted from the URL. | keyword |
| ses.directory_result.url.port | The URL port. | long |
| ses.directory_result.url.provider | The origin of the reputation and category information. | keyword |
| ses.directory_result.url.query | The query portion of the URL. | keyword |
| ses.directory_result.url.referrer | The address accessed prior to this one. | keyword |
| ses.directory_result.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.directory_result.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.directory_result.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.directory_result.url.scheme | The scheme portion of the URL. | keyword |
| ses.directory_result.url.text | The URL. | keyword |
| ses.directory_result.version | The file version. | keyword |
| ses.directory_result.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.displayed_text | The information that is displayed to the user that describes the impact of a client side override action. | keyword |
| ses.domain_uid | The unique domain identifier. | keyword |
| ses.dst_endpoint_app.groups | Reports the group of an application. | keyword |
| ses.dst_endpoint_app.name | Reports the application name. | keyword |
| ses.dst_endpoint_app.operation | Reports the operation (action) of an application. | keyword |
| ses.duration | The duration of the scan (seconds). | long |
| ses.email.direction_id | The direction of the email relative to the scanning host or organization. | keyword |
| ses.email.direction_value | The direction value of the email relative to the scanning host or organization. | keyword |
| ses.email.header_from | The email header From values, as defined by RFC 5322. | keyword |
| ses.email.header_message_id | The email header Message-Id value, as defined by RFC 5322. | keyword |
| ses.email.header_reply_to | The email header Reply-To values, as defined by RFC 5322. | keyword |
| ses.email.header_subject | The email header Subject value, as defined by RFC 5322. | keyword |
| ses.email.header_to | The email header To values, as defined by RFC 5322. | keyword |
| ses.email.sender_ip | The IP address of the sender, in either IPv4 or IPv6 format. | ip |
| ses.email.size | The size in bytes of the email, including attachments. | long |
| ses.email.smtp_from | The value of the SMTP MAIL FROM command. | keyword |
| ses.email.smtp_hello | The value of the SMTP HELO or EHLO command. | keyword |
| ses.email.smtp_to | The value of the SMTP envelope RCPT TO command. | keyword |
| ses.email_auth.dkim_domain | The DomainKeys Identified Mail (DKIM) signing domain of the email. | keyword |
| ses.email_auth.dkim_id | The DomainKeys Identified Mail (DKIM) status of the email. | keyword |
| ses.email_auth.dmarc_id | The Domain-based Message Authentication, Reporting and Conformance (DMARC) status of the email. | keyword |
| ses.email_auth.dmarc_override | The Domain-based Message Authentication, Reporting and Conformance (DMARC) override action. | keyword |
| ses.email_auth.dmarc_policy_id | The Domain-based Message Authentication, Reporting and Conformance (DMARC) policy.. | keyword |
| ses.email_auth.raw_header | The email authentication header. | keyword |
| ses.email_auth.spf_id | The Sender Policy Framework (SPF) status of the email. | keyword |
| ses.email_uid | The unique identifier of the email, used to correlate related email detection and activity events. | keyword |
| ses.end_time | For aggregate events, the Device End Time adjusted to the server clock. | date |
| ses.entity.data | The managed entity content as a JSON object. | flattened |
| ses.entity.name | The name of the managed entity. | keyword |
| ses.entity.type | The managed entity type. | keyword |
| ses.entity.uid | A unique identifier of the managed entity. | keyword |
| ses.entity.version | The version of the managed entity. | keyword |
| ses.entity_result.data | The managed entity content as a JSON object. | flattened |
| ses.entity_result.name | The name of the managed entity. | keyword |
| ses.entity_result.type | The managed entity type. | keyword |
| ses.entity_result.uid | A unique identifier of the managed entity. | keyword |
| ses.entity_result.version | The version of the managed entity. | keyword |
| ses.environment_name | The environment in which the event occurred such as Production, Test, Development, Load. | keyword |
| ses.environment_uid | The unique identifier of the provisioned environment. | keyword |
| ses.event_duration | Time taken (in milliseconds) to process the request (from the first byte of client request data received by the proxy to the last byte sent by the proxy to the client including all of the delays by ICAP and so on). | long |
| ses.event_id | The event ID identifies the event's semantics, structure and outcome. | keyword |
| ses.events | The additional events that pertain to the event or incident. | flattened |
| ses.feature_name | The name of the feature originating the event. Note: The Feature Name is ordinarily defined by the product SKU, but it could be any other name that identifies the software component originating the event. | keyword |
| ses.feature_path | The path of the feature originating the event. | keyword |
| ses.feature_type | The type of feature. | keyword |
| ses.feature_uid | The unique identifier of the feature originating the event. | keyword |
| ses.feature_ver | The version of the feature originating the event. | keyword |
| ses.file.accessed | The time that the file was last accessed. | date |
| ses.file.accessor | The name of the user who last accessed the object. | keyword |
| ses.file.attribute_ids | The array of file attributes. | keyword |
| ses.file.attributes | The bitmask value that represents the file attributes. | long |
| ses.file.company_name | The name of the company that published the file. | keyword |
| ses.file.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.file.content_type.family_id | The top level file classification. | keyword |
| ses.file.content_type.subtype | The specific format for the type of data. | keyword |
| ses.file.content_type.type_id | The general type of a file. | keyword |
| ses.file.created | The time that the file was created. | date |
| ses.file.creator | The name of the user who created the file. | keyword |
| ses.file.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.file.desc | The description of the file, as returned by file system. | keyword |
| ses.file.folder | The parent folder in which the file resides. | keyword |
| ses.file.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.file.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.file.md5 | The MD5 checksum of the object content. | keyword |
| ses.file.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.file.modified | The time when the file was last modified. | date |
| ses.file.modifier | The name of the user who last modified the file. | keyword |
| ses.file.name | The name of the file. | keyword |
| ses.file.normalized_path | The CSIDL normalized path name. | keyword |
| ses.file.original_name | The original name of the file. | keyword |
| ses.file.owner | The owner of the file. | keyword |
| ses.file.parent_name | The name of the file that contains this file. | keyword |
| ses.file.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.file.path | The full path to the file. | keyword |
| ses.file.product_name | The name of the product that includes the file. | keyword |
| ses.file.product_path | The path to the product that includes the file. | keyword |
| ses.file.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.file.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.file.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.file.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.file.rep_score | The reputation score of the file. | long |
| ses.file.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.file.security_descriptor | The object security descriptor. | keyword |
| ses.file.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.file.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.file.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.file.signature_created_date | The date and time when the signature was created. | date |
| ses.file.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.file.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.file.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.file.signature_issuer | The issuer of the object signature. | keyword |
| ses.file.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.file.signature_serial_number | The object serial number. | keyword |
| ses.file.signature_value | The digital signature bitmask. | long |
| ses.file.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.file.size | The size of the object, in bytes. | long |
| ses.file.size_compressed | The compressed size of the object, in bytes. | long |
| ses.file.src_ip | The IP address of the host where the file resides. | ip |
| ses.file.src_name | The name of the host where the file resides. | keyword |
| ses.file.type_id | The file type. | keyword |
| ses.file.type_value | The file type value. | keyword |
| ses.file.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.file.url.categories | The array of URL categories. | keyword |
| ses.file.url.category_ids | The array of URL categories. | keyword |
| ses.file.url.extension | Document extension from the original URL requested. | keyword |
| ses.file.url.host | The URL host as extracted from the URL. | keyword |
| ses.file.url.method | The HTTP method used in the URL request. | keyword |
| ses.file.url.parent_categories | The array of parent URL categories. | keyword |
| ses.file.url.path | The URL path as extracted from the URL. | keyword |
| ses.file.url.port | The URL port. | long |
| ses.file.url.provider | The origin of the reputation and category information. | keyword |
| ses.file.url.query | The query portion of the URL. | keyword |
| ses.file.url.referrer | The address accessed prior to this one. | keyword |
| ses.file.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.file.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.file.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.file.url.scheme | The scheme portion of the URL. | keyword |
| ses.file.url.text | The URL. | keyword |
| ses.file.version | The file version. | keyword |
| ses.file.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.file_diff | File content differences used for change detection. | keyword |
| ses.file_result.accessed | The time that the file was last accessed. | date |
| ses.file_result.accessor | The name of the user who last accessed the object. | keyword |
| ses.file_result.attribute_ids | The array of file attributes. | keyword |
| ses.file_result.attributes | The bitmask value that represents the file attributes. | long |
| ses.file_result.company_name | The name of the company that published the file. | keyword |
| ses.file_result.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.file_result.content_type.family_id | The top level file classification. | keyword |
| ses.file_result.content_type.subtype | The specific format for the type of data. | keyword |
| ses.file_result.content_type.type_id | The general type of a file. | keyword |
| ses.file_result.created | The time that the file was created. | date |
| ses.file_result.creator | The name of the user who created the file. | keyword |
| ses.file_result.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.file_result.desc | The description of the file, as returned by file system. | keyword |
| ses.file_result.folder | The parent folder in which the file resides. | keyword |
| ses.file_result.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.file_result.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.file_result.md5 | The MD5 checksum of the object content. | keyword |
| ses.file_result.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.file_result.modified | The time when the file was last modified. | date |
| ses.file_result.modifier | The name of the user who last modified the file. | keyword |
| ses.file_result.name | The name of the file. | keyword |
| ses.file_result.normalized_path | The CSIDL normalized path name. | keyword |
| ses.file_result.original_name | The original name of the file. | keyword |
| ses.file_result.owner | The owner of the file. | keyword |
| ses.file_result.parent_name | The name of the file that contains this file. | keyword |
| ses.file_result.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.file_result.path | The full path to the file. | keyword |
| ses.file_result.product_name | The name of the product that includes the file. | keyword |
| ses.file_result.product_path | The path to the product that includes the file. | keyword |
| ses.file_result.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.file_result.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.file_result.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.file_result.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.file_result.rep_score | The reputation score of the file. | long |
| ses.file_result.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.file_result.security_descriptor | The object security descriptor. | keyword |
| ses.file_result.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.file_result.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.file_result.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.file_result.signature_created_date | The date and time when the signature was created. | date |
| ses.file_result.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.file_result.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.file_result.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.file_result.signature_issuer | The issuer of the object signature. | keyword |
| ses.file_result.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.file_result.signature_serial_number | The object serial number. | keyword |
| ses.file_result.signature_value | The digital signature bitmask. | long |
| ses.file_result.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.file_result.size | The size of the object, in bytes. | long |
| ses.file_result.size_compressed | The compressed size of the object, in bytes. | long |
| ses.file_result.src_ip | The IP address of the host where the file resides. | ip |
| ses.file_result.src_name | The name of the host where the file resides. | keyword |
| ses.file_result.type_id | The file type. | keyword |
| ses.file_result.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.file_result.url.categories | The array of URL categories. | keyword |
| ses.file_result.url.category_ids | The array of URL categories. | keyword |
| ses.file_result.url.extension | Document extension from the original URL requested. | keyword |
| ses.file_result.url.host | The URL host as extracted from the URL. | keyword |
| ses.file_result.url.method | The HTTP method used in the URL request. | keyword |
| ses.file_result.url.parent_categories | The array of parent URL categories. | keyword |
| ses.file_result.url.path | The URL path as extracted from the URL. | keyword |
| ses.file_result.url.port | The URL port. | long |
| ses.file_result.url.provider | The origin of the reputation and category information. | keyword |
| ses.file_result.url.query | The query portion of the URL. | keyword |
| ses.file_result.url.referrer | The address accessed prior to this one. | keyword |
| ses.file_result.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.file_result.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.file_result.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.file_result.url.scheme | The scheme portion of the URL. | keyword |
| ses.file_result.url.text | The URL. | keyword |
| ses.file_result.version | The file version. | keyword |
| ses.file_result.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.http_status | The HTTP status code returned to the client. | long |
| ses.id | The outcome of the event. | long |
| ses.impersonator_customer_uid | The unique customer identifier of the impersonating agent. | keyword |
| ses.impersonator_domain_uid | The unique domain identifier of the impersonating agent. | keyword |
| ses.impersonator_user_uid | The unique user identifier of the impersonating agent. | keyword |
| ses.incident_uid | The incident unique identifier. | keyword |
| ses.incident_url | The URL used to access the original incident. | keyword |
| ses.injection_type_id | The process injection method. | keyword |
| ses.interpreter | The script interpreter used. | keyword |
| ses.is_user_present | The indication of whether the user was logged on at event generation time. | boolean |
| ses.kernel.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.kernel.name | The name of the kernel resource. | keyword |
| ses.kernel.system_call | The system call that was invoked. | keyword |
| ses.kernel.type_id | The type of the kernel resource. | keyword |
| ses.kernel.type_value | The type value of the kernel resource. | keyword |
| ses.license.count | The number of seats. | long |
| ses.license.end_time | The time at which the license expires. | date |
| ses.license.name | The name of the license. | keyword |
| ses.license.start_time | The time at which the license becomes valid. | date |
| ses.license.type_id | The license type. | keyword |
| ses.license.uid | The unique identifier of the license. | keyword |
| ses.lineage | The lineage of the actor process. | keyword |
| ses.log_level | The log level as reported by the logger subsystem. | keyword |
| ses.log_name | The name of the database, index, or archive where the event was logged. | keyword |
| ses.log_time | The time that the system collected the event. | date |
| ses.logging_device_ip | The IP address of the device that logged the event. | ip |
| ses.logging_device_name | The name of the device that logged the event. | keyword |
| ses.logging_device_post_time | The time when the event was logged by the logging device. | date |
| ses.logging_device_ref_uid | The unique identifier of the device that collects logs from other devices. | keyword |
| ses.logon_type_id | The type of logon. | keyword |
| ses.message | The description of the event. | keyword |
| ses.message_code | The coded string representation of the message, ordinarily used for trouble shooting. | keyword |
| ses.message_id | The numeric representation of the message, ordinarily used for translation purposes. | keyword |
| ses.modified | The time that the incident was modified. | date |
| ses.modifier | The name of the user who modified the incident. | keyword |
| ses.module.accessed | The time that the file was last accessed. | date |
| ses.module.accessor | The name of the user who last accessed the object. | keyword |
| ses.module.attribute_ids | The array of file attributes. | keyword |
| ses.module.attributes | The bitmask value that represents the file attributes. | long |
| ses.module.base_address | The memory address where the module was loaded. | keyword |
| ses.module.company_name | The name of the company that published the file. | keyword |
| ses.module.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.module.content_type.family_id | The top level file classification. | keyword |
| ses.module.content_type.subtype | The specific format for the type of data. | keyword |
| ses.module.content_type.type_id | The general type of a file. | keyword |
| ses.module.created | The time that the module was created. | date |
| ses.module.creator | The name of the user who created the module. | keyword |
| ses.module.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.module.desc | The description of the file, as returned by file system. | keyword |
| ses.module.folder | The parent folder in which the file resides. | keyword |
| ses.module.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.module.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.module.load_type | The load type describes how the module was loaded in memory. | keyword |
| ses.module.load_type_id | The load type identifies how the module was loaded in memory. | keyword |
| ses.module.md5 | The MD5 checksum of the object content. | keyword |
| ses.module.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.module.modified | The time when the module was last modified. | date |
| ses.module.modifier | The name of the user who last modified the module. | keyword |
| ses.module.name | The name of the file. | keyword |
| ses.module.normalized_path | The CSIDL normalized path name. | keyword |
| ses.module.original_name | The original name of the file. | keyword |
| ses.module.owner | The owner of the file. | keyword |
| ses.module.parent_name | The name of the file that contains this file. | keyword |
| ses.module.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.module.path | The full path to the file. | keyword |
| ses.module.product_name | The name of the product that includes the file. | keyword |
| ses.module.product_path | The path to the product that includes the file. | keyword |
| ses.module.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.module.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.module.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.module.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.module.rep_score | The reputation score of the file. | long |
| ses.module.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.module.security_descriptor | The object security descriptor. | keyword |
| ses.module.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.module.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.module.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.module.signature_created_date | The date and time when the signature was created. | date |
| ses.module.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.module.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.module.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.module.signature_issuer | The issuer of the object signature. | keyword |
| ses.module.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.module.signature_serial_number | The object serial number. | keyword |
| ses.module.signature_value | The digital signature bitmask. | long |
| ses.module.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.module.size | The size of the object, in bytes. | long |
| ses.module.size_compressed | The compressed size of the object, in bytes. | long |
| ses.module.src_ip | The IP address of the host where the file resides. | ip |
| ses.module.src_name | The name of the host where the file resides. | keyword |
| ses.module.type_id | The file type. | keyword |
| ses.module.type_value | The file type value. | keyword |
| ses.module.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.module.url.categories | The array of URL categories. | keyword |
| ses.module.url.category_ids | The array of URL categories. | keyword |
| ses.module.url.extension | Document extension from the original URL requested. | keyword |
| ses.module.url.host | The URL host as extracted from the URL. | keyword |
| ses.module.url.method | The HTTP method used in the URL request. | keyword |
| ses.module.url.parent_categories | The array of parent URL categories. | keyword |
| ses.module.url.path | The URL path as extracted from the URL. | keyword |
| ses.module.url.port | The URL port. | long |
| ses.module.url.provider | The origin of the reputation and category information. | keyword |
| ses.module.url.query | The query portion of the URL. | keyword |
| ses.module.url.referrer | The address accessed prior to this one. | keyword |
| ses.module.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.module.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.module.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.module.url.scheme | The scheme portion of the URL. | keyword |
| ses.module.url.text | The URL. | keyword |
| ses.module.version | The file version. | keyword |
| ses.module.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.module_type | The type of module. | keyword |
| ses.net_detection_uid | The application-generated unique identifier of the network detection event that is associated with this detection event. | keyword |
| ses.num_archives | The number of archives scanned. | long |
| ses.num_detections | The number of detections. | long |
| ses.num_errors | The number of files with either scanning or remediation errors. | long |
| ses.num_files | The number of files scanned. | long |
| ses.num_folders | The number of folders scanned. | long |
| ses.num_network | The number of network items scanned. | long |
| ses.num_processes | The number of processes scanned. | long |
| ses.num_registry | The number of registry items scanned. | long |
| ses.num_resolutions | The number of items that were resolved. | long |
| ses.num_skipped | The number of skipped items. | long |
| ses.num_trusted | The number of trusted items. | long |
| ses.num_unresolved | The number of scanned items with threats, but no resolution. | long |
| ses.open_mask_id | The Windows setting needed to open a registry key. | keyword |
| ses.open_mode | The mode in which the file was opened: 'Read' = false, 'Write' = true. Applicable to file open events. | boolean |
| ses.operation | The OS operation that initiated the event. | keyword |
| ses.org_unit_uid | The unique identifier of the organizational unit. | keyword |
| ses.orig_data | The pre-normalized event data. | keyword |
| ses.override_duration | The length in minutes for the override action to remain in place until restored upon expiration of time. If not provided it implies infinite duration of policy enforcement or until such time as another policy action occurs. | long |
| ses.parent.app_name | A label that may be associated with this process, for example, the name of the containment sandbox assigned to the process or, for login detection events, the login application (ssh, telnet, sql server, etc.). | keyword |
| ses.parent.app_uid | The identifier of the application that may be associated with this process. | keyword |
| ses.parent.app_ver | The version of the application that may be associated with this process. | keyword |
| ses.parent.cmd_line | The command line used to launch the startup application, service, process or job. | keyword |
| ses.parent.file.accessed | The time that the file was last accessed. | date |
| ses.parent.file.accessor | The name of the user who last accessed the object. | keyword |
| ses.parent.file.attribute_ids | The array of file attributes. | keyword |
| ses.parent.file.attributes | The bitmask value that represents the file attributes. | long |
| ses.parent.file.company_name | The name of the company that published the file. | keyword |
| ses.parent.file.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.parent.file.content_type.family_id | The top level file classification. | keyword |
| ses.parent.file.content_type.subtype | The specific format for the type of data. | keyword |
| ses.parent.file.content_type.type_id | The general type of a file. | keyword |
| ses.parent.file.created | The time that the file was created. | date |
| ses.parent.file.creator | The name of the user who created the file. | keyword |
| ses.parent.file.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.parent.file.desc | The description of the file, as returned by file system. | keyword |
| ses.parent.file.folder | The parent folder in which the file resides. | keyword |
| ses.parent.file.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.parent.file.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.parent.file.md5 | The MD5 checksum of the object content. | keyword |
| ses.parent.file.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.parent.file.modified | The time when the file was last modified. | date |
| ses.parent.file.modifier | The name of the user who last modified the file. | keyword |
| ses.parent.file.name | The name of the file. | keyword |
| ses.parent.file.normalized_path | The CSIDL normalized path name. | keyword |
| ses.parent.file.original_name | The original name of the file. | keyword |
| ses.parent.file.owner | The owner of the file. | keyword |
| ses.parent.file.parent_name | The name of the file that contains this file. | keyword |
| ses.parent.file.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.parent.file.path | The full path to the file. | keyword |
| ses.parent.file.product_name | The name of the product that includes the file. | keyword |
| ses.parent.file.product_path | The path to the product that includes the file. | keyword |
| ses.parent.file.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.parent.file.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.parent.file.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.parent.file.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.parent.file.rep_score | The reputation score of the file. | long |
| ses.parent.file.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.parent.file.security_descriptor | The object security descriptor. | keyword |
| ses.parent.file.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.parent.file.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.parent.file.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.parent.file.signature_created_date | The date and time when the signature was created. | date |
| ses.parent.file.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.parent.file.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.parent.file.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.parent.file.signature_issuer | The issuer of the object signature. | keyword |
| ses.parent.file.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.parent.file.signature_serial_number | The object serial number. | keyword |
| ses.parent.file.signature_value | The digital signature bitmask. | long |
| ses.parent.file.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.parent.file.size | The size of the object, in bytes. | long |
| ses.parent.file.size_compressed | The compressed size of the object, in bytes. | long |
| ses.parent.file.src_ip | The IP address of the host where the file resides. | ip |
| ses.parent.file.src_name | The name of the host where the file resides. | keyword |
| ses.parent.file.type_id | The file type. | keyword |
| ses.parent.file.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.parent.file.url.categories | The array of URL categories. | keyword |
| ses.parent.file.url.category_ids | The array of URL categories. | keyword |
| ses.parent.file.url.extension | Document extension from the original URL requested. | keyword |
| ses.parent.file.url.host | The URL host as extracted from the URL. | keyword |
| ses.parent.file.url.method | The HTTP method used in the URL request. | keyword |
| ses.parent.file.url.parent_categories | The array of parent URL categories. | keyword |
| ses.parent.file.url.path | The URL path as extracted from the URL. | keyword |
| ses.parent.file.url.port | The URL port. | long |
| ses.parent.file.url.provider | The origin of the reputation and category information. | keyword |
| ses.parent.file.url.query | The query portion of the URL. | keyword |
| ses.parent.file.url.referrer | The address accessed prior to this one. | keyword |
| ses.parent.file.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.parent.file.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.parent.file.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.parent.file.url.scheme | The scheme portion of the URL. | keyword |
| ses.parent.file.url.text | The URL. | keyword |
| ses.parent.file.version | The file version. | keyword |
| ses.parent.file.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.parent.integrity_id | The process integrity level (Windows only). | keyword |
| ses.parent.lineage | The lineage of the actor process. | keyword |
| ses.parent.loaded_modules | The list of loaded module names. | keyword |
| ses.parent.module.accessed | The time that the file was last accessed. | date |
| ses.parent.module.accessor | The name of the user who last accessed the object. | keyword |
| ses.parent.module.attribute_ids | The array of file attributes. | keyword |
| ses.parent.module.attributes | The bitmask value that represents the file attributes. | long |
| ses.parent.module.base_address | The memory address where the module was loaded. | keyword |
| ses.parent.module.company_name | The name of the company that published the file. | keyword |
| ses.parent.module.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.parent.module.content_type.family_id | The top level file classification. | keyword |
| ses.parent.module.content_type.subtype | The specific format for the type of data. | keyword |
| ses.parent.module.content_type.type_id | The general type of a file. | keyword |
| ses.parent.module.created | The time that the module was created. | date |
| ses.parent.module.creator | The name of the user who created the module. | keyword |
| ses.parent.module.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.parent.module.desc | The description of the file, as returned by file system. | keyword |
| ses.parent.module.folder | The parent folder in which the file resides. | keyword |
| ses.parent.module.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.parent.module.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.parent.module.load_type | The load type describes how the module was loaded in memory. | keyword |
| ses.parent.module.load_type_id | The load type identifies how the module was loaded in memory. | keyword |
| ses.parent.module.md5 | The MD5 checksum of the object content. | keyword |
| ses.parent.module.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.parent.module.modified | The time when the module was last modified. | date |
| ses.parent.module.modifier | The name of the user who last modified the module. | keyword |
| ses.parent.module.name | The name of the file. | keyword |
| ses.parent.module.normalized_path | The CSIDL normalized path name. | keyword |
| ses.parent.module.original_name | The original name of the file. | keyword |
| ses.parent.module.owner | The owner of the file. | keyword |
| ses.parent.module.parent_name | The name of the file that contains this file. | keyword |
| ses.parent.module.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.parent.module.path | The full path to the file. | keyword |
| ses.parent.module.product_name | The name of the product that includes the file. | keyword |
| ses.parent.module.product_path | The path to the product that includes the file. | keyword |
| ses.parent.module.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.parent.module.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.parent.module.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.parent.module.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.parent.module.rep_score | The reputation score of the file. | long |
| ses.parent.module.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.parent.module.security_descriptor | The object security descriptor. | keyword |
| ses.parent.module.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.parent.module.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.parent.module.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.parent.module.signature_created_date | The date and time when the signature was created. | date |
| ses.parent.module.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.parent.module.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.parent.module.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.parent.module.signature_issuer | The issuer of the object signature. | keyword |
| ses.parent.module.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.parent.module.signature_serial_number | The object serial number. | keyword |
| ses.parent.module.signature_value | The digital signature bitmask. | long |
| ses.parent.module.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.parent.module.size | The size of the object, in bytes. | long |
| ses.parent.module.size_compressed | The compressed size of the object, in bytes. | long |
| ses.parent.module.src_ip | The IP address of the host where the file resides. | ip |
| ses.parent.module.src_name | The name of the host where the file resides. | keyword |
| ses.parent.module.type_id | The file type. | keyword |
| ses.parent.module.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.parent.module.url.categories | The array of URL categories. | keyword |
| ses.parent.module.url.category_ids | The array of URL categories. | keyword |
| ses.parent.module.url.extension | Document extension from the original URL requested. | keyword |
| ses.parent.module.url.host | The URL host as extracted from the URL. | keyword |
| ses.parent.module.url.method | The HTTP method used in the URL request. | keyword |
| ses.parent.module.url.parent_categories | The array of parent URL categories. | keyword |
| ses.parent.module.url.path | The URL path as extracted from the URL. | keyword |
| ses.parent.module.url.port | The URL port. | long |
| ses.parent.module.url.provider | The origin of the reputation and category information. | keyword |
| ses.parent.module.url.query | The query portion of the URL. | keyword |
| ses.parent.module.url.referrer | The address accessed prior to this one. | keyword |
| ses.parent.module.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.parent.module.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.parent.module.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.parent.module.url.scheme | The scheme portion of the URL. | keyword |
| ses.parent.module.url.text | The URL. | keyword |
| ses.parent.module.version | The file version. | keyword |
| ses.parent.module.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.parent.normalized_cmd_line | The CSIDL normalized command line used to launch the startup application, service, process or job (Windows only). | keyword |
| ses.parent.pid | The process identifier, as reported by the operating system. | long |
| ses.parent.sandbox_name | The name of the containment jail (sandbox) assigned by the policy to this process/module. | keyword |
| ses.parent.session.auth_protocol_id | The authentication protocol. | keyword |
| ses.parent.session.cleartext_credentials | Indicates whether the credentials were passed in clear text.Note: True if the credentials were passed in a clear text protocol such as FTP or TELNET, or if Windows detected that a user's logon password was passed to the authentication package in clear text. | boolean |
| ses.parent.session.direction_id | The direction of the initiated traffic. | keyword |
| ses.parent.session.id | The unique session identifier, as reported by the operating system. | keyword |
| ses.parent.session.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.parent.session.logon_type_id | The type of session logon. | keyword |
| ses.parent.session.port | The port that the remote session connects to; applicable for remote sessions only. | long |
| ses.parent.session.previous_users | An ordered list of the previous user names used within the session, from latest to earliest. | keyword |
| ses.parent.session.remote | The indication of whether the session is remote. | boolean |
| ses.parent.session.remote_host | The host name of the device associated with the remote session. | keyword |
| ses.parent.session.remote_ip | The IP address of the device associated with the remote session. The format is either IPv4 or IPv6. | ip |
| ses.parent.session.user.account_disabled | The indication of whether the user's account is disabled. | boolean |
| ses.parent.session.user.cloud_resource_uid | The cloud resource unique identifier of this user. | keyword |
| ses.parent.session.user.domain | The domain where the user is defined. | keyword |
| ses.parent.session.user.external_account_uid | The user's external account unique identifier. | keyword |
| ses.parent.session.user.external_uid | The user's external unique identifier. | keyword |
| ses.parent.session.user.full_name | The full name of the user. | keyword |
| ses.parent.session.user.groups | The administrative groups to which the user belongs. | keyword |
| ses.parent.session.user.home | The user's home directory. | keyword |
| ses.parent.session.user.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.parent.session.user.logon_name | The name of the authenticated principal that is associated with the event. | keyword |
| ses.parent.session.user.name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.parent.session.user.password_expires | The indication of whether the user's password is configured to expire. | boolean |
| ses.parent.session.user.shell | The user's login shell. | keyword |
| ses.parent.session.user.sid | The user security identifier (SID). | keyword |
| ses.parent.session.user.uid | The unique identifier of the user associated with the event. | keyword |
| ses.parent.session_id | The user session ID from which the process was launched. | keyword |
| ses.parent.start_time | The time that the process started. | date |
| ses.parent.tid | The Identifier of the thread associated with the event, as returned by the operating system. | long |
| ses.parent.uid | The unique identifier of the process. | keyword |
| ses.parent.user.account_disabled | The indication of whether the user's account is disabled. | boolean |
| ses.parent.user.cloud_resource_uid | The cloud resource unique identifier of this user. | keyword |
| ses.parent.user.domain | The domain where the user is defined. | keyword |
| ses.parent.user.external_account_uid | The user's external account unique identifier. | keyword |
| ses.parent.user.external_uid | The user's external unique identifier. | keyword |
| ses.parent.user.full_name | The full name of the user. | keyword |
| ses.parent.user.groups | The administrative groups to which the user belongs. | keyword |
| ses.parent.user.home | The user's home directory. | keyword |
| ses.parent.user.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.parent.user.logon_name | The name of the authenticated principal that is associated with the event. | keyword |
| ses.parent.user.name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.parent.user.password_expires | The indication of whether the user's password is configured to expire. | boolean |
| ses.parent.user.shell | The user's login shell. | keyword |
| ses.parent.user.sid | The user security identifier (SID). | keyword |
| ses.parent.user.uid | The unique identifier of the user associated with the event. | keyword |
| ses.parent.xattributes | An unordered collection of zero or more name/value pairs that represent a process extended attribute. | flattened |
| ses.peripheral_device.class | The class of the peripheral device. | keyword |
| ses.peripheral_device.instance_uid | The unique identifier of the peripheral device instance. | keyword |
| ses.peripheral_device.model | The peripheral device model. | keyword |
| ses.peripheral_device.name | The name of the peripheral device. | keyword |
| ses.peripheral_device.serial | The peripheral device serial number. | keyword |
| ses.peripheral_device.vendor | The peripheral device vendor. | keyword |
| ses.policy.desc | The description of the policy. | keyword |
| ses.policy.effective_date | The date and time that the specific policy and rule was applied and became operational. | date |
| ses.policy.group_desc | The description of the group to which the policy belongs. | keyword |
| ses.policy.group_name | The name of the group to which the policy belongs. | keyword |
| ses.policy.group_uid | The unique identifier of the group to which the policy belongs. | keyword |
| ses.policy.label | The label set for the policy. | keyword |
| ses.policy.name | The name given to the policy. | keyword |
| ses.policy.rule_category_id | The category of the primary rule that triggered the violation. | keyword |
| ses.policy.rule_desc | The description of the primary rule that triggered the policy event. | keyword |
| ses.policy.rule_group_desc | The additional information that describes the group to which the rule belongs. | keyword |
| ses.policy.rule_group_name | The name of the group to which the rule belongs. | keyword |
| ses.policy.rule_group_uid | The unique identifier of the group to which the rule belongs. | keyword |
| ses.policy.rule_name | The name of the primary rule that triggered the policy event. | keyword |
| ses.policy.rule_uid | The unique identifier of the primary rule that triggered the policy event. | keyword |
| ses.policy.rules.category_id | The category of the rule. | keyword |
| ses.policy.rules.desc | The description of the rule. | keyword |
| ses.policy.rules.dlp_type_id | The Data Loss Protection specific rule type. | keyword |
| ses.policy.rules.name | The name given to the rule. | keyword |
| ses.policy.rules.num_violations | The number of times the policy or rule was violated. | long |
| ses.policy.rules.uid | The unique identifier of the rule. | keyword |
| ses.policy.state_ids | The states related to the policy. | keyword |
| ses.policy.type_id | The policy type. | keyword |
| ses.policy.uid | A unique identifier of the policy instance that contains the rule generating the event; ordinarily, client or application-specific. | keyword |
| ses.policy.version | The policy version number. | keyword |
| ses.prev_location.city | The name of the city. | keyword |
| ses.prev_location.continent | The name of the continent. | keyword |
| ses.prev_location.coordinates | A two-element array, containing a longitude/latitude pair. The format conforms with GeoJSON. | float |
| ses.prev_location.country | The ISO 3166-1 Alpha-2 country code. For the complete list of country codes see ISO 3166-1 alpha-2 codes.Note: The two letter country code should be capitalized. | keyword |
| ses.prev_location.desc | The description of the location. | keyword |
| ses.prev_location.isp | The name of the Internet Service Provider (ISP). | keyword |
| ses.prev_location.on_premises | The indication of whether the location is on premises. | boolean |
| ses.prev_location.region | The alphanumeric code that identifies the principal subdivision (e.g. province or state) of the country. Region codes are defined at ISO 3166-2 and have a limit of three characters. | keyword |
| ses.prev_security_level_id | The previous security level of the entity. | keyword |
| ses.prev_security_state_ids | The previous security states of the entity. | keyword |
| ses.prev_ver | The pre-update version of the code, content, configuration or policy. | keyword |
| ses.priority_id | The incident priority. | keyword |
| ses.privileges | The user privileges. | keyword |
| ses.process.app_name | A label that may be associated with this process. | keyword |
| ses.process.app_uid | The identifier of the application that may be associated with this process. | keyword |
| ses.process.app_ver | The version of the application that may be associated with this process. | keyword |
| ses.process.cmd_line | The command line used to launch the startup application, service, process or job. | keyword |
| ses.process.file.accessed | The time that the file was last accessed. | date |
| ses.process.file.accessor | The name of the user who last accessed the object. | keyword |
| ses.process.file.attribute_ids | The array of file attributes. | keyword |
| ses.process.file.attributes | The bitmask value that represents the file attributes. | long |
| ses.process.file.company_name | The name of the company that published the file. | keyword |
| ses.process.file.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.process.file.content_type.family_id | The top level file classification. | keyword |
| ses.process.file.content_type.subtype | The specific format for the type of data. | keyword |
| ses.process.file.content_type.type_id | The general type of a file. | keyword |
| ses.process.file.created | The time that the file was created. | date |
| ses.process.file.creator | The name of the user who created the file. | keyword |
| ses.process.file.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.process.file.desc | The description of the file, as returned by file system. | keyword |
| ses.process.file.folder | The parent folder in which the file resides. | keyword |
| ses.process.file.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.process.file.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.process.file.md5 | The MD5 checksum of the object content. | keyword |
| ses.process.file.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.process.file.modified | The time when the file was last modified. | date |
| ses.process.file.modifier | The name of the user who last modified the file. | keyword |
| ses.process.file.name | The name of the file. | keyword |
| ses.process.file.normalized_path | The CSIDL normalized path name. | keyword |
| ses.process.file.original_name | The original name of the file. | keyword |
| ses.process.file.owner | The owner of the file. | keyword |
| ses.process.file.parent_name | The name of the file that contains this file. | keyword |
| ses.process.file.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.process.file.path | The full path to the file. | keyword |
| ses.process.file.product_name | The name of the product that includes the file. | keyword |
| ses.process.file.product_path | The path to the product that includes the file. | keyword |
| ses.process.file.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.process.file.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.process.file.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.process.file.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.process.file.rep_score | The reputation score of the file. | long |
| ses.process.file.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.process.file.security_descriptor | The object security descriptor. | keyword |
| ses.process.file.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.process.file.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.process.file.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.process.file.signature_created_date | The date and time when the signature was created. | date |
| ses.process.file.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.process.file.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.process.file.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.process.file.signature_issuer | The issuer of the object signature. | keyword |
| ses.process.file.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.process.file.signature_serial_number | The object serial number. | keyword |
| ses.process.file.signature_value | The digital signature bitmask. | long |
| ses.process.file.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.process.file.size | The size of the object, in bytes. | long |
| ses.process.file.size_compressed | The compressed size of the object, in bytes. | long |
| ses.process.file.src_ip | The IP address of the host where the file resides. | ip |
| ses.process.file.src_name | The name of the host where the file resides. | keyword |
| ses.process.file.type_id | The file type. | keyword |
| ses.process.file.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.process.file.url.categories | The array of URL categories. | keyword |
| ses.process.file.url.category_ids | The array of URL categories. | keyword |
| ses.process.file.url.extension | Document extension from the original URL requested. | keyword |
| ses.process.file.url.host | The URL host as extracted from the URL. | keyword |
| ses.process.file.url.method | The HTTP method used in the URL request. | keyword |
| ses.process.file.url.parent_categories | The array of parent URL categories. | keyword |
| ses.process.file.url.path | The URL path as extracted from the URL. | keyword |
| ses.process.file.url.port | The URL port. | long |
| ses.process.file.url.provider | The origin of the reputation and category information. | keyword |
| ses.process.file.url.query | The query portion of the URL. | keyword |
| ses.process.file.url.referrer | The address accessed prior to this one. | keyword |
| ses.process.file.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.process.file.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.process.file.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.process.file.url.scheme | The scheme portion of the URL. | keyword |
| ses.process.file.url.text | The URL. | keyword |
| ses.process.file.version | The file version. | keyword |
| ses.process.file.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.process.integrity_id | The process integrity level (Windows only). | keyword |
| ses.process.lineage | The lineage of the actor process. | keyword |
| ses.process.loaded_modules | The list of loaded module names. | keyword |
| ses.process.module.accessed | The time that the file was last accessed. | date |
| ses.process.module.accessor | The name of the user who last accessed the object. | keyword |
| ses.process.module.attribute_ids | The array of file attributes. | keyword |
| ses.process.module.attributes | The bitmask value that represents the file attributes. | long |
| ses.process.module.base_address | The memory address where the module was loaded. | keyword |
| ses.process.module.company_name | The name of the company that published the file. | keyword |
| ses.process.module.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.process.module.content_type.family_id | The top level file classification. | keyword |
| ses.process.module.content_type.subtype | The specific format for the type of data. | keyword |
| ses.process.module.content_type.type_id | The general type of a file. | keyword |
| ses.process.module.created | The time that the module was created. | date |
| ses.process.module.creator | The name of the user who created the module. | keyword |
| ses.process.module.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.process.module.desc | The description of the file, as returned by file system. | keyword |
| ses.process.module.folder | The parent folder in which the file resides. | keyword |
| ses.process.module.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.process.module.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.process.module.load_type | The load type describes how the module was loaded in memory. | keyword |
| ses.process.module.load_type_id | The load type identifies how the module was loaded in memory. | keyword |
| ses.process.module.md5 | The MD5 checksum of the object content. | keyword |
| ses.process.module.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.process.module.modified | The time when the module was last modified. | date |
| ses.process.module.modifier | The name of the user who last modified the module. | keyword |
| ses.process.module.name | The name of the file. | keyword |
| ses.process.module.normalized_path | The CSIDL normalized path name. | keyword |
| ses.process.module.original_name | The original name of the file. | keyword |
| ses.process.module.owner | The owner of the file. | keyword |
| ses.process.module.parent_name | The name of the file that contains this file. | keyword |
| ses.process.module.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.process.module.path | The full path to the file. | keyword |
| ses.process.module.product_name | The name of the product that includes the file. | keyword |
| ses.process.module.product_path | The path to the product that includes the file. | keyword |
| ses.process.module.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.process.module.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.process.module.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.process.module.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.process.module.rep_score | The reputation score of the file. | long |
| ses.process.module.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.process.module.security_descriptor | The object security descriptor. | keyword |
| ses.process.module.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.process.module.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.process.module.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.process.module.signature_created_date | The date and time when the signature was created. | date |
| ses.process.module.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.process.module.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.process.module.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.process.module.signature_issuer | The issuer of the object signature. | keyword |
| ses.process.module.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.process.module.signature_serial_number | The object serial number. | keyword |
| ses.process.module.signature_value | The digital signature bitmask. | long |
| ses.process.module.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.process.module.size | The size of the object, in bytes. | long |
| ses.process.module.size_compressed | The compressed size of the object, in bytes. | long |
| ses.process.module.src_ip | The IP address of the host where the file resides. | ip |
| ses.process.module.src_name | The name of the host where the file resides. | keyword |
| ses.process.module.type_id | The file type. | keyword |
| ses.process.module.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.process.module.url.categories | The array of URL categories. | keyword |
| ses.process.module.url.category_ids | The array of URL categories. | keyword |
| ses.process.module.url.extension | Document extension from the original URL requested. | keyword |
| ses.process.module.url.host | The URL host as extracted from the URL. | keyword |
| ses.process.module.url.method | The HTTP method used in the URL request. | keyword |
| ses.process.module.url.parent_categories | The array of parent URL categories. | keyword |
| ses.process.module.url.path | The URL path as extracted from the URL. | keyword |
| ses.process.module.url.port | The URL port. | long |
| ses.process.module.url.provider | The origin of the reputation and category information. | keyword |
| ses.process.module.url.query | The query portion of the URL. | keyword |
| ses.process.module.url.referrer | The address accessed prior to this one. | keyword |
| ses.process.module.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.process.module.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.process.module.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.process.module.url.scheme | The scheme portion of the URL. | keyword |
| ses.process.module.url.text | The URL. | keyword |
| ses.process.module.version | The file version. | keyword |
| ses.process.module.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.process.normalized_cmd_line | The CSIDL normalized command line used to launch the startup application, service, process or job (Windows only). | keyword |
| ses.process.pid | The process identifier, as reported by the operating system. | long |
| ses.process.sandbox_name | The name of the containment jail (sandbox) assigned by the policy to this process/module. | keyword |
| ses.process.session.auth_protocol_id | The authentication protocol. | keyword |
| ses.process.session.cleartext_credentials | Indicates whether the credentials were passed in clear text. | boolean |
| ses.process.session.direction_id | The direction of the initiated traffic. | keyword |
| ses.process.session.id | The unique session identifier, as reported by the operating system. | long |
| ses.process.session.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.process.session.logon_type_id | The type of session logon. | keyword |
| ses.process.session.port | The port that the remote session connects to; applicable for remote sessions only. | long |
| ses.process.session.previous_users | An ordered list of the previous user names used within the session, from latest to earliest. | keyword |
| ses.process.session.remote | The indication of whether the session is remote. | boolean |
| ses.process.session.remote_host | The host name of the device associated with the remote session. | keyword |
| ses.process.session.remote_ip | The IP address of the device associated with the remote session. The format is either IPv4 or IPv6. | ip |
| ses.process.session.user.account_disabled | The indication of whether the user's account is disabled. | boolean |
| ses.process.session.user.cloud_resource_uid | The cloud resource unique identifier of this user. | keyword |
| ses.process.session.user.domain | The domain where the user is defined. | keyword |
| ses.process.session.user.external_account_uid | The user's external account unique identifier. | keyword |
| ses.process.session.user.external_uid | The user's external unique identifier. | keyword |
| ses.process.session.user.full_name | The full name of the user. | keyword |
| ses.process.session.user.groups | The administrative groups to which the user belongs. | keyword |
| ses.process.session.user.home | The user's home directory. | keyword |
| ses.process.session.user.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.process.session.user.logon_name | The name of the authenticated principal that is associated with the event. | keyword |
| ses.process.session.user.name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.process.session.user.password_expires | The indication of whether the user's password is configured to expire. | boolean |
| ses.process.session.user.shell | The user's login shell. | keyword |
| ses.process.session.user.sid | The user security identifier (SID). | keyword |
| ses.process.session.user.uid | The unique identifier of the user associated with the event. | keyword |
| ses.process.session_id | The user session ID from which the process was launched. | keyword |
| ses.process.start_time | The time that the process started. | date |
| ses.process.tid | The Identifier of the thread associated with the event, as returned by the operating system. | long |
| ses.process.uid | The unique identifier of the process. | keyword |
| ses.process.user.account_disabled | The indication of whether the user's account is disabled. | boolean |
| ses.process.user.cloud_resource_uid | The cloud resource unique identifier of this user. | keyword |
| ses.process.user.domain | The domain where the user is defined. | keyword |
| ses.process.user.external_account_uid | The user's external account unique identifier. | keyword |
| ses.process.user.external_uid | The user's external unique identifier. | keyword |
| ses.process.user.full_name | The full name of the user. | keyword |
| ses.process.user.groups | The administrative groups to which the user belongs. | keyword |
| ses.process.user.home | The user's home directory. | keyword |
| ses.process.user.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.process.user.logon_name | The name of the authenticated principal that is associated with the event. | keyword |
| ses.process.user.name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.process.user.password_expires | The indication of whether the user's password is configured to expire. | boolean |
| ses.process.user.shell | The user's login shell. | keyword |
| ses.process.user.sid | The user security identifier (SID). | keyword |
| ses.process.user.uid | The unique identifier of the user associated with the event. | keyword |
| ses.process.xattributes | An unordered collection of zero or more name/value pairs that represent a process extended attribute. | flattened |
| ses.product_data | The event attributes that are specific to the reporting product. | flattened |
| ses.product_lang | The two letter lower case language codes as defined by ISO 639-1. | keyword |
| ses.product_name | The name of the product originating the event. | keyword |
| ses.product_uid | The unique identifier of the product originating the event. | keyword |
| ses.product_ver | The version of the product. | keyword |
| ses.proxy_device_ip | The IP address of the proxy device that is collecting events from other devices. | ip |
| ses.proxy_device_name | The name of the proxy device that is collecting events from other devices. | keyword |
| ses.quarantine_uid | If the event id is one of: [12] Quarantined [13] Restored the unique identifier of the item that was quarantined or restored from quarantine. | keyword |
| ses.raw_data | The event data as received. | flattened |
| ses.reason | The reason for the detection. | keyword |
| ses.reason_id | The reason for the detection. | keyword |
| ses.recipient | The Click-time protection email to address. | keyword |
| ses.ref_event | The event source's event id. | long |
| ses.ref_event_name | The event source's event name. | keyword |
| ses.ref_incident_uid | The unique identifier of the original incident. | keyword |
| ses.ref_log_name | The log name of the reference event. | keyword |
| ses.ref_log_time | The log time of the reference event. | date |
| ses.ref_orig_uid | The unique identifier of the external event that corresponds to Reference Event ID (ref_uid) ,if applicable. | keyword |
| ses.ref_uid | The unique external original message or event identifier that was used to record the event. | keyword |
| ses.reg_key.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.reg_key.last_write | The time that the registry key was last written. | date |
| ses.reg_key.path | The full path to the registry key. | keyword |
| ses.reg_key.security_descriptor | The security descriptor of the registry key. | keyword |
| ses.reg_key_result.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.reg_key_result.last_write | The time that the registry key was last written. | date |
| ses.reg_key_result.path | The full path to the registry key. | keyword |
| ses.reg_key_result.security_descriptor | The security descriptor of the registry key. | keyword |
| ses.reg_value.data | The data of the registry value. | keyword |
| ses.reg_value.is_default_value | The indication of whether the value is from a default value name. For example, the value name could be missing. | boolean |
| ses.reg_value.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.reg_value.last_write | The time that the registry value was last written. | date |
| ses.reg_value.name | The name of the registry value. | keyword |
| ses.reg_value.path | The full path to the registry key, where the value is located. | keyword |
| ses.reg_value.type | A string representation of the value type. | keyword |
| ses.reg_value.type_id | The Windows value type, as defined in winnt.h. | keyword |
| ses.reg_value_result.data | The data of the registry value. | keyword |
| ses.reg_value_result.is_default_value | The indication of whether the value is from a default value name. | boolean |
| ses.reg_value_result.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.reg_value_result.last_write | The time that the registry value was last written. | date |
| ses.reg_value_result.name | The name of the registry value. | keyword |
| ses.reg_value_result.path | The full path to the registry key, where the value is located. | keyword |
| ses.reg_value_result.type | A string representation of the value type. | keyword |
| ses.reg_value_result.type_id | The Windows value type, as defined in winnt.h. | keyword |
| ses.remediated | The indication of whether the event was remediated. | boolean |
| ses.remediation | The remediation information. | keyword |
| ses.remediation_ref | The reference to remediation information.Note: The information can be either internal or external to the reporting product. | keyword |
| ses.remediation_uid | The unique identifier of the remediation information. | keyword |
| ses.remote_device_name | The name of the device associated with the remote process. | keyword |
| ses.remote_process.app_name | A label that may be associated with this process, for example, the name of the containment sandbox assigned to the process or, for login detection events, the login application. | keyword |
| ses.remote_process.app_uid | The identifier of the application that may be associated with this process. | keyword |
| ses.remote_process.app_ver | The version of the application that may be associated with this process. | keyword |
| ses.remote_process.cmd_line | The command line used to launch the startup application, service, process or job. | keyword |
| ses.remote_process.file.accessed | The time that the file was last accessed. | date |
| ses.remote_process.file.accessor | The name of the user who last accessed the object. | keyword |
| ses.remote_process.file.attribute_ids | The array of file attributes. | keyword |
| ses.remote_process.file.attributes | The bitmask value that represents the file attributes. | long |
| ses.remote_process.file.company_name | The name of the company that published the file. | keyword |
| ses.remote_process.file.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.remote_process.file.content_type.family_id | The top level file classification. | keyword |
| ses.remote_process.file.content_type.subtype | The specific format for the type of data. | keyword |
| ses.remote_process.file.content_type.type_id | The general type of a file. | keyword |
| ses.remote_process.file.created | The time that the file was created. | date |
| ses.remote_process.file.creator | The name of the user who created the file. | keyword |
| ses.remote_process.file.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.remote_process.file.desc | The description of the file, as returned by file system. | keyword |
| ses.remote_process.file.folder | The parent folder in which the file resides. | keyword |
| ses.remote_process.file.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.remote_process.file.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.remote_process.file.md5 | The MD5 checksum of the object content. | keyword |
| ses.remote_process.file.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.remote_process.file.modified | The time when the file was last modified. | date |
| ses.remote_process.file.modifier | The name of the user who last modified the file. | keyword |
| ses.remote_process.file.name | The name of the file. | keyword |
| ses.remote_process.file.normalized_path | The CSIDL normalized path name. | keyword |
| ses.remote_process.file.original_name | The original name of the file. | keyword |
| ses.remote_process.file.owner | The owner of the file. | keyword |
| ses.remote_process.file.parent_name | The name of the file that contains this file. | keyword |
| ses.remote_process.file.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.remote_process.file.path | The full path to the file. | keyword |
| ses.remote_process.file.product_name | The name of the product that includes the file. | keyword |
| ses.remote_process.file.product_path | The path to the product that includes the file. | keyword |
| ses.remote_process.file.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.remote_process.file.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.remote_process.file.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.remote_process.file.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.remote_process.file.rep_score | The reputation score of the file. | long |
| ses.remote_process.file.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.remote_process.file.security_descriptor | The object security descriptor. | keyword |
| ses.remote_process.file.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.remote_process.file.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.remote_process.file.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.remote_process.file.signature_created_date | The date and time when the signature was created. | date |
| ses.remote_process.file.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.remote_process.file.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.remote_process.file.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.remote_process.file.signature_issuer | The issuer of the object signature. | keyword |
| ses.remote_process.file.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.remote_process.file.signature_serial_number | The object serial number. | keyword |
| ses.remote_process.file.signature_value | The digital signature bitmask. | long |
| ses.remote_process.file.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.remote_process.file.size | The size of the object, in bytes. | long |
| ses.remote_process.file.size_compressed | The compressed size of the object, in bytes. | long |
| ses.remote_process.file.src_ip | The IP address of the host where the file resides. | ip |
| ses.remote_process.file.src_name | The name of the host where the file resides. | keyword |
| ses.remote_process.file.type_id | The file type. | keyword |
| ses.remote_process.file.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.remote_process.file.url.categories | The array of URL categories. | keyword |
| ses.remote_process.file.url.category_ids | The array of URL categories. | keyword |
| ses.remote_process.file.url.extension | Document extension from the original URL requested. | keyword |
| ses.remote_process.file.url.host | The URL host as extracted from the URL. | keyword |
| ses.remote_process.file.url.method | The HTTP method used in the URL request. | keyword |
| ses.remote_process.file.url.parent_categories | The array of parent URL categories. | keyword |
| ses.remote_process.file.url.path | The URL path as extracted from the URL. | keyword |
| ses.remote_process.file.url.port | The URL port. | long |
| ses.remote_process.file.url.provider | The origin of the reputation and category information. | keyword |
| ses.remote_process.file.url.query | The query portion of the URL. | keyword |
| ses.remote_process.file.url.referrer | The address accessed prior to this one. | keyword |
| ses.remote_process.file.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.remote_process.file.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.remote_process.file.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.remote_process.file.url.scheme | The scheme portion of the URL. | keyword |
| ses.remote_process.file.url.text | The URL. | keyword |
| ses.remote_process.file.version | The file version. | keyword |
| ses.remote_process.file.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.remote_process.integrity_id | The process integrity level (Windows only). | keyword |
| ses.remote_process.lineage | The lineage of the actor process. | keyword |
| ses.remote_process.loaded_modules | The list of loaded module names. | keyword |
| ses.remote_process.module.accessed | The time that the file was last accessed. | date |
| ses.remote_process.module.accessor | The name of the user who last accessed the object. | keyword |
| ses.remote_process.module.attribute_ids | The array of file attributes. | keyword |
| ses.remote_process.module.attributes | The bitmask value that represents the file attributes. | long |
| ses.remote_process.module.base_address | The memory address where the module was loaded. | keyword |
| ses.remote_process.module.company_name | The name of the company that published the file. | keyword |
| ses.remote_process.module.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.remote_process.module.content_type.family_id | The top level file classification. | keyword |
| ses.remote_process.module.content_type.subtype | The specific format for the type of data. | keyword |
| ses.remote_process.module.content_type.type_id | The general type of a file. | keyword |
| ses.remote_process.module.created | The time that the module was created. | date |
| ses.remote_process.module.creator | The name of the user who created the module. | keyword |
| ses.remote_process.module.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.remote_process.module.desc | The description of the file, as returned by file system. | keyword |
| ses.remote_process.module.folder | The parent folder in which the file resides. | keyword |
| ses.remote_process.module.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.remote_process.module.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.remote_process.module.load_type | The load type describes how the module was loaded in memory. | keyword |
| ses.remote_process.module.load_type_id | The load type identifies how the module was loaded in memory. | keyword |
| ses.remote_process.module.md5 | The MD5 checksum of the object content. | keyword |
| ses.remote_process.module.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.remote_process.module.modified | The time when the module was last modified. | date |
| ses.remote_process.module.modifier | The name of the user who last modified the module. | keyword |
| ses.remote_process.module.name | The name of the file. | keyword |
| ses.remote_process.module.normalized_path | The CSIDL normalized path name. | keyword |
| ses.remote_process.module.original_name | The original name of the file. | keyword |
| ses.remote_process.module.owner | The owner of the file. | keyword |
| ses.remote_process.module.parent_name | The name of the file that contains this file. | keyword |
| ses.remote_process.module.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.remote_process.module.path | The full path to the file. | keyword |
| ses.remote_process.module.product_name | The name of the product that includes the file. | keyword |
| ses.remote_process.module.product_path | The path to the product that includes the file. | keyword |
| ses.remote_process.module.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.remote_process.module.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.remote_process.module.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.remote_process.module.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.remote_process.module.rep_score | The reputation score of the file. | long |
| ses.remote_process.module.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.remote_process.module.security_descriptor | The object security descriptor. | keyword |
| ses.remote_process.module.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.remote_process.module.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.remote_process.module.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.remote_process.module.signature_created_date | The date and time when the signature was created. | date |
| ses.remote_process.module.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.remote_process.module.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.remote_process.module.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.remote_process.module.signature_issuer | The issuer of the object signature. | keyword |
| ses.remote_process.module.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.remote_process.module.signature_serial_number | The object serial number. | keyword |
| ses.remote_process.module.signature_value | The digital signature bitmask. | long |
| ses.remote_process.module.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.remote_process.module.size | The size of the object, in bytes. | long |
| ses.remote_process.module.size_compressed | The compressed size of the object, in bytes. | long |
| ses.remote_process.module.src_ip | The IP address of the host where the file resides. | ip |
| ses.remote_process.module.src_name | The name of the host where the file resides. | keyword |
| ses.remote_process.module.type_id | The file type. | keyword |
| ses.remote_process.module.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.remote_process.module.url.categories | The array of URL categories. | keyword |
| ses.remote_process.module.url.category_ids | The array of URL categories. | keyword |
| ses.remote_process.module.url.extension | Document extension from the original URL requested. | keyword |
| ses.remote_process.module.url.host | The URL host as extracted from the URL. | keyword |
| ses.remote_process.module.url.method | The HTTP method used in the URL request. | keyword |
| ses.remote_process.module.url.parent_categories | The array of parent URL categories. | keyword |
| ses.remote_process.module.url.path | The URL path as extracted from the URL. | keyword |
| ses.remote_process.module.url.port | The URL port. | long |
| ses.remote_process.module.url.provider | The origin of the reputation and category information. | keyword |
| ses.remote_process.module.url.query | The query portion of the URL. | keyword |
| ses.remote_process.module.url.referrer | The address accessed prior to this one. | keyword |
| ses.remote_process.module.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.remote_process.module.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.remote_process.module.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.remote_process.module.url.scheme | The scheme portion of the URL. | keyword |
| ses.remote_process.module.url.text | The URL. | keyword |
| ses.remote_process.module.version | The file version. | keyword |
| ses.remote_process.module.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.remote_process.normalized_cmd_line | The CSIDL normalized command line used to launch the startup application, service, process or job (Windows only). | keyword |
| ses.remote_process.pid | The process identifier, as reported by the operating system. | long |
| ses.remote_process.sandbox_name | The name of the containment jail (sandbox) assigned by the policy to this process/module. | keyword |
| ses.remote_process.session.auth_protocol_id | The authentication protocol. | keyword |
| ses.remote_process.session.cleartext_credentials | Indicates whether the credentials were passed in clear text.Note: True if the credentials were passed in a clear text protocol such as FTP or TELNET, or if Windows detected that a user's logon password was passed to the authentication package in clear text. | boolean |
| ses.remote_process.session.direction_id | The direction of the initiated traffic. | keyword |
| ses.remote_process.session.id | The unique session identifier, as reported by the operating system. | long |
| ses.remote_process.session.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.remote_process.session.logon_type_id | The type of session logon. | keyword |
| ses.remote_process.session.port | The port that the remote session connects to; applicable for remote sessions only. | long |
| ses.remote_process.session.previous_users | An ordered list of the previous user names used within the session, from latest to earliest. | keyword |
| ses.remote_process.session.remote | The indication of whether the session is remote. | boolean |
| ses.remote_process.session.remote_host | The host name of the device associated with the remote session. | keyword |
| ses.remote_process.session.remote_ip | The IP address of the device associated with the remote session. The format is either IPv4 or IPv6. | ip |
| ses.remote_process.session.user.account_disabled | The indication of whether the user's account is disabled. | boolean |
| ses.remote_process.session.user.cloud_resource_uid | The cloud resource unique identifier of this user. | keyword |
| ses.remote_process.session.user.domain | The domain where the user is defined. | keyword |
| ses.remote_process.session.user.external_account_uid | The user's external account unique identifier. | keyword |
| ses.remote_process.session.user.external_uid | The user's external unique identifier. | keyword |
| ses.remote_process.session.user.full_name | The full name of the user. | keyword |
| ses.remote_process.session.user.groups | The administrative groups to which the user belongs. | keyword |
| ses.remote_process.session.user.home | The user's home directory. | keyword |
| ses.remote_process.session.user.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.remote_process.session.user.logon_name | The name of the authenticated principal that is associated with the event. If the event originates from a feature on a computer, the logon_name is the name of the user that the software feature is running as, for example, “root” or “admin”. If the event originates from a mobile device, the logon_name  is the user name reported by the OS. | keyword |
| ses.remote_process.session.user.name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.remote_process.session.user.password_expires | The indication of whether the user's password is configured to expire. | boolean |
| ses.remote_process.session.user.shell | The user's login shell. | keyword |
| ses.remote_process.session.user.sid | The user security identifier (SID). | keyword |
| ses.remote_process.session.user.uid | The unique identifier of the user associated with the event. | keyword |
| ses.remote_process.session_id | The user session ID from which the process was launched. | keyword |
| ses.remote_process.start_time | The time that the process started. | date |
| ses.remote_process.tid | The Identifier of the thread associated with the event, as returned by the operating system. | long |
| ses.remote_process.uid | The unique identifier of the process. | keyword |
| ses.remote_process.user.account_disabled | The indication of whether the user's account is disabled. | boolean |
| ses.remote_process.user.cloud_resource_uid | The cloud resource unique identifier of this user. | keyword |
| ses.remote_process.user.domain | The domain where the user is defined. | keyword |
| ses.remote_process.user.external_account_uid | The user's external account unique identifier. | keyword |
| ses.remote_process.user.external_uid | The user's external unique identifier. | keyword |
| ses.remote_process.user.full_name | The full name of the user. | keyword |
| ses.remote_process.user.groups | The administrative groups to which the user belongs. | keyword |
| ses.remote_process.user.home | The user's home directory. | keyword |
| ses.remote_process.user.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.remote_process.user.logon_name | The name of the authenticated principal that is associated with the event. If the event originates from a feature on a computer, the logon_name is the name of the user that the software feature is running as, for example, “root” or “admin”. If the event originates from a mobile device, the logon_name  is the user name reported by the OS. | keyword |
| ses.remote_process.user.name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.remote_process.user.password_expires | The indication of whether the user's password is configured to expire. | boolean |
| ses.remote_process.user.shell | The user's login shell. | keyword |
| ses.remote_process.user.sid | The user security identifier (SID). | keyword |
| ses.remote_process.user.uid | The unique identifier of the user associated with the event. | keyword |
| ses.remote_process.xattributes | An unordered collection of zero or more name/value pairs that represent a process extended attribute. | flattened |
| ses.request_uid | The unique identifier of the request. | keyword |
| ses.requested_permissions | The permissions requested by the actor process. | long |
| ses.resolution_id | The incident resolution. | keyword |
| ses.resolution_value | The incident resolution value. | keyword |
| ses.resource | The target resource. | keyword |
| ses.restart_required | The device requires a restart in order to complete the disposition identified in the "id" field. | boolean |
| ses.risk_ref_value | The Anti-malware Scan Interface (AMSI) risk level. | long |
| ses.rule_criteria_target | The target of the rule criteria. | keyword |
| ses.rule_name | The rule that triggered the incident. | keyword |
| ses.scan_end | The time that the scan ended. | date |
| ses.scan_name | The administrator-supplied or application-generated name of the scan. . | keyword |
| ses.scan_start | The time that the scan started. | date |
| ses.scan_type_id | The type of scan. | keyword |
| ses.scan_type_value | The type value of scan. | keyword |
| ses.scan_uid | The identifier of this Scan. | keyword |
| ses.schedule_uid | The schedule identifier that is associated with this Scan event; required if the scan was initiated by a schedule. | keyword |
| ses.sender_ip | The IP address of the sender, in either IPv4 or IPv6 format. | ip |
| ses.seq_num | A 32-bit positive number that indicates the order of events sent by the client. | long |
| ses.session.auth_protocol_id | The authentication protocol. | keyword |
| ses.session.auth_protocol_value | The authentication protocol value. | keyword |
| ses.session.cleartext_credentials | Indicates whether the credentials were passed in clear text.Note: True if the credentials were passed in a clear text protocol such as FTP or TELNET, or if Windows detected that a user's logon password was passed to the authentication package in clear text. | boolean |
| ses.session.direction_id | The direction of the initiated traffic. | keyword |
| ses.session.id | The unique session identifier, as reported by the operating system. | long |
| ses.session.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.session.logon_type_id | The type of session logon. | keyword |
| ses.session.port | The port that the remote session connects to; applicable for remote sessions only. | long |
| ses.session.previous_users | An ordered list of the previous user names used within the session, from latest to earliest. | keyword |
| ses.session.remote | The indication of whether the session is remote. | boolean |
| ses.session.remote_host | The host name of the device associated with the remote session. | keyword |
| ses.session.remote_ip | The IP address of the device associated with the remote session. The format is either IPv4 or IPv6. | ip |
| ses.session.user.account_disabled | The indication of whether the user's account is disabled. | boolean |
| ses.session.user.cloud_resource_uid | The cloud resource unique identifier of this user. | keyword |
| ses.session.user.domain | The domain where the user is defined. | keyword |
| ses.session.user.external_account_uid | The user's external account unique identifier. | keyword |
| ses.session.user.external_uid | The user's external unique identifier. | keyword |
| ses.session.user.full_name | The full name of the user. | keyword |
| ses.session.user.groups | The administrative groups to which the user belongs. | keyword |
| ses.session.user.home | The user's home directory. | keyword |
| ses.session.user.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.session.user.logon_name | The name of the authenticated principal that is associated with the event. | keyword |
| ses.session.user.name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.session.user.password_expires | The indication of whether the user's password is configured to expire. | boolean |
| ses.session.user.shell | The user's login shell. | keyword |
| ses.session.user.sid | The user security identifier (SID). | keyword |
| ses.session.user.uid | The unique identifier of the user associated with the event. | keyword |
| ses.session_id | The user session ID from which the override action was performed (Windows only). | keyword |
| ses.session_uid | The unique ID of the user session that pertains to the event. | keyword |
| ses.sessions.auth_protocol_id | The authentication protocol. | keyword |
| ses.sessions.cleartext_credentials | Indicates whether the credentials were passed in clear text.Note: True if the credentials were passed in a clear text protocol such as FTP or TELNET, or if Windows detected that a user's logon password was passed to the authentication package in clear text. | boolean |
| ses.sessions.direction_id | The direction of the initiated traffic. | keyword |
| ses.sessions.id | The unique session identifier, as reported by the operating system. | long |
| ses.sessions.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.sessions.logon_type_id | The type of session logon. | keyword |
| ses.sessions.port | The port that the remote session connects to; applicable for remote sessions only. | long |
| ses.sessions.previous_users | An ordered list of the previous user names used within the session, from latest to earliest. | keyword |
| ses.sessions.remote | The indication of whether the session is remote. | boolean |
| ses.sessions.remote_host | The host name of the device associated with the remote session. | keyword |
| ses.sessions.remote_ip | The IP address of the device associated with the remote session. The format is either IPv4 or IPv6. | ip |
| ses.sessions.user.account_disabled | The indication of whether the user's account is disabled. | boolean |
| ses.sessions.user.cloud_resource_uid | The cloud resource unique identifier of this user. | keyword |
| ses.sessions.user.domain | The domain where the user is defined. | keyword |
| ses.sessions.user.external_account_uid | The user's external account unique identifier. | keyword |
| ses.sessions.user.external_uid | The user's external unique identifier. | keyword |
| ses.sessions.user.full_name | The full name of the user. | keyword |
| ses.sessions.user.groups | The administrative groups to which the user belongs. | keyword |
| ses.sessions.user.home | The user's home directory. | keyword |
| ses.sessions.user.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.sessions.user.logon_name | The name of the authenticated principal that is associated with the event. | keyword |
| ses.sessions.user.name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.sessions.user.password_expires | The indication of whether the user's password is configured to expire. | boolean |
| ses.sessions.user.shell | The user's login shell. | keyword |
| ses.sessions.user.sid | The user security identifier (SID). | keyword |
| ses.sessions.user.uid | The unique identifier of the user associated with the event. | keyword |
| ses.severity_id | The severity of the event. | keyword |
| ses.severity_value | The severity value of the event. | keyword |
| ses.source.facility | The subsystem or application that is providing the event data. | keyword |
| ses.source.facility_detail | Additional detail about the source facility. For example, details could include a the name of a particular application instance (such as a database name) or a path to a monitored log file. | keyword |
| ses.source.facility_uid | The unique identifier of the facility. | keyword |
| ses.source.type_id | The type of the source from which the event was derived. | keyword |
| ses.startup_app.cmd_line | The command line used to launch the startup application, service, process or job. | keyword |
| ses.startup_app.desc | The description of the startup application. | keyword |
| ses.startup_app.device_os_integrity_protection | The operating system integrity protection status. | boolean |
| ses.startup_app.file.accessed | The time that the file was last accessed. | date |
| ses.startup_app.file.accessor | The name of the user who last accessed the object. | keyword |
| ses.startup_app.file.attribute_ids | The array of file attributes. | keyword |
| ses.startup_app.file.attributes | The bitmask value that represents the file attributes. | long |
| ses.startup_app.file.company_name | The name of the company that published the file. | keyword |
| ses.startup_app.file.confidentiality_id | The file content confidentiality indicator. | keyword |
| ses.startup_app.file.content_type.family_id | The top level file classification. | keyword |
| ses.startup_app.file.content_type.subtype | The specific format for the type of data. | keyword |
| ses.startup_app.file.content_type.type_id | The general type of a file. | keyword |
| ses.startup_app.file.created | The time that the file was created. | date |
| ses.startup_app.file.creator | The name of the user who created the file. | keyword |
| ses.startup_app.file.creator_process | The name of the process that created (or downloaded) the file or module. | keyword |
| ses.startup_app.file.desc | The description of the file, as returned by file system. | keyword |
| ses.startup_app.file.folder | The parent folder in which the file resides. | keyword |
| ses.startup_app.file.folder_uid | The unique identifier of the folder in which the file resides. | keyword |
| ses.startup_app.file.is_system | The indication of whether the object is part of the operating system. | boolean |
| ses.startup_app.file.md5 | The MD5 checksum of the object content. | keyword |
| ses.startup_app.file.mime_type | The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable. | keyword |
| ses.startup_app.file.modified | The time when the file was last modified. | date |
| ses.startup_app.file.modifier | The name of the user who last modified the file. | keyword |
| ses.startup_app.file.name | The name of the file. | keyword |
| ses.startup_app.file.normalized_path | The CSIDL normalized path name. | keyword |
| ses.startup_app.file.original_name | The original name of the file. | keyword |
| ses.startup_app.file.owner | The owner of the file. | keyword |
| ses.startup_app.file.parent_name | The name of the file that contains this file. | keyword |
| ses.startup_app.file.parent_sha2 | The SHA-256 checksum of the parent file. | keyword |
| ses.startup_app.file.path | The full path to the file. | keyword |
| ses.startup_app.file.product_name | The name of the product that includes the file. | keyword |
| ses.startup_app.file.product_path | The path to the product that includes the file. | keyword |
| ses.startup_app.file.rep_discovered_band | The discovery fuzzed band number, expressed as the number of days since discovery. | long |
| ses.startup_app.file.rep_discovered_date | The Symantec discovery date of the reputed file or URL. | date |
| ses.startup_app.file.rep_prevalence | The file reputation prevalence, as provided by a reputation query. | long |
| ses.startup_app.file.rep_prevalence_band | The file reputation prevalence fuzzed band number. | long |
| ses.startup_app.file.rep_score | The reputation score of the file. | long |
| ses.startup_app.file.rep_score_band | The file reputation score fuzzed band number. | long |
| ses.startup_app.file.security_descriptor | The object security descriptor. | keyword |
| ses.startup_app.file.sha1 | The SHA-1 checksum of the object content. | keyword |
| ses.startup_app.file.sha2 | The SHA-256 checksum of the object content. | keyword |
| ses.startup_app.file.signature_company_name | The company name on the certificate that signed the file. | keyword |
| ses.startup_app.file.signature_created_date | The date and time when the signature was created. | date |
| ses.startup_app.file.signature_developer_uid | The developer ID on the certificate that signed the file. | keyword |
| ses.startup_app.file.signature_fingerprints.algorithm | The algorithm used to create the fingerprint. | keyword |
| ses.startup_app.file.signature_fingerprints.value | The fingerprint value.Note: The submission format is a lower-case string. | keyword |
| ses.startup_app.file.signature_issuer | The issuer of the object signature. | keyword |
| ses.startup_app.file.signature_level_id | A numeric representation of the signature level. The signature levels are defined by STAR. | keyword |
| ses.startup_app.file.signature_serial_number | The object serial number. | keyword |
| ses.startup_app.file.signature_value | The digital signature bitmask. | long |
| ses.startup_app.file.signature_value_ids | The array of signature values as derived from the Signature Bits. | keyword |
| ses.startup_app.file.size | The size of the object, in bytes. | long |
| ses.startup_app.file.size_compressed | The compressed size of the object, in bytes. | long |
| ses.startup_app.file.src_ip | The IP address of the host where the file resides. | ip |
| ses.startup_app.file.src_name | The name of the host where the file resides. | keyword |
| ses.startup_app.file.type_id | The file type. | keyword |
| ses.startup_app.file.uid | The unique identifier of the file as defined by the storage system, such the file system file ID. | keyword |
| ses.startup_app.file.url.categories | The array of URL categories. | keyword |
| ses.startup_app.file.url.category_ids | The array of URL categories. | keyword |
| ses.startup_app.file.url.extension | Document extension from the original URL requested. | keyword |
| ses.startup_app.file.url.host | The URL host as extracted from the URL. | keyword |
| ses.startup_app.file.url.method | The HTTP method used in the URL request. | keyword |
| ses.startup_app.file.url.parent_categories | The array of parent URL categories. | keyword |
| ses.startup_app.file.url.path | The URL path as extracted from the URL. | keyword |
| ses.startup_app.file.url.port | The URL port. | long |
| ses.startup_app.file.url.provider | The origin of the reputation and category information. | keyword |
| ses.startup_app.file.url.query | The query portion of the URL. | keyword |
| ses.startup_app.file.url.referrer | The address accessed prior to this one. | keyword |
| ses.startup_app.file.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.startup_app.file.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.startup_app.file.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.startup_app.file.url.scheme | The scheme portion of the URL. | keyword |
| ses.startup_app.file.url.text | The URL. | keyword |
| ses.startup_app.file.version | The file version. | keyword |
| ses.startup_app.file.xattributes | An unordered collection of zero or more name/value pairs where each pair represents a file or directory extended attribute. | flattened |
| ses.startup_app.name | The unique name of the startup application. | keyword |
| ses.startup_app.normalized_cmd_line | The CSIDL normalized command line used to launch the startup application, service, process or job (Windows only). | keyword |
| ses.startup_app.run_state_id | The service state. | keyword |
| ses.startup_app.start_id | The start type of the service or startup application. | keyword |
| ses.startup_app.subtype_ids | Array of Category Identifiers. | keyword |
| ses.startup_app.subtypes | Array of Category Identifiers. | keyword |
| ses.startup_app.type_ids | The startup application type identifiers. | keyword |
| ses.startup_app.vendor | ID of the Vendor who signed the system extension. | keyword |
| ses.state_id | The incident state. | keyword |
| ses.state_value | The incident state value. | keyword |
| ses.status_detail | The status details. | keyword |
| ses.status_exception | The operating system exception message. | keyword |
| ses.status_id | The cross-platform event status. | keyword |
| ses.status_os | The operating system result code. | keyword |
| ses.status_os_src | The indication of whether the OS Code (status_os) returned to the application for the requested operation was returned by the OS (0) or generated by the security product (1). | long |
| ses.status_stack_trace | The list of calls that the application was making when an exception was thrown. | keyword |
| ses.status_thread_name | The name of the thread that pertains to the status. | keyword |
| ses.status_value | The cross-platform event status value. | keyword |
| ses.stic_has_pii | The indication of whether the event has any Personally Identifiable Information (PII). | boolean |
| ses.stic_hw_uid | The device hardware ID. | keyword |
| ses.stic_ip_hash | The STIC hash of the IP address. | keyword |
| ses.stic_legacy_ent_uids | The list of Enterprise IDs (related to license entitlement) that have been associated with the device. | keyword |
| ses.stic_legacy_hw_uids | The list of Hardware IDs that have been associated with the device. | keyword |
| ses.stic_legacy_uids | The list of Machine IDs that have been associated with the device. | keyword |
| ses.stic_schema_id | The telemetry submission control data identifier, represented as an 8 byte hexadecimal string. | keyword |
| ses.stic_uid | The device Machine ID. | keyword |
| ses.stic_version | The version of the STIC library. | keyword |
| ses.subfeature_name | The name of the sub-feature originating the event. | keyword |
| ses.summary | The incident summary that was originally produced using Generative AI technology. | keyword |
| ses.suspected_breach | The indication of whether a breach is suspected. | boolean |
| ses.target | The target is the object of the Action. | flattened |
| ses.target_name | The target name. | keyword |
| ses.threat.classification | The threat classification. | keyword |
| ses.threat.classification_ids | The array of threat classifications. | keyword |
| ses.threat.cve_uid | The common vulnerabilities and exposures (CVE) identifier. | keyword |
| ses.threat.id | The threat identifier as reported by the detection engine; for example a virus id or an IPS signature id. | long |
| ses.threat.name | The threat name as reported by the detection engine. | keyword |
| ses.threat.provider | The origin of the reputation and category information. | keyword |
| ses.threat.risk_id | The cumulative risk rating of the threat as defined by the Foresight policy. | keyword |
| ses.threat.risk_value | The cumulative risk rating value of the threat as defined by the Foresight policy. | keyword |
| ses.threat.sub_id | The threat sub identifier as reported by the detection engine. | keyword |
| ses.threat.type_id | The threat type as reported by the detection engine. | keyword |
| ses.threat.type_value | The threat type value as reported by the detection engine. | keyword |
| ses.threats.classification | The threat classification. | keyword |
| ses.threats.classification_ids | The array of threat classifications. | keyword |
| ses.threats.cve_uid | The common vulnerabilities and exposures (CVE) identifier. | keyword |
| ses.threats.id | The threat identifier as reported by the detection engine; for example a virus id or an IPS signature id. | long |
| ses.threats.name | The threat name as reported by the detection engine. | keyword |
| ses.threats.provider | The origin of the reputation and category information. | keyword |
| ses.threats.risk_id | The cumulative risk rating of the threat as defined by the Foresight policy. | keyword |
| ses.threats.sub_id | The threat sub identifier as reported by the detection engine. | keyword |
| ses.threats.type_id | The threat type as reported by the detection engine. | keyword |
| ses.time | The event occurrence time (Device Time) adjusted to the server clock. | date |
| ses.timezone | Returns a Long value that represents the difference in minutes of between the local time in this time zone and the Coordinated Universal Time (UTC). | long |
| ses.total | The total number of items that were scanned; zero if no items were scanned. Required for all events except START. | long |
| ses.type | The event type. | keyword |
| ses.type_id | The event type id. | keyword |
| ses.url.categories | The array of URL categories. | keyword |
| ses.url.category_ids | The array of URL categories. | keyword |
| ses.url.extension | Document extension from the original URL requested. | keyword |
| ses.url.host | The URL host as extracted from the URL. | keyword |
| ses.url.method | The HTTP method used in the URL request. | keyword |
| ses.url.parent_categories | The array of parent URL categories. | keyword |
| ses.url.path | The URL path as extracted from the URL. | keyword |
| ses.url.port | The URL port. | long |
| ses.url.provider | The origin of the reputation and category information. | keyword |
| ses.url.query | The query portion of the URL. | keyword |
| ses.url.referrer | The address accessed prior to this one. | keyword |
| ses.url.referrer_categories | All content categories of the Referrer header URL. | keyword |
| ses.url.referrer_category_ids | The array of Referrer URL categories IDs. | keyword |
| ses.url.rep_score_id | The reputation score of the URL. | keyword |
| ses.url.scheme | The scheme portion of the URL. | keyword |
| ses.url.text | The URL. | keyword |
| ses.user.account_disabled | The indication of whether the user's account is disabled. | boolean |
| ses.user.cloud_resource_uid | The cloud resource unique identifier of this user. | keyword |
| ses.user.domain | The domain where the user is defined. | keyword |
| ses.user.external_account_uid | The user's external account unique identifier. | keyword |
| ses.user.external_uid | The user's external unique identifier. | keyword |
| ses.user.full_name | The full name of the user. | keyword |
| ses.user.groups | The administrative groups to which the user belongs. | keyword |
| ses.user.home | The user's home directory. | keyword |
| ses.user.is_admin | The indication of whether the user or user session is admin/root. | boolean |
| ses.user.logon_name | The name of the authenticated principal that is associated with the event. | keyword |
| ses.user.name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.user.password_expires | The indication of whether the user's password is configured to expire. | boolean |
| ses.user.shell | The user's login shell. | keyword |
| ses.user.sid | The user security identifier (SID). | keyword |
| ses.user.uid | The unique identifier of the user associated with the event. | keyword |
| ses.user_name | The name of the user that originated or caused the event (if the event involves a user) or the user on whose behalf the event occurred. | keyword |
| ses.user_uid | The unique identifier of the user associated with the event. | keyword |
| ses.uuid | The system-assigned unique identifier of an event occurrence. | keyword |
| ses.verdict_id | The outcome of the Scan. | keyword |
| ses.verdict_value | The outcome value of the Scan. | keyword |
| ses.version | The event type version, in the form major.minor. | keyword |


### Incident

This is the `Incident` dataset.

#### Example

An example event for `incident` looks as following:

```json
{
    "@timestamp": "2023-04-26T21:46:10.400Z",
    "agent": {
        "ephemeral_id": "ddc4c842-e33f-4613-bed9-a71411bb8eec",
        "id": "8d5f9e50-329d-42d2-af28-c8823fcbb3c4",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "symantec_endpoint_security.incident",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8d5f9e50-329d-42d2-af28-c8823fcbb3c4",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "created": "2023-04-26T21:46:10.400Z",
        "dataset": "symantec_endpoint_security.incident",
        "id": "8e7edfb1-27d2-4837-98ca-e7d794119c3b",
        "ingested": "2024-06-25T12:40:47Z",
        "kind": "alert",
        "original": "{\"category_id\":1,\"conclusion\":\"Suspicious Activity\",\"created\":\"2023-04-26T21:46:10.400+00:00\",\"customer_uid\":\"TEST-JvOsaJktSS-eyL-dXhxOvA\",\"detection_type\":\"Advanced Analytics\",\"device_time\":1682545570400,\"domain_uid\":\"TEST-ZBg_IqnyTAijNjP2BOOcuw\",\"event_id\":8075004,\"id\":4,\"incident_uid\":\"8e7edfb1-27d2-4837-98ca-e7d794119c3b\",\"incident_url\":\"https://sep.securitycloud.symantec.com/v2/incidents/incidentListing/8e7edfb1-27d2-4837-98ca-e7d794119c3b/details\",\"message\":\"Victim-2:Signed Binary Proxy Execution, Deobfuscate/Decode Files or Information, Command and Scripting Interpreter: PowerShell, System Services: Service Execution\",\"modified\":\"2023-04-26T22:01:58.648+00:00\",\"priority_id\":4,\"product_name\":\"Symantec Integrated Cyber Defense Manager\",\"product_uid\":\"31B0C880-0229-49E8-94C5-48D56B1BD7B9\",\"ref_incident_uid\":102110,\"remediation\":\"Investigate further activity at the endpoint by downloading a full dump of the endpoint's recorded data. Give particular attention to activities performed by cmd.exe.\",\"resolution_id\":1,\"rule_name\":\"Advanced Attack Technique\",\"severity_id\":4,\"state_id\":1,\"suspected_breach\":\"Yes\",\"time\":1682545570400,\"type\":\"INCIDENT_CREATION\",\"type_id\":8075,\"version\":\"1.0\"}",
        "provider": "Symantec Integrated Cyber Defense Manager",
        "reason": "Suspicious Activity",
        "severity": 4,
        "type": [
            "info"
        ],
        "url": "https://sep.securitycloud.symantec.com/v2/incidents/incidentListing/8e7edfb1-27d2-4837-98ca-e7d794119c3b/details"
    },
    "http": {
        "version": "1.0"
    },
    "input": {
        "type": "cel"
    },
    "message": "Victim-2:Signed Binary Proxy Execution, Deobfuscate/Decode Files or Information, Command and Scripting Interpreter: PowerShell, System Services: Service Execution",
    "rule": {
        "name": "Advanced Attack Technique"
    },
    "ses": {
        "incident": {
            "category": "Security",
            "category_id": "1",
            "conclusion": "Suspicious Activity",
            "created": "2023-04-26T21:46:10.400Z",
            "customer_uid": "TEST-JvOsaJktSS-eyL-dXhxOvA",
            "detection_type": "Advanced Analytics",
            "device_time": "2023-04-26T21:46:10.400Z",
            "domain_uid": "TEST-ZBg_IqnyTAijNjP2BOOcuw",
            "event": "Incident Creation: Logged",
            "event_id": "8075004",
            "id": "4",
            "incident_uid": "8e7edfb1-27d2-4837-98ca-e7d794119c3b",
            "incident_url": "https://sep.securitycloud.symantec.com/v2/incidents/incidentListing/8e7edfb1-27d2-4837-98ca-e7d794119c3b/details",
            "message": "Victim-2:Signed Binary Proxy Execution, Deobfuscate/Decode Files or Information, Command and Scripting Interpreter: PowerShell, System Services: Service Execution",
            "modified": "2023-04-26T22:01:58.648Z",
            "outcome": "Logged",
            "priority": "Critical",
            "priority_id": "4",
            "product_name": "Symantec Integrated Cyber Defense Manager",
            "product_uid": "31B0C880-0229-49E8-94C5-48D56B1BD7B9",
            "ref_incident_uid": "102110",
            "remediation": "Investigate further activity at the endpoint by downloading a full dump of the endpoint's recorded data. Give particular attention to activities performed by cmd.exe.",
            "resolution": "Insufficient data",
            "resolution_id": "1",
            "rule_name": "Advanced Attack Technique",
            "severity": "Major",
            "severity_id": 4,
            "state": "New",
            "state_id": "1",
            "suspected_breach": true,
            "time": "2023-04-26T21:46:10.400Z",
            "type": "INCIDENT_CREATION",
            "type_id": "8075",
            "version": "1.0"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "ses-incident"
    ],
    "url": {
        "domain": "sep.securitycloud.symantec.com",
        "original": "https://sep.securitycloud.symantec.com/v2/incidents/incidentListing/8e7edfb1-27d2-4837-98ca-e7d794119c3b/details",
        "path": "/v2/incidents/incidentListing/8e7edfb1-27d2-4837-98ca-e7d794119c3b/details",
        "scheme": "https"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| ses.incident.category |  | keyword |
| ses.incident.category_id | Event type category. | keyword |
| ses.incident.conclusion |  | keyword |
| ses.incident.created | The creation time of the incident in ISO 8601 format. | date |
| ses.incident.customer_uid | Customer id. | keyword |
| ses.incident.detection_type |  | keyword |
| ses.incident.device_time | The time that the event occurred at the device. | date |
| ses.incident.domain_uid | Domain Id. | keyword |
| ses.incident.event |  | keyword |
| ses.incident.event_id | ID that identifies the semantics, structure and outcome. | keyword |
| ses.incident.id | The outcome of the event. | keyword |
| ses.incident.incident_uid | A unique identifier for this incident. | keyword |
| ses.incident.incident_url | The url pointing to ICDM console for this incident details. | keyword |
| ses.incident.log_time |  | date |
| ses.incident.message |  | keyword |
| ses.incident.modified |  | date |
| ses.incident.outcome |  | keyword |
| ses.incident.priority |  | keyword |
| ses.incident.priority_id |  | keyword |
| ses.incident.product_name | The name of the product originating the incident. | keyword |
| ses.incident.product_uid | The unique identifier of the product originating the incident. | keyword |
| ses.incident.ref_incident_uid | User friendly ID for this incident_uid. | keyword |
| ses.incident.remediation | Recommended action. | keyword |
| ses.incident.resolution |  | keyword |
| ses.incident.resolution_id |  | keyword |
| ses.incident.rule_name | The rule that triggered the incident. | keyword |
| ses.incident.severity |  | keyword |
| ses.incident.severity_id |  | long |
| ses.incident.state |  | keyword |
| ses.incident.state_id |  | keyword |
| ses.incident.suspected_breach |  | boolean |
| ses.incident.time | The event occurrence time. | date |
| ses.incident.type | Event type. | keyword |
| ses.incident.type_id |  | keyword |
| ses.incident.version | API version in the form major.minor. | keyword |

