# Cloudflare Logpush

## Overview

The [Cloudflare Logpush](https://www.cloudflare.com/) integration allows you to monitor Access Request, Audit, CASB, Device Posture, DNS, DNS Firewall, Firewall Event, Gateway DNS, Gateway HTTP, Gateway Network, HTTP Request, Magic IDS, NEL Report, Network Analytics, Sinkhole HTTP, Spectrum Event, Network Session and Workers Trace Events logs. Cloudflare is a content delivery network and DDoS mitigation company. Cloudflare provides a network designed to make everything you connect to the Internet secure, private, fast, and reliable; secure your websites, APIs, and Internet applications; protect corporate networks, employees, and devices; and write and deploy code that runs on the network edge.

The Cloudflare Logpush integration can be used in the following modes to collect data:
- HTTP Endpoint mode - Cloudflare pushes logs directly to an HTTP endpoint hosted by your Elastic Agent.
- AWS S3 polling mode - Cloudflare writes data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode - Cloudflare writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.
- Azure Blob Storage polling mode - Cloudflare writes data to Azure Blob Storage and Elastic Agent polls the Azure Blob Storage containers by listing its contents and reading new files.
- Google Cloud Storage polling mode - Cloudflare writes data to Google Cloud Storage and Elastic Agent polls the GCS buckets by listing its contents and reading new files.

For example, you could use the data from this integration to know which websites have the highest traffic, which areas have the highest network traffic, or observe mitigation statistics.

## Data streams

The Cloudflare Logpush integration collects logs for the following types of events. For more information on each dataset, refer to the Logs reference section at the end of this page.

### Zero Trust events

**Access Request**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/access_requests/).

**Audit**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/audit_logs/).

**CASB findings**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/casb_findings/).

**Device Posture Results**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/device_posture_results/).

**DLP Forensic Copies**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/dlp_forensic_copies/).

**Email Security Alerts**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/email_security_alerts/).

**Gateway DNS**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/gateway_dns/).

**Gateway HTTP**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/gateway_http/).

**Gateway Network**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/gateway_network/).

**Zero Trust Network Session**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/zero_trust_network_sessions/).

### Non Zero Trust events

**DNS**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/dns_logs/).

**DNS Firewall**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/dns_firewall_logs/).

**Firewall Event**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events/).

**HTTP Request**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/).

**Magic IDS**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/magic_ids_detections/).

**NEL Report**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/nel_reports/).

**Network Analytics**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/network_analytics_logs/).

**Page Shield events**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/page_shield_events/).

**Sinkhole HTTP**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/sinkhole_http_logs/).

**Spectrum Event**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/spectrum_events/).

**Workers Trace Events**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/workers_trace_events/).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has been tested against **Cloudflare version v4**.

**Note**: It is recommended to use AWS SQS for Cloudflare Logpush.

## Setup

### Collect data from AWS S3 Bucket

- Configure [Cloudflare Logpush to Amazon S3](https://developers.cloudflare.com/logs/get-started/enable-destinations/aws-s3/) to send Cloudflare's data to an AWS S3 bucket.
- The default values of the "Bucket List Prefix" are listed below. However, users can set the parameter "Bucket List Prefix" according to their requirements.

  | Data Stream Name           | Bucket List Prefix     |
  | -------------------------- | ---------------------- |
  | Access Request             | access_request         |
  | Audit Logs                 | audit_logs             |
  | CASB findings              | casb                   |
  | Device Posture Results     | device_posture         |
  | DNS                        | dns                    |
  | DNS Firewall               | dns_firewall           |
  | Firewall Event             | firewall_event         |
  | Gateway DNS                | gateway_dns            |
  | Gateway HTTP               | gateway_http           |
  | Gateway Network            | gateway_network        |
  | HTTP Request               | http_request           |
  | Magic IDS                  | magic_ids              |
  | NEL Report                 | nel_report             |
  | Network Analytics          | network_analytics_logs |
  | Zero Trust Network Session | network_session        |
  | Sinkhole HTTP              | sinkhole_http          |
  | Spectrum Event             | spectrum_event         |
  | Workers Trace Events       | workers_trace          |

### Collect data from AWS SQS

1. If Logpush forwarding to an AWS S3 Bucket hasn't been configured, then first setup an AWS S3 Bucket as mentioned in the above documentation.
2. Follow the steps below for each Logpush data stream that has been enabled:
     1. Create an SQS queue
         - To setup an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Amazon documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
         - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
     2. Setup event notification from the S3 bucket using the instructions [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html). Use the following settings:
        - Event type: `All object create events` (`s3:ObjectCreated:*`)
         - Destination: SQS Queue
         - Prefix (filter): enter the prefix for this Logpush data stream, e.g. `audit_logs/`
         - Select the SQS queue that has been created for this data stream

 **Note**:
  - A separate SQS queue and S3 bucket notification is required for each enabled data stream.
  - Permissions for the above AWS S3 bucket and SQS queues should be configured according to the [Filebeat S3 input documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#_aws_permissions_2)
  - Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.

### Collect data from S3-Compatible Cloudflare R2 Buckets

- Configure the [Data Forwarder](https://developers.cloudflare.com/logs/get-started/enable-destinations/r2/) to push logs to Cloudflare R2.

**Note**:
- When creating the API token, make sure it has [Admin permissions](https://developers.cloudflare.com/r2/api/s3/tokens/#permissions). This is needed to list buckets and view bucket configuration.

When configuring the integration to read from S3-Compatible Buckets such as Cloudflare R2, the following steps are required:
- Enable the toggle `Collect logs via S3 Bucket`.
- Make sure that the Bucket Name is set.
- Although you have to create an API token, that token should not be used for authentication with the S3 API. You just have to set the Access Key ID and Secret Access Key.
- Set the endpoint URL which can be found in Bucket Details. Endpoint should be a full URI that will be used as the API endpoint of the service. For Cloudflare R2 buckets, the URI is typically in the form of `https(s)://<accountid>.r2.cloudflarestorage.com`.
- Bucket Prefix is optional for each data stream.

**Note**:
- The AWS region is not a requirement when configuring the R2 Bucket, as the region for any R2 Bucket is `auto` from the [API perspective](https://developers.cloudflare.com/r2/api/s3/api/#bucket-region). However, the error `failed to get AWS region for bucket: operation error S3: GetBucketLocation` may appear when starting the integration. The reason is that `GetBucketLocation` is the first request made to the API when starting the integration, so any configuration, credentials or permissions errors would cause this. Focus on the API response error to identify the original issue.

### Collect data from GCS Buckets

- Configure the [Data Forwarder](https://developers.cloudflare.com/logs/get-started/enable-destinations/google-cloud-storage/) to ingest data into a GCS bucket.
- Configure the GCS bucket names and credentials along with the required configurations under the "Collect Cloudflare Logpush logs via Google Cloud Storage" section. 
- Make sure the service account and authentication being used, has proper levels of access to the GCS bucket [Manage Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys/)

**Note**:
- The GCS input currently does not support fetching of buckets using bucket prefixes, so the bucket names have to be configured manually for each data stream.
- The GCS input currently accepts a service account JSON key or a service account JSON file for authentication.
- The GCS input currently supports JSON/NDJSON data.

### Collect data from Azure Blob Storage

- [Enable Microsoft Azure](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/azure/) to ingest data into Azure Blob Storage containers.
- Configure Azure Blob Storage container names and credentials along with the required configurations under the "Collect Cloudflare Logpush logs via Azure Blob Storage" section. 
- Make sure the storage account and authentication being used, has proper levels of access to the Azure Blob Storage Container. Please follow the documentation [here](https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-data-operations-portal) for more details.
- If you want to use RBAC for your account please follow the documentation [here](https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-access-azure-active-directory).

**Note**:
- The Azure Blob Storage input currently does not support fetching of buckets using bucket prefixes, so the bucket names have to be configured manually for each data stream.
- The Azure Blob Storage input currently accepts a service account key (shared credentials key), service account URI (connection string) and OAuth2 credentials for authentication.
- The Azure Blob Storage input currently only supports JSON/NDJSON data.

### Collect data from the Cloudflare HTTP Endpoint

- Refer to [Enable HTTP destination](https://developers.cloudflare.com/logs/get-started/enable-destinations/http/) for Cloudflare Logpush.
- Add same custom header along with its value on both the side for additional security.
- For example, while creating a job along with a header and value for a particular dataset:
```
curl --location --request POST 'https://api.cloudflare.com/client/v4/zones/<ZONE ID>/logpush/jobs' \
--header 'X-Auth-Key: <X-AUTH-KEY>' \
--header 'X-Auth-Email: <X-AUTH-EMAIL>' \
--header 'Authorization: <BASIC AUTHORIZATION>' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name":"<public domain>",
    "destination_conf": "https://<public domain>:<public port>/<dataset path>?header_Content-Type=application/json&header_<secret_header>=<secret_value>",
    "dataset": "audit",
    "logpull_options": "fields=RayID,EdgeStartTimestamp&timestamps=rfc3339"
}'
```

**Note**:
- The destination_conf parameter inside the request data should set the Content-Type header to `application/json`. This is the content type that the HTTP endpoint expects for incoming events.
- Default port for the HTTP Endpoint is _9560_.
- When using the same port for more than one dataset, be sure to specify different dataset paths.
- To enable request ACKing, add a `wait_for_completion_timeout` request query with the timeout for an ACK. See the [HTTP Endpoint documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-http_endpoint.html) for details.

### Enable the integration in Elastic

1. In Kibana, go to **Management** > **Integrations**.
2. In the integrations search bar type **Cloudflare Logpush**.
3. Click the **Cloudflare Logpush** integration from the search results.
4. Click the **Add Cloudflare Logpush** button to add Cloudflare Logpush integration.
5. Enable the Integration with the HTTP Endpoint, AWS S3 input or GCS input.
6. Under the AWS S3 input, there are two types of inputs: using AWS S3 Bucket or using SQS.
7. Configure Cloudflare to send logs to the Elastic Agent via HTTP Endpoint, or any R2, AWS or GCS Bucket following the specific guides above.

## Logs reference

### access_request

This is the `access_request` dataset.

#### Example

An example event for `access_request` looks as following:

```json
{
    "@timestamp": "2023-05-23T17:18:33.000Z",
    "agent": {
        "ephemeral_id": "2b4df883-4b38-4a00-a2aa-1c7998be5b86",
        "id": "7cc81c22-a2a4-4178-a575-95fd38a17b40",
        "name": "elastic-agent-91273",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "client": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.93"
    },
    "cloudflare_logpush": {
        "access_request": {
            "action": "login",
            "allowed": true,
            "app": {
                "domain": "partner-zt-logs.cloudflareaccess.com/warp",
                "uuid": "123e4567-e89b-12d3-a456-426614174000"
            },
            "client": {
                "ip": "67.43.156.93"
            },
            "connection": "onetimepin",
            "country": "us",
            "ray": {
                "id": "00c0ffeeabc12345"
            },
            "request": {
                "prompt": "Please provide your reason for accessing the application.",
                "response": "I need to access the application for work purposes."
            },
            "temp_access": {
                "approvers": [
                    "approver1@example.com",
                    "approver2@example.com"
                ],
                "duration": 7200
            },
            "timestamp": "2023-05-23T17:18:33.000Z",
            "user": {
                "email": "user@example.com",
                "id": "166befbb-00e3-5e20-bd6e-27245333949f"
            }
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.access_request",
        "namespace": "71792",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7cc81c22-a2a4-4178-a575-95fd38a17b40",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "action": "login",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.access_request",
        "id": "00c0ffeeabc12345",
        "ingested": "2025-03-13T20:43:05Z",
        "kind": "event",
        "original": "{\"Action\":\"login\",\"Allowed\":true,\"AppDomain\":\"partner-zt-logs.cloudflareaccess.com/warp\",\"AppUUID\":\"123e4567-e89b-12d3-a456-426614174000\",\"Connection\":\"onetimepin\",\"Country\":\"us\",\"CreatedAt\":1684862313000000000,\"Email\":\"user@example.com\",\"IPAddress\":\"67.43.156.93\",\"PurposeJustificationPrompt\":\"Please provide your reason for accessing the application.\",\"PurposeJustificationResponse\":\"I need to access the application for work purposes.\",\"RayID\":\"00c0ffeeabc12345\",\"TemporaryAccessApprovers\":[\"approver1@example.com\",\"approver2@example.com\"],\"TemporaryAccessDuration\":7200,\"UserUID\":\"166befbb-00e3-5e20-bd6e-27245333949f\"}",
        "type": [
            "access",
            "allowed"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "ip": [
            "67.43.156.93"
        ],
        "user": [
            "166befbb-00e3-5e20-bd6e-27245333949f",
            "user@example.com",
            "approver1@example.com",
            "approver2@example.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-access_request"
    ],
    "url": {
        "domain": "partner-zt-logs.cloudflareaccess.com/warp"
    },
    "user": {
        "email": "user@example.com",
        "id": "166befbb-00e3-5e20-bd6e-27245333949f"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.access_request.action | What type of record is this. login | logout. | keyword |
| cloudflare_logpush.access_request.allowed | If request was allowed or denied. | boolean |
| cloudflare_logpush.access_request.app.domain | The domain of the Application that Access is protecting. | keyword |
| cloudflare_logpush.access_request.app.uuid | Access Application UUID. | keyword |
| cloudflare_logpush.access_request.client.ip | The IP address of the client. | ip |
| cloudflare_logpush.access_request.connection | Identity provider used for the login. | keyword |
| cloudflare_logpush.access_request.country | Request’s country of origin. | keyword |
| cloudflare_logpush.access_request.ray.id | Identifier of the request. | keyword |
| cloudflare_logpush.access_request.request.prompt | Message prompted to the client when accessing the application. | keyword |
| cloudflare_logpush.access_request.request.response | Justification given by the client when accessing the application. | keyword |
| cloudflare_logpush.access_request.temp_access.approvers | List of approvers for this access request. | keyword |
| cloudflare_logpush.access_request.temp_access.duration | Approved duration for this access request. | long |
| cloudflare_logpush.access_request.timestamp | The date and time the corresponding access request was made. | date |
| cloudflare_logpush.access_request.user.email | Email of the user who logged in. | keyword |
| cloudflare_logpush.access_request.user.id | The uid of the user who logged in. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### audit

This is the `audit` dataset.


#### Example

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-11-30T20:19:48.000Z",
    "agent": {
        "ephemeral_id": "4ea9dc4d-b7b3-4be7-92ea-81f40763f7f7",
        "id": "0b87dda3-a048-491f-96c6-e9ebcfa11499",
        "name": "elastic-agent-84381",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "audit": {
            "action": {
                "result": "success",
                "type": "token_create"
            },
            "actor": {
                "email": "user@example.com",
                "id": "enl3j9du8rnx2swwd9l32qots7l54t9s",
                "ip": "81.2.69.142",
                "type": "user"
            },
            "id": "73fd39ed-5aab-4a2a-b93c-c9a4abf0c425",
            "interface": "UI",
            "metadata": {
                "token_name": "test",
                "token_tag": "b7261c49a793a82678d12285f0bc1401"
            },
            "new_value": {
                "key1": "value1",
                "key2": "value2"
            },
            "old_value": {
                "key3": "value4",
                "key4": "value4"
            },
            "owner": {
                "id": "enl3j9du8rnx2swwd9l32qots7l54t9s"
            },
            "resource": {
                "id": "enl3j9du8rnx2swwd9l32qots7l54t9s",
                "type": "account"
            },
            "timestamp": "2021-11-30T20:19:48.000Z"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.audit",
        "namespace": "26626",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0b87dda3-a048-491f-96c6-e9ebcfa11499",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "action": "token_create",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "dataset": "cloudflare_logpush.audit",
        "id": "73fd39ed-5aab-4a2a-b93c-c9a4abf0c425",
        "ingested": "2025-03-13T20:45:31Z",
        "kind": "event",
        "original": "{\"ActionResult\":true,\"ActionType\":\"token_create\",\"ActorEmail\":\"user@example.com\",\"ActorID\":\"enl3j9du8rnx2swwd9l32qots7l54t9s\",\"ActorIP\":\"81.2.69.142\",\"ActorType\":\"user\",\"ID\":\"73fd39ed-5aab-4a2a-b93c-c9a4abf0c425\",\"Interface\":\"UI\",\"Metadata\":{\"token_name\":\"test\",\"token_tag\":\"b7261c49a793a82678d12285f0bc1401\"},\"NewValue\":{\"key1\":\"value1\",\"key2\":\"value2\"},\"OldValue\":{\"key3\":\"value4\",\"key4\":\"value4\"},\"OwnerID\":\"enl3j9du8rnx2swwd9l32qots7l54t9s\",\"ResourceID\":\"enl3j9du8rnx2swwd9l32qots7l54t9s\",\"ResourceType\":\"account\",\"When\":\"2021-11-30T20:19:48Z\"}",
        "outcome": "success",
        "provider": "UI",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ],
        "user": [
            "enl3j9du8rnx2swwd9l32qots7l54t9s"
        ]
    },
    "source": {
        "ip": "81.2.69.142"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-audit"
    ],
    "user": {
        "email": "user@example.com",
        "id": "enl3j9du8rnx2swwd9l32qots7l54t9s"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.audit.action.result | Whether the action was successful. | keyword |
| cloudflare_logpush.audit.action.type | Type of action taken. | keyword |
| cloudflare_logpush.audit.actor.email | Email of the actor. | keyword |
| cloudflare_logpush.audit.actor.id | Unique identifier of the actor in Cloudflare system. | keyword |
| cloudflare_logpush.audit.actor.ip | Physical network address of the actor. | ip |
| cloudflare_logpush.audit.actor.type | Type of user that started the audit trail. | keyword |
| cloudflare_logpush.audit.id | Unique identifier of an audit log. | keyword |
| cloudflare_logpush.audit.interface | Entry point or interface of the audit log. | text |
| cloudflare_logpush.audit.metadata | Additional audit log-specific information, Metadata is organized in key:value pairs, Key and Value formats can vary by ResourceType. | flattened |
| cloudflare_logpush.audit.new_value | Contains the new value for the audited item. | flattened |
| cloudflare_logpush.audit.old_value | Contains the old value for the audited item. | flattened |
| cloudflare_logpush.audit.owner.id | The identifier of the user that was acting or was acted on behalf of. | keyword |
| cloudflare_logpush.audit.resource.id | Unique identifier of the resource within Cloudflare system. | keyword |
| cloudflare_logpush.audit.resource.type | The type of resource that was changed. | keyword |
| cloudflare_logpush.audit.timestamp | When the change happened. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### casb

This is the `casb` dataset.

#### Example

An example event for `casb` looks as following:

```json
{
    "@timestamp": "2023-05-16T10:00:00.000Z",
    "agent": {
        "ephemeral_id": "4f130315-183e-4673-a15f-73acc2754802",
        "id": "4593b0e8-4c7d-413e-842e-88c2814364cf",
        "name": "elastic-agent-66118",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "casb": {
            "asset": {
                "id": "0051N000004mG2LAAA",
                "metadata": {
                    "Address": {
                        "city": "Singapore",
                        "country": "Singapore",
                        "countryCode": "SG"
                    },
                    "Alias": "JDoe",
                    "BannerPhotoUrl": "/profilephoto/001",
                    "CommunityNickname": "Doe.John",
                    "CompanyName": "MyCompany",
                    "DefaultGroupNotificationFrequency": "N",
                    "Department": "521",
                    "DigestFrequency": "D",
                    "Email": "user@example.com",
                    "EmailEncodingKey": "UTF-8",
                    "EmailPreferencesAutoBcc": true,
                    "EmployeeNumber": "18124",
                    "FirstName": "John",
                    "ForecastEnabled": false,
                    "FullPhotoUrl": "https://photos.com/profilephoto/001",
                    "Id": "0051N000004mG2LAAA",
                    "IsActive": false,
                    "IsProfilePhotoActive": false,
                    "LanguageLocaleKey": "en_US",
                    "LastLoginDate": "2021-10-06T06:32:09.000+0000",
                    "LastName": "Doe",
                    "LocaleSidKey": "en_SG",
                    "MediumBannerPhotoUrl": "/profilephoto/001/E",
                    "Name": "John Doe",
                    "Phone": "+3460000000",
                    "ReceivesAdminInfoEmails": true,
                    "ReceivesInfoEmails": true,
                    "SenderEmail": "sender@example.com",
                    "SmallBannerPhotoUrl": "/profilephoto/001/D",
                    "SmallPhotoUrl": "https://photos.com/photo/001",
                    "TimeZoneSidKey": "Asia/Singapore",
                    "Title": "Customer Solutions Engineer",
                    "UserPermissionsCallCenterAutoLogin": false,
                    "UserPermissionsInteractionUser": true,
                    "UserPermissionsMarketingUser": false,
                    "UserPermissionsOfflineUser": false,
                    "UserPermissionsSupportUser": false,
                    "UserRoleId": "00E2G000001E",
                    "UserType": "Standard",
                    "attributes": {
                        "type": "User",
                        "url": "/services/data/userID"
                    }
                },
                "name": "John Doe",
                "url": "https://example.com/resource"
            },
            "finding": {
                "id": "6b187be4-2dd5-42c5-a37b-111111111111",
                "type": {
                    "id": "a2790c4f-03f5-449f-b209-5f4447f417aa",
                    "name": "Salesforce User Sending Email with Different Email Address",
                    "severity": "Medium"
                }
            },
            "integration": {
                "id": "c772678d-5cf1-4c73-bf3f-111111111111",
                "name": "Salesforce Testing",
                "policy_vendor": "Salesforce Connection"
            },
            "timestamp": "2023-05-16T10:00:00.000Z"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.casb",
        "namespace": "17784",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "4593b0e8-4c7d-413e-842e-88c2814364cf",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.casb",
        "id": "6b187be4-2dd5-42c5-a37b-111111111111",
        "ingested": "2025-03-13T20:47:53Z",
        "kind": "event",
        "original": "{\"AssetDisplayName\":\"John Doe\",\"AssetExternalID\":\"0051N000004mG2LAAA\",\"AssetLink\":\"https://example.com/resource\",\"AssetMetadata\":{\"AccountId\":null,\"Address\":{\"city\":\"Singapore\",\"country\":\"Singapore\",\"countryCode\":\"SG\",\"geocodeAccuracy\":null,\"latitude\":null,\"longitude\":null,\"postalCode\":null,\"state\":null,\"stateCode\":null,\"street\":null},\"Alias\":\"JDoe\",\"BadgeText\":\"\",\"BannerPhotoUrl\":\"/profilephoto/001\",\"CallCenterId\":null,\"CommunityNickname\":\"Doe.John\",\"CompanyName\":\"MyCompany\",\"ContactId\":null,\"DefaultGroupNotificationFrequency\":\"N\",\"Department\":\"521\",\"DigestFrequency\":\"D\",\"Division\":null,\"Email\":\"user@example.com\",\"EmailEncodingKey\":\"UTF-8\",\"EmailPreferencesAutoBcc\":true,\"EmployeeNumber\":\"18124\",\"Extension\":null,\"Fax\":null,\"FederationIdentifier\":null,\"FirstName\":\"John\",\"ForecastEnabled\":false,\"FullPhotoUrl\":\"https://photos.com/profilephoto/001\",\"Id\":\"0051N000004mG2LAAA\",\"IsActive\":false,\"IsProfilePhotoActive\":false,\"LanguageLocaleKey\":\"en_US\",\"LastLoginDate\":\"2021-10-06T06:32:09.000+0000\",\"LastName\":\"Doe\",\"LastReferencedDate\":null,\"LastViewedDate\":null,\"LocaleSidKey\":\"en_SG\",\"MediumBannerPhotoUrl\":\"/profilephoto/001/E\",\"MobilePhone\":null,\"Name\":\"John Doe\",\"OfflineTrialExpirationDate\":null,\"Phone\":\"+3460000000\",\"ReceivesAdminInfoEmails\":true,\"ReceivesInfoEmails\":true,\"SenderEmail\":\"sender@example.com\",\"SenderName\":null,\"Signature\":null,\"SmallBannerPhotoUrl\":\"/profilephoto/001/D\",\"SmallPhotoUrl\":\"https://photos.com/photo/001\",\"TimeZoneSidKey\":\"Asia/Singapore\",\"Title\":\"Customer Solutions Engineer\",\"UserPermissionsCallCenterAutoLogin\":false,\"UserPermissionsInteractionUser\":true,\"UserPermissionsMarketingUser\":false,\"UserPermissionsOfflineUser\":false,\"UserPermissionsSupportUser\":false,\"UserRoleId\":\"00E2G000001E\",\"UserType\":\"Standard\",\"attributes\":{\"type\":\"User\",\"url\":\"/services/data/userID\"}},\"DetectedTimestamp\":\"2023-05-16T10:00:00Z\",\"FindingTypeDisplayName\":\"Salesforce User Sending Email with Different Email Address\",\"FindingTypeID\":\"a2790c4f-03f5-449f-b209-5f4447f417aa\",\"FindingTypeSeverity\":\"Medium\",\"InstanceID\":\"6b187be4-2dd5-42c5-a37b-111111111111\",\"IntegrationDisplayName\":\"Salesforce Testing\",\"IntegrationID\":\"c772678d-5cf1-4c73-bf3f-111111111111\",\"IntegrationPolicyVendor\":\"Salesforce Connection\"}",
        "severity": 2,
        "type": [
            "access"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-casb"
    ],
    "url": {
        "domain": "example.com",
        "original": "https://example.com/resource",
        "path": "/resource",
        "scheme": "https"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.casb.asset.id | Unique identifier for an asset of this type. Format will vary by policy vendor. | keyword |
| cloudflare_logpush.casb.asset.metadata | Metadata associated with the asset. Structure will vary by policy vendor. | flattened |
| cloudflare_logpush.casb.asset.name | Asset display name. | keyword |
| cloudflare_logpush.casb.asset.url | URL to the asset. This may not be available for some policy vendors and asset types. | keyword |
| cloudflare_logpush.casb.finding.id | UUID of the finding in Cloudflare´s system. | keyword |
| cloudflare_logpush.casb.finding.type.id | UUID of the finding type in Cloudflare´s system. | keyword |
| cloudflare_logpush.casb.finding.type.name | Human-readable name of the finding type. | keyword |
| cloudflare_logpush.casb.finding.type.severity | Severity of the finding type. | keyword |
| cloudflare_logpush.casb.integration.id | UUID of the integration in Cloudflare´s system. | keyword |
| cloudflare_logpush.casb.integration.name | Human-readable name of the integration. | keyword |
| cloudflare_logpush.casb.integration.policy_vendor | Human-readable vendor name of the integration´s policy. | keyword |
| cloudflare_logpush.casb.timestamp | Date and time the finding was first identified. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### device_posture

This is the `device_posture` dataset.

#### Example

An example event for `device_posture` looks as following:

```json
{
    "@timestamp": "2023-05-17T12:00:00.000Z",
    "agent": {
        "ephemeral_id": "69b49749-bbd8-440d-8bb1-7c23748f8dc4",
        "id": "2ca7060b-ba6e-48e5-8083-c9c12344256d",
        "name": "elastic-agent-26178",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "device_posture": {
            "eval": {
                "expected": {
                    "operator": "==",
                    "os_distro_name": "ubuntu",
                    "os_distro_revision": "20.04",
                    "version": "5.15.0-1025-gcp"
                },
                "received": {
                    "operator": "==",
                    "os_distro_name": "ubuntu",
                    "os_distro_revision": "20.04",
                    "version": "5.15.0-1025-gcp"
                },
                "result": true
            },
            "host": {
                "id": "083a8354-d56c-11ed-9771-111111111",
                "manufacturer": "Google Compute Engine",
                "model": "Google Compute Engine",
                "name": "zt-test-vm1",
                "os": {
                    "family": "linux",
                    "version": "5.15.0"
                },
                "serial": "GoogleCloud-ABCD1234567890"
            },
            "rule": {
                "category": "os_version",
                "id": "policy-abcdefgh",
                "name": "Ubuntu"
            },
            "timestamp": "2023-05-17T12:00:00.000Z",
            "user": {
                "email": "user@example.com",
                "id": "user-abcdefgh"
            },
            "version": "2023.3.258"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.device_posture",
        "namespace": "30714",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2ca7060b-ba6e-48e5-8083-c9c12344256d",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "cloudflare_logpush.device_posture",
        "ingested": "2025-03-13T20:48:45Z",
        "kind": "event",
        "original": "{\"ClientVersion\":\"2023.3.258\",\"DeviceID\":\"083a8354-d56c-11ed-9771-111111111\",\"DeviceManufacturer\":\"Google Compute Engine\",\"DeviceModel\":\"Google Compute Engine\",\"DeviceName\":\"zt-test-vm1\",\"DeviceSerialNumber\":\"GoogleCloud-ABCD1234567890\",\"DeviceType\":\"linux\",\"Email\":\"user@example.com\",\"OSVersion\":\"5.15.0\",\"PolicyID\":\"policy-abcdefgh\",\"PostureCheckName\":\"Ubuntu\",\"PostureCheckType\":\"os_version\",\"PostureEvaluatedResult\":true,\"PostureExpectedJSON\":{\"operator\":\"==\",\"os_distro_name\":\"ubuntu\",\"os_distro_revision\":\"20.04\",\"version\":\"5.15.0-1025-gcp\"},\"PostureReceivedJSON\":{\"operator\":\"==\",\"os_distro_name\":\"ubuntu\",\"os_distro_revision\":\"20.04\",\"version\":\"5.15.0-1025-gcp\"},\"Timestamp\":\"2023-05-17T12:00:00Z\",\"UserUID\":\"user-abcdefgh\"}",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "083a8354-d56c-11ed-9771-111111111",
        "name": "zt-test-vm1",
        "os": {
            "family": "linux",
            "version": "5.15.0"
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "hosts": [
            "083a8354-d56c-11ed-9771-111111111",
            "zt-test-vm1"
        ],
        "user": [
            "user-abcdefgh",
            "user@example.com"
        ]
    },
    "rule": {
        "category": "os_version",
        "id": "policy-abcdefgh",
        "name": "Ubuntu"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-device_posture"
    ],
    "user": {
        "email": "user@example.com",
        "id": "user-abcdefgh"
    },
    "user_agent": {
        "version": "2023.3.258"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.device_posture.eval.expected | JSON object of what the posture check expects from the Zero Trust client. | flattened |
| cloudflare_logpush.device_posture.eval.received | JSON object of what the Zero Trust client actually uploads. | flattened |
| cloudflare_logpush.device_posture.eval.result | Whether this posture upload passes the associated posture check, given the requirements posture check at the time of the timestamp. | boolean |
| cloudflare_logpush.device_posture.host.id | The device ID that performed the posture upload. | keyword |
| cloudflare_logpush.device_posture.host.manufacturer | The manufacturer of the device that the Zero Trust client is running on. | keyword |
| cloudflare_logpush.device_posture.host.model | The model of the device that the Zero Trust client is running on. | keyword |
| cloudflare_logpush.device_posture.host.name | The name of the device that the Zero Trust client is running on. | keyword |
| cloudflare_logpush.device_posture.host.os.family | The Zero Trust client operating system type. | keyword |
| cloudflare_logpush.device_posture.host.os.version | The operating system version at the time of upload. | keyword |
| cloudflare_logpush.device_posture.host.serial | The serial number of the device that the Zero Trust client is running on. | keyword |
| cloudflare_logpush.device_posture.rule.category | The type of the Zero Trust client check or service provider check. | keyword |
| cloudflare_logpush.device_posture.rule.id | The posture check ID associated with this device posture result. | keyword |
| cloudflare_logpush.device_posture.rule.name | The name of the posture check associated with this device posture result. | keyword |
| cloudflare_logpush.device_posture.timestamp | The date and time the corresponding device posture upload was performed. | date |
| cloudflare_logpush.device_posture.user.email | The email used to register the device with the Zero Trust client. | keyword |
| cloudflare_logpush.device_posture.user.id | The uid of the user who registered the device. | keyword |
| cloudflare_logpush.device_posture.version | The Zero Trust client version at the time of upload. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### dlp_forensic_copies

This is the `dlp_forensic_copies` dataset.

#### Example

An example event for `dlp_forensic_copies` looks as following:

```json
{
    "@timestamp": "2023-05-04T11:29:14.000Z",
    "agent": {
        "ephemeral_id": "789cd08b-09d8-41e3-a274-ec906d936a50",
        "id": "f70d9043-9bff-4e8a-b37c-830532cb98ce",
        "name": "elastic-agent-96295",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "dlp_forensic_copies": {
            "account_id": "acc-id",
            "datetime": "2023-05-04T11:29:14.000Z",
            "forensic_copy_id": "copy-id",
            "gateway_request_id": "req-id",
            "headers": {
                "key1": "val1",
                "key2": "val2"
            },
            "payload": "Tm90aGluZyB0byBzZWUgaGVyZS4gTW92ZSBhbG9uZy4K",
            "phase": "request",
            "triggered_rule_id": "9"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.dlp_forensic_copies",
        "namespace": "21206",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f70d9043-9bff-4e8a-b37c-830532cb98ce",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.dlp_forensic_copies",
        "ingested": "2025-03-13T20:51:14Z",
        "kind": "event",
        "original": "{\"AccountID\":\"acc-id\",\"Datetime\":\"2023-05-04T11:29:14Z\",\"ForensicCopyID\":\"copy-id\",\"GatewayRequestID\":\"req-id\",\"Headers\":{\"key1\":\"val1\",\"key2\":\"val2\"},\"Payload\":\"Tm90aGluZyB0byBzZWUgaGVyZS4gTW92ZSBhbG9uZy4K\",\"Phase\":\"request\",\"TriggeredRuleID\":\"9\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-dlp_forensic_copies"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.dlp_forensic_copies.account_id | Cloudflare account ID. | keyword |
| cloudflare_logpush.dlp_forensic_copies.datetime | The date and time the corresponding HTTP request was made. | date |
| cloudflare_logpush.dlp_forensic_copies.forensic_copy_id | The unique ID for this particular forensic copy. | keyword |
| cloudflare_logpush.dlp_forensic_copies.gateway_request_id | Cloudflare request ID, as found in Gateway logs. | keyword |
| cloudflare_logpush.dlp_forensic_copies.headers.\* |  | keyword |
| cloudflare_logpush.dlp_forensic_copies.payload | Captured request/response data, base64-encoded. | keyword |
| cloudflare_logpush.dlp_forensic_copies.phase | Phase of the HTTP request this forensic copy was captured from (i.e. "request" or "response"). | keyword |
| cloudflare_logpush.dlp_forensic_copies.triggered_rule_id | The ID of the Gateway firewall rule that triggered this forensic copy. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### dns

This is the `dns` dataset.

#### Example

An example event for `dns` looks as following:

```json
{
    "@timestamp": "2022-05-26T09:23:54.000Z",
    "agent": {
        "ephemeral_id": "2823a3ec-ab20-44db-9711-9852fcd66513",
        "id": "5d67020f-468b-4aa0-808e-36f6f3451616",
        "name": "elastic-agent-72593",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "dns": {
            "colo": {
                "code": "MRS"
            },
            "edns": {
                "subnet": "1.128.0.0",
                "subnet_length": 0
            },
            "query": {
                "name": "example.com",
                "type": 65535
            },
            "response": {
                "cached": false,
                "code": 0
            },
            "source": {
                "ip": "175.16.199.0"
            },
            "timestamp": "2022-05-26T09:23:54.000Z"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.dns",
        "namespace": "14563",
        "type": "logs"
    },
    "dns": {
        "question": {
            "name": "example.com"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5d67020f-468b-4aa0-808e-36f6f3451616",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.dns",
        "ingested": "2025-03-13T20:53:44Z",
        "kind": "event",
        "original": "{\"ColoCode\":\"MRS\",\"EDNSSubnet\":\"1.128.0.0\",\"EDNSSubnetLength\":0,\"QueryName\":\"example.com\",\"QueryType\":65535,\"ResponseCached\":false,\"ResponseCode\":0,\"SourceIP\":\"175.16.199.0\",\"Timestamp\":\"2022-05-26T09:23:54Z\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "ip": [
            "175.16.199.0",
            "1.128.0.0"
        ]
    },
    "source": {
        "ip": "175.16.199.0"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-dns"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.dns.colo.code | IATA airport code of data center that received the request. | keyword |
| cloudflare_logpush.dns.edns.subnet | EDNS Client Subnet (IPv4 or IPv6). | ip |
| cloudflare_logpush.dns.edns.subnet_length | EDNS Client Subnet length. | long |
| cloudflare_logpush.dns.query.name | Name of the query that was sent. | keyword |
| cloudflare_logpush.dns.query.type | Integer value of query type. | long |
| cloudflare_logpush.dns.response.cached | Whether the response was cached or not. | boolean |
| cloudflare_logpush.dns.response.code | Integer value of response code. | long |
| cloudflare_logpush.dns.source.ip | IP address of the client (IPv4 or IPv6). | ip |
| cloudflare_logpush.dns.timestamp | Timestamp at which the query occurred. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### dns_firewall

This is the `dns_firewall` dataset.

#### Example

An example event for `dns_firewall` looks as following:

```json
{
    "@timestamp": "2023-09-19T12:30:00.000Z",
    "agent": {
        "ephemeral_id": "7e440646-0bda-436b-9a50-35dce2c96fc5",
        "id": "7c1c87d5-bfe3-4794-9e9b-44b4df5baec7",
        "name": "elastic-agent-68004",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "dns_firewall": {
            "cluster_id": "CLUSTER-001",
            "colo": {
                "code": "SFO"
            },
            "edns": {
                "subnet": "67.43.156.0",
                "subnet_length": 24
            },
            "question": {
                "dnssec_ok": true,
                "name": "example.com",
                "recursion_desired": true,
                "size": 60,
                "tcp": false,
                "type": 1
            },
            "response": {
                "cached": true,
                "cached_stale": false,
                "code": "0"
            },
            "source": {
                "ip": "67.43.156.2"
            },
            "timestamp": "2023-09-19T12:30:00.000Z",
            "upstream": {
                "ip": "81.2.69.144",
                "response_code": "0",
                "response_time_ms": 30
            }
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.dns_firewall",
        "namespace": "24424",
        "type": "logs"
    },
    "dns": {
        "question": {
            "name": "example.com"
        },
        "response_code": "0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7c1c87d5-bfe3-4794-9e9b-44b4df5baec7",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.dns_firewall",
        "ingested": "2025-03-13T20:54:35Z",
        "kind": "event",
        "original": "{\"ClientResponseCode\":0,\"ClusterID\":\"CLUSTER-001\",\"ColoCode\":\"SFO\",\"EDNSSubnet\":\"67.43.156.0\",\"EDNSSubnetLength\":24,\"QueryDO\":true,\"QueryName\":\"example.com\",\"QueryRD\":true,\"QuerySize\":60,\"QueryTCP\":false,\"QueryType\":1,\"ResponseCached\":true,\"ResponseCachedStale\":false,\"SourceIP\":\"67.43.156.2\",\"Timestamp\":\"2023-09-19T12:30:00Z\",\"UpstreamIP\":\"81.2.69.144\",\"UpstreamResponseCode\":0,\"UpstreamResponseTimeMs\":30}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "transport": "udp"
    },
    "related": {
        "ip": [
            "67.43.156.2",
            "67.43.156.0",
            "81.2.69.144"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.2"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-dns_firewall"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.dns_firewall.cluster_id | The ID of the cluster which handled this request. | keyword |
| cloudflare_logpush.dns_firewall.colo.code | IATA airport code of data center that received the request. | keyword |
| cloudflare_logpush.dns_firewall.edns.subnet | EDNS Client Subnet (IPv4 or IPv6). | ip |
| cloudflare_logpush.dns_firewall.edns.subnet_length | EDNS Client Subnet length. | long |
| cloudflare_logpush.dns_firewall.question.dnssec_ok | Indicates if the client is capable of handling a signed response (DNSSEC answer OK). | boolean |
| cloudflare_logpush.dns_firewall.question.name | Name of the query that was sent. | keyword |
| cloudflare_logpush.dns_firewall.question.recursion_desired | Indicates if the client means a recursive query (Recursion Desired). | boolean |
| cloudflare_logpush.dns_firewall.question.size | The size of the query sent from the client in bytes. | long |
| cloudflare_logpush.dns_firewall.question.tcp | Indicates if the query from the client was made via TCP (if false, then UDP). | boolean |
| cloudflare_logpush.dns_firewall.question.type | Integer value of query type. | long |
| cloudflare_logpush.dns_firewall.response.cached | Whether the response was cached or not. | boolean |
| cloudflare_logpush.dns_firewall.response.cached_stale | Whether the response was cached stale. In other words, the TTL had expired and the upstream nameserver was not reachable. | boolean |
| cloudflare_logpush.dns_firewall.response.code | DNS response code. | keyword |
| cloudflare_logpush.dns_firewall.response.reason | Short descriptions with more context around the final DNS Firewall response. See [Cloudflare docs](https://developers.cloudflare.com/dns/dns-firewall/analytics/) for details. | keyword |
| cloudflare_logpush.dns_firewall.source.ip | The source IP address of the request. | ip |
| cloudflare_logpush.dns_firewall.timestamp | Timestamp at which the query occurred. | date |
| cloudflare_logpush.dns_firewall.upstream.ip | IP of the upstream nameserver (IPv4 or IPv6). | ip |
| cloudflare_logpush.dns_firewall.upstream.response_code | Response code from the upstream nameserver. | keyword |
| cloudflare_logpush.dns_firewall.upstream.response_time_ms | Upstream response time in milliseconds. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### email_security_alerts

This is the `email_security_alerts` dataset.

#### Example

An example event for `email_security_alerts` looks as following:

```json
{
    "@timestamp": "2024-08-28T15:32:35.000Z",
    "agent": {
        "ephemeral_id": "28bec0af-6f35-49da-a1b0-f502ad71bcb5",
        "id": "ffbe7c1e-4c20-4905-8625-361ef532d965",
        "name": "elastic-agent-71551",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "email_security_alerts": {
            "alert_id": "4WtWkr6nlBz9sNH-2024-08-28T15:32:35",
            "alert_reasons": [
                "because",
                "said-so"
            ],
            "attachments": [
                {
                    "ContentTypeComputed": "application/x-msi",
                    "ContentTypeProvided": "image/gif",
                    "Decrypted": true,
                    "Encrypted": true,
                    "Md5": "91f073bd208689ddbd248e8989ecae90",
                    "Name": "attachment.gif",
                    "Sha1": "62b77e14e2c43049c45b5725018e78d0f9986930",
                    "Sha256": "3b57505305e7162141fd898ed87d08f92fc42579b5047495859e56b3275a6c06",
                    "Ssdeep": "McAQ8tPlH25e85Q2OiYpD08NvHmjJ97UfPMO47sekO:uN9M553OiiN/OJ9MM+e3"
                }
            ],
            "cc": [
                "firstlast+cc@cloudflare.com"
            ],
            "cc_name": [
                "First Last (cc)"
            ],
            "final_disposition": "malicious",
            "from": "firstlast+from@cloudflare.com",
            "from_name": "First Last (from)",
            "links": [
                "https://example.com"
            ],
            "message_delivery_mode": "unset",
            "message_id": "<Message-ID>",
            "origin": "unset",
            "original_sender": "firstlast+origin@cloudflare.com",
            "reply_to": "firstlast+reply@cloudflare.com",
            "reply_to_name": "First Last (reply)",
            "smtp_envelope_from": "firstlast+env_from@cloudflare.com",
            "smtp_envelope_to": [
                "firstlast+env_to@cloudflare.com"
            ],
            "smtp_helo_server_ip": "81.2.69.144",
            "smtp_helo_server_ip_as_name": "asn",
            "smtp_helo_server_ip_as_number": "42",
            "smtp_helo_server_ip_geo": "US/NV/Las Vegas",
            "smtp_helo_server_name": "servername",
            "subject": "innocuous message: please read",
            "threat_categories": [
                "CredentialHarvester",
                "Dropper"
            ],
            "timestamp": "2024-08-28T15:32:35.000Z",
            "to": "firstlast+to@cloudflare.com",
            "to_name": "First Last (to)"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.email_security_alerts",
        "namespace": "33688",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ffbe7c1e-4c20-4905-8625-361ef532d965",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email",
            "network"
        ],
        "dataset": "cloudflare_logpush.email_security_alerts",
        "ingested": "2025-03-13T20:57:01Z",
        "kind": "alert",
        "original": "{\"AlertID\":\"4WtWkr6nlBz9sNH-2024-08-28T15:32:35\",\"AlertReasons\":[\"because\",\"said-so\"],\"Attachments\":[{\"ContentTypeComputed\":\"application/x-msi\",\"ContentTypeProvided\":\"image/gif\",\"Decrypted\":true,\"Encrypted\":true,\"Md5\":\"91f073bd208689ddbd248e8989ecae90\",\"Name\":\"attachment.gif\",\"Sha1\":\"62b77e14e2c43049c45b5725018e78d0f9986930\",\"Sha256\":\"3b57505305e7162141fd898ed87d08f92fc42579b5047495859e56b3275a6c06\",\"Ssdeep\":\"McAQ8tPlH25e85Q2OiYpD08NvHmjJ97UfPMO47sekO:uN9M553OiiN/OJ9MM+e3\"}],\"CC\":[\"firstlast+cc@cloudflare.com\"],\"CCName\":[\"First Last (cc)\"],\"FinalDisposition\":\"malicious\",\"From\":\"firstlast+from@cloudflare.com\",\"FromName\":\"First Last (from)\",\"Links\":[\"https://example.com\"],\"MessageDeliveryMode\":\"unset\",\"MessageID\":\"\\u003cMessage-ID\\u003e\",\"Origin\":\"unset\",\"OriginalSender\":\"firstlast+origin@cloudflare.com\",\"ReplyTo\":\"firstlast+reply@cloudflare.com\",\"ReplyToName\":\"First Last (reply)\",\"SMTPEnvelopeFrom\":\"firstlast+env_from@cloudflare.com\",\"SMTPEnvelopeTo\":[\"firstlast+env_to@cloudflare.com\"],\"SMTPHeloServerIP\":\"81.2.69.144\",\"SMTPHeloServerIPAsName\":\"asn\",\"SMTPHeloServerIPAsNumber\":\"42\",\"SMTPHeloServerIPGeo\":\"US/NV/Las Vegas\",\"SMTPHeloServerName\":\"servername\",\"Subject\":\"innocuous message: please read\",\"ThreatCategories\":[\"CredentialHarvester\",\"Dropper\"],\"Timestamp\":\"2024-08-28T15:32:35Z\",\"To\":\"firstlast+to@cloudflare.com\",\"ToName\":\"First Last (to)\"}",
        "type": [
            "info"
        ]
    },
    "file": [
        {
            "hash": {
                "md5": "91f073bd208689ddbd248e8989ecae90",
                "sha1": "62b77e14e2c43049c45b5725018e78d0f9986930",
                "sha256": "3b57505305e7162141fd898ed87d08f92fc42579b5047495859e56b3275a6c06",
                "ssdeep": "McAQ8tPlH25e85Q2OiYpD08NvHmjJ97UfPMO47sekO:uN9M553OiiN/OJ9MM+e3"
            },
            "mime_type": "application/x-msi",
            "name": "attachment.gif"
        }
    ],
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "hash": [
            "3b57505305e7162141fd898ed87d08f92fc42579b5047495859e56b3275a6c06",
            "62b77e14e2c43049c45b5725018e78d0f9986930",
            "McAQ8tPlH25e85Q2OiYpD08NvHmjJ97UfPMO47sekO:uN9M553OiiN/OJ9MM+e3",
            "91f073bd208689ddbd248e8989ecae90"
        ],
        "hosts": [
            "servername",
            "cloudflare.com",
            "example.com"
        ],
        "ip": [
            "81.2.69.144"
        ],
        "user": [
            "firstlast+from@cloudflare.com",
            "First Last (from)",
            "firstlast+env_from@cloudflare.com",
            "firstlast+env_to@cloudflare.com",
            "firstlast+cc@cloudflare.com",
            "First Last (cc)"
        ]
    },
    "server": {
        "address": "servername",
        "domain": "servername",
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.144"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-email_security_alerts"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.email_security_alerts.alert_id | The canonical ID for an Email Security Alert. | keyword |
| cloudflare_logpush.email_security_alerts.alert_reasons | Human-readable list of findings which contributed to this message's final disposition. | keyword |
| cloudflare_logpush.email_security_alerts.attachments.\* | Metadata of attachments contained in this message. | keyword |
| cloudflare_logpush.email_security_alerts.attachments.Decrypted | Whether the attachment was decrypted. | boolean |
| cloudflare_logpush.email_security_alerts.attachments.Encrypted | Whether the attachment was encrypted. | boolean |
| cloudflare_logpush.email_security_alerts.cc | Email address portions of the CC header provided by the sender. | keyword |
| cloudflare_logpush.email_security_alerts.cc_name | Name portions of the CC header provided by the sender. | keyword |
| cloudflare_logpush.email_security_alerts.final_disposition | Final disposition attributed to the message. Possible values are (unset, malicious, suspicious, spoof, spam, and bulk). | keyword |
| cloudflare_logpush.email_security_alerts.from | Email address portion of the From header provided by the sender. | keyword |
| cloudflare_logpush.email_security_alerts.from_name | Name portion of the From header provided by the sender. | keyword |
| cloudflare_logpush.email_security_alerts.links | List of links detected in this message, benign or otherwise; limited to 100 in total. | keyword |
| cloudflare_logpush.email_security_alerts.message_delivery_mode | The message's mode of transport to Email Security. Possible values are (unset, api, direct, bcc, journal, and retroScan). | keyword |
| cloudflare_logpush.email_security_alerts.message_id | Value of the Message-ID header provided by the sender. | keyword |
| cloudflare_logpush.email_security_alerts.origin | The origin of the message. Possible values are (unset, internal, external, secondPartyInternal, thirdPartyInternal, and outbound). | keyword |
| cloudflare_logpush.email_security_alerts.original_sender | The original sender address as determined by Email Security mail processing. | keyword |
| cloudflare_logpush.email_security_alerts.reply_to | Email address portion of the Reply-To header provided by the sender. | keyword |
| cloudflare_logpush.email_security_alerts.reply_to_name | Name portion of the Reply-To header provided by the sender. | keyword |
| cloudflare_logpush.email_security_alerts.smtp_envelope_from | Value of the SMTP MAIL FROM command provided by the sender. | keyword |
| cloudflare_logpush.email_security_alerts.smtp_envelope_to | Values of the SMTP RCPT TO command provided by the sender. | keyword |
| cloudflare_logpush.email_security_alerts.smtp_helo_server_ip | IPv4/v6 of the SMTP HELO server. | ip |
| cloudflare_logpush.email_security_alerts.smtp_helo_server_ip_as_name | Autonomous System Name of the SMTP HELO server's IP. | keyword |
| cloudflare_logpush.email_security_alerts.smtp_helo_server_ip_as_number | Autonomous System Number of the SMTP HELO server's IP. | keyword |
| cloudflare_logpush.email_security_alerts.smtp_helo_server_ip_geo | SMTP HELO server geolocation info (for example, 'US/NV/Las Vegas'). | keyword |
| cloudflare_logpush.email_security_alerts.smtp_helo_server_name | Hostname provided by the SMTP HELO server. | keyword |
| cloudflare_logpush.email_security_alerts.subject | Value of the Subject header provided by the sender. | keyword |
| cloudflare_logpush.email_security_alerts.threat_categories | Threat categories attributed by Email Security processing. | keyword |
| cloudflare_logpush.email_security_alerts.timestamp | Start time of message processing. | date |
| cloudflare_logpush.email_security_alerts.to | Email address portions of the To header provided by the sender. | keyword |
| cloudflare_logpush.email_security_alerts.to_name | Name portions of the To header provided by the sender. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### firewall_event

This is the `firewall_event` dataset.

#### Example

An example event for `firewall_event` looks as following:

```json
{
    "@timestamp": "2022-05-31T05:23:43.000Z",
    "agent": {
        "ephemeral_id": "c8450a0e-189b-4ec0-afb5-fca633fb8c4e",
        "id": "5323ad35-0547-47a0-b643-1e5600cbe6b3",
        "name": "elastic-agent-22662",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "firewall_event": {
            "action": "block",
            "client": {
                "asn": {
                    "description": "CLOUDFLARENET",
                    "value": 15169
                },
                "country": "us",
                "ip": "175.16.199.0",
                "ip_class": "searchEngine",
                "referer": {
                    "host": "abc.example.com",
                    "path": "/abc/checkout",
                    "query": "?sourcerer=(default%3A(id%3A!n%2CselectedPatterns%3A!(eqldemo%2C%27logs-endpoint.*-eqldemo%27%2C%27logs-system.*-eqldemo%27%2C%27logs-windows.*-eqldemo%27%2Cmetricseqldemo)))&timerange=(global%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.199Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.200Z%27%2CtoStr%3Anow))%2Ctimeline%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.201Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.202Z%27%2CtoStr%3Anow)))",
                    "scheme": "referer URL scheme"
                },
                "request": {
                    "host": "xyz.example.com",
                    "method": "GET",
                    "path": "/abc/checkout",
                    "protocol": "HTTP/1.1",
                    "query": "?sourcerer=(default%3A(id%3A!n%2CselectedPatterns%3A!(eqldemo%2C%27logs-endpoint.*-eqldemo%27%2C%27logs-system.*-eqldemo%27%2C%27logs-windows.*-eqldemo%27%2Cmetricseqldemo)))&timerange=(global%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.199Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.200Z%27%2CtoStr%3Anow))%2Ctimeline%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.201Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.202Z%27%2CtoStr%3Anow)))",
                    "scheme": "https",
                    "user": {
                        "agent": "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
                    }
                }
            },
            "edge": {
                "colo": {
                    "code": "IAD"
                },
                "response": {
                    "status": 403
                }
            },
            "kind": "firewall",
            "match_index": 1,
            "meta_data": {
                "filter": "1ced07e066a34abf8b14f2a99593bc8d",
                "type": "customer"
            },
            "origin": {
                "ray": {
                    "id": "00"
                },
                "response": {
                    "status": 0
                }
            },
            "ray": {
                "id": "713d477539b55c29"
            },
            "rule": {
                "id": "7dc666e026974dab84884c73b3e2afe1"
            },
            "source": "firewallrules",
            "timestamp": "2022-05-31T05:23:43.000Z"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.firewall_event",
        "namespace": "85768",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5323ad35-0547-47a0-b643-1e5600cbe6b3",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "action": "block",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.firewall_event",
        "id": "713d477539b55c29",
        "ingested": "2025-03-13T20:59:22Z",
        "kind": "event",
        "original": "{\"Action\":\"block\",\"ClientASN\":15169,\"ClientASNDescription\":\"CLOUDFLARENET\",\"ClientCountry\":\"us\",\"ClientIP\":\"175.16.199.0\",\"ClientIPClass\":\"searchEngine\",\"ClientRefererHost\":\"abc.example.com\",\"ClientRefererPath\":\"/abc/checkout\",\"ClientRefererQuery\":\"?sourcerer=(default%3A(id%3A!n%2CselectedPatterns%3A!(eqldemo%2C%27logs-endpoint.*-eqldemo%27%2C%27logs-system.*-eqldemo%27%2C%27logs-windows.*-eqldemo%27%2Cmetricseqldemo)))\\u0026timerange=(global%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.199Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.200Z%27%2CtoStr%3Anow))%2Ctimeline%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.201Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.202Z%27%2CtoStr%3Anow)))\",\"ClientRefererScheme\":\"referer URL scheme\",\"ClientRequestHost\":\"xyz.example.com\",\"ClientRequestMethod\":\"GET\",\"ClientRequestPath\":\"/abc/checkout\",\"ClientRequestProtocol\":\"HTTP/1.1\",\"ClientRequestQuery\":\"?sourcerer=(default%3A(id%3A!n%2CselectedPatterns%3A!(eqldemo%2C%27logs-endpoint.*-eqldemo%27%2C%27logs-system.*-eqldemo%27%2C%27logs-windows.*-eqldemo%27%2Cmetricseqldemo)))\\u0026timerange=(global%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.199Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.200Z%27%2CtoStr%3Anow))%2Ctimeline%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.201Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.202Z%27%2CtoStr%3Anow)))\",\"ClientRequestScheme\":\"https\",\"ClientRequestUserAgent\":\"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\",\"Datetime\":\"2022-05-31T05:23:43Z\",\"EdgeColoCode\":\"IAD\",\"EdgeResponseStatus\":403,\"Kind\":\"firewall\",\"MatchIndex\":1,\"Metadata\":{\"filter\":\"1ced07e066a34abf8b14f2a99593bc8d\",\"type\":\"customer\"},\"OriginResponseStatus\":0,\"OriginatorRayID\":\"00\",\"RayID\":\"713d477539b55c29\",\"RuleID\":\"7dc666e026974dab84884c73b3e2afe1\",\"Source\":\"firewallrules\"}",
        "type": [
            "info"
        ]
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 403
        },
        "version": "1.1"
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "protocol": "http"
    },
    "related": {
        "hosts": [
            "abc.example.com",
            "xyz.example.com"
        ],
        "ip": [
            "175.16.199.0"
        ]
    },
    "rule": {
        "id": "7dc666e026974dab84884c73b3e2afe1"
    },
    "source": {
        "as": {
            "number": 15169
        },
        "geo": {
            "country_iso_code": "us"
        },
        "ip": "175.16.199.0"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-firewall_event"
    ],
    "url": {
        "domain": "xyz.example.com",
        "path": "/abc/checkout",
        "query": "sourcerer=(default%3A(id%3A!n%2CselectedPatterns%3A!(eqldemo%2C%27logs-endpoint.*-eqldemo%27%2C%27logs-system.*-eqldemo%27%2C%27logs-windows.*-eqldemo%27%2Cmetricseqldemo)))&timerange=(global%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.199Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.200Z%27%2CtoStr%3Anow))%2Ctimeline%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.201Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.202Z%27%2CtoStr%3Anow)))",
        "scheme": "https"
    },
    "user_agent": {
        "device": {
            "name": "Spider"
        },
        "name": "Googlebot",
        "original": "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "os": {
            "full": "Android 6.0.1",
            "name": "Android",
            "version": "6.0.1"
        },
        "version": "2.1"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.firewall_event.action | The code of the first-class action the Cloudflare Firewall took on this request. | keyword |
| cloudflare_logpush.firewall_event.client.asn.description | The ASN of the visitor as string. | keyword |
| cloudflare_logpush.firewall_event.client.asn.value | The ASN number of the visitor. | long |
| cloudflare_logpush.firewall_event.client.country | Country from which request originated. | keyword |
| cloudflare_logpush.firewall_event.client.ip | The visitor IP address (IPv4 or IPv6). | ip |
| cloudflare_logpush.firewall_event.client.ip_class | The classification of the visitor IP address, possible values are:- 'unknown', 'badHost', 'searchEngine', 'allowlist', 'monitoringService', 'noRecord', 'scan' and 'tor'. | keyword |
| cloudflare_logpush.firewall_event.client.referer.host | The referer host. | keyword |
| cloudflare_logpush.firewall_event.client.referer.path | The referer path requested by visitor. | text |
| cloudflare_logpush.firewall_event.client.referer.query | The referer query-string was requested by the visitor. | keyword |
| cloudflare_logpush.firewall_event.client.referer.scheme | The referer URL scheme requested by the visitor. | text |
| cloudflare_logpush.firewall_event.client.request.host | The HTTP hostname requested by the visitor. | keyword |
| cloudflare_logpush.firewall_event.client.request.method | The HTTP method used by the visitor. | keyword |
| cloudflare_logpush.firewall_event.client.request.path | The path requested by visitor. | text |
| cloudflare_logpush.firewall_event.client.request.protocol | The version of HTTP protocol requested by the visitor. | keyword |
| cloudflare_logpush.firewall_event.client.request.query | The query-string was requested by the visitor. | keyword |
| cloudflare_logpush.firewall_event.client.request.scheme | The URL scheme requested by the visitor. | text |
| cloudflare_logpush.firewall_event.client.request.user.agent | Visitor's user-agent string. | text |
| cloudflare_logpush.firewall_event.content_scan.results | List of content scan results. | keyword |
| cloudflare_logpush.firewall_event.content_scan.sizes | List of content object sizes. | long |
| cloudflare_logpush.firewall_event.content_scan.types | List of content types. | keyword |
| cloudflare_logpush.firewall_event.edge.colo.code | The airport code of the Cloudflare datacenter that served this request. | keyword |
| cloudflare_logpush.firewall_event.edge.response.status | HTTP response status code returned to browser. | long |
| cloudflare_logpush.firewall_event.kind | The kind of event, currently only possible values are. | keyword |
| cloudflare_logpush.firewall_event.leaked_credential_check | Result of the check for leaked credentials. Possible results are: password_leaked | username_and_password_leaked | username_password_similar | username_leaked | clean. | keyword |
| cloudflare_logpush.firewall_event.match_index | Rules match index in the chain. | long |
| cloudflare_logpush.firewall_event.meta_data | Additional product-specific information. | flattened |
| cloudflare_logpush.firewall_event.origin.ray.id | HTTP origin response status code returned to browser. | keyword |
| cloudflare_logpush.firewall_event.origin.response.status | The RayID of the request that issued the challenge/jschallenge. | long |
| cloudflare_logpush.firewall_event.ray.id | The RayID of the request. | keyword |
| cloudflare_logpush.firewall_event.ref | The user-defined identifier for the rule triggered by this request. | keyword |
| cloudflare_logpush.firewall_event.rule.description | The Cloudflare security product-specific Description of the rule triggered by this request. | keyword |
| cloudflare_logpush.firewall_event.rule.id | The Cloudflare security product-specific RuleID triggered by this request. | keyword |
| cloudflare_logpush.firewall_event.source | The Cloudflare security product triggered by this request. | keyword |
| cloudflare_logpush.firewall_event.timestamp | The date and time the event occurred at the edge. | date |
| cloudflare_logpush.firewall_event.zone.name | The human-readable name of the zone. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### gateway_dns

This is the `gateway_dns` dataset.

#### Example

An example event for `gateway_dns` looks as following:

```json
{
    "@timestamp": "2023-05-02T22:49:53.000Z",
    "agent": {
        "ephemeral_id": "e8121e5d-917d-4d3e-b79b-31325381689f",
        "id": "164d9879-9767-41c4-98a4-a47a5b644fc2",
        "name": "elastic-agent-12279",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "gateway_dns": {
            "answers": [
                {
                    "data": "CHNlY3VyaXR5BnVidW50dQMjb20AAAEAAQAAAAgABLl9vic=",
                    "type": "1"
                },
                {
                    "data": "CHNlY3VyaXR5BnVidW50dQNjb20AAAEAABAAAAgABLl9viQ=",
                    "type": "1"
                },
                {
                    "data": "CHNlT3VyaXR5BnVidW50dQNjb20AAAEAAQAAAAgABFu9Wyc=",
                    "type": "1"
                }
            ],
            "application_id": 0,
            "colo": {
                "code": "ORD",
                "id": 14
            },
            "destination": {
                "ip": "89.160.20.129",
                "port": 443
            },
            "host": {
                "id": "083a8354-d56c-11ed-9771-6a842b111aaa",
                "name": "zt-test-vm1"
            },
            "location": {
                "id": "f233bd67-78c7-4050-9aff-ad63cce25732",
                "name": "GCP default"
            },
            "matched": {
                "category": {
                    "ids": [
                        7,
                        163
                    ],
                    "names": [
                        "Photography",
                        "Weather"
                    ]
                }
            },
            "policy": {
                "id": "1412",
                "name": "7bdc7a9c-81d3-4816-8e56-de1acad3dec5"
            },
            "protocol": "https",
            "question": {
                "category": {
                    "ids": [
                        26,
                        155
                    ],
                    "names": [
                        "Technology",
                        "Technology"
                    ]
                },
                "name": "security.ubuntu.com",
                "reversed": "com.ubuntu.security",
                "size": 48,
                "type": "A",
                "type_id": 1
            },
            "resolved_ip": [
                "67.43.156.1",
                "67.43.156.2",
                "67.43.156.3"
            ],
            "resolver_decision": "allowedOnNoPolicyMatch",
            "response_code": "0",
            "source": {
                "ip": "67.43.156.2",
                "port": 0
            },
            "timestamp": "2023-05-02T22:49:53.000Z",
            "timezone": "UTC",
            "timezone_inferred_method": "fromLocalTime",
            "user": {
                "email": "user@test.com",
                "id": "166befbb-00e3-5e20-bd6e-27245000000"
            }
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.gateway_dns",
        "namespace": "39559",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.129",
        "port": 443
    },
    "dns": {
        "answers": [
            {
                "data": "CHNlY3VyaXR5BnVidW50dQMjb20AAAEAAQAAAAgABLl9vic=",
                "type": "1"
            },
            {
                "data": "CHNlY3VyaXR5BnVidW50dQNjb20AAAEAABAAAAgABLl9viQ=",
                "type": "1"
            },
            {
                "data": "CHNlT3VyaXR5BnVidW50dQNjb20AAAEAAQAAAAgABFu9Wyc=",
                "type": "1"
            }
        ],
        "question": {
            "name": "security.ubuntu.com",
            "type": "A"
        },
        "resolved_ip": [
            "67.43.156.1",
            "67.43.156.2",
            "67.43.156.3"
        ],
        "response_code": "0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "164d9879-9767-41c4-98a4-a47a5b644fc2",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.gateway_dns",
        "ingested": "2025-03-13T21:01:42Z",
        "kind": "event",
        "original": "{\"ApplicationID\":0,\"ColoCode\":\"ORD\",\"ColoID\":14,\"Datetime\":\"2023-05-02T22:49:53Z\",\"DeviceID\":\"083a8354-d56c-11ed-9771-6a842b111aaa\",\"DeviceName\":\"zt-test-vm1\",\"DstIP\":\"89.160.20.129\",\"DstPort\":443,\"Email\":\"user@test.com\",\"Location\":\"GCP default\",\"LocationID\":\"f233bd67-78c7-4050-9aff-ad63cce25732\",\"MatchedCategoryIDs\":[7,163],\"MatchedCategoryNames\":[\"Photography\",\"Weather\"],\"Policy\":\"7bdc7a9c-81d3-4816-8e56-de1acad3dec5\",\"PolicyID\":\"1412\",\"Protocol\":\"https\",\"QueryCategoryIDs\":[26,155],\"QueryCategoryNames\":[\"Technology\",\"Technology\"],\"QueryName\":\"security.ubuntu.com\",\"QueryNameReversed\":\"com.ubuntu.security\",\"QuerySize\":48,\"QueryType\":1,\"QueryTypeName\":\"A\",\"RCode\":0,\"RData\":[{\"data\":\"CHNlY3VyaXR5BnVidW50dQMjb20AAAEAAQAAAAgABLl9vic=\",\"type\":\"1\"},{\"data\":\"CHNlY3VyaXR5BnVidW50dQNjb20AAAEAABAAAAgABLl9viQ=\",\"type\":\"1\"},{\"data\":\"CHNlT3VyaXR5BnVidW50dQNjb20AAAEAAQAAAAgABFu9Wyc=\",\"type\":\"1\"}],\"ResolvedIPs\":[\"67.43.156.1\",\"67.43.156.2\",\"67.43.156.3\"],\"ResolverDecision\":\"allowedOnNoPolicyMatch\",\"SrcIP\":\"67.43.156.2\",\"SrcPort\":0,\"TimeZone\":\"UTC\",\"TimeZoneInferredMethod\":\"fromLocalTime\",\"UserID\":\"166befbb-00e3-5e20-bd6e-27245000000\"}",
        "outcome": "success",
        "timezone": "UTC",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "083a8354-d56c-11ed-9771-6a842b111aaa",
        "name": "zt-test-vm1"
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "protocol": "https"
    },
    "related": {
        "hosts": [
            "083a8354-d56c-11ed-9771-6a842b111aaa",
            "zt-test-vm1"
        ],
        "ip": [
            "67.43.156.2",
            "89.160.20.129"
        ],
        "user": [
            "166befbb-00e3-5e20-bd6e-27245000000",
            "user@test.com"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.2",
        "port": 0
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-gateway_dns"
    ],
    "user": {
        "email": "user@test.com",
        "id": "166befbb-00e3-5e20-bd6e-27245000000"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.gateway_dns.account_id | Cloudflare account ID. | keyword |
| cloudflare_logpush.gateway_dns.answers | The response data objects. | flattened |
| cloudflare_logpush.gateway_dns.application_id | ID of the application the domain belongs to. | long |
| cloudflare_logpush.gateway_dns.application_name | Name of the application the domain belongs to. | keyword |
| cloudflare_logpush.gateway_dns.authoritative_name_server_ip | The IPs of the authoritative nameservers that provided the answers, if any. | ip |
| cloudflare_logpush.gateway_dns.cname | Resolved intermediate cname domains. | keyword |
| cloudflare_logpush.gateway_dns.cname_category.ids | ID or IDs of category that the intermediate cname domains belongs to. | keyword |
| cloudflare_logpush.gateway_dns.cname_category.names | Name or names of category that the intermediate cname domains belongs to. | keyword |
| cloudflare_logpush.gateway_dns.cname_reversed | Resolved intermediate cname domains in reverse. | keyword |
| cloudflare_logpush.gateway_dns.colo.code | The name of the colo that received the DNS query. | keyword |
| cloudflare_logpush.gateway_dns.colo.id | The ID of the colo that received the DNS query. | long |
| cloudflare_logpush.gateway_dns.custom_resolver.address | IP and port combo used to resolve the custom dns resolver query, if any. | keyword |
| cloudflare_logpush.gateway_dns.custom_resolver.duration_milli | The time it took for the custom resolver to respond in milliseconds. | long |
| cloudflare_logpush.gateway_dns.custom_resolver.policy.ids | Custom resolver policy UUID, if matched. | keyword |
| cloudflare_logpush.gateway_dns.custom_resolver.policy.names | Custom resolver policy name, if matched. | keyword |
| cloudflare_logpush.gateway_dns.custom_resolver.response | Status of the custom resolver response. | keyword |
| cloudflare_logpush.gateway_dns.destination.ip | The destination IP address the DNS query was made to. | ip |
| cloudflare_logpush.gateway_dns.destination.port | The destination port used at the edge. The port changes based on the protocol used by the DNS query. | long |
| cloudflare_logpush.gateway_dns.doh_subdomain | The destination DoH subdomain the DNS query was made to. | keyword |
| cloudflare_logpush.gateway_dns.dot_subdomain | The destination DoT subdomain the DNS query was made to. | keyword |
| cloudflare_logpush.gateway_dns.extended_dns_error_codes | List of returned Extended DNS Error Codes. | keyword |
| cloudflare_logpush.gateway_dns.host.id | UUID of the device where the HTTP request originated from. | keyword |
| cloudflare_logpush.gateway_dns.host.name | The name of the device where the HTTP request originated from. | keyword |
| cloudflare_logpush.gateway_dns.initial_category.ids | ID or IDs of category that the queried domains belongs to. | keyword |
| cloudflare_logpush.gateway_dns.initial_category.names | Name or names of category that the queried domains belongs to. | keyword |
| cloudflare_logpush.gateway_dns.is_response_cached | Response comes from cache or not. | boolean |
| cloudflare_logpush.gateway_dns.location.id | UUID of the location the DNS request is coming from. | keyword |
| cloudflare_logpush.gateway_dns.location.name | Name of the location the DNS request is coming from. | keyword |
| cloudflare_logpush.gateway_dns.matched.category.ids | ID or IDs of category that the domain was matched with the policy. | long |
| cloudflare_logpush.gateway_dns.matched.category.names | Name or names of category that the domain was matched with the policy. | keyword |
| cloudflare_logpush.gateway_dns.matched.indicator_feed.ids | ID or IDs of indicator feed(s) that the domain was matched with the policy. | keyword |
| cloudflare_logpush.gateway_dns.matched.indicator_feed.names | Name or names of indicator feed(s) that the domain was matched with the policy. | keyword |
| cloudflare_logpush.gateway_dns.policy.id | ID of the policy/rule that was applied (if any). | keyword |
| cloudflare_logpush.gateway_dns.policy.name | Name of the policy that was applied (if any) | keyword |
| cloudflare_logpush.gateway_dns.protocol | The protocol used for the DNS query by the client. | keyword |
| cloudflare_logpush.gateway_dns.question.category.ids | ID or IDs of category that the domain belongs to. | long |
| cloudflare_logpush.gateway_dns.question.category.names | Name or names of category that the domain belongs to. | keyword |
| cloudflare_logpush.gateway_dns.question.id | Globally unique identifier of the query. | keyword |
| cloudflare_logpush.gateway_dns.question.indicator_feed.ids | ID or IDs of indicator feed(s) that the domain belongs to. | long |
| cloudflare_logpush.gateway_dns.question.indicator_feed.names | Name or names of indicator feed(s) that the domain belongs to. | keyword |
| cloudflare_logpush.gateway_dns.question.name | The query name. | keyword |
| cloudflare_logpush.gateway_dns.question.reversed | Query name in reverse. | keyword |
| cloudflare_logpush.gateway_dns.question.size | The size of the DNS request in bytes. | long |
| cloudflare_logpush.gateway_dns.question.type | The type of DNS query. | keyword |
| cloudflare_logpush.gateway_dns.question.type_id | ID of the type of DNS query. | long |
| cloudflare_logpush.gateway_dns.resolved_ip | The resolved IPs in the response, if any. | ip |
| cloudflare_logpush.gateway_dns.resolved_ip_details.category.ids | ID or IDs of category that the IPs in the response belongs to. | keyword |
| cloudflare_logpush.gateway_dns.resolved_ip_details.category.names | Name or names of category that the IPs in the response belongs to. | keyword |
| cloudflare_logpush.gateway_dns.resolved_ip_details.continent_codes | Continent code of each resolved IP, if any. | keyword |
| cloudflare_logpush.gateway_dns.resolved_ip_details.country_codes | Country code of each resolved IP, if any. | keyword |
| cloudflare_logpush.gateway_dns.resolved_ip_details.ips | The resolved IPs in the response, if any. | ip |
| cloudflare_logpush.gateway_dns.resolver.policy.id | Resolver policy UUID, if any matched. | keyword |
| cloudflare_logpush.gateway_dns.resolver.policy.names | Resolver policy name, if any matched. | keyword |
| cloudflare_logpush.gateway_dns.resolver_decision | Result of the DNS query. | keyword |
| cloudflare_logpush.gateway_dns.resource_records.json | String that represents the JSON array with the returned resource records. | match_only_text |
| cloudflare_logpush.gateway_dns.resource_records.object | The rdata objects. | flattened |
| cloudflare_logpush.gateway_dns.response_code | The return code sent back by the DNS resolver. | keyword |
| cloudflare_logpush.gateway_dns.source.ip | The source IP address making the DNS query. | ip |
| cloudflare_logpush.gateway_dns.source.port | The port used by the client when they sent the DNS request. | long |
| cloudflare_logpush.gateway_dns.source_id.continent_code | Continent code of the source IP address making the DNS query. | keyword |
| cloudflare_logpush.gateway_dns.source_id.country_code | Country code of the source IP address making the DNS query. | keyword |
| cloudflare_logpush.gateway_dns.timestamp | The date and time the corresponding DNS request was made. | date |
| cloudflare_logpush.gateway_dns.timezone | Time zone used to calculate the current time, if a matched rule was scheduled with it. | keyword |
| cloudflare_logpush.gateway_dns.timezone_inferred_method | Method used to pick the time zone for the schedule. | keyword |
| cloudflare_logpush.gateway_dns.user.email | Email used to authenticate the client. | keyword |
| cloudflare_logpush.gateway_dns.user.id | User identity where the HTTP request originated from. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### gateway_http

This is the `gateway_http` dataset.

#### Example

An example event for `gateway_http` looks as following:

```json
{
    "@timestamp": "2023-05-03T20:55:05.000Z",
    "agent": {
        "ephemeral_id": "422a9db8-990a-4401-990d-78bc07f50303",
        "id": "35a71f1e-244f-46e7-b53b-cf8c2913d40f",
        "name": "elastic-agent-18936",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "gateway_http": {
            "account_id": "e1836771179f98aabb828da5ea69a348",
            "action": "block",
            "blocked_file": {
                "hash": "91dc1db739a705105e1c763bfdbdaa84c0de8",
                "name": "downloaded_test",
                "reason": "malware",
                "size": 43,
                "type": "bin"
            },
            "destination": {
                "ip": "89.160.20.129",
                "port": 443
            },
            "downloaded_files": [
                "downloaded_file",
                "downloaded_test"
            ],
            "file_info": {
                "files": [
                    {
                        "name": "downloaded_file",
                        "size": 43
                    },
                    {
                        "name": "downloaded_test",
                        "size": 341
                    }
                ]
            },
            "host": {
                "id": "083a8354-d56c-11ed-9771-6a842b100cff",
                "name": "zt-test-vm1"
            },
            "isolated": false,
            "policy": {
                "id": "85063bec-74cb-4546-85a3-e0cde2cdfda2",
                "name": "Block Yahoo"
            },
            "request": {
                "host": "guce.yahoo.com",
                "method": "GET",
                "referrer": "https://www.example.com/",
                "version": "HTTP/2"
            },
            "request_id": "1884fec9b600007fb06a299400000001",
            "response": {
                "status_code": 302
            },
            "source": {
                "internal_ip": "192.168.1.123",
                "ip": "67.43.156.2",
                "port": 47924
            },
            "timestamp": "2023-05-03T20:55:05.000Z",
            "untrusted_certificate_action": "none",
            "uploaded_files": [
                "uploaded_file",
                "uploaded_test"
            ],
            "url": "https://test.com",
            "user": {
                "email": "user@example.com",
                "id": "166befbb-00e3-5e20-bd6e-27245723949f"
            },
            "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/112.0"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.gateway_http",
        "namespace": "29625",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.129",
        "port": 443
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "35a71f1e-244f-46e7-b53b-cf8c2913d40f",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "action": "block",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.gateway_http",
        "ingested": "2025-03-13T21:04:53Z",
        "kind": "event",
        "original": "{\"AccountID\":\"e1836771179f98aabb828da5ea69a348\",\"Action\":\"block\",\"BlockedFileHash\":\"91dc1db739a705105e1c763bfdbdaa84c0de8\",\"BlockedFileName\":\"downloaded_test\",\"BlockedFileReason\":\"malware\",\"BlockedFileSize\":43,\"BlockedFileType\":\"bin\",\"Datetime\":\"2023-05-03T20:55:05Z\",\"DestinationIP\":\"89.160.20.129\",\"DestinationPort\":443,\"DeviceID\":\"083a8354-d56c-11ed-9771-6a842b100cff\",\"DeviceName\":\"zt-test-vm1\",\"DownloadedFileNames\":[\"downloaded_file\",\"downloaded_test\"],\"Email\":\"user@example.com\",\"FileInfo\":{\"files\":[{\"name\":\"downloaded_file\",\"size\":43},{\"name\":\"downloaded_test\",\"size\":341}]},\"HTTPHost\":\"guce.yahoo.com\",\"HTTPMethod\":\"GET\",\"HTTPStatusCode\":302,\"HTTPVersion\":\"HTTP/2\",\"IsIsolated\":false,\"PolicyID\":\"85063bec-74cb-4546-85a3-e0cde2cdfda2\",\"PolicyName\":\"Block Yahoo\",\"Referer\":\"https://www.example.com/\",\"RequestID\":\"1884fec9b600007fb06a299400000001\",\"SourceIP\":\"67.43.156.2\",\"SourceInternalIP\":\"192.168.1.123\",\"SourcePort\":47924,\"URL\":\"https://test.com\",\"UntrustedCertificateAction\":\"none\",\"UploadedFileNames\":[\"uploaded_file\",\"uploaded_test\"],\"UserAgent\":\"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/112.0\",\"UserID\":\"166befbb-00e3-5e20-bd6e-27245723949f\"}",
        "type": [
            "info",
            "denied"
        ]
    },
    "host": {
        "id": "083a8354-d56c-11ed-9771-6a842b100cff",
        "name": "zt-test-vm1"
    },
    "http": {
        "request": {
            "method": "GET",
            "referrer": "https://www.example.com/"
        },
        "response": {
            "status_code": 302
        },
        "version": "HTTP/2"
    },
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "hosts": [
            "083a8354-d56c-11ed-9771-6a842b100cff",
            "zt-test-vm1"
        ],
        "ip": [
            "67.43.156.2",
            "89.160.20.129"
        ],
        "user": [
            "166befbb-00e3-5e20-bd6e-27245723949f",
            "user@example.com"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.2",
        "port": 47924
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-gateway_http"
    ],
    "url": {
        "domain": "test.com",
        "original": "https://test.com",
        "scheme": "https"
    },
    "user": {
        "email": "user@example.com",
        "id": "166befbb-00e3-5e20-bd6e-27245723949f"
    },
    "user_agent": {
        "original": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/112.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.gateway_http.account_id | Cloudflare account tag. | keyword |
| cloudflare_logpush.gateway_http.action | Action performed by gateway on the HTTP request. | keyword |
| cloudflare_logpush.gateway_http.application.ids | IDs of the applications that matched the session parameters. | keyword |
| cloudflare_logpush.gateway_http.application.names | Names of the applications that matched the session parameters. | keyword |
| cloudflare_logpush.gateway_http.blocked_file.hash | Hash of the file blocked in the response, if any. | keyword |
| cloudflare_logpush.gateway_http.blocked_file.name | File name blocked in the request, if any. | keyword |
| cloudflare_logpush.gateway_http.blocked_file.reason | Reason file was blocked in the response, if any. | keyword |
| cloudflare_logpush.gateway_http.blocked_file.size | File size(bytes) blocked in the response, if any. | long |
| cloudflare_logpush.gateway_http.blocked_file.type | File type blocked in the response eg. exe, bin, if any. | keyword |
| cloudflare_logpush.gateway_http.category.ids | IDs of the categories that matched the session parameters. | keyword |
| cloudflare_logpush.gateway_http.category.names | Names of the categories that matched the session parameters. | keyword |
| cloudflare_logpush.gateway_http.destination.ip | Destination IP of the request. | ip |
| cloudflare_logpush.gateway_http.destination.port | Destination port of the request. | long |
| cloudflare_logpush.gateway_http.destination_ip.continent_code | Continent code of the destination IP of the network session. | keyword |
| cloudflare_logpush.gateway_http.destination_ip.country_code | Country code of the destination IP of the network session. | keyword |
| cloudflare_logpush.gateway_http.download_matched_dlp.profile_entries | List of matched DLP entries in the HTTP request. | keyword |
| cloudflare_logpush.gateway_http.download_matched_dlp.profiles | List of matched DLP profiles in the HTTP request. | keyword |
| cloudflare_logpush.gateway_http.downloaded_files | List of files downloaded in the HTTP request. | keyword |
| cloudflare_logpush.gateway_http.file_info | Information about files detected within the HTTP request. | flattened |
| cloudflare_logpush.gateway_http.forensic_copy_status | Status of any associated forensic copies that may have been captured during the request. | keyword |
| cloudflare_logpush.gateway_http.host.id | UUID of the device where the HTTP request originated from. | keyword |
| cloudflare_logpush.gateway_http.host.name | The name of the device where the HTTP request originated from. | keyword |
| cloudflare_logpush.gateway_http.isolated | If the requested was isolated with Cloudflare Browser Isolation or not. | boolean |
| cloudflare_logpush.gateway_http.policy.id | The gateway policy UUID applied to the request, if any. | keyword |
| cloudflare_logpush.gateway_http.policy.name | The name of the gateway policy applied to the request, if any. | keyword |
| cloudflare_logpush.gateway_http.private_app_aud | The private app AUD, if any. | keyword |
| cloudflare_logpush.gateway_http.proxy_endpoint | The proxy endpoint used on this network session, if any. | keyword |
| cloudflare_logpush.gateway_http.quarantined | If the request content was quarantined. | keyword |
| cloudflare_logpush.gateway_http.request.host | Content of the host header in the HTTP request. | keyword |
| cloudflare_logpush.gateway_http.request.method | HTTP request method. | keyword |
| cloudflare_logpush.gateway_http.request.referrer | Contents of the referer header in the HTTP request. | keyword |
| cloudflare_logpush.gateway_http.request.version | Version name for the HTTP request. | keyword |
| cloudflare_logpush.gateway_http.request_id | Cloudflare request ID. | keyword |
| cloudflare_logpush.gateway_http.response.status_code | HTTP status code gateway returned to the user. Zero if nothing was returned. | long |
| cloudflare_logpush.gateway_http.session_id | The session identifier of this network session. | keyword |
| cloudflare_logpush.gateway_http.source.internal_ip | Local LAN IP of the device. Only available when connected via a GRE/IPsec tunnel on-ramp. | ip |
| cloudflare_logpush.gateway_http.source.ip | Source IP of the request. | ip |
| cloudflare_logpush.gateway_http.source.port | Source port of the request. | long |
| cloudflare_logpush.gateway_http.source_ip.continent_code | Continent code of the source IP of the network session. | keyword |
| cloudflare_logpush.gateway_http.source_ip.country_code | Country code of the source IP of the network session. | keyword |
| cloudflare_logpush.gateway_http.timestamp | The date and time the corresponding HTTP request was made. | date |
| cloudflare_logpush.gateway_http.untrusted_certificate_action | Action taken when an untrusted origin certificate error occurs. | keyword |
| cloudflare_logpush.gateway_http.upload_matched_dlp.profile_entries | List of matched DLP entries in the HTTP request. | keyword |
| cloudflare_logpush.gateway_http.upload_matched_dlp.profiles | List of matched DLP profiles in the HTTP request. | keyword |
| cloudflare_logpush.gateway_http.uploaded_files | List of files uploaded in the HTTP request. | keyword |
| cloudflare_logpush.gateway_http.url | HTTP request URL. | keyword |
| cloudflare_logpush.gateway_http.user.email | Email used to authenticate the client. | keyword |
| cloudflare_logpush.gateway_http.user.id | User identity where the HTTP request originated from. | keyword |
| cloudflare_logpush.gateway_http.user_agent | Contents of the user agent header in the HTTP request. | keyword |
| cloudflare_logpush.gateway_http.virtual_network.id | The identifier of the virtual network the device was connected to, if any. | keyword |
| cloudflare_logpush.gateway_http.virtual_network.name | The name of the virtual network the device was connected to, if any. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### gateway_network

This is the `gateway_network` dataset.

#### Example

An example event for `gateway_network` looks as following:

```json
{
    "@timestamp": "2023-05-18T21:12:57.058Z",
    "agent": {
        "ephemeral_id": "74d79ad1-7adf-4f23-8f5e-43bc2f26fa05",
        "id": "8468faf8-5efa-45c9-92e3-8616cee72a54",
        "name": "elastic-agent-97827",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "gateway_network": {
            "account_id": "e1836771179f98aabb828da5ea69a111",
            "action": "allowedOnNoRuleMatch",
            "destination": {
                "ip": "89.160.20.129",
                "port": 443
            },
            "host": {
                "id": "083a8354-d56c-11ed-9771-6a842b100cff",
                "name": "zt-test-vm1"
            },
            "override": {
                "ip": "175.16.199.4",
                "port": 8080
            },
            "policy": {
                "id": "85063bec-74cb-4546-85a3-e0cde2cdfda2",
                "name": "My policy"
            },
            "session_id": "5f2d04be-3512-11e8-b467-0ed5f89f718b",
            "sni": "www.elastic.co",
            "source": {
                "internal_ip": "192.168.1.3",
                "ip": "67.43.156.2",
                "port": 47924
            },
            "timestamp": "2023-05-18T21:12:57.058Z",
            "transport": "tcp",
            "user": {
                "email": "user@test.com",
                "id": "166befbb-00e3-5e20-bd6e-27245723949f"
            }
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.gateway_network",
        "namespace": "93574",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "domain": "www.elastic.co",
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.129",
        "port": 443
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8468faf8-5efa-45c9-92e3-8616cee72a54",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "action": "allowedOnNoRuleMatch",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.gateway_network",
        "id": "5f2d04be-3512-11e8-b467-0ed5f89f718b",
        "ingested": "2025-03-13T21:05:52Z",
        "kind": "event",
        "original": "{\"AccountID\":\"e1836771179f98aabb828da5ea69a111\",\"Action\":\"allowedOnNoRuleMatch\",\"Datetime\":1684444377058000000,\"DestinationIP\":\"89.160.20.129\",\"DestinationPort\":443,\"DeviceID\":\"083a8354-d56c-11ed-9771-6a842b100cff\",\"DeviceName\":\"zt-test-vm1\",\"Email\":\"user@test.com\",\"OverrideIP\":\"175.16.199.4\",\"OverridePort\":8080,\"PolicyID\":\"85063bec-74cb-4546-85a3-e0cde2cdfda2\",\"PolicyName\":\"My policy\",\"SNI\":\"www.elastic.co\",\"SessionID\":\"5f2d04be-3512-11e8-b467-0ed5f89f718b\",\"SourceIP\":\"67.43.156.2\",\"SourceInternalIP\":\"192.168.1.3\",\"SourcePort\":47924,\"Transport\":\"tcp\",\"UserID\":\"166befbb-00e3-5e20-bd6e-27245723949f\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "083a8354-d56c-11ed-9771-6a842b100cff",
        "name": "zt-test-vm1"
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "transport": "tcp"
    },
    "related": {
        "hosts": [
            "www.elastic.co",
            "083a8354-d56c-11ed-9771-6a842b100cff",
            "zt-test-vm1"
        ],
        "ip": [
            "67.43.156.2",
            "89.160.20.129",
            "175.16.199.4"
        ],
        "user": [
            "166befbb-00e3-5e20-bd6e-27245723949f",
            "user@test.com"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.2",
        "port": 47924
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-gateway_network"
    ],
    "tls": {
        "client": {
            "server_name": "www.elastic.co"
        }
    },
    "user": {
        "email": "user@test.com",
        "id": "166befbb-00e3-5e20-bd6e-27245723949f"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.gateway_network.account_id | Cloudflare account tag. | keyword |
| cloudflare_logpush.gateway_network.action | Action performed by gateway on the session. | keyword |
| cloudflare_logpush.gateway_network.application.ids | IDs of the applications that matched the session parameters. | keyword |
| cloudflare_logpush.gateway_network.application.names | Names of the applications that matched the session parameters. | keyword |
| cloudflare_logpush.gateway_network.category.ids | IDs of the categories that matched the session parameters. | keyword |
| cloudflare_logpush.gateway_network.category.names | Names of the categories that matched the session parameters. | keyword |
| cloudflare_logpush.gateway_network.destination.ip | Destination IP of the network session. | ip |
| cloudflare_logpush.gateway_network.destination.port | Destination port of the network session. | long |
| cloudflare_logpush.gateway_network.destination_ip.continent_code | Continent code of the destination IP of the network session. | keyword |
| cloudflare_logpush.gateway_network.destination_ip.country_code | Country code of the destination IP of the network session. | keyword |
| cloudflare_logpush.gateway_network.detected_protocol | Detected traffic protocol of the network session. | keyword |
| cloudflare_logpush.gateway_network.host.id | UUID of the device where the network session originated from. | keyword |
| cloudflare_logpush.gateway_network.host.name | The name of the device where the network session originated from. | keyword |
| cloudflare_logpush.gateway_network.override.ip | Overriden IP of the network session, if any. | ip |
| cloudflare_logpush.gateway_network.override.port | Overriden port of the network session, if any. | long |
| cloudflare_logpush.gateway_network.policy.id | Identifier of the policy/rule that was applied, if any. | keyword |
| cloudflare_logpush.gateway_network.policy.name | The name of the gateway policy applied to the session, if any. | keyword |
| cloudflare_logpush.gateway_network.proxy_endpoint | The proxy endpoint used on this network session, if any. | keyword |
| cloudflare_logpush.gateway_network.session_id | The session identifier of this network session. | keyword |
| cloudflare_logpush.gateway_network.sni | Content of the SNI (Server Name Indication) for the TLS network session, if any. | keyword |
| cloudflare_logpush.gateway_network.source.internal_ip | Local LAN IP of the device. Only available when connected via a GRE/IPsec tunnel on-ramp. | ip |
| cloudflare_logpush.gateway_network.source.ip | Source IP of the network session. | ip |
| cloudflare_logpush.gateway_network.source.port | Source port of the network session. | long |
| cloudflare_logpush.gateway_network.source_ip.continent_code | Continent code of the source IP of the network session. | keyword |
| cloudflare_logpush.gateway_network.source_ip.country_code | Country code of the source IP of the network session. | keyword |
| cloudflare_logpush.gateway_network.timestamp | The date and time the corresponding network session was made. | date |
| cloudflare_logpush.gateway_network.transport | Transport protocol used for this session. | keyword |
| cloudflare_logpush.gateway_network.user.email | Email associated with the user identity where the network sesion originated from. | keyword |
| cloudflare_logpush.gateway_network.user.id | User identity where the network session originated from. | keyword |
| cloudflare_logpush.gateway_network.virtual_network.id | The identifier of the virtual network the device was connected to, if any. | keyword |
| cloudflare_logpush.gateway_network.virtual_network.name | The name of the virtual network the device was connected to, if any. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### http_request

This is the `http_request` dataset.

#### Example

An example event for `http_request` looks as following:

```json
{
    "@timestamp": "2022-05-25T13:25:26.000Z",
    "agent": {
        "ephemeral_id": "3d7bb881-29a8-487a-a69d-146c10236cf1",
        "id": "c3e8acfc-07d7-4e90-868e-a0f2c762068d",
        "name": "elastic-agent-47256",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "http_request": {
            "bot": {
                "detection_ids": [
                    7,
                    8,
                    9
                ],
                "score": {
                    "src": "Verified Bot",
                    "value": 20
                },
                "tag": [
                    "bing",
                    "api"
                ]
            },
            "cache": {
                "response": {
                    "bytes": 983828,
                    "status": 200
                },
                "status": "dynamic",
                "tiered_fill": false
            },
            "client": {
                "asn": 43766,
                "country": "sa",
                "device": {
                    "type": "desktop"
                },
                "ip": "175.16.199.0",
                "ip_class": "noRecord",
                "mtls": {
                    "auth": {
                        "fingerprint": "Fingerprint",
                        "status": "unknown"
                    }
                },
                "request": {
                    "bytes": 5800,
                    "host": "xyz.example.com",
                    "method": "POST",
                    "path": "/xyz/checkout",
                    "protocol": "HTTP/1.1",
                    "referer": "https://example.com/s/example/default?sourcerer=(default:(id:!n,selectedPatterns:!(example,%27logs-endpoint.*-example%27,%27logs-system.*-example%27,%27logs-windows.*-example%27)))&timerange=(global:(linkTo:!(),timerange:(from:%272022-05-16T06:26:36.340Z%27,fromStr:now-24h,kind:relative,to:%272022-05-17T06:26:36.340Z%27,toStr:now)),timeline:(linkTo:!(),timerange:(from:%272022-04-17T22:00:00.000Z%27,kind:absolute,to:%272022-04-18T21:59:59.999Z%27)))&timeline=(activeTab:notes,graphEventId:%27%27,id:%279844bdd4-4dd6-5b22-ab40-3cd46fce8d6b%27,isOpen:!t)",
                    "scheme": "https",
                    "source": "edgeWorkerFetch",
                    "uri": "/s/example/api/telemetry/v2/clusters/_stats",
                    "user": {
                        "agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
                    }
                },
                "src": {
                    "port": 0
                },
                "ssl": {
                    "cipher": "NONE",
                    "protocol": "TLSv1.2"
                },
                "tcp_rtt": {
                    "ms": 0
                },
                "xrequested_with": "Request With"
            },
            "cookies": {
                "key": "value"
            },
            "edge": {
                "cf_connecting_o2o": false,
                "colo": {
                    "code": "RUH",
                    "id": 339
                },
                "end_time": "2022-05-25T13:25:32.000Z",
                "pathing": {
                    "op": "wl",
                    "src": "macro",
                    "status": "nr"
                },
                "rate": {
                    "limit": {
                        "action": "unknown",
                        "id": 0
                    }
                },
                "request": {
                    "host": "abc.example.com"
                },
                "response": {
                    "body_bytes": 980397,
                    "bytes": 981308,
                    "compression_ratio": 0,
                    "content_type": "application/json",
                    "status": 200
                },
                "server": {
                    "ip": "1.128.0.0"
                },
                "start_time": "2022-05-25T13:25:26.000Z",
                "time_to_first_byte": {
                    "ms": 5333
                }
            },
            "origin": {
                "dns_response_time": {
                    "ms": 3
                },
                "ip": "67.43.156.0",
                "request_header_send_duration": {
                    "ms": 0
                },
                "response": {
                    "bytes": 0,
                    "duration": {
                        "ms": 5319
                    },
                    "header_receive_duration": {
                        "ms": 5155
                    },
                    "http": {
                        "expires": "2022-05-27T13:25:26.000Z",
                        "last_modified": "2022-05-26T13:25:26.000Z"
                    },
                    "status": 200,
                    "time": 5232000000
                },
                "ssl_protocol": "TLSv1.2",
                "tcp_handshake_duration": {
                    "ms": 24
                },
                "tls_handshake_duration": {
                    "ms": 53
                }
            },
            "parent_ray": {
                "id": "710e98d93d50357d"
            },
            "ray": {
                "id": "710e98d9367f357d"
            },
            "security_level": "off",
            "smart_route": {
                "colo": {
                    "id": 20
                }
            },
            "upper_tier": {
                "colo": {
                    "id": 0
                }
            },
            "waf": {
                "action": "unknown",
                "flag": "0",
                "matched_var": "example",
                "profile": "unknown",
                "rule": {
                    "id": "98d93d5",
                    "message": "matchad variable message"
                },
                "score": {
                    "global": 50,
                    "rce": 1,
                    "sqli": 99,
                    "xss": 90
                }
            },
            "worker": {
                "cpu_time": 0,
                "status": "unknown",
                "subrequest": {
                    "count": 0,
                    "value": true
                }
            },
            "zone": {
                "id": 393347122,
                "name": "example.com"
            }
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.http_request",
        "namespace": "70990",
        "type": "logs"
    },
    "destination": {
        "ip": "67.43.156.0"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c3e8acfc-07d7-4e90-868e-a0f2c762068d",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.http_request",
        "id": "710e98d9367f357d",
        "ingested": "2025-05-13T05:53:56Z",
        "kind": "event",
        "original": "{\"BotDetectionIDs\":[7,8,9],\"BotScore\":20,\"BotScoreSrc\":\"Verified Bot\",\"BotTags\":[\"bing\",\"api\"],\"CacheCacheStatus\":\"dynamic\",\"CacheResponseBytes\":983828,\"CacheResponseStatus\":200,\"CacheTieredFill\":false,\"ClientASN\":43766,\"ClientCountry\":\"sa\",\"ClientDeviceType\":\"desktop\",\"ClientIP\":\"175.16.199.0\",\"ClientIPClass\":\"noRecord\",\"ClientMTLSAuthCertFingerprint\":\"Fingerprint\",\"ClientMTLSAuthStatus\":\"unknown\",\"ClientRequestBytes\":5800,\"ClientRequestHost\":\"xyz.example.com\",\"ClientRequestMethod\":\"POST\",\"ClientRequestPath\":\"/xyz/checkout\",\"ClientRequestProtocol\":\"HTTP/1.1\",\"ClientRequestReferer\":\"https://example.com/s/example/default?sourcerer=(default:(id:!n,selectedPatterns:!(example,%27logs-endpoint.*-example%27,%27logs-system.*-example%27,%27logs-windows.*-example%27)))\\u0026timerange=(global:(linkTo:!(),timerange:(from:%272022-05-16T06:26:36.340Z%27,fromStr:now-24h,kind:relative,to:%272022-05-17T06:26:36.340Z%27,toStr:now)),timeline:(linkTo:!(),timerange:(from:%272022-04-17T22:00:00.000Z%27,kind:absolute,to:%272022-04-18T21:59:59.999Z%27)))\\u0026timeline=(activeTab:notes,graphEventId:%27%27,id:%279844bdd4-4dd6-5b22-ab40-3cd46fce8d6b%27,isOpen:!t)\",\"ClientRequestScheme\":\"https\",\"ClientRequestSource\":\"edgeWorkerFetch\",\"ClientRequestURI\":\"/s/example/api/telemetry/v2/clusters/_stats\",\"ClientRequestUserAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36\",\"ClientSSLCipher\":\"NONE\",\"ClientSSLProtocol\":\"TLSv1.2\",\"ClientSrcPort\":0,\"ClientTCPRTTMs\":0,\"ClientXRequestedWith\":\"Request With\",\"Cookies\":{\"key\":\"value\"},\"EdgeCFConnectingO2O\":false,\"EdgeColoCode\":\"RUH\",\"EdgeColoID\":339,\"EdgeEndTimestamp\":\"2022-05-25T13:25:32Z\",\"EdgePathingOp\":\"wl\",\"EdgePathingSrc\":\"macro\",\"EdgePathingStatus\":\"nr\",\"EdgeRateLimitAction\":\"unknown\",\"EdgeRateLimitID\":0,\"EdgeRequestHost\":\"abc.example.com\",\"EdgeResponseBodyBytes\":980397,\"EdgeResponseBytes\":981308,\"EdgeResponseCompressionRatio\":0,\"EdgeResponseContentType\":\"application/json\",\"EdgeResponseStatus\":200,\"EdgeServerIP\":\"1.128.0.0\",\"EdgeStartTimestamp\":\"2022-05-25T13:25:26Z\",\"EdgeTimeToFirstByteMs\":5333,\"OriginDNSResponseTimeMs\":3,\"OriginIP\":\"67.43.156.0\",\"OriginRequestHeaderSendDurationMs\":0,\"OriginResponseBytes\":0,\"OriginResponseDurationMs\":5319,\"OriginResponseHTTPExpires\":\"2022-05-27T13:25:26Z\",\"OriginResponseHTTPLastModified\":\"2022-05-26T13:25:26Z\",\"OriginResponseHeaderReceiveDurationMs\":5155,\"OriginResponseStatus\":200,\"OriginResponseTime\":5232000000,\"OriginSSLProtocol\":\"TLSv1.2\",\"OriginTCPHandshakeDurationMs\":24,\"OriginTLSHandshakeDurationMs\":53,\"ParentRayID\":\"710e98d93d50357d\",\"RayID\":\"710e98d9367f357d\",\"SecurityAction\":\"unknown\",\"SecurityLevel\":\"off\",\"SecurityRuleDescription\":\"matchad variable message\",\"SecurityRuleID\":\"98d93d5\",\"SmartRouteColoID\":20,\"UpperTierColoID\":0,\"WAFAttackScore\":50,\"WAFFlags\":\"0\",\"WAFMatchedVar\":\"example\",\"WAFProfile\":\"unknown\",\"WAFRCEAttackScore\":1,\"WAFSQLiAttackScore\":99,\"WAFXSSAttackScore\":90,\"WorkerCPUTime\":0,\"WorkerStatus\":\"unknown\",\"WorkerSubrequest\":true,\"WorkerSubrequestCount\":0,\"ZoneID\":393347122,\"ZoneName\":\"example.com\"}",
        "type": [
            "info"
        ]
    },
    "http": {
        "request": {
            "method": "POST"
        },
        "response": {
            "mime_type": "application/json",
            "status_code": 200
        },
        "version": "1.1"
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "protocol": "http"
    },
    "related": {
        "ip": [
            "175.16.199.0",
            "67.43.156.0"
        ]
    },
    "source": {
        "as": {
            "number": 43766
        },
        "geo": {
            "country_iso_code": "sa"
        },
        "ip": "175.16.199.0"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-http_request"
    ],
    "tls": {
        "cipher": "NONE",
        "version": "1.2",
        "version_protocol": "tls"
    },
    "url": {
        "domain": "xyz.example.com",
        "original": "/s/example/api/telemetry/v2/clusters/_stats",
        "path": "/s/example/api/telemetry/v2/clusters/_stats",
        "scheme": "https"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.10.5",
            "name": "Mac OS X",
            "version": "10.10.5"
        },
        "version": "51.0.2704.103"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.http_request.bot.detection_ids | List of IDs that correlate to the Bot Management Heuristic detections made on a request. Available in Logpush v2 only. | long |
| cloudflare_logpush.http_request.bot.detection_tags | List of tags that correlate to the Bot Management Heuristic detections made on a request. Available only for Bot Management customers. To enable this feature, contact your account team. | keyword |
| cloudflare_logpush.http_request.bot.score.src | Detection engine responsible for generating the Bot Score. Possible values are Not Computed, Heuristics, Machine Learning, Behavioral Analysis, Verified Bot, JS Fingerprinting, Cloudflare Service. | text |
| cloudflare_logpush.http_request.bot.score.value | Cloudflare Bot Score. Scores below 30 are commonly associated with automated traffic. | long |
| cloudflare_logpush.http_request.bot.tag | Type of bot traffic (if available). Available in Logpush v2 only. | text |
| cloudflare_logpush.http_request.cache.reserve_used | Cache Reserve was used to serve this request. | boolean |
| cloudflare_logpush.http_request.cache.response.bytes | Number of bytes returned by the cache. | long |
| cloudflare_logpush.http_request.cache.response.status | Cache status. | long |
| cloudflare_logpush.http_request.cache.status | HTTP status code returned by the cache to the edge. | keyword |
| cloudflare_logpush.http_request.cache.tiered_fill | Tiered Cache was used to serve this request. | boolean |
| cloudflare_logpush.http_request.client.asn | Client AS number. | long |
| cloudflare_logpush.http_request.client.city | Approximate city of the client. | keyword |
| cloudflare_logpush.http_request.client.country | Country of the client IP address. | keyword |
| cloudflare_logpush.http_request.client.device.type | Client device type. | keyword |
| cloudflare_logpush.http_request.client.ip | IP address of the client. | ip |
| cloudflare_logpush.http_request.client.ip_class | Class IP. | keyword |
| cloudflare_logpush.http_request.client.latitude | Approximate latitude of the client. | keyword |
| cloudflare_logpush.http_request.client.longitude | Approximate longitude of the client. | keyword |
| cloudflare_logpush.http_request.client.mtls.auth.fingerprint | The SHA256 fingerprint of the certificate presented by the client during mTLS authentication. | keyword |
| cloudflare_logpush.http_request.client.mtls.auth.status | The status of mTLS authentication, Only populated on the first request on an mTLS connection. | keyword |
| cloudflare_logpush.http_request.client.region_code | The ISO-3166-2 region code of the client IP address. | keyword |
| cloudflare_logpush.http_request.client.request.bytes | Number of bytes in the client request. | long |
| cloudflare_logpush.http_request.client.request.host | Host requested by the client. | keyword |
| cloudflare_logpush.http_request.client.request.method | HTTP method of client request. | text |
| cloudflare_logpush.http_request.client.request.path | URI path requested by the client. | text |
| cloudflare_logpush.http_request.client.request.protocol | HTTP protocol of client request. | keyword |
| cloudflare_logpush.http_request.client.request.referer | HTTP request referrer. | text |
| cloudflare_logpush.http_request.client.request.scheme | The URL scheme requested by the visitor. | text |
| cloudflare_logpush.http_request.client.request.source | Identifies requests as coming from an external source or another service within Cloudflare. | keyword |
| cloudflare_logpush.http_request.client.request.uri | URI requested by the client. | text |
| cloudflare_logpush.http_request.client.request.user.agent | User agent reported by the client. | text |
| cloudflare_logpush.http_request.client.src.port | Client source port. | long |
| cloudflare_logpush.http_request.client.ssl.cipher | Client SSL cipher. | text |
| cloudflare_logpush.http_request.client.ssl.protocol | Client SSL (TLS) protocol. | keyword |
| cloudflare_logpush.http_request.client.tcp_rtt.ms | The smoothed average of TCP round-trip time (SRTT), For the initial request on a connection, this is measured only during connection setup, For a subsequent request on the same connection, it is measured over the entire connection lifetime up until the time that request is received. | long |
| cloudflare_logpush.http_request.client.xrequested_with | X-Requested-With HTTP header. | text |
| cloudflare_logpush.http_request.content_scan.results | List of content scan results. | keyword |
| cloudflare_logpush.http_request.content_scan.sizes | List of content object sizes. | long |
| cloudflare_logpush.http_request.content_scan.types | List of content types. | keyword |
| cloudflare_logpush.http_request.cookies | String key-value pairs for Cookies. | flattened |
| cloudflare_logpush.http_request.datetime | Timestamp when the request was received | date |
| cloudflare_logpush.http_request.edge.cf_connecting_o2o | True if the request looped through multiple zones on the Cloudflare edge. | boolean |
| cloudflare_logpush.http_request.edge.colo.code | IATA airport code of data center that received the request. | keyword |
| cloudflare_logpush.http_request.edge.colo.id | Cloudflare edge colo id. | long |
| cloudflare_logpush.http_request.edge.end_time | Timestamp at which the edge finished sending response to the client. | date |
| cloudflare_logpush.http_request.edge.pathing.op | Indicates what type of response was issued for this request. | text |
| cloudflare_logpush.http_request.edge.pathing.src | Details how the request was classified based on security checks. | text |
| cloudflare_logpush.http_request.edge.pathing.status | Indicates what data was used to determine the handling of this request. | text |
| cloudflare_logpush.http_request.edge.rate.limit.action | The action taken by the blocking rule; empty if no action taken. | keyword |
| cloudflare_logpush.http_request.edge.rate.limit.id | The internal rule ID of the rate-limiting rule that triggered a block (ban) or log action. | long |
| cloudflare_logpush.http_request.edge.request.host | Host header on the request from the edge to the origin. | keyword |
| cloudflare_logpush.http_request.edge.response.body_bytes | Size of the HTTP response body returned to clients. | long |
| cloudflare_logpush.http_request.edge.response.bytes | Number of bytes returned by the edge to the client. | long |
| cloudflare_logpush.http_request.edge.response.compression_ratio | Edge response compression ratio. | double |
| cloudflare_logpush.http_request.edge.response.content_type | Edge response Content-Type header value. | text |
| cloudflare_logpush.http_request.edge.response.status | HTTP status code returned by Cloudflare to the client. | long |
| cloudflare_logpush.http_request.edge.server.ip | IP of the edge server making a request to the origin. | ip |
| cloudflare_logpush.http_request.edge.start_time | Timestamp at which the edge received request from the client. | date |
| cloudflare_logpush.http_request.edge.time_to_first_byte.ms | Total view of Time To First Byte as measured at Cloudflare edge. | long |
| cloudflare_logpush.http_request.firewall.matches.action | Array of actions the Cloudflare firewall products performed on this request. | keyword |
| cloudflare_logpush.http_request.firewall.matches.rule_id | Array of RuleIDs of the firewall product that has matched the request. | keyword |
| cloudflare_logpush.http_request.firewall.matches.sources | The firewall products that matched the request. | keyword |
| cloudflare_logpush.http_request.ja3_hash | The MD5 hash of the JA3 fingerprint used to profile SSL/TLS clients. | keyword |
| cloudflare_logpush.http_request.ja4 | The JA4 fingerprint used to profile SSL/TLS clients. Available only for Bot Management customers. | keyword |
| cloudflare_logpush.http_request.ja4_signals | Inter-request statistics computed for this JA4 fingerprint. JA4Signals field is organized in key:value pairs, where values are numbers. Available only for Bot Management customers. | flattened |
| cloudflare_logpush.http_request.origin.dns_response_time.ms | Time taken to receive a DNS response for an origin name. | long |
| cloudflare_logpush.http_request.origin.ip | IP of the origin server. | ip |
| cloudflare_logpush.http_request.origin.request_header_send_duration.ms | Time taken to send request headers to origin after establishing a connection. | long |
| cloudflare_logpush.http_request.origin.response.bytes | Number of bytes returned by the origin server. | long |
| cloudflare_logpush.http_request.origin.response.duration.ms | Upstream response time, measured from the first datacenter that receives a request. | long |
| cloudflare_logpush.http_request.origin.response.header_receive_duration.ms | Time taken for origin to return response headers after Cloudflare finishes sending request headers. | long |
| cloudflare_logpush.http_request.origin.response.http.expires | Value of the origin expires header in RFC1123 format. | date |
| cloudflare_logpush.http_request.origin.response.http.last_modified | Value of the origin last-modified header in RFC1123 format. | date |
| cloudflare_logpush.http_request.origin.response.status | Status returned by the origin server. | long |
| cloudflare_logpush.http_request.origin.response.time | Number of nanoseconds it took the origin to return the response to edge. | long |
| cloudflare_logpush.http_request.origin.ssl_protocol | SSL (TLS) protocol used to connect to the origin. | text |
| cloudflare_logpush.http_request.origin.tcp_handshake_duration.ms | Time taken to complete TCP handshake with origin. | long |
| cloudflare_logpush.http_request.origin.tls_handshake_duration.ms | Time taken to complete TLS handshake with origin. | long |
| cloudflare_logpush.http_request.parent_ray.id | Ray ID of the parent request if this request was made using a Worker script. | keyword |
| cloudflare_logpush.http_request.ray.id | ID of the request. | keyword |
| cloudflare_logpush.http_request.request.headers | String key-value pairs for RequestHeaders. | flattened |
| cloudflare_logpush.http_request.response.headers | String key-value pairs for ResponseHeaders. | flattened |
| cloudflare_logpush.http_request.security_level | The security level configured at the time of this request. This is used to determine the sensitivity of the IP Reputation system. | text |
| cloudflare_logpush.http_request.smart_route.colo.id | The Cloudflare datacenter used to connect to the origin server if Argo Smart Routing is used. Available in Logpush v2 only. | long |
| cloudflare_logpush.http_request.upper_tier.colo.id | The “upper tier” datacenter that was checked for a cached copy if Tiered Cache is used. Available in Logpush v2 only. | long |
| cloudflare_logpush.http_request.waf.action | Action taken by the WAF, if triggered. | text |
| cloudflare_logpush.http_request.waf.flag | Additional configuration flags. | text |
| cloudflare_logpush.http_request.waf.matched_var | The full name of the most-recently matched variable. | text |
| cloudflare_logpush.http_request.waf.profile | The Profile of WAF. possible values are:- 'low', 'med', 'high'. | keyword |
| cloudflare_logpush.http_request.waf.rule.id | ID of the applied WAF rule. | keyword |
| cloudflare_logpush.http_request.waf.rule.message | Rule message associated with the triggered rule. | text |
| cloudflare_logpush.http_request.waf.score.global | Overall request score generated by the WAF detection module. | long |
| cloudflare_logpush.http_request.waf.score.rce | WAF score for a Remote Code Execution (RCE) attack. | long |
| cloudflare_logpush.http_request.waf.score.sqli | WAF score for an SQL injection (SQLi) attack. | long |
| cloudflare_logpush.http_request.waf.score.xss | WAF score for a Cross-site scripting (XSS) attack. | long |
| cloudflare_logpush.http_request.worker.cpu_time | Amount of time in microseconds spent executing a worker, if any. | long |
| cloudflare_logpush.http_request.worker.status | Status returned from worker daemon. | text |
| cloudflare_logpush.http_request.worker.subrequest.count | Number of subrequests issued by a worker when handling this request. | long |
| cloudflare_logpush.http_request.worker.subrequest.value | Whether or not this request was a worker subrequest. | boolean |
| cloudflare_logpush.http_request.worker.wall_time_us | Real-time in microseconds elapsed between start and end of worker invocation. | long |
| cloudflare_logpush.http_request.zone.id | Internal zone ID. | long |
| cloudflare_logpush.http_request.zone.name | The human-readable name of the zone. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### magic_ids

This is the `magic_ids` dataset.

#### Example

An example event for `magic_ids` looks as following:

```json
{
    "@timestamp": "2023-09-11T03:02:57.000Z",
    "agent": {
        "ephemeral_id": "e46bb125-e156-44bd-8ffb-17e3f689e070",
        "id": "2bea071c-88dd-45e5-8a18-8e10c9aa41ce",
        "name": "elastic-agent-79361",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "magic_ids": {
            "action": "pass",
            "colo": {
                "city": "Tokyo",
                "code": "NRT"
            },
            "destination": {
                "ip": "89.160.20.129",
                "port": 80
            },
            "signature": {
                "id": 2031296,
                "message": "ET CURRENT_EVENTS [Fireeye] POSSIBLE HackTool.TCP.Rubeus.[User32LogonProcesss]",
                "revision": 1
            },
            "source": {
                "ip": "67.43.156.2",
                "port": 44667
            },
            "timestamp": "2023-09-11T03:02:57.000Z",
            "transport": "tcp"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.magic_ids",
        "namespace": "22852",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.129",
        "port": 80
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2bea071c-88dd-45e5-8a18-8e10c9aa41ce",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "action": "pass",
        "agent_id_status": "verified",
        "category": [
            "network",
            "intrusion_detection"
        ],
        "dataset": "cloudflare_logpush.magic_ids",
        "ingested": "2025-03-13T21:10:31Z",
        "kind": "event",
        "original": "{\"Action\":\"pass\",\"ColoCity\":\"Tokyo\",\"ColoCode\":\"NRT\",\"DestinationIP\":\"89.160.20.129\",\"DestinationPort\":80,\"Protocol\":\"tcp\",\"SignatureID\":2031296,\"SignatureMessage\":\"ET CURRENT_EVENTS [Fireeye] POSSIBLE HackTool.TCP.Rubeus.[User32LogonProcesss]\",\"SignatureRevision\":1,\"SourceIP\":\"67.43.156.2\",\"SourcePort\":44667,\"Timestamp\":\"2023-09-11T03:02:57Z\"}",
        "type": [
            "info",
            "allowed"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "transport": "tcp"
    },
    "related": {
        "ip": [
            "89.160.20.129",
            "67.43.156.2"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.2",
        "port": 44667
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-magic_ids"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.magic_ids.action | What action was taken on the packet. Possible values are pass | block. | keyword |
| cloudflare_logpush.magic_ids.colo.city | The city where the detection occurred. | keyword |
| cloudflare_logpush.magic_ids.colo.code | The IATA airport code corresponding to where the detection occurred. | keyword |
| cloudflare_logpush.magic_ids.destination.ip | The destination IP of the packet which triggered the detection. | ip |
| cloudflare_logpush.magic_ids.destination.port | The destination port of the packet which triggered the detection. It is set to 0 if the protocol field is set to any. | long |
| cloudflare_logpush.magic_ids.signature.id | The signature ID of the detection. | long |
| cloudflare_logpush.magic_ids.signature.message | The signature message of the detection. Describes what the packet is attempting to do. | keyword |
| cloudflare_logpush.magic_ids.signature.revision | The signature revision of the detection. | long |
| cloudflare_logpush.magic_ids.source.ip | The source IP of packet which triggered the detection. | ip |
| cloudflare_logpush.magic_ids.source.port | The source port of the packet which triggered the detection. It is set to 0 if the protocol field is set to any. | long |
| cloudflare_logpush.magic_ids.timestamp | A timestamp of when the detection occurred. | date |
| cloudflare_logpush.magic_ids.transport | The layer 4 protocol of the packet which triggered the detection. Possible values are tcp | udp | any. Variant any means a detection occurred at a lower layer (such as IP). | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### nel_report

This is the `nel_report` dataset.

#### Example

An example event for `nel_report` looks as following:

```json
{
    "@timestamp": "2021-07-27T00:01:07.000Z",
    "agent": {
        "ephemeral_id": "b93139ac-3837-48bb-a64b-1ce3cd2bff3c",
        "id": "6be166c3-f0ce-4cec-a062-f340b55774c8",
        "name": "elastic-agent-82893",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "nel_report": {
            "client": {
                "ip": {
                    "asn": {
                        "description": "CLOUDFLARENET",
                        "value": 13335
                    },
                    "country": "US"
                }
            },
            "error": {
                "type": "network-error"
            },
            "last_known_good": {
                "colo": {
                    "code": "SJC"
                }
            },
            "phase": "connection",
            "timestamp": "2021-07-27T00:01:07.000Z"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.nel_report",
        "namespace": "27906",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "6be166c3-f0ce-4cec-a062-f340b55774c8",
        "snapshot": false,
        "version": "8.16.5"
    },
    "error": {
        "type": "network-error"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.nel_report",
        "ingested": "2025-03-13T21:11:24Z",
        "kind": "event",
        "original": "{\"ClientIPASN\":\"13335\",\"ClientIPASNDescription\":\"CLOUDFLARENET\",\"ClientIPCountry\":\"US\",\"LastKnownGoodColoCode\":\"SJC\",\"Phase\":\"connection\",\"Timestamp\":\"2021-07-27T00:01:07Z\",\"Type\":\"network-error\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-nel_report"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.nel_report.client.ip.asn.description | Client ASN description. | keyword |
| cloudflare_logpush.nel_report.client.ip.asn.value | Client ASN. | long |
| cloudflare_logpush.nel_report.client.ip.country | Client country. | keyword |
| cloudflare_logpush.nel_report.error.type | The type of error in the phase. | keyword |
| cloudflare_logpush.nel_report.last_known_good.colo.code | IATA airport code of colo client connected to. | keyword |
| cloudflare_logpush.nel_report.phase | The phase of connection the error occurred in. | keyword |
| cloudflare_logpush.nel_report.timestamp | Timestamp for error report. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### network_analytics

This is the `network_analytics` dataset.

#### Example

An example event for `network_analytics` looks as following:

```json
{
    "@timestamp": "2021-07-27T00:01:07.000Z",
    "agent": {
        "ephemeral_id": "4135cd65-74d7-486f-aa2f-cd5a17b5af98",
        "id": "017a1c42-fec0-437b-835d-988ba25a0a94",
        "name": "elastic-agent-57363",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "network_analytics": {
            "attack": {
                "campaign": {
                    "id": "xyz987"
                },
                "id": "abc777"
            },
            "colo": {
                "country": "AD",
                "geo_hash": "gbuun",
                "geo_location": "gbuun",
                "id": 46,
                "name": "SJC"
            },
            "destination": {
                "as": {
                    "number": {
                        "description": "asn description"
                    }
                },
                "asn": 1900,
                "country": "AD",
                "geo_hash": "gbuun",
                "geo_location": "gbuun",
                "ip": "175.16.199.0",
                "port": 0
            },
            "direction": "ingress",
            "gre": {
                "checksum": 10,
                "ether": {
                    "type": 10
                },
                "header": {
                    "length": 1024
                },
                "key": 10,
                "sequence": {
                    "number": 10
                },
                "version": 10
            },
            "icmp": {
                "checksum": 10,
                "code": 10,
                "type": 10
            },
            "ip": {
                "destination": {
                    "subnet": "/24"
                },
                "fragment": {
                    "offset": 1480
                },
                "header": {
                    "length": 20
                },
                "more": {
                    "fragments": 1480
                },
                "protocol": {
                    "name": "tcp",
                    "value": 6
                },
                "source": {
                    "subnet": "/24"
                },
                "total": {
                    "length": {
                        "buckets": 10,
                        "value": 1024
                    }
                },
                "ttl": {
                    "buckets": 2,
                    "value": 240
                }
            },
            "ipv4": {
                "checksum": 0,
                "dont_fragment": 0,
                "dscp": 46,
                "ecn": 1,
                "identification": 1,
                "options": 1
            },
            "ipv6": {
                "dscp": 46,
                "ecn": 1,
                "extension_headers": "header",
                "flow_label": 1,
                "identification": 1
            },
            "mitigation": {
                "reason": "BLOCKED",
                "scope": "local",
                "system": "flowtrackd"
            },
            "outcome": "success",
            "protocol_state": "OPEN",
            "rule": {
                "id": "rule1",
                "set": {
                    "id": "3b64149bfa6e4220bbbc2bd6db589552",
                    "override": {
                        "id": "id1"
                    }
                }
            },
            "sample_interval": 1,
            "source": {
                "as": {
                    "number": {
                        "description": "Source ASN Description"
                    }
                },
                "asn": 1500,
                "country": "AD",
                "geo_hash": "gbuun",
                "geo_location": "gbuun",
                "ip": "67.43.156.0",
                "port": 0
            },
            "tcp": {
                "acknowledgement_number": 1000,
                "checksum": 10,
                "dataoffset": 0,
                "flags": {
                    "string": "Human-readable flags string",
                    "value": 1
                },
                "mss": 512,
                "options": "mss",
                "sack": {
                    "blocks": 1,
                    "permitted": 1
                },
                "sequence_number": 100,
                "timestamp": {
                    "ecr": 100,
                    "value": 100
                },
                "urgent_pointer": 10,
                "window": {
                    "scale": 10,
                    "size": 10
                }
            },
            "timestamp": "2021-07-27T00:01:07.000Z",
            "udp": {
                "checksum": 10,
                "payload_length": 10
            },
            "verdict": "pass"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.network_analytics",
        "namespace": "54848",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 1900
        },
        "ip": "175.16.199.0",
        "port": 0
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "017a1c42-fec0-437b-835d-988ba25a0a94",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.network_analytics",
        "ingested": "2025-03-13T21:12:23Z",
        "kind": "event",
        "original": "{\"AttackCampaignID\":\"xyz987\",\"AttackID\":\"abc777\",\"ColoCountry\":\"AD\",\"ColoGeoHash\":\"gbuun\",\"ColoID\":46,\"ColoName\":\"SJC\",\"Datetime\":\"2021-07-27T00:01:07Z\",\"DestinationASN\":1900,\"DestinationASNDescription\":\"asn description\",\"DestinationCountry\":\"AD\",\"DestinationGeoHash\":\"gbuun\",\"DestinationPort\":0,\"Direction\":\"ingress\",\"GREChecksum\":10,\"GREEthertype\":10,\"GREHeaderLength\":1024,\"GREKey\":10,\"GRESequenceNumber\":10,\"GREVersion\":10,\"ICMPChecksum\":10,\"ICMPCode\":10,\"ICMPType\":10,\"IPDestinationAddress\":\"175.16.199.0\",\"IPDestinationSubnet\":\"/24\",\"IPFragmentOffset\":1480,\"IPHeaderLength\":20,\"IPMoreFragments\":1480,\"IPProtocol\":6,\"IPProtocolName\":\"tcp\",\"IPSourceAddress\":\"67.43.156.0\",\"IPSourceSubnet\":\"/24\",\"IPTotalLength\":1024,\"IPTotalLengthBuckets\":10,\"IPTtl\":240,\"IPTtlBuckets\":2,\"IPv4Checksum\":0,\"IPv4DontFragment\":0,\"IPv4Dscp\":46,\"IPv4Ecn\":1,\"IPv4Identification\":1,\"IPv4Options\":1,\"IPv6Dscp\":46,\"IPv6Ecn\":1,\"IPv6ExtensionHeaders\":\"header\",\"IPv6FlowLabel\":1,\"IPv6Identification\":1,\"MitigationReason\":\"BLOCKED\",\"MitigationScope\":\"local\",\"MitigationSystem\":\"flowtrackd\",\"Outcome\":\"pass\",\"ProtocolState\":\"OPEN\",\"RuleID\":\"rule1\",\"RulesetID\":\"3b64149bfa6e4220bbbc2bd6db589552\",\"RulesetOverrideID\":\"id1\",\"SampleInterval\":1,\"SourceASN\":1500,\"SourceASNDescription\":\"Source ASN Description\",\"SourceCountry\":\"AD\",\"SourceGeoHash\":\"gbuun\",\"SourcePort\":0,\"TCPAcknowledgementNumber\":1000,\"TCPChecksum\":10,\"TCPDataOffset\":0,\"TCPFlags\":1,\"TCPFlagsString\":\"Human-readable flags string\",\"TCPMss\":512,\"TCPOptions\":\"mss\",\"TCPSackBlocks\":1,\"TCPSacksPermitted\":1,\"TCPSequenceNumber\":100,\"TCPTimestampEcr\":100,\"TCPTimestampValue\":100,\"TCPUrgentPointer\":10,\"TCPWindowScale\":10,\"TCPWindowSize\":10,\"UDPChecksum\":10,\"UDPPayloadLength\":10,\"Verdict\":\"pass\"}",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "direction": "ingress",
        "transport": "tcp"
    },
    "related": {
        "hash": [
            "gbuun"
        ],
        "ip": [
            "67.43.156.0",
            "175.16.199.0"
        ]
    },
    "rule": {
        "id": "rule1"
    },
    "source": {
        "as": {
            "number": 1500
        },
        "ip": "67.43.156.0",
        "port": 0
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-network_analytics"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.network_analytics.attack.campaign.id | Unique identifier of the attack campaign that this packet was a part of, if any. | keyword |
| cloudflare_logpush.network_analytics.attack.id | Unique identifier of the mitigation that matched the packet, if any. | keyword |
| cloudflare_logpush.network_analytics.attack.vector | Descriptive name of the type of attack that this packet was a part of, if any. Only for packets matching rules contained within the Cloudflare L3/4 managed ruleset. | keyword |
| cloudflare_logpush.network_analytics.colo.city | The city where the Cloudflare datacenter that received the packet is located. | keyword |
| cloudflare_logpush.network_analytics.colo.code | The Cloudflare datacenter that received the packet (nearest IATA airport code). | keyword |
| cloudflare_logpush.network_analytics.colo.country | The country of colo that received the packet (ISO 3166-1 alpha-2). | keyword |
| cloudflare_logpush.network_analytics.colo.geo_hash | The Geo Hash where the colo that received the packet is located. | keyword |
| cloudflare_logpush.network_analytics.colo.geo_location | The latitude and longitude where the colo that received the packet is located. | geo_point |
| cloudflare_logpush.network_analytics.colo.id | The ID of the colo that received the DNS query. | long |
| cloudflare_logpush.network_analytics.colo.name | The name of the colo that received the DNS query. | keyword |
| cloudflare_logpush.network_analytics.destination.as.number.description | The ASN description associated with the destination IP of the packet. | text |
| cloudflare_logpush.network_analytics.destination.as.number.name | The name of the ASN associated with the destination IP of the packet. | text |
| cloudflare_logpush.network_analytics.destination.asn | The ASN associated with the destination IP of the packet. | long |
| cloudflare_logpush.network_analytics.destination.country | The country where the destination IP of the packet is located. | keyword |
| cloudflare_logpush.network_analytics.destination.geo_hash | The Geo Hash where the destination IP of the packet is located. | keyword |
| cloudflare_logpush.network_analytics.destination.geo_location | The latitude and longitude where the destination IP of the packet is located. | geo_point |
| cloudflare_logpush.network_analytics.destination.ip | Value of the Destination Address header field in the IPv4 or IPv6 packet. | ip |
| cloudflare_logpush.network_analytics.destination.port | Value of the Destination Port header field in the TCP or UDP packet. | long |
| cloudflare_logpush.network_analytics.direction | The direction in relation to customer network. | keyword |
| cloudflare_logpush.network_analytics.gre.checksum | Value of the Checksum header field in the GRE packet. | long |
| cloudflare_logpush.network_analytics.gre.ether.type | Value of the Ethertype header field in the GRE packet. | long |
| cloudflare_logpush.network_analytics.gre.header.length | Length of the GRE packet header, in bytes. | long |
| cloudflare_logpush.network_analytics.gre.key | Value of the Key header field in the GRE packet. | long |
| cloudflare_logpush.network_analytics.gre.sequence.number | Value of the Sequence Number header field in the GRE packet. | long |
| cloudflare_logpush.network_analytics.gre.version | Value of the Version header field in the GRE packet. | long |
| cloudflare_logpush.network_analytics.icmp.checksum | Value of the Checksum header field in the ICMP packet | long |
| cloudflare_logpush.network_analytics.icmp.code | Value of the Code header field in the ICMP packet | long |
| cloudflare_logpush.network_analytics.icmp.type | Value of the Type header field in the ICMP packet | long |
| cloudflare_logpush.network_analytics.ip.destination.subnet | Computed subnet of the Destination Address header field in the IPv4 or IPv6 packet. | keyword |
| cloudflare_logpush.network_analytics.ip.fragment.offset | Value of the Fragment Offset header field in the IPv4 or IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ip.header.length | Length of the IPv4 or IPv6 packet header, in bytes. | long |
| cloudflare_logpush.network_analytics.ip.more.fragments | Value of the More Fragments header field in the IPv4 or IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ip.protocol.name | Name of the protocol specified by the Protocol header field in the IPv4 or IPv6 packet. | text |
| cloudflare_logpush.network_analytics.ip.protocol.value | Value of the Protocol header field in the IPv4 or IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ip.source.subnet | Computed subnet of the Source Address header field in the IPv4 or IPv6 packet. | keyword |
| cloudflare_logpush.network_analytics.ip.total.length.buckets | Total length of the IPv4 or IPv6 packet, in bytes, with the last two digits truncated. | long |
| cloudflare_logpush.network_analytics.ip.total.length.value | Total length of the IPv4 or IPv6 packet, in bytes. | long |
| cloudflare_logpush.network_analytics.ip.ttl.buckets | Value of the TTL header field in the IPv4 packet or the Hop Limit header field in the IPv6 packet, with the last digit truncated. | long |
| cloudflare_logpush.network_analytics.ip.ttl.value | Value of the TTL header field in the IPv4 packet or the Hop Limit header field in the IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.checksum | Value of the Checksum header field in the IPv4 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.dont_fragment | Value of the Don’t Fragment header field in the IPv4 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.dscp | Value of the Differentiated Services Code Point header field in the IPv4 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.ecn | Value of the Explicit Congestion Notification header field in the IPv4 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.identification | Value of the Identification header field in the IPv4 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.options | List of Options numbers included in the IPv4 packet header. | long |
| cloudflare_logpush.network_analytics.ipv6.dscp | Value of the Differentiated Services Code Point header field in the IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ipv6.ecn | Value of the Explicit Congestion Notification header field in the IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ipv6.extension_headers | List of Extension Header numbers included in the IPv6 packet header. | text |
| cloudflare_logpush.network_analytics.ipv6.flow_label | Value of the Flow Label header field in the IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ipv6.identification | Value of the Identification extension header field in the IPv6 packet. | long |
| cloudflare_logpush.network_analytics.mitigation.reason | Reason for applying a mitigation to the packet, if any. | keyword |
| cloudflare_logpush.network_analytics.mitigation.scope | Whether the packet matched a local or global mitigation, if any. | keyword |
| cloudflare_logpush.network_analytics.mitigation.system | Which Cloudflare system dropped the packet, if any. | keyword |
| cloudflare_logpush.network_analytics.outcome | The action that Cloudflare systems took on the packet. | keyword |
| cloudflare_logpush.network_analytics.protocol_state | State of the packet in the context of the protocol, if any. | keyword |
| cloudflare_logpush.network_analytics.rule.id | Unique identifier of the rule contained with the Cloudflare L3/4 managed ruleset that this packet matched, if any. | text |
| cloudflare_logpush.network_analytics.rule.name | Human-readable name of the rule contained within the Cloudflare L3/4 managed ruleset that this packet matched, if any. | text |
| cloudflare_logpush.network_analytics.rule.set.id | Unique identifier of the Cloudflare L3/4 managed ruleset containing the rule that this packet matched, if any. | keyword |
| cloudflare_logpush.network_analytics.rule.set.override.id | Unique identifier of the rule within the accounts root ddos_l4 phase ruleset which resulted in an override of the default sensitivity or action being applied/evaluated, if any. | text |
| cloudflare_logpush.network_analytics.sample_interval | The sample interval for this log. | long |
| cloudflare_logpush.network_analytics.source.as.number.description | The ASN description associated with the source IP of the packet. | text |
| cloudflare_logpush.network_analytics.source.as.number.name | The name of the ASN associated with the source IP of the packet. | text |
| cloudflare_logpush.network_analytics.source.asn | The ASN associated with the source IP of the packet. | long |
| cloudflare_logpush.network_analytics.source.country | The country where the source IP of the packet is located. | keyword |
| cloudflare_logpush.network_analytics.source.geo_hash | The Geo Hash where the source IP of the packet is located. | keyword |
| cloudflare_logpush.network_analytics.source.geo_location | The latitude and longitude where the source IP of the packet is located. | geo_point |
| cloudflare_logpush.network_analytics.source.ip | Value of the Source Address header field in the IPv4 or IPv6 packet. | ip |
| cloudflare_logpush.network_analytics.source.port | Value of the Source Port header field in the TCP or UDP packet. | long |
| cloudflare_logpush.network_analytics.tcp.acknowledgement_number | Value of the Acknowledgement Number header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.checksum | Value of the Checksum header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.dataoffset | Value of the Data Offset header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.flags.string | Human-readable string representation of the Flags header field in the TCP packet. | text |
| cloudflare_logpush.network_analytics.tcp.flags.value | Value of the Flags header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.mss | Value of the MSS option header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.options | List of Options numbers included in the TCP packet header. | text |
| cloudflare_logpush.network_analytics.tcp.sack.blocks | Value of the SACK Blocks option header in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.sack.permitted | Value of the SACK Permitted option header in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.sequence_number | Value of the Sequence Number header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.timestamp.ecr | Value of the Timestamp Echo Reply option header in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.timestamp.value | Value of the Timestamp option header in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.urgent_pointer | Value of the Urgent Pointer header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.window.scale | Value of the Window Scale option header in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.window.size | Value of the Window Size header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.timestamp | The date and time the event occurred at the edge. | date |
| cloudflare_logpush.network_analytics.udp.checksum | Value of the Checksum header field in the UDP packet. | long |
| cloudflare_logpush.network_analytics.udp.payload_length | Value of the Payload Length header field in the UDP packet. | long |
| cloudflare_logpush.network_analytics.verdict | The action that Cloudflare systems think should be taken on the packet (pass | drop). | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### network_session

This is the `network_session` dataset.

#### Example

An example event for `network_session` looks as following:

```json
{
    "@timestamp": "2023-05-04T11:29:14.000Z",
    "agent": {
        "ephemeral_id": "80af543f-477e-477e-83dd-7728c08e8f34",
        "id": "b603eb6b-a036-4430-ad22-cf0878c2fdfd",
        "name": "elastic-agent-40752",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "network_session": {
            "account_id": "e1836771179f98aabb828da5ea69a111",
            "destination": {
                "bytes": 679,
                "ip": "89.160.20.129",
                "port": 80,
                "tunnel_id": "00000000-0000-0000-0000-000000000000"
            },
            "egress": {
                "colo_name": "ORD",
                "ip": "2a02:cf40::23",
                "port": 41052,
                "rule": {
                    "id": "00000000-0000-0000-0000-000000000000",
                    "name": "Egress Rule 1"
                }
            },
            "host": {
                "id": "083a8354-d56c-11ed-9771-6a842b100cff",
                "name": "zt-test-vm1"
            },
            "ingress": {
                "colo_name": "ORD"
            },
            "offramp": "INTERNET",
            "rule_evaluation": {
                "time_ms": 10
            },
            "session": {
                "end": "2023-05-04T11:29:14.000Z",
                "id": "18881f179300007fb0d06d6400000001",
                "start": "2023-05-04T11:29:14.000Z"
            },
            "source": {
                "bytes": 2333,
                "internal_ip": "1.128.0.1",
                "ip": "67.43.156.2",
                "port": 52994
            },
            "tcp": {
                "client": {
                    "handshake_time_ms": 12
                },
                "connection": {
                    "close_reason": "CLIENT_CLOSED",
                    "reuse": false
                }
            },
            "timestamp": "2023-05-04T11:29:14.000Z",
            "tls": {
                "client": {
                    "cipher": "TLS_AES_128_GCM_SHA256",
                    "handshake_time_ms": 125,
                    "version": "TLS 1.3"
                },
                "server": {
                    "certificate": {
                        "issuer": "DigiCert Inc",
                        "validation_result": "VALID"
                    },
                    "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "handshake_time_ms": 130,
                    "version": "TLS 1.2"
                }
            },
            "transport": "TCP",
            "user": {
                "email": "user@test.com",
                "id": "166befbb-00e3-5e20-bd6e-27245723949f"
            },
            "vlan": {
                "id": "0ce99869-63d3-4d5d-bdaf-d4f33df964aa"
            }
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.network_session",
        "namespace": "75573",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "bytes": 679,
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.129",
        "port": 80
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "b603eb6b-a036-4430-ad22-cf0878c2fdfd",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network",
            "session"
        ],
        "dataset": "cloudflare_logpush.network_session",
        "end": "2023-05-04T11:29:14.000Z",
        "id": "18881f179300007fb0d06d6400000001",
        "ingested": "2025-03-13T21:14:54Z",
        "kind": "event",
        "original": "{\"AccountID\":\"e1836771179f98aabb828da5ea69a111\",\"BytesReceived\":679,\"BytesSent\":2333,\"ClientTCPHandshakeDurationMs\":12,\"ClientTLSCipher\":\"TLS_AES_128_GCM_SHA256\",\"ClientTLSHandshakeDurationMs\":125,\"ClientTLSVersion\":\"TLS 1.3\",\"ConnectionCloseReason\":\"CLIENT_CLOSED\",\"ConnectionReuse\":false,\"DestinationTunnelID\":\"00000000-0000-0000-0000-000000000000\",\"DeviceID\":\"083a8354-d56c-11ed-9771-6a842b100cff\",\"DeviceName\":\"zt-test-vm1\",\"EgressColoName\":\"ORD\",\"EgressIP\":\"2a02:cf40::23\",\"EgressPort\":41052,\"EgressRuleID\":\"00000000-0000-0000-0000-000000000000\",\"EgressRuleName\":\"Egress Rule 1\",\"Email\":\"user@test.com\",\"IngressColoName\":\"ORD\",\"Offramp\":\"INTERNET\",\"OriginIP\":\"89.160.20.129\",\"OriginPort\":80,\"OriginTLSCertificateIssuer\":\"DigiCert Inc\",\"OriginTLSCertificateValidationResult\":\"VALID\",\"OriginTLSCipher\":\"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\",\"OriginTLSHandshakeDurationMs\":130,\"OriginTLSVersion\":\"TLS 1.2\",\"Protocol\":\"TCP\",\"RuleEvaluationDurationMs\":10,\"SessionEndTime\":\"2023-05-04T11:29:14Z\",\"SessionID\":\"18881f179300007fb0d06d6400000001\",\"SessionStartTime\":\"2023-05-04T11:29:14Z\",\"SourceIP\":\"67.43.156.2\",\"SourceInternalIP\":\"1.128.0.1\",\"SourcePort\":52994,\"UserID\":\"166befbb-00e3-5e20-bd6e-27245723949f\",\"VirtualNetworkID\":\"0ce99869-63d3-4d5d-bdaf-d4f33df964aa\"}",
        "start": "2023-05-04T11:29:14.000Z",
        "type": [
            "connection"
        ]
    },
    "host": {
        "id": "083a8354-d56c-11ed-9771-6a842b100cff",
        "name": "zt-test-vm1"
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "transport": "TCP",
        "vlan": {
            "id": "0ce99869-63d3-4d5d-bdaf-d4f33df964aa"
        }
    },
    "related": {
        "hosts": [
            "083a8354-d56c-11ed-9771-6a842b100cff",
            "zt-test-vm1"
        ],
        "ip": [
            "67.43.156.2",
            "89.160.20.129",
            "2a02:cf40::23"
        ],
        "user": [
            "166befbb-00e3-5e20-bd6e-27245723949f",
            "user@test.com"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "bytes": 2333,
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.2",
        "port": 52994
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-network_session"
    ],
    "tls": {
        "server": {
            "issuer": "DigiCert Inc"
        }
    },
    "user": {
        "email": "user@test.com",
        "id": "166befbb-00e3-5e20-bd6e-27245723949f"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.network_session.account_id | Cloudflare account ID. | keyword |
| cloudflare_logpush.network_session.destination.bytes | The number of bytes sent from the origin to the client during the network session. | long |
| cloudflare_logpush.network_session.destination.ip | The IP of the destination (origin) for the network session. | ip |
| cloudflare_logpush.network_session.destination.port | The port of the destination origin for the network session. | long |
| cloudflare_logpush.network_session.destination.tunnel_id | Identifier of the Cloudflare One connector to which the network session was routed to, if any. | keyword |
| cloudflare_logpush.network_session.detected_protocol | Detected traffic protocol of the network session. | keyword |
| cloudflare_logpush.network_session.egress.colo_name | The name of the Cloudflare colo from which traffic egressed to the origin. | keyword |
| cloudflare_logpush.network_session.egress.ip | Source IP used when egressing traffic from Cloudflare to the origin. | ip |
| cloudflare_logpush.network_session.egress.port | Source port used when egressing traffic from Cloudflare to the origin. | long |
| cloudflare_logpush.network_session.egress.rule.id | Identifier of the egress rule that was applied by the Secure Web Gateway, if any. | keyword |
| cloudflare_logpush.network_session.egress.rule.name | The name of the egress rule that was applied by the Secure Web Gateway, if any. | keyword |
| cloudflare_logpush.network_session.host.id | Identifier of the client device which initiated the network session, if applicable. | keyword |
| cloudflare_logpush.network_session.host.name | Name of the client device which initiated the network session, if applicable. | keyword |
| cloudflare_logpush.network_session.ingress.colo_name | The name of the Cloudflare colo to which traffic ingressed. | keyword |
| cloudflare_logpush.network_session.offramp | The type of destination to which the network session was routed. | keyword |
| cloudflare_logpush.network_session.rule_evaluation.time_ms | The duration taken by Secure Web Gateway applying applicable Network, HTTP, and Egress rules to the network session in milliseconds. | long |
| cloudflare_logpush.network_session.session.end | The network session end timestamp with nanosecond precision. | date |
| cloudflare_logpush.network_session.session.id | The identifier of this network session. | keyword |
| cloudflare_logpush.network_session.session.start | The network session start timestamp with nanosecond precision. | date |
| cloudflare_logpush.network_session.source.bytes | The number of bytes sent from the client to the origin during the network session. | long |
| cloudflare_logpush.network_session.source.internal_ip | Local LAN IP of the device. Only available when connected via a GRE/IPsec tunnel on-ramp. | ip |
| cloudflare_logpush.network_session.source.ip | Source IP of the network session. | ip |
| cloudflare_logpush.network_session.source.port | Source port of the network session. | long |
| cloudflare_logpush.network_session.tcp.client.handshake_time_ms | Duration of handshaking the TCP connection between the client and Cloudflare in milliseconds. | long |
| cloudflare_logpush.network_session.tcp.connection.close_reason | The reason for closing the connection, only applicable for TCP. | keyword |
| cloudflare_logpush.network_session.tcp.connection.reuse | Whether the TCP connection was reused for multiple HTTP requests. | boolean |
| cloudflare_logpush.network_session.timestamp | The network session start timestamp with nanosecond precision. | date |
| cloudflare_logpush.network_session.tls.client.cipher | TLS cipher suite used in the connection between the client and Cloudflare. | keyword |
| cloudflare_logpush.network_session.tls.client.handshake_time_ms | Duration of handshaking the TLS connection between the client and Cloudflare in milliseconds. | long |
| cloudflare_logpush.network_session.tls.client.version | TLS protocol version used in the connection between the client and Cloudflare. | keyword |
| cloudflare_logpush.network_session.tls.server.certificate.issuer | The issuer of the origin TLS certificate. | keyword |
| cloudflare_logpush.network_session.tls.server.certificate.validation_result | The result of validating the TLS certificate of the origin. | keyword |
| cloudflare_logpush.network_session.tls.server.cipher | TLS cipher suite used in the connection between Cloudflare and the origin. | keyword |
| cloudflare_logpush.network_session.tls.server.handshake_time_ms | Duration of handshaking the TLS connection between Cloudflare and the origin in milliseconds. | long |
| cloudflare_logpush.network_session.tls.server.version | TLS protocol version used in the connection between Cloudflare and the origin. | keyword |
| cloudflare_logpush.network_session.transport | Network protocol used for this network session. | keyword |
| cloudflare_logpush.network_session.user.email | Email address associated with the user identity which initiated the network session. | keyword |
| cloudflare_logpush.network_session.user.id | User identity where the network session originated from. | keyword |
| cloudflare_logpush.network_session.vlan.id | Identifier of the virtual network configured for the client. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### page_shield_events

This is the `page_shield_events` dataset.

#### Example

An example event for `page_shield_events` looks as following:

```json
{
    "@timestamp": "2023-05-04T11:29:14.000Z",
    "agent": {
        "ephemeral_id": "b1b4bb89-5be1-4aa5-bac8-684e1f65de1e",
        "id": "ec6ada7f-bc5d-4cae-8032-5a6cb07c9c56",
        "name": "elastic-agent-28072",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "page_shield_events": {
            "action": "log",
            "csp_directive": "directive",
            "host": "hostymchost.face",
            "page_url": "http://example.com/?query=42",
            "policy_id": "9",
            "resource_type": "other",
            "timestamp": "2023-05-04T11:29:14.000Z",
            "url": "https://example.com/?query=hog",
            "url_contains_cdn_cgi_path": true,
            "url_host": "example.com"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.page_shield_events",
        "namespace": "13616",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ec6ada7f-bc5d-4cae-8032-5a6cb07c9c56",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "action": "log",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.page_shield_events",
        "ingested": "2025-03-13T21:17:25Z",
        "kind": "event",
        "original": "{\"Action\":\"log\",\"CSPDirective\":\"directive\",\"Host\":\"hostymchost.face\",\"PageURL\":\"http://example.com/?query=42\",\"PolicyID\":\"9\",\"ResourceType\":\"other\",\"Timestamp\":\"2023-05-04T11:29:14Z\",\"URL\":\"https://example.com/?query=hog\",\"URLContainsCDNCGIPath\":true,\"URLHost\":\"example.com\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "hostymchost.face"
    },
    "input": {
        "type": "http_endpoint"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-page_sheild_events"
    ],
    "url": {
        "domain": "example.com",
        "original": "https://example.com/?query=hog",
        "path": "/",
        "query": "query=hog",
        "scheme": "https"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.page_shield_events.action | The action which was taken against the violation. Possible values are (log, allow). | keyword |
| cloudflare_logpush.page_shield_events.csp_directive | The violated directive in the report. | keyword |
| cloudflare_logpush.page_shield_events.host | The host where the resource was seen. | keyword |
| cloudflare_logpush.page_shield_events.page | The page URL the violation was seen on. | keyword |
| cloudflare_logpush.page_shield_events.page_url | The page URL the violation was seen on. | keyword |
| cloudflare_logpush.page_shield_events.policy_id | The ID of the policy which was violated. | keyword |
| cloudflare_logpush.page_shield_events.resource_type | The resource type of the violated directive. Possible values are 'script', 'connection' or 'other' for unmonitored resource types. | keyword |
| cloudflare_logpush.page_shield_events.timestamp | The timestamp for when the report was received. | date |
| cloudflare_logpush.page_shield_events.url | The resource URL. | keyword |
| cloudflare_logpush.page_shield_events.url_contains_cdn_cgi_path | Whether the resource URL contains the CDN-CGI path. (deprecated by Cloudflare) | boolean |
| cloudflare_logpush.page_shield_events.url_host | The domain host of the URL. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### sinkhole_http

This is the `sinkhole_http` dataset.

#### Example

An example event for `sinkhole_http` looks as following:

```json
{
    "@timestamp": "2023-09-19T12:00:00.000Z",
    "agent": {
        "ephemeral_id": "e7a26e8a-d046-4ec0-b52d-60015c9dffb3",
        "id": "335803c3-9568-46c4-88a8-a317dd223f9d",
        "name": "elastic-agent-16149",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "sinkhole_http": {
            "account_id": "AC123456",
            "destination": {
                "ip": "89.160.20.129"
            },
            "host": {
                "name": "example.com"
            },
            "request": {
                "body": {
                    "bytes": 39,
                    "content": "{\"action\": \"login\", \"user\": \"john_doe\"}"
                },
                "headers": [
                    "Host: example.com",
                    "User-Agent: Mozilla/5.0",
                    "Accept: */*",
                    "Connection: keep-alive"
                ],
                "method": "POST",
                "password": "password123",
                "referrer": "https://searchengine.com/",
                "uri": "/api/v1/login",
                "url": "https://example.com/api/v1/login"
            },
            "sinkhole_id": "SH001",
            "source": {
                "ip": "67.43.156.2"
            },
            "timestamp": "2023-09-19T12:00:00.000Z",
            "user": {
                "name": "john_doe"
            },
            "user_agent": "Mozilla/5.0"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.sinkhole_http",
        "namespace": "10065",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.129"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "335803c3-9568-46c4-88a8-a317dd223f9d",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.sinkhole_http",
        "ingested": "2025-03-13T21:19:52Z",
        "kind": "event",
        "original": "{\"AccountID\":\"AC123456\",\"Body\":\"{\\\"action\\\": \\\"login\\\", \\\"user\\\": \\\"john_doe\\\"}\",\"BodyLength\":39,\"DestAddr\":\"89.160.20.129\",\"Headers\":\"Host: example.com\\nUser-Agent: Mozilla/5.0\\nAccept: */*\\nConnection: keep-alive\",\"Host\":\"example.com\",\"Method\":\"POST\",\"Password\":\"password123\",\"R2Path\":\"\",\"Referrer\":\"https://searchengine.com/\",\"SinkholeID\":\"SH001\",\"SrcAddr\":\"67.43.156.2\",\"Timestamp\":\"2023-09-19T12:00:00Z\",\"URI\":\"/api/v1/login\",\"URL\":\"https://example.com/api/v1/login\",\"UserAgent\":\"Mozilla/5.0\",\"Username\":\"john_doe\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "example.com"
    },
    "http": {
        "request": {
            "body": {
                "bytes": 39,
                "content": "{\"action\": \"login\", \"user\": \"john_doe\"}"
            },
            "method": "POST",
            "referrer": "https://searchengine.com/"
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "hosts": [
            "example.com"
        ],
        "ip": [
            "89.160.20.129",
            "67.43.156.2"
        ],
        "user": [
            "john_doe"
        ]
    },
    "source": {
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.2"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-sinkhole_http"
    ],
    "url": {
        "domain": "example.com",
        "original": "https://example.com/api/v1/login",
        "path": "/api/v1/login",
        "scheme": "https"
    },
    "user": {
        "name": "john_doe"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Other",
        "original": "Mozilla/5.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.sinkhole_http.account_id | The Account ID. | keyword |
| cloudflare_logpush.sinkhole_http.destination.ip | The destination IP address of the request. | ip |
| cloudflare_logpush.sinkhole_http.host.name | The host the request was sent to. | keyword |
| cloudflare_logpush.sinkhole_http.r2path | The path to the object within the R2 bucket linked to this sinkhole that stores overflow body and header data. Blank if neither headers nor body was larger than 256 bytes. | keyword |
| cloudflare_logpush.sinkhole_http.request.body.bytes | The length of request body. | long |
| cloudflare_logpush.sinkhole_http.request.body.content | The request body. | keyword |
| cloudflare_logpush.sinkhole_http.request.headers | The request headers. | keyword |
| cloudflare_logpush.sinkhole_http.request.method | The request method. | keyword |
| cloudflare_logpush.sinkhole_http.request.password | The request password. | keyword |
| cloudflare_logpush.sinkhole_http.request.referrer | The referrer of the request. | keyword |
| cloudflare_logpush.sinkhole_http.request.uri | The request Uniform Resource Identifier. | keyword |
| cloudflare_logpush.sinkhole_http.request.url | The request Uniform Resource Locator. | keyword |
| cloudflare_logpush.sinkhole_http.sinkhole_id | The ID of the Sinkhole that logged the HTTP Request. | keyword |
| cloudflare_logpush.sinkhole_http.source.ip | The source IP address of the request. | ip |
| cloudflare_logpush.sinkhole_http.timestamp | The date and time the sinkhole HTTP request was logged. | date |
| cloudflare_logpush.sinkhole_http.user.name | The request username. | keyword |
| cloudflare_logpush.sinkhole_http.user_agent | The request user agent. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### spectrum_event

This is the `spectrum_event` dataset.

#### Example

An example event for `spectrum_event` looks as following:

```json
{
    "@timestamp": "2022-05-26T09:24:00.000Z",
    "agent": {
        "ephemeral_id": "38f3ce1d-b4ca-43ce-b3e4-7b23f9e85b32",
        "id": "ad8d9c5d-17fd-4c54-b73e-c8a05035dca0",
        "name": "elastic-agent-58633",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "spectrum_event": {
            "action": "connect",
            "application": "7ef659a2f8ef4810a9bade96fdad7c75",
            "client": {
                "asn": 200391,
                "bytes": 0,
                "country": "bg",
                "ip": "67.43.156.0",
                "matched_ip_firewall": "UNKNOWN",
                "port": 40456,
                "protocol": "tcp",
                "tcp_rtt": 0,
                "tls": {
                    "cipher": "UNK",
                    "client_hello_server_name": "server name",
                    "protocol": "unknown",
                    "status": "UNKNOWN"
                }
            },
            "colo": {
                "code": "SOF"
            },
            "connect": {
                "time": "2022-05-26T09:24:00.000Z"
            },
            "disconnect": {
                "time": "1970-01-01T00:00:00.000Z"
            },
            "ip_firewall": false,
            "origin": {
                "bytes": 0,
                "ip": "175.16.199.0",
                "port": 3389,
                "protocol": "tcp",
                "tcp_rtt": 0,
                "tls": {
                    "cipher": "UNK",
                    "fingerprint": "0000000000000000000000000000000000000000000000000000000000000000.",
                    "mode": "off",
                    "protocol": "unknown",
                    "status": "UNKNOWN"
                }
            },
            "proxy": {
                "protocol": "off"
            },
            "status": 0,
            "timestamp": "2022-05-26T09:24:00.000Z"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.spectrum_event",
        "namespace": "99326",
        "type": "logs"
    },
    "destination": {
        "bytes": 0,
        "ip": "175.16.199.0",
        "port": 3389
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ad8d9c5d-17fd-4c54-b73e-c8a05035dca0",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "action": "connect",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.spectrum_event",
        "end": "1970-01-01T00:00:00.000Z",
        "id": "7ef659a2f8ef4810a9bade96fdad7c75",
        "ingested": "2025-03-13T21:22:21Z",
        "kind": "event",
        "original": "{\"Application\":\"7ef659a2f8ef4810a9bade96fdad7c75\",\"ClientAsn\":200391,\"ClientBytes\":0,\"ClientCountry\":\"bg\",\"ClientIP\":\"67.43.156.0\",\"ClientMatchedIpFirewall\":\"UNKNOWN\",\"ClientPort\":40456,\"ClientProto\":\"tcp\",\"ClientTcpRtt\":0,\"ClientTlsCipher\":\"UNK\",\"ClientTlsClientHelloServerName\":\"server name\",\"ClientTlsProtocol\":\"unknown\",\"ClientTlsStatus\":\"UNKNOWN\",\"ColoCode\":\"SOF\",\"ConnectTimestamp\":\"2022-05-26T09:24:00Z\",\"DisconnectTimestamp\":\"1970-01-01T00:00:00Z\",\"Event\":\"connect\",\"IpFirewall\":false,\"OriginBytes\":0,\"OriginIP\":\"175.16.199.0\",\"OriginPort\":3389,\"OriginProto\":\"tcp\",\"OriginTcpRtt\":0,\"OriginTlsCipher\":\"UNK\",\"OriginTlsFingerprint\":\"0000000000000000000000000000000000000000000000000000000000000000.\",\"OriginTlsMode\":\"off\",\"OriginTlsProtocol\":\"unknown\",\"OriginTlsStatus\":\"UNKNOWN\",\"ProxyProtocol\":\"off\",\"Status\":0,\"Timestamp\":\"2022-05-26T09:24:00Z\"}",
        "start": "2022-05-26T09:24:00.000Z",
        "type": [
            "info"
        ]
    },
    "http": {
        "response": {
            "status_code": 0
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "community_id": "1:X7lywUVKlduqRq5SyCRaBj4hLP0=",
        "transport": "tcp"
    },
    "related": {
        "ip": [
            "67.43.156.0",
            "175.16.199.0"
        ]
    },
    "source": {
        "as": {
            "number": 200391
        },
        "bytes": 0,
        "geo": {
            "country_iso_code": "bg"
        },
        "ip": "67.43.156.0",
        "port": 40456
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-spectrum_event"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.spectrum_event.action | Event Action. | keyword |
| cloudflare_logpush.spectrum_event.application | The unique public ID of the application on which the event occurred. | keyword |
| cloudflare_logpush.spectrum_event.client.asn | Client AS number. | long |
| cloudflare_logpush.spectrum_event.client.bytes | The number of bytes read from the client by the Spectrum service. | long |
| cloudflare_logpush.spectrum_event.client.country | Country of the client IP address. | keyword |
| cloudflare_logpush.spectrum_event.client.ip | Client IP address. | ip |
| cloudflare_logpush.spectrum_event.client.matched_ip_firewall | Whether the connection matched any IP Firewall rules. | keyword |
| cloudflare_logpush.spectrum_event.client.port | Client port. | long |
| cloudflare_logpush.spectrum_event.client.protocol | Transport protocol used by client. | keyword |
| cloudflare_logpush.spectrum_event.client.tcp_rtt | The TCP round-trip time in nanoseconds between the client and Spectrum. | long |
| cloudflare_logpush.spectrum_event.client.tls.cipher | The cipher negotiated between the client and Spectrum. | keyword |
| cloudflare_logpush.spectrum_event.client.tls.client_hello_server_name | The server name in the Client Hello message from client to Spectrum. | keyword |
| cloudflare_logpush.spectrum_event.client.tls.protocol | The TLS version negotiated between the client and Spectrum. | keyword |
| cloudflare_logpush.spectrum_event.client.tls.status | Indicates state of TLS session from the client to Spectrum. | keyword |
| cloudflare_logpush.spectrum_event.colo.code | IATA airport code of data center that received the request. | keyword |
| cloudflare_logpush.spectrum_event.connect.time | Timestamp at which both legs of the connection (client/edge, edge/origin or nexthop) were established. | date |
| cloudflare_logpush.spectrum_event.disconnect.time | Timestamp at which the connection was closed. | date |
| cloudflare_logpush.spectrum_event.ip_firewall | Whether IP Firewall was enabled at time of connection. | boolean |
| cloudflare_logpush.spectrum_event.origin.bytes | The number of bytes read from the origin by Spectrum. | long |
| cloudflare_logpush.spectrum_event.origin.ip | Origin IP address. | ip |
| cloudflare_logpush.spectrum_event.origin.port | Origin Port. | long |
| cloudflare_logpush.spectrum_event.origin.protocol | Transport protocol used by origin. | keyword |
| cloudflare_logpush.spectrum_event.origin.tcp_rtt | The TCP round-trip time in nanoseconds between Spectrum and the origin. | long |
| cloudflare_logpush.spectrum_event.origin.tls.cipher | The cipher negotiated between Spectrum and the origin. | keyword |
| cloudflare_logpush.spectrum_event.origin.tls.fingerprint | SHA256 hash of origin certificate. | keyword |
| cloudflare_logpush.spectrum_event.origin.tls.mode | If and how the upstream connection is encrypted. | keyword |
| cloudflare_logpush.spectrum_event.origin.tls.protocol | The TLS version negotiated between Spectrum and the origin. | keyword |
| cloudflare_logpush.spectrum_event.origin.tls.status | The state of the TLS session from Spectrum to the origin. | keyword |
| cloudflare_logpush.spectrum_event.proxy.protocol | Which form of proxy protocol is applied to the given connection. | keyword |
| cloudflare_logpush.spectrum_event.status | A code indicating reason for connection closure. | long |
| cloudflare_logpush.spectrum_event.timestamp | Timestamp at which the event took place. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |


### workers_trace

This is the `workers_trace` dataset.

#### Example

An example event for `workers_trace` looks as following:

```json
{
    "@timestamp": "2023-07-20T11:35:46.804Z",
    "agent": {
        "ephemeral_id": "57c92f82-a8e6-46e2-8c02-7e06ed603cf9",
        "id": "e6701a33-813b-4e4f-915d-bbd126f89485",
        "name": "elastic-agent-36364",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "cloudflare_logpush": {
        "workers_trace": {
            "dispatch_namespace": "my-worker-dispatch",
            "event": {
                "ray_id": "7e9ae7157ac0c33a",
                "request": {
                    "method": "GET",
                    "url": "http://chat-gpt-little-butterfly-0c3d.example.workers.dev/v2/_catalog"
                },
                "response": {
                    "status": 404
                }
            },
            "exceptions": [
                {
                    "message": "Uncaught TypeError: Cannot read property 'x' of undefined",
                    "stack": "TypeError: Cannot read property 'x' of undefined\n    at fetchHandler (/workers/script.js:12:27)\n    at handleRequest (/workers/script.js:6:13)"
                }
            ],
            "logs": [
                {
                    "level": "info",
                    "message": "Request received for /api/data"
                },
                {
                    "level": "error",
                    "message": "Something went wrong"
                }
            ],
            "outcome": "exception",
            "script": {
                "name": "chat-gpt-little-butterfly-0c3d",
                "tags": [
                    "api",
                    "chatgpt"
                ]
            },
            "timestamp": "2023-07-20T11:35:46.804Z",
            "type": "fetch"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.workers_trace",
        "namespace": "52981",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e6701a33-813b-4e4f-915d-bbd126f89485",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "action": "fetch",
        "agent_id_status": "verified",
        "category": [
            "web"
        ],
        "dataset": "cloudflare_logpush.workers_trace",
        "id": "7e9ae7157ac0c33a",
        "ingested": "2025-03-13T21:24:42Z",
        "kind": "event",
        "original": "{\"DispatchNamespace\":\"my-worker-dispatch\",\"Event\":{\"RayID\":\"7e9ae7157ac0c33a\",\"Request\":{\"Method\":\"GET\",\"URL\":\"http://chat-gpt-little-butterfly-0c3d.example.workers.dev/v2/_catalog\"},\"Response\":{\"Status\":404}},\"EventTimestampMs\":1689852946804,\"EventType\":\"fetch\",\"Exceptions\":[{\"Message\":\"Uncaught TypeError: Cannot read property 'x' of undefined\",\"Stack\":\"TypeError: Cannot read property 'x' of undefined\\n    at fetchHandler (/workers/script.js:12:27)\\n    at handleRequest (/workers/script.js:6:13)\"}],\"Logs\":[{\"level\":\"info\",\"message\":\"Request received for /api/data\"},{\"level\":\"error\",\"message\":\"Something went wrong\"}],\"Outcome\":\"exception\",\"ScriptName\":\"chat-gpt-little-butterfly-0c3d\",\"ScriptTags\":[\"api\",\"chatgpt\"]}",
        "outcome": "failure",
        "type": [
            "info",
            "error"
        ]
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 404
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush-workers_trace"
    ],
    "url": {
        "domain": "chat-gpt-little-butterfly-0c3d.example.workers.dev",
        "original": "http://chat-gpt-little-butterfly-0c3d.example.workers.dev/v2/_catalog",
        "path": "/v2/_catalog",
        "scheme": "http"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloudflare_logpush.workers_trace.dispatch_namespace | The Cloudflare Worker dispatch namespace. | keyword |
| cloudflare_logpush.workers_trace.entrypoint | The name of the entrypoint class in which the Worker began execution. | keyword |
| cloudflare_logpush.workers_trace.event | Details about the source event. | flattened |
| cloudflare_logpush.workers_trace.exceptions | List of uncaught exceptions during the invocation. | flattened |
| cloudflare_logpush.workers_trace.logs | List of console messages emitted during the invocation. | flattened |
| cloudflare_logpush.workers_trace.outcome | The outcome of the worker script invocation. Possible values are ok | exception. | keyword |
| cloudflare_logpush.workers_trace.script.name | The Cloudflare Worker script name. | keyword |
| cloudflare_logpush.workers_trace.script.tags | A list of user-defined tags used to categorize the Worker. | keyword |
| cloudflare_logpush.workers_trace.script.version | The version of the script that was invoked. | flattened |
| cloudflare_logpush.workers_trace.timestamp | The timestamp of when the event was received. | date |
| cloudflare_logpush.workers_trace.type | The event type that triggered the invocation. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |

