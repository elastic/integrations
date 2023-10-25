# Cloudflare Logpush

## Overview

The [Cloudflare Logpush](https://www.cloudflare.com/) integration allows you to monitor Access Request, Audit, CASB, Device Posture, DNS, DNS Firewall, Firewall Event, Gateway DNS, Gateway HTTP, Gateway Network, HTTP Request, Magic IDS, NEL Report, Network Analytics, Sinkhole HTTP, Spectrum Event, Network Session and Workers Trace Events logs. Cloudflare is a content delivery network and DDoS mitigation company. Cloudflare provides a network designed to make everything you connect to the Internet secure, private, fast, and reliable; secure your websites, APIs, and Internet applications; protect corporate networks, employees, and devices; and write and deploy code that runs on the network edge.

The Cloudflare Logpush integration can be used in three different modes to collect data:
- HTTP Endpoint mode - Cloudflare pushes logs directly to an HTTP endpoint hosted by your Elastic Agent.
- AWS S3 polling mode - Cloudflare writes data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode - Cloudflare writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

For example, you could use the data from this integration to know which websites have the highest traffic, which areas have the highest network traffic, or observe mitigation statistics.

## Data streams

The Cloudflare Logpush integration collects logs for the following types of events.

### Zero Trust events

**Access Request**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/access_requests/).

**Audit**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/audit_logs/).

**CASB findings**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/casb_findings/).

**Device Posture Results**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/device_posture_results/).

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

**Sinkhole HTTP**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/sinkhole_http_logs/).

**Spectrum Event**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/spectrum_events/).

**Workers Trace Events**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/workers_trace_events/).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has been tested against **Cloudflare version v4**.

**Note**: It is recommended to use AWS SQS for Cloudflare Logpush.

## Setup

### To collect data from AWS S3 Bucket, follow the below steps:
- Configure the [Data Forwarder](https://developers.cloudflare.com/logs/get-started/enable-destinations/aws-s3/) to ingest data into an AWS S3 bucket.
- The default value of the "Bucket List Prefix" is listed below. However, the user can set the parameter "Bucket List Prefix" according to the requirement.

  | Data Stream Name           | Bucket List Prefix     |
  | -------------------------- | ---------------------- |
  | Access Request             | access_request         |
  | Audit Logs                 | audit_logs             |
  | CASB findings              | casb                   |
  | Device Posture Results     | device_posture         |
  | DNS                        | dns                    |
  | DNS Firewall               | dns_firewall           |
  | Firewall Event             | firewall_event         |
  | Gateway DNS                | gateway_dns            |
  | Gateway HTTP               | gateway_http           |
  | Gateway Network            | gateway_network        |
  | HTTP Request               | http_request           |
  | Magic IDS                  | magic_ids              |
  | NEL Report                 | nel_report             |
  | Network Analytics          | network_analytics_logs |
  | Zero Trust Network Session | network_session        |
  | Sinkhole HTTP              | sinkhole_http          |
  | Spectrum Event             | spectrum_event         |
  | Workers Trace Events       | workers_trace          |


**Note**:
- It is possible to ingest data from Cloudflare R2, an S3-compatible storage service, by setting the parameter `Cloudflare R2`. Using non-AWS S3 compatible buckets requires the use of Access Key ID and Secret Access Key for authentication, as well as the endpoint must be set to replace the default API endpoint. Endpoint should be a full URI, tipically in the form of `https(s)://<accountid>.r2.cloudflarestorage.com`, that will be used as the API endpoint of the service.
- This setting can be also used to ingest data from other S3-compatible storage services.

### To collect data from AWS SQS, follow the below steps:
1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first setup an AWS S3 Bucket as mentioned in the above documentation.
2. To setup an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
3. Setup event notification for an S3 bucket. Follow this [Link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - The user has to perform Step 3 for all the data-streams individually, and each time prefix parameter should be set the same as the S3 Bucket List Prefix as created earlier. (for example, `audit_logs/` for audit data stream.)
  - For all the event notifications that have been created, select the event type as s3:ObjectCreated:*, select the destination type SQS Queue, and select the queue that has been created in Step 2.

**Note**:
  - Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.
  - You can configure a global SQS queue for all data streams or a local SQS queue for each data stream. Configuring
    data stream specific SQS queues will enable better performance and scalability. Data stream specific SQS queues
    will always override any global queue definitions for that specific data stream.

### To collect data from GCS Buckets, follow the below steps:
- Configure the [Data Forwarder](https://developers.cloudflare.com/logs/get-started/enable-destinations/google-cloud-storage/) to ingest data into a GCS bucket.
- Configure the GCS bucket names and credentials along with the required configs under the "Collect Cloudflare Logpush logs via Google Cloud Storage" section. 
- Make sure the service account and authentication being used, has proper levels of access to the GCS bucket [Manage Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys/)

**Note**:
- The GCS input currently does not support fetching of buckets using bucket prefixes, so the bucket names have to be configured manually for each data stream.
- The GCS input currently only accepts a service account JSON key or a service account JSON file for authentication.
- The GCS input currently only supports json data.

### To collect data from the Cloudflare HTTP Endpoint, follow the below steps:
- Reference link to [Enable HTTP destination](https://developers.cloudflare.com/logs/get-started/enable-destinations/http/) for Cloudflare Logpush.
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
    "destination_conf": "https://<public domain>:<public port>/<dataset path>?header_<secret_header>=<secret_value>",
    "dataset": "audit",
    "logpull_options": "fields=RayID,EdgeStartTimestamp&timestamps=rfc3339"
}'
```
- Default port for the HTTP Endpoint is _9560_.
- When using the same port for more than one dataset, be sure to specify different dataset paths.

### Enabling the integration in Elastic
1. In Kibana, go to Management > Integrations
2. In the integrations search bar type **Cloudflare Logpush**.
3. Click the **Cloudflare Logpush** integration from the search results.
4. Click the **Add Cloudflare Logpush** button to add Cloudflare Logpush integration.
5. Enable the Integration with the HTTP Endpoint, AWS S3 input or GCS input.
6. Under the AWS S3 input, there are two types of inputs: using AWS S3 Bucket or using SQS.
7. Configure Cloudflare to send logs to the Elastic Agent.

## Logs reference

### access_request

This is the `access_request` dataset.

#### Example

{{event "access_request"}}

{{fields "access_request"}}

### audit

This is the `audit` dataset.


#### Example

{{event "audit"}}

{{fields "audit"}}

### casb

This is the `casb` dataset.

#### Example

{{event "casb"}}

{{fields "casb"}}

### device_posture

This is the `device_posture` dataset.

#### Example

{{event "device_posture"}}

{{fields "device_posture"}}

### dns

This is the `dns` dataset.

#### Example

{{event "dns"}}

{{fields "dns"}}

### dns_firewall

This is the `dns_firewall` dataset.

#### Example

{{event "dns_firewall"}}

{{fields "dns_firewall"}}

### firewall_event

This is the `firewall_event` dataset.

#### Example

{{event "firewall_event"}}

{{fields "firewall_event"}}

### gateway_dns

This is the `gateway_dns` dataset.

#### Example

{{event "gateway_dns"}}

{{fields "gateway_dns"}}

### gateway_http

This is the `gateway_http` dataset.

#### Example

{{event "gateway_http"}}

{{fields "gateway_http"}}

### gateway_network

This is the `gateway_network` dataset.

#### Example

{{event "gateway_network"}}

{{fields "gateway_network"}}

### http_request

This is the `http_request` dataset.

#### Example

{{event "http_request"}}

{{fields "http_request"}}

### magic_ids

This is the `magic_ids` dataset.

#### Example

{{event "magic_ids"}}

{{fields "magic_ids"}}

### nel_report

This is the `nel_report` dataset.

#### Example

{{event "nel_report"}}

{{fields "nel_report"}}

### network_analytics

This is the `network_analytics` dataset.

#### Example

{{event "network_analytics"}}

{{fields "network_analytics"}}

### network_session

This is the `network_session` dataset.

#### Example

{{event "network_session"}}

{{fields "network_session"}}

### sinkhole_http

This is the `sinkhole_http` dataset.

#### Example

{{event "sinkhole_http"}}

{{fields "sinkhole_http"}}

### spectrum_event

This is the `spectrum_event` dataset.

#### Example

{{event "spectrum_event"}}

{{fields "spectrum_event"}}

### workers_trace

This is the `workers_trace` dataset.

#### Example

{{event "workers_trace"}}

{{fields "workers_trace"}}
