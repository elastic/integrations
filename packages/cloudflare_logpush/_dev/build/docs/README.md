# Cloudflare Logpush

## Overview

The [Cloudflare Logpush](https://www.cloudflare.com/) integration allows you to monitor Audit, DNS, Firewall Event, HTTP Request, NEL Report, Network Analytics and Spectrum Event Logs. Cloudflare is a content delivery network and DDoS mitigation company. Cloudflare provides a network designed to make everything you connect to the Internet secure, private, fast, and reliable; secure your websites, APIs, and Internet applications; protect corporate networks, employees, and devices; and write and deploy code that runs on the network edge.

The Cloudflare Logpush integration can be used in three different modes to collect data:
- HTTP Endpoint mode - Cloudflare pushes logs directly to an HTTP endpoint hosted by your Elastic Agent.
- AWS S3 polling mode - Cloudflare writes data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode - Cloudflare writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

For example, you could use the data from this integration to know which websites have the highest traffic, which areas have the highest network traffic, or observe mitigation statistics.

## Data streams

The Cloudflare Logpush integration collects logs for seven types of events: Audit, DNS, Firewall Event, HTTP Request, NEL Report, Network Analytics, and Spectrum Event.

**Audit**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/audit_logs/).

**DNS**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/dns_logs/).

**Firewall Event**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events/).

**HTTP Request**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/).

**NEL Report**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/nel_reports/).

**Network Analytics**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/network_analytics_logs/).

**Spectrum Event**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/spectrum_events/).

**Gateway DNS**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/gateway_dns/).

**Gateway HTTP**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/gateway_http/).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has been tested against **Cloudflare version v4**.

**Note**: It is recommended to use AWS SQS for Cloudflare Logpush.

## Setup

### To collect data from AWS S3 Bucket, follow the below steps:
- Configure the [Data Forwarder](https://developers.cloudflare.com/logs/get-started/enable-destinations/aws-s3/) to ingest data into an AWS S3 bucket.
- The default value of the "Bucket List Prefix" is listed below. However, the user can set the parameter "Bucket List Prefix" according to the requirement.

  | Data Stream Name  | Bucket List Prefix     |
  | ----------------- | ---------------------- |
  | Audit Logs        | audit_logs             |
  | DNS               | dns                    |
  | Firewall Event    | firewall_event         |
  | HTTP Request      | http_request           |
  | NEL Report        | nel_report             |
  | Network Analytics | network_analytics_logs |
  | Spectrum Event    | spectrum_event         |
  | Gateway DNS       | gateway_dns            |
  | Gateway HTTP      | gateway_http           |

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
    "destination_conf": "https://<public domain>:<public port>?header_<secret_header>=<secret_value>",
    "dataset": "http_requests",
    "logpull_options": "fields=RayID,EdgeStartTimestamp&timestamps=rfc3339"
}'
```

### Enabling the integration in Elastic
1. In Kibana, go to Management > Integrations
2. In the integrations search bar type **Cloudflare Logpush**.
3. Click the **Cloudflare Logpush** integration from the search results.
4. Click the **Add Cloudflare Logpush** button to add Cloudflare Logpush integration.
5. Enable the Integration with the HTTP Endpoint, AWS S3 input or GCS input.
6. Under the AWS S3 input, there are two types of inputs: using AWS S3 Bucket or using SQS.
7. Configure Cloudflare to send logs to the Elastic Agent.

## Logs reference

### audit

This is the `audit` dataset.
Default port for HTTP Endpoint: _9560_

#### Example

{{event "audit"}}

{{fields "audit"}}

### dns

This is the `dns` dataset.
Default port for HTTP Endpoint: _9561_

#### Example

{{event "dns"}}

{{fields "dns"}}

### firewall_event

This is the `firewall_event` dataset.
Default port for HTTP Endpoint: _9562_

#### Example

{{event "firewall_event"}}

{{fields "firewall_event"}}

### http_request

This is the `http_request` dataset.
Default port for HTTP Endpoint: _9563_

#### Example

{{event "http_request"}}

{{fields "http_request"}}

### nel_report

This is the `nel_report` dataset.
Default port for HTTP Endpoint: _9564_

#### Example

{{event "nel_report"}}

{{fields "nel_report"}}

### network_analytics

This is the `network_analytics` dataset.
Default port for HTTP Endpoint: _9565_

#### Example

{{event "network_analytics"}}

{{fields "network_analytics"}}

### spectrum_event

This is the `spectrum_event` dataset.
Default port for HTTP Endpoint: _9566_

#### Example

{{event "spectrum_event"}}

{{fields "spectrum_event"}}

### gateway_dns

This is the `gateway_dns` dataset.
Default port for HTTP Endpoint: _9567_

#### Example

{{event "gateway_dns"}}

{{fields "gateway_dns"}}

### gateway_http

This is the `gateway_http` dataset.
Default port for HTTP Endpoint: _9568_

#### Example

{{event "gateway_http"}}

{{fields "gateway_http"}}
