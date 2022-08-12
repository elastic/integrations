# Cloudflare Logpush

## Overview

The [Cloudflare Logpush](https://www.cloudflare.com/) integration allows you to monitor Audit, DNS, Firewall Event, Http Request,NEL Report, Network Analytics, Spectrum Event Logs. Cloudflare is content delivery network and DDoS mitigation company. Cloudflare is a global network designed to make everything you connect to the Internet secure, private, fast, and reliable. Secure your websites, APIs, and Internet applications. Protect corporate networks, employees, and devices. Write and deploy code that runs on the network edge.

Use the Cloudflare Logpush integration to collect and parse data from the HTTP Endpoint, AWS S3 Bucket or AWS SQS. Then visualise that data in Kibana.

For example, you could use the data from this integration to know about which websites have the highest traffic, which areas have the highest network traffic, or mitigation statistics.

## Data streams

The Cloudflare Logpush integration collects logs for seven types of events: Audit, DNS, Firewall Event, Http Request, NEL Report, Network Analytics and Spectrum Event.

**Audit**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/audit_logs/).

**DNS**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/dns_logs/).

**Firewall Event**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events/).

**Http Request**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/).

**NEL Report**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/nel_reports/).

**Network Analytics**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/network_analytics_logs/).

**Spectrum Event**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/spectrum_events/).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has been tested against **Cloudflare version v4**.

**Note**: We recommend using AWS SQS for Cloudflare Logpush.

## Setup

### To collect data from AWS S3 Bucket, follow the below steps:
- Configure the [Data Forwarder](https://developers.cloudflare.com/logs/get-started/enable-destinations/aws-s3/) to ingest data into an AWS S3 bucket.
- The default value of the "Bucket List Prefix" is listed below. But the user can set the parameter "Bucket List Prefix" according to the requirement.

  | Data Stream Name  | Bucket List Prefix     |
  | ----------------- | ---------------------- |
  | Audit Logs        | audit_logs             |
  | DNS               | dns                    |
  | Firewall Event    | firewall_event         |
  | HTTP Request      | http_request           |
  | NEL Report        | nel_report             |
  | Network Analytics | network_analytics_logs |
  | Spectrum Event    | spectrum_event         |

### To collect data from AWS SQS, follow the below steps:
- Setup AWS S3 Bucket as mentioned in the above documentation.
- Setup AWS SQS queue as mentioned in this [Link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html). (Step 1)
  1. Above, enter the Bucket ARN of the bucket that you've created.
- Setup event notification for an S3 bucket. Follow this [Link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  1. The user has to perform the above step for all the data-streams individually, and each time prefix parameter should be set as S3 Bucket List Prefix as we've defined earlier. (for Example, `audit_logs/` for audit data stream.)
  2. For all the event notifications, select the event type as s3:ObjectCreated:*, select the destination type as SQS Queue, and select the queue that you've created.

**Note**:
  - Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.

### To collect data from the Cloudflare HTTP Endpoint, follow the below steps:
- Reference link to [Enable HTTP destination](https://developers.cloudflare.com/logs/get-started/enable-destinations/http/) for Cloudflare Logpush.

### Enabling the integration in Elastic
1. In Kibana, go to Management > Integrations
2. In the integrations search bar type **Cloudflare Logpush**.
3. Click the **Cloudflare Logpush** integration from the search results.
4. Click the **Add Cloudflare Logpush** button to add Cloudflare Logpush integration.
5. Enable the Integration with the HTTP Endpoint or AWS S3 input.
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