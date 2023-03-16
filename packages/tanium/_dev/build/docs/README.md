# Tanium

The [Tanium](https://www.tanium.com/) integration allows you to monitor Action History, Client Status, Discover, Endpoint Config, Reporting, and Threat Response Logs. Tanium is an enterprise platform that's primarily used as an endpoint management tool. It empowers security and IT operations teams with quick visibility and control to secure and manage every endpoint on the network, scaling to millions of endpoints with limited infrastructure. Tanium Connect is used to capture accurate and complete endpoint data from Tanium.

The Tanium integration can be used in four different modes to collect data:
- TCP mode: Tanium pushes logs directly to a TCP port hosted by your Elastic Agent.
- HTTP Endpoint mode: Tanium pushes logs directly to an HTTP endpoint hosted by your Elastic Agent.
- AWS S3 polling mode: Tanium writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode: Tanium writes data to S3, S3 sends a notification of a new object to SQS, the Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple agents can be used in this mode.

## Compatibility

This module has been tested against the latest Tanium Instance version **7.5.5.1162**.
Versions above this are expected to work but have not been tested.

## Data streams

The Tanium integration collects logs for six types of events: action history, client status, discover, endpoint config, reporting, and threat response.

## Requirements

You need Elasticsearch to store and search your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your hardware.

## Setup

### To collect data from an AWS S3 bucket, follow the below steps:
- Considering you already have an AWS S3 bucket setup, to create a connection for AWS S3 as a destination, follow this [link](https://docs.tanium.com/connect/connect/aws.html ).
- As we are always expecting data in JSON format, while creating the connection, select the format as JSON and deselect the `Generate Document option`.
- The default value of the field `Bucket List Prefix` is listed below.

  | Data Stream Name  | Bucket List Prefix     |
  | ----------------- | ---------------------- |
  | Action History    | action_history         |
  | Client Status     | client_status          |
  | Discover          | discover               |
  | Endpoint Config   | endpoint_config        |
  | Reporting         | reporting              |
  | Threat Response   | threat_response        |

**NOTE**: User can have any value which should match with bucket List Prefix.
### To collect data from AWS SQS, follow the below steps:
1. Assuming you've already set up a connection to push data into the AWS bucket; if not, see the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" mentioned in the [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an Access Policy, use the bucket name configured to create a connection for AWS S3 in Tanium.
3. Configure event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - It is recommended to configure separate `event notification` for each data stream using different bucket list prefixes.
  - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue and select the queue name created in Step 2.

### To collect data from the Tanium HTTP Endpoint, follow the below steps:
- Considering you already have HTTP endpoint hosted, to create a connection for HTTP as destination follow this [link](https://docs.tanium.com/connect/connect/http.html).
- As we are always expecting data in JSON format so while Creating the Connection, Select the Format as Json and deselect the `Generate Document option`.
- Add some custom header and its value for additional security.

### To collect data from TCP, follow the below steps:
- While creating a connection, select the Socket Receiver as a destination.
- Choose the type of source you want to obtain.
- As we are always expecting data in JSON format so while Creating the Connection, Select the Format as Json and deselect the `Generate Document option`.
- Mention HTTP endpoint in the field Host
- Mention port in the field Port to create a TCP connection.
- Finally, select TCP as Network Protocol.

## Logs reference

### Action-History

This is the `action_history` dataset.
The HTTP Endpoint's default port is _9577_.
TCP's default port is _9578_.

#### Example

{{event "action_history"}}

{{fields "action_history"}}

### Client-Status

This is the `client_status` dataset.
The HTTP Endpoint's default port is _9579_.
TCP's default port is _9580_.

#### Example

{{event "client_status"}}

{{fields "client_status"}}

### Discover

This is the `discover` dataset.
The HTTP Endpoint's default port is _9581_.
TCP's default port is _9582_.

#### Example

{{event "discover"}}

{{fields "discover"}}

### Endpoint-Config

This is the `endpoint_config` dataset.
The HTTP Endpoint's default port is _9583_.
TCP's default port is _9584_.

#### Example

{{event "endpoint_config"}}

{{fields "endpoint_config"}}

### Reporting

This is the `reporting` dataset.
The HTTP Endpoint's default port is _9585_.
TCP's default port is _9586_.

#### Example

{{event "reporting"}}

{{fields "reporting"}}

### Threat-Response

This is the `threat_response` dataset.
The HTTP Endpoint's default port is _9587_.
TCP's default port is _9588_.

#### Example

{{event "threat_response"}}

{{fields "threat_response"}}
