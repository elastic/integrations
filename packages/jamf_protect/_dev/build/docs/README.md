# Jamf Protect

The Jamf Protect integration collects and parses data received from [Jamf Protect](https://learn.jamf.com/bundle/jamf-protect-documentation/page/About_Jamf_Protect.html) using the following methods.

- HTTP Endpoint mode - Jamf Protect streams logs directly to an HTTP endpoint hosted by your Elastic Agent.
- AWS S3 polling mode - Jamf Protect forwards data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode - Jamf Protect writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

Use the Jamf Protect integration to collect logs from your machines.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

## Data streams

The Jamf Protect integration collects 4 types of events: alerts, telemetry, web threat events, and web traffic events.

[**Alerts**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Alerts.html) help you keep a record of Alerts and Unified Logs happening on endpoints using Jamf Protect.

[**Telemetry**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Creating_an_Action_Configuration.html) help you keep a record of audit events happening on endpoints using Jamf Protect.

[**Web threat events**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Data_Streams_Overview.html) help you keep a record of web threat events happening on endpoints using Jamf Protect.

[**Web traffic events**](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Data_Streams_Overview.html) help you keep a record of content filtering and network requests happening on endpoints using Jamf Protect.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

To use this integration, you will also need to:
- Enable the integration in Elastic
- Configure Jamf Protect (macOS Security) to send logs to AWS S3 or the Elastic Agent (HTTP Endpoint)
    - Alerts
    - Unified Logs
    - Telemetry
- Configure Jamf Protect (Jamf Security Cloud) to send logs to AWS S3 or the Elastic Agent (HTTP Endpoint)
    - Threat Event Stream 
    - Network Traffic Stream


### Enable the integration in Elastic

For step-by-step instructions on how to set up an new integration in Elastic, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.
When setting up the integration, you will choose to collect logs via either S3 or HTTP Endpoint.

### Configure Jamf Protect using HTTP Endpoint

After validating settings, you can configure Jamf Protect to send events to Elastic.
For more information on configuring Jamf Protect, see 
- [Creating an Action Configuration](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Creating_an_Action_Configuration.html)
- [Configure Threat Event Stream](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Configuring_the_Network_Threat_Events_Stream_to_send_HTTP_Events.html)
- [Configure Network Traffic Stream](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Configuring_the_Network_Threat_Events_Stream_to_send_HTTP_Events.html)

Then, depending on which events you want to send to Elastic, configure one or multiple HTTP endpoints:

**Remote Alert Collection Endpoints**:
- In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Unified Logs Collection Endpoints**:
- In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Telemetry Collection Endpoints**:
- In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Threats Event Stream**:
- In the Server hostname or IP field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Network Traffic Stream**:
- In the Server hostname or IP field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.


### Configure Jamf Protect using AWS S3

After validating settings, you can configure Jamf Protect to send events to AWS S3.
For more information on configuring Jamf Protect, see 
- [Creating an Action Configuration](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Creating_an_Action_Configuration.html)
- [Enabling Data Forwarding to AWS S3](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Data_Forwarding_to_a_Third_Party_Storage_Solution.html#ariaid-title2)
- [Configure Threat Event Stream](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Configuring_the_Threat_Events_Stream_to_Send_Events_to_AWS_S3.html)


**Copyright (c) 2024, Jamf Software, LLC.  All rights reserved.**

## Logs reference

#### alerts

This is the `Alerts` dataset.

##### Example

{{event "alerts"}}

{{fields "alerts"}}

#### telemetry

This is the `Telemetry` dataset.

##### Example

{{event "telemetry"}}

{{fields "telemetry"}}

#### threats event stream

This is the `Threats Event Stream` dataset.

##### Example

{{event "web_threat_events"}}

{{fields "web_threat_events"}}

#### network traffic stream

This is the `Network Traffic Stream` dataset.

##### Example

{{event "web_traffic_events"}}

{{fields "web_traffic_events"}}