# Jamf Protect

The Jamf Protect integration collects and parses data received from [Jamf Protect](https://learn.jamf.com/bundle/jamf-protect-documentation/page/About_Jamf_Protect.html) using a HTTP endpoint.

Use the Jamf Protect integration to collect logs from your machines.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

<!-- For example, if you wanted to monitor shell script commands performed by the root user, you could [configure Jamf to monitor those events](https://docs.jamf.com/compliance-reporter/documentation/Audit_Log_Levels_in_Compliance_Reporter.html) and then send them to Elastic for further investigation. -->

## Data streams

The Jamf Protect integration collects one type of data stream: alerts, telemetry, and web threat events.

**Alerts** help you keep a record of Alerts happening on endpoints using Jamf Protect.
See more details in the [Alerts](#logs-reference).

**Telemetry** help you keep a record of audit events happening on endpoints using Jamf Protect.
See more details in the [Telemetry](#logs-reference).

**Web threat events** help you keep a record of web threat events happening on endpoints using Jamf Protect.
See more details in the [Web](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

<!-- The integration requires

- Elastic Agent
    - Custom HTTP Endpoint Logs    -->

## Setup

To use this integration, you will also need to:
- Enable the integration in Elastic
- Configure Jamf Protect (macOS Security) to send logs to the Elastic Agent (Custom HTTP Endpoint Logs)
    - Remote Alert Collection Endpoints
    - Unified Logs Collection Endpoints
    - Telemetry Collection Endpoints
- Configure Jamf Protect (Jamf Security Cloud) to send logs to the Elastic Agent (Custom HTTP Endpoint Logs)
    - Threat Event Stream 


### Enable the integration in Elastic

For step-by-step instructions on how to set up an new integration in Elastic, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.
When setting up the integration, you will choose to collect logs via HTTP Endpoint.

### Configure Jamf Protect

After validating settings, you can configure Jamf Protect to send events to Elastic.
For more information on configuring Jamf Protect, see 
- [Creating an Action Configuration](https://learn.jamf.com/bundle/jamf-protect-documentation/page/Creating_an_Action_Configuration.html)
- [Configure Threat Event Stream](https://learn.jamf.com/bundle/jamf-security-documentation/page/Configuring_the_Threat_Events_Stream_to_Send_HTTP_Events.html)

Then, depding on which events you want to send to Elastic, configure one or multiple HTTP endpoints:

**Remote Alert Collection Endpoints**:
- [ ] In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Unified Logs Collection Endpoints**:
- [ ] In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}/`.

**Telemetry Collection Endpoints**:
- [ ] In the URL field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.

**Threat Event Stream**:
- [ ] In the Server hostname or IP field, enter the full URL with port using this format: `http[s]://{ELASTICAGENT_ADDRESS}:{AGENT_PORT}`.
