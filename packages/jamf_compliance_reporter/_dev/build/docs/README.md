# Jamf Compliance Reporter

The Jamf Compliance Reporter integration collects and parses data received from [Jamf Compliance Reporter](https://docs.jamf.com/compliance-reporter/documentation/Compliance_Reporter_Overview.html) using a TLS or HTTP endpoint.

Use the Jamf Compliance Reporter integration to collect logs from your machines.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

For example, if you wanted to monitor shell script commands performed by the root user, you could [configure Jamf to monitor those events](https://docs.jamf.com/compliance-reporter/documentation/Audit_Log_Levels_in_Compliance_Reporter.html) and then send them to Elastic for further investigation.

## Data streams

The Jamf Compliance Reporter integration collects one type of data stream: logs.

**Logs** help you keep a record of events happening on computers using Jamf.
The log data stream collected by the Jamf Compliance Reporter integration includes events that are related to security compliance requirements. See more details in the [Logs](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Note: This package has been tested for Compliance Reporter against Jamf Pro version 10.39.0 and Jamf Compliance Reporter version 1.0.4.

## Setup

To use this integration, you will also need to:
- Enable the integration in Elastic
- Configure Jamf Compliance Reporter to send logs to the Elastic Agent

### Enable the integration in Elastic

For step-by-step instructions on how to set up an new integration in Elastic, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.
When setting up the integration, you will choose to collect logs either via TLS or HTTP Endpoint.

### Configure Jamf Compliance Reporter

After validating settings, you can use a configuration profile in Jamf Pro to deploy certificates to endpoints in production.
For more information on using configuration profiles in Jamf Pro, see [Creating a Configuration Profile](https://docs.jamf.com/compliance-reporter/documentation/Configuring_Compliance_Reporter_Properties_Using_Jamf_Pro.html).

Then, follow _one_ of the below methods to collect logs from Jamf Compliance Reporter:

**REST Endpoint Remote logging**:
1. Read [Jamf's REST Endpoint Remote logging documentation](https://docs.jamf.com/compliance-reporter/documentation/REST_Endpoint_Remote_Logging.html).
2. In your Jamf Configuration Profile, form the full URL with port using this format: `http[s]://{AGENT_ADDRESS}:{AGENT_PORT}/{URL}`.

**TLS Remote Logging**:
1. Read [Jamf's TLS Remote Logging documentation](https://docs.jamf.com/compliance-reporter/documentation/TLS_Remote_Logging.html).
2. In your Jamf Configuration Profile, form the full URL with port using this format: `tls://{AGENT_ADDRESS}:{AGENT_PORT}`.

**Configure the Jamf Compliance Reporter integration with REST Endpoint Remote logging for Rest Endpoint Input**:
1. Enter values for "Listen Address", "Listen Port" and "URL" to form the endpoint URL. Make note of the **Endpoint URL** `http[s]://{AGENT_ADDRESS}:{AGENT_PORT}/{URL}`.

**Configure the Jamf Compliance Reporter integration with TLS Remote Logging for TCP Input**:
1. Enter values for "Listen Address" and "Listen Port" to form the TLS.

## Logs reference

### log

- Default port for HTTP Endpoint: _9551_
- Default port for TLS: _9552_

This is the `log` data stream.

{{event "log"}}

{{fields "log"}}
