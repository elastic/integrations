# Jamf Compliance Reporter

The [Jamf Compliance Reporter](https://docs.jamf.com/compliance-reporter/documentation/Compliance_Reporter_Overview.html) Integration collects and parses data received from Jamf Compliance Reporter using TLS or HTTP Endpoint.  

## Requirements
- Enable the Integration with the TLS or HTTP Endpoint input.
- Configure Jamf Compliance Reporter to send logs to the Elastic Agent.

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**.
2. In "Search for integrations" search bar type **Jamf Compliance Reporter**.
3. Click on "Jamf Compliance Reporter" integration from the search results.
4. Click on **Add Jamf Compliance Reporter** button to add Jamf Compliance Reporter integration.

### Configure the Jamf Compliance Reporter integration for REST Endpoint Remote logging

1. Enter values for "Listen Address", "Listen Port" and "URL" to form the endpoint URL. Make note of the **Endpoint URL** `http[s]://{AGENT_ADDRESS}:{AGENT_PORT}/{URL}`.

### Configure the Jamf Compliance Reporter integration for TLS Remote Logging

1. Enter values for "Listen Address" and "Listen Port" to form the TLS. `http://{AGENT_ADDRESS}:{AGENT_PORT}`.

## Setup Steps

- After validating settings, you can use a configuration profile in Jamf Pro to deploy certificates to endpoints in production.

- Reference link for [Creating a Configuration Profile](https://docs.jamf.com/compliance-reporter/documentation/Configuring_Compliance_Reporter_Properties_Using_Jamf_Pro.html) using Jamf Pro.

## Follow one of the below methods to collect logs from Jamf Compliance Reporter

- Reference link for generating [REST Endpoint Remote logging](https://docs.jamf.com/compliance-reporter/documentation/REST_Endpoint_Remote_Logging.html) for Compliance Reporter.

- Reference link for generating [TLS Remote Logging](https://docs.jamf.com/compliance-reporter/documentation/TLS_Remote_Logging.html) for Compliance Reporter.

## Compatibility
This package has been tested for Compliance Reporter against Jamf pro version 10.18.0.

## Logs

### App Metrics Logs

- Default port for HTTP Endpoint: _9550_  
- Default port for TLS: _9553_

### Audit Logs

- Default port for HTTP Endpoint: _9551_  
- Default port for TLS: _9554_

### Event Logs

- Default port for HTTP Endpoint: _9552_  
- Default port for TLS: _9555_

## Fields and Sample Event

### App Metrics Logs

This is the `app_metrics` dataset.

{{event "app_metrics"}}

{{fields "app_metrics"}}

### Audit Logs

This is the `audit` dataset.

{{event "audit"}}

{{fields "audit"}}

### Event Logs

This is the `event` dataset.

{{event "event"}}

{{fields "event"}}
