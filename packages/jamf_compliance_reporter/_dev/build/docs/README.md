# Jamf Compliance Reporter

The [Jamf Compliance Reporter](https://docs.jamf.com/compliance-reporter/documentation/Compliance_Reporter_Overview.html) Integration collects and parses data received from Jamf Compliance Reporter using a TLS or HTTP endpoint.

## Requirements
- Enable the Integration with the TLS or HTTP Endpoint input.
- Configure Jamf Compliance Reporter to send logs to the Elastic Agent.

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**.
2. In "Search for integrations" search bar type **Jamf Compliance Reporter**.
3. Click on "Jamf Compliance Reporter" integration from the search results.
4. Click on **Add Jamf Compliance Reporter** button to add Jamf Compliance Reporter integration.

## Setup Steps

- After validating settings, you can use a configuration profile in Jamf Pro to deploy certificates to endpoints in production.

- Reference link for [Creating a Configuration Profile](https://docs.jamf.com/compliance-reporter/documentation/Configuring_Compliance_Reporter_Properties_Using_Jamf_Pro.html) using Jamf Pro.

## Follow one of the below methods to collect logs from Jamf Compliance Reporter

### REST Endpoint Remote logging
1. Reference link for configuring [REST Endpoint Remote logging](https://docs.jamf.com/compliance-reporter/documentation/REST_Endpoint_Remote_Logging.html) for Compliance Reporter.
2. In Jamf Configuration Profile, form the full URL with port in the form `http[s]://{AGENT_ADDRESS}:{AGENT_PORT}/{URL}`.

### TLS Remote Logging
1. Reference link for generating [TLS Remote Logging](https://docs.jamf.com/compliance-reporter/documentation/TLS_Remote_Logging.html) for Compliance Reporter.
2. In Jamf Configuration Profile, form the full URL with port in the form `tls://{AGENT_ADDRESS}:{AGENT_PORT}`.

### Configure the Jamf Compliance Reporter integration with REST Endpoint Remote logging for Rest Endpoint Input

- Enter values for "Listen Address", "Listen Port" and "URL" to form the endpoint URL. Make note of the **Endpoint URL** `http[s]://{AGENT_ADDRESS}:{AGENT_PORT}/{URL}`.

### Configure the Jamf Compliance Reporter integration with TLS Remote Logging for TCP Input

- Enter values for "Listen Address" and "Listen Port" to form the TLS.

## Compatibility
This package has been tested for Compliance Reporter against Jamf pro version 10.39.0 and Jamf Compliance Reporter version 1.0.4.

## Logs

### log

- Default port for HTTP Endpoint: _9551_
- Default port for TLS: _9552_

This is the `log` data stream.

{{event "log"}}

{{fields "log"}}
