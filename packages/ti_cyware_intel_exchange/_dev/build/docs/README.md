# Cyware Intel Exchange

## Overview

[Cyware Intel Exchange](https://www.cyware.com/products/intel-exchange) is an intelligent client-server exchange that leverages advanced technologies like Artificial Intelligence and Machine Learning to automatically ingest, analyze, correlate and act upon the threat data ingested from multiple external sources and internally deployed security tools.

## Data streams

The Cyware Intel Exchange integration collects the following events:
- **[Indicator](https://ctixapiv3.cyware.com/rules/save-result-set/retrieve-saved-result-set-data)** - This fetches all the saved result set data for conditional IOCs present in the application..

## Requirements

### Agentless-enabled integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation
Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Compatibility

For Rest API, this module has been tested against the **[CTIX API v3](https://ctixapiv3.cyware.com/intel-exchange-api-reference)** version.

## Setup

**Note** - Before you start the setup, ensure that you have **Create** and **Update** permissions for **CTIX Integrators**.

### Follow below steps to generate Open API credentials for collecting data from the CTIX API:

1. Go to **Administration** > **Integration Management**.
2. In **Third Party Developers**, click **CTIX Integrators**.
3. Click **Add New**. Enter the following details:
   - **Name**: Enter a unique name for the API credentials in 50 characters.
   - **Description**: Enter a description for the credentials within 1000 characters.
   - **Expiry Date**: Select an expiry date for open API keys. To apply an expiration date for the credentials, you can select **Expires On** and select the date. To ensure the credentials never expire, you can select **Never Expire**.
4. Click **Add New**.
5. Click **Download** to download the API credentials in CSV format. You can also click **Copy** to copy the endpoint URL, secret key, and access ID.

For more details, refer to the [Authentication](https://ctixapiv3.cyware.com/authentication) documentation and the guide on how to [Generate Open API Credentials](https://techdocs.cyware.com/en/299670-447852-configure-open-api.html).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Cyware Intel Exchange**.
3. Select the **Cyware Intel Exchange** integration afrom the search results.
4. Click on the "Add Cyware Intel Exchange" button to add the integration.
5. Add all the required integration configuration parameters: URL, Access ID and Secret Key.
6. Save the integration.

## Logs reference

### Indicator

This is the `Indicator` dataset.

#### Example

{{event "indicator"}}

{{fields "indicator"}}
