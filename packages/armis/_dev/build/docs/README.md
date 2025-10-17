# Armis

## Overview

[Armis](https://www.armis.com/) is an enterprise-class security platform designed to provide visibility and protection for managed, unmanaged, and IoT devices. It enables organizations to detect threats, manage vulnerabilities, and enforce security policies across their network.

Use this integration to collect and parse data from your Armis instance.

### Compatibility

This module has been tested against the Armis API version **v1**.

## What data does this integration collect?

The Armis integration collects three types of logs.

- **Devices**: Fetches the latest updates for all devices monitored by Armis.
- **Alerts**: Gathers alerts associated with all devices monitored by Armis.
- **Vulnerabilities**: Retrieves detected vulnerabilities and possible mitigation steps across all devices monitored by Armis.

**Note**:

1. The **vulnerability data stream** retrieves information by first fetching vulnerabilities and then identifying the devices where these vulnerabilities were detected, using a chained call between the vulnerability search and vulnerability match endpoints.

## What do I need to use this integration?

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect logs through REST API

1. Log in to your Armis portal.
2. Navigate to the **Settings** tab.
3. Select **Asset Management & Security**.
4. Go to **API Management** and generate a **Secret Key**.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Armis**.
3. Select the **Armis** integration and add it.
4. Add all the required integration configuration parameters, including the URL, Secret Key to enable data collection.
5. Save the integration.

## Limitations

In the **vulnerability data stream**, our filtering mechanism for the **vulnerability search API** relies specifically on the `lastDetected` field. This means that when a user takes action on a vulnerability and `lastDetected` updates, only then will the event for that vulnerability be retrieved. Initially, we assumed this field would always have a value and could be used as a cursor timestamp for fetching data between intervals. However, due to inconsistencies in the API response, we observed cases where `lastDetected` is `null`.

## Troubleshooting

- If you get the following errors in the **vulnerability data stream**, reduce the page size in your request.

  **Common errors:**
  - `502 Bad Gateway`
  - `414 Request-URI Too Large`

- If you encounter issues in the **alert data stream**, particularly during the initial data fetch, reduce the initial interval.

  **Example error:**
  - `The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.`

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

An example event for `alert` looks as following:

{{event "alert"}}

#### Exported fields

{{fields "alert"}}

### Device

This is the `device` dataset.

#### Example

An example event for `device` looks as following:

{{event "device"}}

#### Exported fields

{{fields "device"}}

### Vulnerability

This is the `vulnerability` dataset.

#### Example

An example event for `vulnerability` looks as following:

{{event "vulnerability"}}

#### Exported fields

{{fields "vulnerability"}}
