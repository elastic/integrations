# Sysdig Integration
This integration allows for the shipping of [Sysdig](https://sysdig.com/) logs to Elastic for security, observability and organizational awareness. Logs can then be analyzed by using either the dashboard included with the integration or via the creation of custom dashboards within Kibana.

## Data Streams
The Sysdig integration collects two type of logs:

**Alerts** The Alerts data stream collected by the Sysdig integration is comprised of Sysdig Alerts. See more details about Sysdig Alerts in [Sysdig's Alerts Documentation](https://docs.sysdig.com/en/docs/sysdig-monitor/alerts/). A complete list of potential fields used by this integration can be found in the [Logs reference](#logs-reference)

**Event** The event data stream collected through the Sysdig integration consists of Sysdig Security Events. See more details about Security Events in [Sysdig's Events Feed Documentation](https://docs.sysdig.com/en/docs/sysdig-secure/threats/activity/events-feed/).

## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).

Sysdig must be configured to output alerts to a supported output channel as defined in [Setup](#setup). The system will only receive common fields output by Sysdig's rules, meaning that if a rule does not include a desired field the rule must be edited in Sysdig to add the field.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

In order to capture alerts from Sysdig you **must** configure Sysdig to output Alerts as JSON via [HTTP](#http-input).

### HTTP Input

The HTTP input allows the Elastic Agent to receive Sysdig Alerts via HTTP webhook.

**Required:** To configure Sysdig to output JSON, you must set up as webhook notification channel as outlined in the [Sysdig Documentation](https://docs.sysdig.com/en/docs/administration/administration-settings/outbound-integrations/notifications-management/set-up-notification-channels/configure-a-webhook-channel/).

### To collect data from the Sysdig Next Gen API:

- Retrieve the API Token by following [Sysdig's API Token Guide](https://docs.sysdig.com/en/retrieve-the-sysdig-api-token).

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Sysdig`.
3. Select the "Sysdig" integration from the search results.
4. Select "Add Sysdig" to add the integration.
5. Add all the required integration configuration parameters, including the URL, API Token, Interval, and Initial Interval, to enable data collection.
6. Select "Save and continue" to save the integration.

**Note**:
  - The URL may vary depending on your region. Please refer to the [Documentation](https://docs.sysdig.com/en/developer-tools/sysdig-api/#access-the-sysdig-api-using-the-regional-endpoints) to find the correct URL for your region.
  - If you see an error saying `exceeded maximum number of CEL executions` during data ingestion, it usually means a large volume of data is being processed for the selected time interval. To fix this, try increasing the Max Executions setting in the configuration.

## Logs Reference

### Alerts

Sysdig alerts can contain a multitude of various fields pertaining to the type of activity on the host machine.

{{ fields "alerts" }}

#### Example

{{ event "alerts" }}

### Event

This is the `event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}
