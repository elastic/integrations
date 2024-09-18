# Sysdig Integration
This integration allows for the shipping of [Sysdig](https://sysdig.com/) alerts to Elastic for observability and organizational awareness. Alerts can then be analyzed by using either the dashboard included with the integration or via the creation of custom dashboards within Kibana.

## Data Streams
The Sysdig integration collects one type of data stream: alerts.

**Alerts** The Alerts data stream collected by the Sysdig integration is comprised of Sysdig Alerts. See more details about Sysdig Alerts in [Sysdig's Alerts Documentation](https://docs.sysdig.com/en/docs/sysdig-monitor/alerts/). A complete list of potential fields used by this integration can be found in the [Logs reference](#logs-reference)

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Sysdig must be configured to output alerts to a supported output channel as defined in [Setup](#setup). The system will only receive common fields output by Sysdig's rules, meaning that if a rule does not include a desired field the rule must be edited in Sysdig to add the field.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

In order to capture alerts from Sysdig you **must** configure Sysdig to output Alerts as JSON via [HTTP](#http-input).

### HTTP Input

The HTTP input allows the Elastic Agent to receive Sysdig Alerts via HTTP webhook.

**Required:** To configure Sysdig to output JSON, you must set up as webhook notification channel as outlined in the [Sysdig Documentation](https://docs.sysdig.com/en/docs/administration/administration-settings/outbound-integrations/notifications-management/set-up-notification-channels/configure-a-webhook-channel/).

## Logs Reference

### alerts

Sysdig alerts can contain a multitude of various fields pertaining to the type of activity on the host machine.

{{ fields "alerts" }}

**Example event**

{{ event "alerts" }}