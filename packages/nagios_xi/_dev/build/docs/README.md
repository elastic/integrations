# Nagios XI

## Overview

The Nagios XI integration is used to fetch observability data from [Nagios XI](https://www.nagios.org/documentation/) and ingest it into Elasticsearch.

Use the Nagios XI integration to:

- Collect metrics related to the current load, current users, ping, http, ssh, root partition, swap users, total processes, round-trip time, and packet loss. Additionally, gather logs related to system events.
- Create visualizations to monitor, measure and analyze the usage trend and key data, and derive business insights.
- Set up alerts to minimize Mean Time to Detect (MTTD) and Mean Time to Resolve (MTTR) by quickly referencing relevant logs during troubleshooting.

## Data streams

The Nagios XI integration collects logs and metrics data.

Logs provide insights into operations and events within the Nagios XI environment. The `Log` data stream collected by the Nagios XI integration is events. This allows users to track `system events`, understand their causes, and address issues related to infrastructure monitoring and alert management.

Metrics offer insights into the performance and health of user's Nagios XI instance. The `Metric` data stream collected by the Nagios XI integration are host and service. These enable users to monitor and troubleshoot the performance of hosts and services within their Nagios XI environment, covering aspects such as `network round trip time`, `packet loss`, `service load`, `user count`, and various other critical indicators.

Data streams:
- `events`: This data stream gives Nagios XI system event logs.
- `host`: This data stream gives Nagios XI Host Round Trip Travel Time (rta) and Packet Loss (pl) metrics.
- `service `: This dataset gives Nagios XI services current load, current users, ping, http, ssh, root partition, swap users and total processes metrics by default.

Note:
- Users can monitor and see the log inside the ingested documents for Nagios XI in the `logs-*` index pattern from `Discover`, and for metrics, the index pattern is `metrics-*`.

## Compatibility

This integration has been tested against `Nagios-XI Version: 5.8.7`

## Prerequisites

User need Elasticsearch for storing and searching user's data and Kibana for visualizing and managing it. User can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on user's own hardware.

In order to ingest data from Nagios XI:
- User must know the host for Nagios XI, add that host while configuring the integration package.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Nagios XI Integration should display a list of available dashboards. Click on the dashboard available for user's configured data stream. It should be populated with the required data.

## Logs reference

### Event Logs 

This is the `events` data stream.

- This data stream gives Nagios XI system event logs.

{{event "events"}}

{{fields "events"}}

## Metrics reference

### Host Metrics

This is the `host` data stream.

- This data stream gives Nagios XI Host Round Trip Travel Time (rta) and Packet Loss (pl) metrics.

{{event "host"}}

{{fields "host"}}

### Service Metrics

This is the `service` dataset.

- This dataset gives Nagios XI services current load, current users, ping, http, ssh, root partition, swap users and total processes metrics by default.
- If the user enters a display name of a custom check command, then the integration would also fetch and index that but not parse/perform additional extractions. Additionally, the user can provide a custom processor through the configuration page if they are interested in parsing it
- If the user enters the host name and no display name, then similar to 1, the integration will fetch all the services from that host and index, but only parse the default one i.e the 8 services. The user can provide a custom processor in this case
- If the user enters both the host name and the display name, then the integration would only fetch those services with the entered display name and only from the entered hosts. It is not possible to fetch 1 service from host1 and another service from host2 in this case as it will fetch all the services from all the hosts that are configured

{{event "service"}}

{{fields "service"}}
