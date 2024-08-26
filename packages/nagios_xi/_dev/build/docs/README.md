# Nagios XI

## Overview

The Nagios XI integration is used to fetch observability data from [Nagios XI](https://www.nagios.org/documentation/) and ingest it into Elasticsearch.

Use the Nagios XI integration to:

- Collect metrics on current load, users, ping, HTTP, SSH, root partition, swap users, total processes, round-trip time, and packet loss, along with system event logs.
- Create visualizations to monitor, measure, and analyze usage trends and key data for business insights.
- Set up alerts to minimize Mean Time to Detect (MTTD) and Mean Time to Resolve (MTTR) by quickly referencing relevant logs during troubleshooting.

## Data streams

The Nagios XI integration collects logs and metrics data.

Logs provide insights into operations and events within the Nagios XI environment. The log data stream collected by the Nagios XI integration is `events`. This allows you to track system events, understand their causes, and address issues related to infrastructure monitoring and alert management.

Metrics provide insights into the performance and health of your Nagios XI instance. The Nagios XI integration collects `host` and `service` metric data streams. These metrics enable you to monitor and troubleshoot the performance of hosts and services within your Nagios XI environment, covering aspects such as `network round trip time`, `packet loss`, `service load`, `user count`, and other critical indicators.

Data streams:
- `events`: Provides Nagios XI system event logs.
- `host`: Provides Nagios XI Host Round Trip Travel Time (rta) and Packet Loss (pl) metrics.
- `service `: Provides Nagios XI service metrics by default, including current load, current users, ping, HTTP, SSH, root partition, swap users, and total processes.

Note:
You can monitor and view logs from the ingested documents for Nagios XI in the `logs-*` index pattern in `Discover`. For metrics, the index pattern is `metrics-*`.

## Compatibility

This integration has been tested against `Nagios-XI Version: 5.8.7`

## Prerequisites:
- Elasticsearch: For storing and searching data.
- Kibana: For visualizing and managing data.

You have two options for deploying Elasticsearch and Kibana:
1. Elastic Cloud (Recommended): Fully managed and hosted by Elastic.
2. Self-Managed: Deploy and manage the Elastic Stack on your own hardware.

In order to ingest data from Nagios XI, you must know the host for Nagios XI and add that host when configuring the integration package.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Validation

1. After configuring the integration, go to the **Assets** tab in the Nagios XI Integration.
2. You should see a list of available dashboards.
3. Click on the dashboard corresponding to your configured data stream.
4. Verify that the dashboard is populated with the expected data.

## Logs reference

### Event Logs 

This is the `events` data stream.

- This data stream gives Nagios XI system event logs.

{{event "events"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "events"}}

## Metrics reference

### Host Metrics

This is the `host` data stream.

- This data stream gives Nagios XI Host Round Trip Travel Time (rta) and Packet Loss (pl) metrics.

{{event "host"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "host"}}

### Service Metrics

This is the `service` dataset.

- This dataset gives Nagios XI services current load, current users, ping, http, ssh, root partition, swap users and total processes metrics by default.
- If the user enters a display name of a custom check command, then the integration would also fetch and index that but not parse/perform additional extractions. Additionally, the user can provide a custom processor through the configuration page if they are interested in parsing it
- If the user enters the host name and no display name, then similar to 1, the integration will fetch all the services from that host and index, but only parse the default one i.e the 8 services. The user can provide a custom processor in this case
- If the user enters both the host name and the display name, then the integration would only fetch those services with the entered display name and only from the entered hosts. It is not possible to fetch 1 service from host1 and another service from host2 in this case as it will fetch all the services from all the hosts that are configured

{{event "service"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "service"}}
