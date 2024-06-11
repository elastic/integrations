# Traefik Integration

## Overview

[Traefik](https://traefik.io/) is a modern reverse proxy and load balancer that helps to manage and route incoming web traffic to the user's applications. It is designed to dynamically adjust to the changes in user's infrastructure, making it easy to deploy and scale user's services. Traefik integrates well with containerized environments and provides features like automatic SSL certificate management and support for multiple backends.

Use the Traefik integration to:

- Collect logs related to access.
- Create informative visualizations to track usage trends, measure key logs, and derive actionable business insights.
- Set up alerts to minimize Mean Time to Detect (MTTD) and Mean Time to Resolve (MTTR) by quickly referencing relevant logs during troubleshooting.

## Data streams

The Traefik integration collects logs data.

Logs help User keep a record of events that happen on user's machine. Users can monitor and troubleshoot the performance of their Traefik instance by accessing the `Log` data stream, which includes client IP, host, username, request address, duration, and content.

Data streams:
- `access`: Collects information related to the client IP, host, username, request address, duration, and content.

Note:
- Users can monitor and see the log inside the ingested documents for Traefik in the `logs-*` index pattern from `Discover`.

## Compatibility

The Traefik datasets were tested with Traefik 1.6, 1.7 and 2.9 versions.

## Prerequisites

User need Elasticsearch for storing and searching user's data and Kibana for visualizing and managing it. User can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on user's own hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Validation

After the integration is successfully configured, clicking on the Assets tab of the Traefik Integration should display a list of available dashboards. Click on the dashboard available for user's configured data stream. It should be populated with the required data.

## Metrics
Note:
- The `/health` API endpoint which is used to collect the metrics is removed from Traefik `v2` version. Please refer this [issue](https://github.com/traefik/traefik/issues/7629) for more information.
- We are currently working on the metrics collection using the suggested [alternative](https://doc.traefik.io/traefik/v2.3/observability/metrics/prometheus/). Keep a watch on this [issue](https://github.com/elastic/integrations/issues/9820) for more updates.

## Logs

### Access Logs

The `access` data stream collects Traefik access logs. This data stream collects logs related to client IP, host, username, request address, duration, and content.

An example event for `access` looks as following:

{{event "access"}}

{{fields "access"}}
