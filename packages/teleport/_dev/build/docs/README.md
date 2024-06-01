# Teleport Audit Events Integration


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration,
see the {{ url "getting-started-observability" "Getting started" }} guide.

## Data streams

The Teleport Audit data stream `audit` provides events from Teleport audit logs.
Event fields are grouped into logical categories.

{ { event "audit"}}

{{fields "audit"}}

## Sources

- [Teleport icon](https://goteleport.com/static/favicon.svg)
- [Events description](https://github.com/gravitational/teleport/blob/master/api/proto/teleport/legacy/types/events/events.proto)
- [List of example events](https://github.com/gravitational/teleport/blob/master/web/packages/teleport/src/Audit/fixtures/index.ts)
