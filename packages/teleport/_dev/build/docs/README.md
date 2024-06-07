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

{{ event "audit" }}

{{ fields "audit" }}
