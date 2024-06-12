# Teleport Audit Events Integration

Teleport provides connectivity, authentication, access controls and audit for infrastructure.

This integration processes audit events from Teleport. You can use it to perform historical analysis, 
detect unusual behavior, and form a better understanding of how users interact with your Teleport cluster.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack 
on your own hardware.

## Setup

To set up this integration, you need to configure Teleport to send audit logs 
to the Elasticsearch instance. Follow [this guide to configure Teleport's Event Handler plugin](https://goteleport.com/docs/management/export-audit-events/)

For step-by-step instructions on how to set up an integration,
see the {{ url "getting-started-observability" "Getting started" }} guide.

## Data streams

The Teleport Audit data stream `audit` provides events from Teleport audit logs.

Event fields are mapped into the Elastic Common Schema or into custom fields, which are grouped into logical categories, such as `teleport.audit.session.`.

{{ event "audit" }}

{{ fields "audit" }}
