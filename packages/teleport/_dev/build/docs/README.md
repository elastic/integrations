# Teleport Audit Events Integration

[Teleport](https://goteleport.com/docs/) provides connectivity, authentication, access controls and audit for infrastructure.

This integration ingests audit events from Teleport. You can use it to perform historical analysis, 
detect unusual behavior, and form a better understanding of how users interact with your Teleport cluster.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack 
on your own hardware.

## Setup

Check out [Teleport's guide on configuring Teleport's Event Handler plugin(https://goteleport.com/docs/management/export-audit-events/)
to make it send audit logs to the Elasticsearch instance.

## Data streams

The data stream `audit` provides events from Teleport audit logs.

Event fields are mapped into the Elastic Common Schema, its extensions, or into custom fields. The latter are grouped 
into logical categories, such as `teleport.audit.session.*`.

{{ event "audit" }}

{{ fields "audit" }}
