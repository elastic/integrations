# Teleport Audit Events Integration

## Overview

[Teleport](https://goteleport.com/docs/) provides connectivity, authentication, access controls, and audit for infrastructure.

This integration ingests audit events from Teleport. You can use it to perform historical analysis, 
detect unusual behavior, and form a better understanding of how users interact with your Teleport cluster.

Use this integration to collect and parse audit event logs from various events supported by Teleport. 
Then visualize that data in Kibana using the included dashboard, create alerts to notify you if 
something goes wrong, and reference logs when troubleshooting an issue.

For example, you can filter for failed authorization events and examine the graph of the number of these attempts 
by time, as well as such data points as the geographical location of clients and related user names.

## Data streams

The [data stream `audit`](#audit) provides events from Teleport audit logs.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack
on your own hardware.

## Setup

Check out [Teleport's guide on configuring Teleport's Event Handler plugin](https://goteleport.com/docs/management/export-audit-events/)
to make it send audit logs to the Elasticsearch instance.

See the {{ url "getting-started-observability" "Getting started" }} for instructions on setting up the Elastic Stack.



## Reference

Provide detailed information about the log or metric types we support within the integration. Check the [reference guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-reference) for more information.

## Logs

**Logs** help you keep a record of events happening in Teleport.

### Audit

Collects JSON documents from Teleport audit logs.

Event fields are mapped into the Elastic Common Schema, its extensions, or into custom fields. The latter are grouped
into logical categories, such as `teleport.audit.session.*`. Each event is categorized into the four Elastic Common Schema
categorizations fields: `event.kind`, `event.category`, `event.type`, and `event.outcome`.

{{ event "audit" }}

{{ fields "audit" }}
