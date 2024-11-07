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

The `teleport` integration collects the following logs:

- **audit** provides events from Teleport audit logs.

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

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the  [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).


## Setup

Check out [the guide on configuring Teleport's Event Handler plugin](https://goteleport.com/docs/management/export-audit-events/)
to make it send audit logs to the Elasticsearch instance.

See the {{ url "getting-started-observability" "Getting started guide" }} for instructions on setting up the Elastic Stack.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Teleport`.
3. Select the "Teleport" integration from the search results.
4. Select "Add Teleport" to add the integration.
5. Add all the required integration configuration parameters, including Paths.
6. Select "Save and continue" to save the integration.


## Reference

**Logs** help you keep a record of events happening in Teleport.

### Audit Events Log

The `audit` data stream collects JSON documents from Teleport audit logs.

Event fields are mapped either into the Elastic Common Schema, its extensions, or into custom fields. The latter are grouped
into logical categories, such as `teleport.audit.session.*`. 

Each event is categorized into the four Elastic Common Schema
categorizations fields: `event.kind`, `event.category`, `event.type`, and `event.outcome`.

{{ event "audit" }}

{{ fields "audit" }}
