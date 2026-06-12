{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# EfficientIP Integration for Elastic

The EfficientIP integration collects and parses data from [EfficientIP](https://efficientip.com/) DDI (DNS, DHCP, and IPAM) solutions, enabling centralized monitoring and analysis of network infrastructure events within Elastic.

## Overview
{{/* Complete this section with a short summary of what data this integration collects and what use cases it enables */}}
The EfficientIP integration for Elastic enables collection of event logs from DNS, DHCP and IPAM. This integration enables the
following use cases:
- DNS query monitoring and threat detection
- DHCP lease management and IP address tracking
- IPAM auditing and infrastructure compliance
- Network anomaly identification and security investigations

### Compatibility
{{/* Complete this section with information on what 3rd party software or hardware versions this integration is compatible with */}}
This integration is tested with EfficientIP version 8.4.7e

## What data does this integration collect?
{{/* Complete this section with information on what types of data the integration collects, and link to reference documentation if available */}}
This integration collects the following data types from EfficientIP DDI solutions:

- **DNS Events**: Query logs, response codes, and DNS transactions
- **DHCP Events**: Lease assignments, renewals, releases, and IP address allocations
- **IPAM Events**: Address space changes, subnet modifications, and infrastructure audits

All events are forwarded via syslog and processed through Elastic ingest pipelines for analysis and visualization within the Elastic Stack.


## What do I need to use this integration?
{{/* List any vendor-specific prerequisites needed before starting to install the integration. */}}
Minimum requierment Elastic stack 9.0.x and EfficientIP version 8.4.7e


## Deployment methods
This integration supports the following deployment methods:

**Syslog-based**: EfficientIP nodes forward events to a syslog destination where Elastic Agent collects and processes the data.

To configure syslog forwarding on an EfficientIP node:

1. Access the EfficientIP administration interface
2. Navigate to **System Settings** > **Logging** or **Event Forwarding**
3. Select **Syslog** as the destination type
4. Enter the syslog receiver host IP address and port
6. Verify the connection and enable syslog forwarding
7. Configure Elastic Agent to listen on the syslog port and ingest the forwarded events

Refer to the EfficientIP documentation for your version for detailed configuration steps specific to your deployment.

### Agent-based deployment
Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}
