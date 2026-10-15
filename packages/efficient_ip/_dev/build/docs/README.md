{{- generatedHeader }}
# EfficientIP Integration for Elastic

## Overview

The EfficientIP integration for Elastic collects and parses logs from [EfficientIP](https://efficientip.com/) DDI (DNS, DHCP, and IPAM) solutions, enabling centralized monitoring and analysis of network infrastructure events within the Elastic Stack. By ingesting DNS and DHCP events, you gain visibility into name resolution activity and IP address allocation across your network.

### Compatibility

This integration is tested with EfficientIP version 8.4.7e.

This integration requires:
- Elastic Stack version `9.1.0` or later.
- An active Elastic Agent enrolled in a Fleet policy.

### How it works

EfficientIP DDI appliances forward their DNS and DHCP events over syslog. You configure the appliance to send events to the host running Elastic Agent, which listens for incoming messages over `UDP`. The agent processes the messages into the Elastic Common Schema (ECS) and maps them to the `log` data stream, where DNS queries, DNS answers, and DHCP transactions are parsed through the integration's ingest pipelines.

## What data does this integration collect?

This integration collects log messages from EfficientIP DDI solutions using the syslog protocol. These events are processed and mapped to the Elastic Common Schema (ECS) within the `log` data stream.

This integration collects the following types of data:
- **DNS events**: Query logs, DNS answers, response codes, and zone transfer activity.
- **DHCP events**: Lease assignments, renewals, releases, declines, and IP address allocations.

### Supported use cases

Integrating EfficientIP logs with the Elastic Stack provides visibility into your network services and operational status. You can use this integration for the following use cases:
- **DNS query monitoring and threat detection**: Analyze DNS query and answer activity to identify suspicious domains, resolution failures, and anomalous traffic patterns.
- **DHCP lease management and IP address tracking**: Track lease activity and IP allocations to audit address usage and troubleshoot connectivity issues.

## What do I need to use this integration?

To use this integration, you'll need the following vendor prerequisites:
- Administrative access to the EfficientIP administration interface to configure syslog event forwarding.
- Network connectivity between the EfficientIP appliance and the Elastic Agent host. Ensure any intermediate firewalls allow traffic on the selected syslog port (it's `9028` by default).
- The IP address or hostname of the machine running the Elastic Agent to configure the remote syslog target.

You'll also need the following Elastic prerequisites:
- Elastic Stack (Elasticsearch and Kibana) version `9.1.0` or later.
- An active Elastic Agent installed and enrolled in Fleet.
- The EfficientIP integration added to an Elastic Agent policy.
- Port `9028` (or your custom-configured port) open on the Elastic Agent host to accept incoming UDP syslog traffic.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that'll receive the syslog data from your EfficientIP appliance. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog receiver and ship the data to Elastic, where the events will then be processed using the integration's ingest pipelines.

### Set up steps in EfficientIP

Configure your EfficientIP appliance to forward events to the Elastic Agent host:

1. Access the EfficientIP administration interface.
2. Navigate to **System Settings** > **Logging** or **Event Forwarding**.
3. Select **Syslog** as the destination type.
4. Enter the syslog receiver host IP address and the port configured in the integration (default is `9028`).
5. Verify the connection and enable syslog forwarding.

Refer to the EfficientIP documentation for your version for detailed configuration steps specific to your deployment.

### Set up steps in Kibana

To add the integration to your Elastic Agent policy, follow these steps:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **EfficientIP** and select the integration.
3. Click **Add EfficientIP**.
4. Configure the UDP input using the settings below.

#### UDP input configuration

This input collects logs over a UDP socket. Configure the following settings:
- **Listen Address**: The interface address to bind the UDP listener. Set to `0.0.0.0` to listen on all interfaces. Default: `localhost`.
- **Listen Port**: The UDP port number to receive syslog traffic. Default: `9028`.
- **Preserve original event**: If enabled, this preserves a raw copy of the original event in the `event.original` field. Default: `false`.
- **Tags**: Custom tags for the event. Default: `forwarded`, `efficientip-log`.
- **Timezone Offset**: IANA time zone (for example, `Europe/Amsterdam`), abbreviation (for example, `EST`), or offset (for example, `-05:00`) used to interpret timestamps that don't include a timezone. Default: `local`.
- **Processors**: Optional Agent-side processors to filter or enhance data before ingestion. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

After configuring the input, assign the integration to an agent policy and click **Save and continue**.

### Validation

After the configuration is complete, follow these steps to verify data is flowing correctly from EfficientIP to the Elastic Stack:

1. Generate DNS and DHCP activity on the network served by the EfficientIP appliance (for example, resolve a hostname or renew a DHCP lease).
2. Check the data in Kibana:
   - Navigate to **Analytics > Discover**.
   - Select the `logs-*` data view.
   - In the search bar, enter the filter: `data_stream.dataset: "efficient_ip.log"`.
   - Verify that logs appear. Expand a log entry and confirm fields such as `event.dataset` (should be `efficient_ip.log`), `network.protocol` (`dns` or `dhcp`), and `message`.
   - Navigate to **Analytics > Dashboards** and search for "EfficientIP" to view pre-built visualizations.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

If you encounter issues while setting up or using the EfficientIP integration, consider the following:
- **Port mismatch**: Ensure the port configured on the EfficientIP appliance matches the **Listen Port** configured in the integration (default `9028`).
- **Binding failures**: If the Elastic Agent can't bind to the configured host (like `localhost`), the listener might fail to start. Set the **Listen Address** to `0.0.0.0` to listen on all available network interfaces.
- **Network firewalls**: If your Elastic Agent host has a local firewall like `ufw` or `firewalld`, explicitly allow incoming UDP traffic on the configured port.
- **Parsing failures**: If you see events tagged with `preserve_original_event` and an `error.message`, verify the appliance sends logs in the expected EfficientIP DNS/DHCP syslog format.
- **Timestamp mismatches**: If timestamps look incorrect, set the **Timezone Offset** to match the timezone of the EfficientIP appliance.

## Performance and scaling

To ensure optimal performance in high-volume environments, consider the following:
- Forward only the DNS and DHCP event categories you need to reduce ingestion load and storage requirements.
- Deploy multiple Elastic Agents behind a network load balancer to distribute UDP syslog traffic in high-throughput environments, and place agents close to the data source to minimize latency.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Logs reference

The `log` data stream collects EfficientIP DNS and DHCP syslog events.

{{event "log"}}

{{fields "log"}}

### Inputs used

{{ inputDocs }}

### Future updates

Working on future updates:
- IPAM auditing and infrastructure compliance
- Network anomaly identification and security investigations