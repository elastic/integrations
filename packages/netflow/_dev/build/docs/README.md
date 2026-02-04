# NetFlow Records Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The NetFlow Records integration for Elastic enables you to collect and analyze flow records from your network infrastructure. By transforming raw flow packets into searchable documents, you gain deep visibility into network traffic patterns without the resource overhead of full packet capture.

This integration facilitates:
- Network traffic analysis: Identify top talkers, most used protocols, and bandwidth consumption patterns across the enterprise network to help you optimize performance and plan capacity.
- Security monitoring and forensics: Detect anomalous traffic patterns, such as potential data exfiltration or lateral movement, by analyzing source and destination IP pairs, flow volumes, and unusual port usage.
- Troubleshooting connectivity: Investigate network outages or latency issues by reviewing flow records to confirm if traffic is reaching specific segments or being dropped by intermediate devices like firewalls or routers.
- Compliance and auditing: Maintain long-term records of network sessions to meet regulatory requirements, such as PCI-DSS or HIPAA, for data logging and audit trails regarding internal and external communications.

### Compatibility

This integration is compatible with any network hardware or software that supports standard flow export protocols, including:
- Cisco Systems devices supporting NetFlow v1, v5, v7, or v9.
- IETF IPFIX (ANSI/TIA-1057) compliant devices from various vendors including Juniper, Palo Alto Networks, and Fortinet.
- Software-based flow exporters like `fprobe` or `nProbe` that generate standard NetFlow or IPFIX records.

To use this integration, you'll need:
- Elastic Stack version 8.14.0 or later to support all ECS mappings and dashboard visualizations.
- Elastic Agent installed and enrolled in a Fleet policy.

### How it works

This integration acts as a network flow collector. You configure your network devices to export flow packets to the host running the Elastic Agent. The agent's `netflow` input receives these exported packets over UDP. The integration then parses the records, handles template management for protocols like NetFlow v9 and IPFIX, and maps the fields into the Elastic Common Schema (ECS). For legacy versions older than NetFlow v9, the integration automatically maps fields to the NetFlow v9 schema to ensure consistent analysis across different hardware generations. Once processed, the records are sent to your Elastic deployment for visualization and monitoring.

## What data does this integration collect?

The NetFlow Records integration collects flow-based network traffic data by receiving exported flow packets over UDP and parsing them into the Elastic Common Schema (ECS). It's a standardized format that helps you analyze network data consistently across different vendors.

The NetFlow Records integration collects log messages of the following types:
*   Network flow records: Detailed session information including source and destination IP addresses, port numbers, protocol identifiers, and byte and packet counts.
*   NetFlow versions: Records from legacy and modern versions, including NetFlow v1, v5, v6, v7, v8, and v9.
*   IPFIX (IP Flow Information Export) records: Template-based flow records that follow the IETF standard (ANSI/TIA-1057).

For flow records from NetFlow versions older than `v9`, the integration automatically maps fields to the NetFlow `v9` schema to ensure consistent analysis across different hardware generations. All collected data is stored in the `log` data stream.

### Supported use cases

Integrating NetFlow records with Elastic provides visibility into your network traffic and helps you monitor performance and security. You can use this integration for the following use cases:
*   Network traffic analysis: You can use Kibana dashboards to visualize and analyze network traffic patterns, which helps you identify anomalies and optimize network performance.
*   Security threat detection: You can monitor flow records to detect suspicious connection patterns, potential lateral movement, or data exfiltration.
*   Capacity planning: You can track bandwidth usage across your infrastructure to help you plan network upgrades and resource allocation.
*   Compliance and auditing: You can maintain a searchable, long-term archive of network communications to meet regulatory requirements and support forensic investigations.

## What do I need to use this integration?

To use the NetFlow Records integration, you'll need the following:

### Vendor prerequisites
You must ensure your network devices meet these requirements:
- Administrative access to the command-line interface (CLI) or web-based management console of the network device, such as a router or firewall.
- Network connectivity from the network device to the Elastic Agent host via the configured UDP port, which is `2055` by default (replace with your actual port if it's different).
- Firewall permissions or Access Control Lists (ACLs) that allow UDP traffic from the exporter's IP to the Elastic Agent's IP.
- The necessary software features or license enabled on the device to support NetFlow or IPFIX export.
- Knowledge of the local interface names and IP addresses used for source-interface binding.

### Elastic prerequisites
You also need to set up your Elastic environment:
- Elastic Agent installed and enrolled in a Fleet policy.
- A compatible version of the Elastic Stack, it's recommended to use version `8.14.0` or later.
- Connectivity so the network device can reach the Elastic Agent host over the network.
- The NetFlow Records integration added to the Elastic Agent's policy with the correct UDP host and port settings.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the NetFlow or IPFIX exporter and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in NetFlow Records

To begin collecting data, you must configure your network devices to export NetFlow or IPFIX records to the IP address and port where the Elastic Agent is running. Follow the steps for your specific network device vendor to configure the export.

### Set up steps in Kibana

To set up the integration in Kibana, follow these steps:

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for **NetFlow** and click **Add NetFlow Records**.
3.  Configure the integration settings under the **Collecting NetFlow logs using the netflow input** section.

This integration supports the following configuration options:

| Setting                   | Description                                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **UDP host to listen on** | The IP address the agent should bind to (e.g., `0.0.0.0` to listen on all interfaces). Default: `localhost`. |
| **UDP port to listen on** | The UDP port used to receive NetFlow packets from your network devices. Default: `2055`.                     |
| **Internal Networks**     | A list of CIDR ranges describing the IP addresses that are considered internal. Default: `[private]`.        |

Under **Advanced Options**, you can configure the following optional parameters:

| Setting                                           | Description                                                                                      |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| **Expiration timeout**                            | Time duration before an idle session or unused template is expired (e.g., `30m`).                |
| **Number of Workers**                             | The number of workers to read and decode NetFlow packets concurrently. Default: `1`.             |
| **Queue size**                                    | Maximum number of packets that can be queued for processing. Default: `8192`.                    |
| **Read Buffer Size**                              | The size of the OS read buffer on the UDP socket (e.g., `10MiB`).                                |
| **Custom definitions**                            | Optional user-defined field mappings for proprietary NetFlow implementations.                    |
| **Whether to detect sequence reset**              | Identify if flow sequence numbers have reset (e.g., after a device reboot). Default: `true`.     |
| **Maximum size of the message received over UDP** | The maximum size allowed for a single packet. Default: `10KiB`.                                  |
| **Tags**                                          | Custom tags to apply to the events for easier filtering. Default: `['netflow', 'forwarded']`.    |
| **Read timeout**                                  | The specific time limit for socket read actions (e.g., `30s`).                                   |
| **Processors**                                    | Add custom Elastic Agent processors to filter or enhance data before it's sent to Elasticsearch. |

4. Click **Save and continue** to save the integration and deploy it to your Elastic Agent policy.

### Validation

After configuration is complete, you'll need to verify that data is flowing correctly.

#### 1. Verify Elastic Agent status

You'll first want to ensure the agent is healthy and communicating with Fleet:
1. Navigate to **Management > Fleet > Agents**.
2. Locate the agent where you deployed the NetFlow integration.
3. Verify that the agent status is **Healthy**.

#### 2. Trigger data flow

Generate activity to ensure records are being exported:
- **Generate Network Traffic:** Initiate traffic through the monitored network device by pinging external IP addresses or browsing websites from a host behind the router.
- **Force Cache Export:** On Cisco devices, you can use the `clear ip flow stats` command to force an immediate export of current flow records.
- **Authentication Event:** Log into the management console of your network device to generate administrative traffic flows.

#### 3. Check data in Kibana

Finally, confirm the data is available in Elasticsearch:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the following KQL filter in the search bar: `data_stream.dataset : "netflow.log"`.
4. Verify logs appear and expand a log entry to confirm fields like `flow.id`, `flow.locality`, `network.bytes`, and `network.packets` are populated.
5. Navigate to **Analytics > Dashboards** and search for "Netflow" to view pre-built traffic visualizations.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

You can use the following information to resolve common issues with the NetFlow Records integration:

- **UDP port blocked**: Ensure that the host firewall (such as iptables, ufw, or Windows Firewall) on the Elastic Agent machine is configured to allow inbound UDP traffic on the specified port.
- **Incorrect listening interface**: If you set the UDP host to listen on `localhost`, the agent won't receive packets from external network devices. Change this to `0.0.0.0` or the specific LAN IP of the agent host.
- **Template mismatch (NetFlow v9/IPFIX)**: NetFlow v9 and IPFIX protocols use templates. If the agent starts after the device has already sent templates, it might take several minutes (depending on the device's template refresh rate) before the agent can decode the incoming data.
- **Clock skew**: Ensure the clocks on your network devices and the Elastic Agent host are synchronized via NTP. Significant timing differences can cause issues with flow duration calculations and event timestamps.
- **Parsing failures**: Check the `error.message` field in Kibana. This often occurs if the incoming data format doesn't match the expected NetFlow version or if you use custom vendor fields without defining them in the configuration.
- **UDP packet drops**: If the `read_buffer` or `queue_size` settings are too small, the operating system might drop UDP packets during traffic spikes. Monitor the agent host's network statistics for dropped packets and increase these values in the integration settings if necessary.
- **Sequence resets**: If you've enabled `detect_sequence_reset`, logs might indicate resets if the network device reboots or the flow engine restarts. This is normal behavior but helps you diagnose gaps in collected data.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

When you collect NetFlow Records at scale, you should consider several factors to ensure optimal performance and prevent data loss. The integration uses the UDP protocol, which is connectionless and can result in dropped packets during periods of network congestion.

To handle high-volume environments and bursts of data, you can tune the following settings:
- Increase the `read_buffer` (Read Buffer Size) to allow the operating system to buffer more incoming data.
- Adjust the `queue_size` (Maximum number of packets that can be queued for processing) to handle larger spikes in incoming flow records.

You can manage high data volumes by implementing these strategies:
- Enable flow sampling at the exporter (network device) level, especially for high-throughput interfaces.
- Configure internal networks to classify traffic correctly.
- Use processors to filter out unnecessary fields at the Elastic Agent level before ingestion.

To scale the processing capacity of the Elastic Agent, you can use these methods:
- Increase the `workers` (Number of Workers) to decode NetFlow packets concurrently across multiple CPU cores.
- Switch the output to the `throughput` preset to optimize for high-volume data ingestion.
- Deploy multiple Elastic Agents behind a network load balancer to distribute the processing load across several instances.

## Reference

### Inputs used

{{ inputDocs }}

### Data streams

The NetFlow Records integration includes the following data stream:
- `log`: Collects flow records from NetFlow and IPFIX exporters.

#### log

The `log` data stream provides events from NetFlow and IPFIX exporters of the following types: flow records including source and destination IP addresses, ports, protocols, and byte/packet counts.

##### log fields

{{ fields "log" }}

##### log sample event

{{ event "log" }}

### Vendor documentation links

You can find more information about NetFlow and IPFIX in the following resources:
- [Cisco Systems NetFlow Services Export Version 9 (RFC 3954)](https://www.ietf.org/rfc/rfc3954.txt)
- [Specification of the IPFIX Protocol (RFC 7011)](https://www.ietf.org/rfc/rfc7011.txt)
