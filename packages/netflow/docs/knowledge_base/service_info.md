# Service Info

## Common use cases

The NetFlow integration acts as a network flow collector, enabling the Elastic Stack to ingest, process, and visualize flow records exported from network infrastructure. By transforming raw flow packets into searchable documents, organizations gain deep visibility into network traffic patterns without the overhead of full packet capture.

- **Network Traffic Analysis:** Identify top talkers, most used protocols, and bandwidth consumption patterns across the enterprise network. This helps administrators optimize performance, plan capacity upgrades, and identify misconfigured devices.
- **Security Monitoring and Forensics:** Detect anomalous traffic patterns, such as potential data exfiltration or lateral movement, by analyzing source/destination IP pairs, flow volumes, and unusual port usage.
- **Troubleshooting Connectivity:** Investigate network outages or latency issues by reviewing flow records to confirm if traffic is reaching specific segments or being dropped by intermediate devices like firewalls or routers.
- **Compliance and Auditing:** Maintain long-term records of network sessions to meet regulatory requirements (such as PCI-DSS or HIPAA) for data logging and audit trails regarding internal and external communications.

## Data types collected

This integration collects flow-based network traffic data. It supports the following data stream:

- **log (NetFlow logs):** Collect NetFlow logs using the netflow input. This stream receives exported flow packets over UDP and parses them into the Elastic Common Schema (ECS), providing a standardized format for analysis across different vendors.

The integration handles several specific flow record types:
- **Network Flow Records:** Detailed session information including source and destination IP addresses, port numbers, protocol identifiers, and byte/packet counts.
- **NetFlow Versions:** Support for legacy and modern versions including NetFlow v1, v5, v6, v7, v8, and v9.
- **IPFIX (IP Flow Information Export):** Support for the IETF standard IPFIX records (ANSI/TIA-1057), providing a flexible template-based approach to flow logging.
- **Legacy Mapping:** For versions older than NetFlow v9, the integration automatically maps fields to the NetFlow v9 schema for consistent analysis across different hardware generations.

## Compatibility

The NetFlow integration is compatible with any network hardware or software that supports standard flow export protocols.

- **Vendor Compatibility:**
  - **Cisco Systems** devices supporting NetFlow v1, v5, v7, or v9.
  - **IETF IPFIX** compliant devices from various vendors including **Juniper**, **Palo Alto Networks**, and **Fortinet**.
  - Software-based flow exporters like **fprobe** or **nProbe** that generate standard NetFlow or IPFIX records.
- **Elastic Requirements:**
  - **Kibana and Elasticsearch:** Version 8.14.0 or later is recommended to support all ECS mappings and dashboard visualizations.
  - **Elastic Agent:** Requires Elastic Agent to be installed and enrolled in a Fleet policy.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:
- **Transport/Collection Considerations:** This integration utilizes the UDP protocol for data collection. While UDP offers high performance and low overhead, it is connectionless. In environments with significant network congestion, packets may be dropped. To mitigate this, ensure the **Read Buffer Size** (`read_buffer`) and **Maximum number of packets that can be queued for processing** (`queue_size`) are adequately tuned to handle bursts of incoming flow records.
- **Data Volume Management:** Flow records can generate extremely high volumes of data. It is highly recommended to implement flow sampling at the exporter (network device) level for high-throughput interfaces. Additionally, use the **Internal Networks** configuration to classify traffic and consider using **Processors** to filter unnecessary fields at the agent level before ingestion.
- **Elastic Agent Scaling:** For high-throughput environments, the integration allows for multiple **Number of Workers** (`workers`) to decode NetFlow packets concurrently. It is advised to increase this value and switch the corresponding output to the `throughput` preset. In large-scale deployments, deploy multiple Elastic Agents behind a network load balancer to distribute the processing load effectively.

# Set Up Instructions

## Vendor prerequisites
- **Administrative Access:** Ability to access the command-line interface (CLI) or web-based management console of the network device (e.g., router, firewall).
- **Network Connectivity:** The network device must have a clear network path to the Elastic Agent host via the configured UDP port (default 2055).
- **Firewall Permissions:** Intermediate firewalls or Access Control Lists (ACLs) must allow UDP traffic from the exporter's IP to the Elastic Agent's IP.
- **NetFlow License:** Ensure the device has the necessary software features enabled to support NetFlow or IPFIX export.
- **Configuration Knowledge:** Knowledge of the local interface names and IP addresses used for source-interface binding.

## Elastic prerequisites
1. **Elastic Agent:** Must be installed and enrolled in a Fleet policy.
2. **Elastic Stack Version:** Ensure you are running a compatible version of the Elastic Stack (8.x recommended).
3. **Network Configuration:** The Elastic Agent host must be reachable by the network device over the network.
4. **Integration Policy:** The NetFlow integration must be added to the Elastic Agent's policy with the correct UDP host and port settings.

## Vendor set up steps

Configure your network devices to export NetFlow or IPFIX records to the IP address and port where the Elastic Agent is running. Follow the steps for your specific network device vendor to configure the export.

## Kibana set up steps

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **NetFlow** and click **Add NetFlow Records**.
3. Configure the integration settings under the **Collecting NetFlow logs using the netflow input** section:

### Collecting NetFlow logs using the netflow input
- **UDP host to listen on** (`host`): The IP address the agent should bind to. Use `0.0.0.0` to listen on all interfaces. Default: `localhost`.
- **UDP port to listen on** (`port`): The UDP port used to receive NetFlow packets from your network devices. Default: `2055`.
- **Internal Networks** (`internal_networks`): List of CIDR ranges describing the IP addresses that are considered internal. This is used in determining `source.locality`, `destination.locality`, and `flow.locality`. Default: `[private]`.
- **Time duration before an idle session or unused template is expired. Valid time units are h, m, s.** (`expiration_timeout`): Period after which inactive templates or sessions are removed from memory. Default: `30m`.
- **Number of Workers** (`workers`): The number of workers to read and decode concurrently netflow packets. Increase this for higher performance. Default: `1`.
- **Maximum number of packets that can be queued for processing** (`queue_size`): The buffer size for incoming packets before they are processed. Default: `8192`.
- **Read Buffer Size** (`read_buffer`): Sets the size of the OS read buffer on the UDP socket in format KiB/MiB (e.g., `10MiB`). If not set, the OS default is used.
- **Custom definitions** (`custom_definitions`): Optional user-defined field mappings for proprietary NetFlow implementations.
- **Whether to detect sequence reset** (`detect_sequence_reset`): Boolean to identify if flow sequence numbers have reset (e.g., after a device reboot). Default: `True`.
- **Maximum size of the message received over UDP** (`max_message_size`): The maximum size allowed for a single packet. Default: `10KiB`.
- **Tags** (`tags`): Custom tags to apply to the events for easier filtering. Default: `['netflow', 'forwarded']`.
- **Read timeout for socket operations. Valid time units are ns, us, ms, s, m, h.** (`timeout`): The specific time limit for socket read actions.
- **Processors** (`processors`): Add custom Elastic Agent processors to filter or enhance data (e.g., adding metadata) before it is sent to Elasticsearch.

4. Click **Save and continue** to save the integration and deploy it to your Elastic Agent policy.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on NetFlow Records (NetFlow and IPFIX):
- **Generate Network Traffic:** Initiate traffic through the monitored network device by pinging external IP addresses or browsing websites from a host behind the router.
- **Force Cache Export:** On Cisco devices, use the command `clear ip flow stats` to force an immediate export of current flow records to the collector.
- **Authentication Event:** Log into the management console of your network device to generate administrative traffic flows.

### 2. Check Data in Kibana:
1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "netflow.log"`
4. Verify logs appear. Expand a log entry and confirm these fields:
   - `event.dataset` (should be `netflow.log`)
   - `flow.id` and `flow.locality`
   - `network.transport` (e.g., `tcp`, `udp`, or `icmp`)
   - `network.bytes` and `network.packets`
   - `message` (the raw log payload or flow summary)
5. Navigate to **Analytics > Dashboards** and search for "Netflow" to view the pre-built traffic overview dashboards.

# Troubleshooting

## Common Configuration Issues

- **UDP Port Blocked**: Ensure that the host firewall (e.g., iptables, ufw, or Windows Firewall) on the Elastic Agent machine is configured to allow inbound UDP traffic on the specified port (default 2055).
- **Incorrect Listening Interface**: If the **UDP host to listen on** is set to `localhost`, the agent will not receive packets from external network devices. Change this to `0.0.0.0` or the specific LAN IP of the agent host.
- **Template Mismatch (NetFlow v9/IPFIX)**: NetFlow v9 and IPFIX use templates. If the agent starts after the device has already sent templates, it may take several minutes (depending on the device's template refresh rate) before the agent can decode the incoming data.
- **Clock Skew**: Ensure the clocks on the network devices and the Elastic Agent host are synchronized via NTP, as significant timing differences can cause issues with flow duration calculations.

## Ingestion Errors

- **Parsing Failures**: Check the `error.message` field in Kibana. This often occurs if the incoming data format does not match the expected NetFlow/IPFIX version or if custom vendor fields are used without being defined.
- **UDP Packet Drops**: If the **read_buffer** or **queue_size** is too small, the operating system may drop UDP packets during traffic spikes. Monitor the agent host's network statistics for dropped packets.
- **Sequence Resets**: If **detect_sequence_reset** is enabled, logs may indicate resets if the network device reboots or the flow engine restarts, which is normal behavior but helpful for diagnosing gaps in data.

## Vendor Resources
- [Cisco Systems NetFlow Services Export Version 9 (RFC 3954)](https://www.ietf.org/rfc/rfc3954.txt)
- [IPFIX Protocol Specification (RFC 7011)](https://www.ietf.org/rfc/rfc7011.txt)

# Documentation sites

- [Cisco Systems NetFlow Services Export Version 9 (RFC 3954)](https://www.ietf.org/rfc/rfc3954.txt)
- [Specification of the IPFIX Protocol (RFC 7011)](https://www.ietf.org/rfc/rfc7011.txt)
