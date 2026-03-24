# Service Info

## Common use cases
The Iptables integration provides a robust solution for monitoring network traffic filtered by Linux kernel firewalls and Ubiquiti networking equipment. It allows administrators to gain deep visibility into allowed and denied connections across their infrastructure.
- **Security Monitoring and Auditing:** Track all dropped or rejected packets to identify potential scanning activities, brute-force attempts, or unauthorized access patterns within the network. By monitoring fields like `event.action` and `network.transport`, security teams can distinguish between standard reconnaissance and active exploitation.
- **Network Troubleshooting:** Analyze firewall logs to diagnose connectivity issues by verifying if specific traffic is being blocked by iptables rules or Ubiquiti firewall policies. Detailed field extraction allows for filtering by `source.ip` and `destination.port` to pinpoint specific blocked services.
- **Compliance Reporting:** Maintain a centralized audit trail of network traffic modifications and security events required for regulatory frameworks. The integration ensures that raw payloads are captured and timestamped for historical review.
- **Ubiquiti Environment Visibility:** Leverage specialized parsing for EdgeOS-based devices to extract granular details such as rule set names, specific rule numbers, and the final action taken on the traffic.

## Data types collected
This integration collects several data types through specific data streams. Each stream is designed to handle different log ingestion methods:
- **Data Stream: Iptables syslog logs:** Collects iptables logs using the **udp** input. This stream is intended for collecting logs forwarded over the network from remote Linux hosts or Ubiquiti devices.
- **Data Stream: Iptables log logs:** Collects iptables logs using the **logfile** input. This stream is used for reading local filesystem logs (e.g., `/var/log/iptables.log`) directly from the host where the firewall rules are active.
- **Data Stream: Iptables logs from journald:** Collects iptables logs logged by the kernel to the systemd journal. This stream queries the local journal for firewall-related events using the **journald** input.

## Compatibility
The **iptables** integration is compatible with the following:

*   **Iptables / Ip6tables** versions running on standard Linux distributions.
*   **Ubiquiti** firewalls and other Ubiquiti hardware that supports remote syslog forwarding.
*   **Systemd Journald** implementations for local log collection on modern Linux systems.

## Scaling and Performance
To ensure optimal performance in high-volume environments, consider the following:
- **Transport/Collection Considerations:** When using the **udp** input for syslog collection, be aware that UDP does not guarantee delivery. For critical environments where log loss must be avoided, use the **logfile** input with a local log forwarder or the **journald** input. If using UDP, adjust the **Custom UDP Options** such as `read_buffer` and `max_message_size` to handle spikes in traffic.
- **Data Volume Management:** Configure the vendor appliance or iptables rules to forward only necessary events. Use the `--limit` flag in iptables to throttle the rate of log generation for noisy rules, preventing the ingestion pipeline from being overwhelmed by repetitive events.
- **Elastic Agent Scaling:** For high-throughput environments processing significant firewall event volumes, deploy multiple Elastic Agents behind a network load balancer to distribute the UDP syslog traffic evenly.

# Set Up Instructions

## Vendor prerequisites
- **Administrative Access:** Root or sudo permissions are required on the Linux host to modify iptables rules and rsyslog configurations.
- **Network Connectivity:** Port `9001` (UDP) must be open on the Elastic Agent host to receive syslog traffic from remote firewalls or Ubiquiti devices.
- **Logging Configuration:** The `LOG` target must be manually added to iptables chains; logging is not enabled by default in the kernel.
- **Ubiquiti Access:** SSH or Console access to the Ubiquiti EdgeRouter/Firewall is required to configure remote syslog destinations.
- **System Utilities:** The `journalctl` binary must be available on the host if using the Journald input method.

## Elastic prerequisites
- **Elastic Agent:** An active Elastic Agent must be enrolled in Fleet and running on a supported Linux host or container.
- **Docker Image:** If running the Agent in a container and using the Journald input, the `elastic-agent-complete` image variant must be used to provide the necessary `journalctl` dependencies.
- **Connectivity:** The Agent must have outbound connectivity to Elasticsearch and Kibana for data delivery and management.

## Vendor set up steps

### For Standard Linux Iptables (Syslog Forwarding):
1. **Add Logging Rules:** Identify the chain to monitor and append a rule with the `LOG` target. Ensure this rule is positioned before any `DROP` or `REJECT` rules.
   ```bash
   sudo iptables -I INPUT -j LOG --log-prefix "IPTABLES: "
   ```
2. **Configure Rsyslog:** Create a new configuration file in `/etc/rsyslog.d/` (e.g., `10-iptables.conf`).
3. **Define Filter and Destination:** Add the following line to forward logs to the Elastic Agent (replace `<ELASTIC_AGENT_IP>` with the actual IP):
   ```text
   :msg, startswith, "IPTABLES" @<ELASTIC_AGENT_IP>:9001
   ```
4. **Optional Log Suppression:** To prevent these logs from filling local system logs, add a stop directive on the next line (syntax varies by rsyslog version).
5. **Restart Service:** Apply changes by restarting rsyslog:
   ```bash
   sudo systemctl restart rsyslog
   ```

### For Ubiquiti EdgeOS:
1. **Access CLI:** Connect to your Ubiquiti device via SSH.
2. **Enter Config Mode:** Type `configure`.
3. **Set Syslog Host:** Direct logs to the Elastic Agent host on port 9001.
   ```bash
   set system syslog host <ELASTIC_AGENT_IP> port 9001
   ```
4. **Enable Rule Logging:** Enable logging on the specific firewall rules you want to monitor.
   ```bash
   set firewall name <RULESET_NAME> rule <RULE_NUMBER> log enable
   ```
5. **Commit Changes:** Type `commit` then `save` to persist the configuration.

### Vendor Set up Resources
- Refer to iptables and rsyslog documentation for detailed configuration options.
- Consult Ubiquiti EdgeOS documentation for syslog configuration.

## Kibana set up steps

### Collecting application logs from iptables instances (input: udp)
1. In Kibana, navigate to **Management > Integrations** and search for **Iptables**.
2. Click **Add Iptables**.
3. Under the **Collect iptables application logs (input: udp)** section, configure the following:
   - **Syslog Host** (`syslog_host`): The interface to listen to UDP based syslog traffic. Default: `localhost`. Set to `0.0.0.0` to bind to all available interfaces.
   - **Syslog Port** (`syslog_port`): The UDP port to listen for syslog traffic. Default: `9001`. Ports below 1024 require the Elastic Agent to run with elevated privileges.
   - **Preserve original event** (`preserve_original_event`): If enabled, a raw copy of the original event is added to the field `event.original`. Default: `False`.
   - **Tags** (`tags`): List of tags to append to the event. Default: `['iptables-log', 'forwarded']`.
   - **Custom UDP Options** (`udp_options`): Specify custom configuration such as `read_buffer: 100MiB` or `max_message_size: 50KiB`.
   - **Processors** (`processors`): Add custom processors to reduce fields or enhance metadata before the logs are parsed.
4. Save the integration to an Elastic Agent policy.

### Collecting application logs from iptables instances (input: logfile)
1. In Kibana, navigate to the Iptables integration configuration.
2. Under the **Collect iptables application logs (input: logfile)** section, configure the following:
   - **Paths** (`paths`): Provide a list of paths to the iptables log files. Default: `['/var/log/iptables.log']`.
   - **Preserve original event** (`preserve_original_event`): If enabled, preserves a raw copy of the original event in `event.original`. Default: `False`.
   - **Tags** (`tags`): List of tags to append to the log events. Default: `['iptables-log', 'forwarded']`.
   - **Processors** (`processors`): Define optional processors for filtering or data enhancement.
3. Save the integration to an Elastic Agent policy.

### Collecting application logs from iptables instances (input: journald)
1. In Kibana, navigate to the Iptables integration configuration.
2. Under the **Collect iptables application logs (input: journald)** section, configure the following:
   - **Journal paths** (`paths`): List of journal directories or files to read from. Defaults to the system journal if left empty.
   - **Tags** (`tags`): List of tags to append to the journal logs. Default: `['iptables-log']`.
   - **Processors** (`processors`): Define optional processors for metadata enrichment.
3. Save the integration to an Elastic Agent policy.

# Validation Steps

After configuration is complete, verify that data is flowing correctly.

### 1. Trigger Data Flow on Iptables:
- **Generate Test Log Rule:** On the Linux host, add a temporary rule to log ICMP traffic: `sudo iptables -I INPUT -p icmp -j LOG --log-prefix "IPTABLES_TEST: "`
- **Generate Traffic:** From another machine on the network, ping the Linux host to trigger the logging rule.
- **Check Local Logs:** Verify the log exists locally by running `dmesg | grep IPTABLES_TEST` or checking the log file specified in your config.
- **Clean Up:** Once verified, remove the test rule using: `sudo iptables -D INPUT -p icmp -j LOG --log-prefix "IPTABLES_TEST: "`

### 2. Check Data in Kibana:
1. Navigate to **Discover** (or **Analytics > Discover** in some Kibana versions).
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "iptables.log"`
4. Verify logs appear. Expand a log entry and confirm these fields:
   - `event.dataset` (should match `iptables.log`)
   - `source.ip`
   - `event.action`
   - `message`
5. Navigate to **Dashboards** (or **Analytics > Dashboards**) and search for "Iptables" to view pre-built visualizations.

# Troubleshooting

## Common Configuration Issues
- **Port Conflict**: If the Elastic Agent fails to start the UDP input, verify that port `9001` is not already in use by another service.
- **Rsyslog Filter Not Matching**: Ensure the `--log-prefix` in your iptables command exactly matches the filter string in your rsyslog configuration.
- **Ubiquiti Remote Host Reachability**: Confirm the Ubiquiti device can reach the Elastic Agent IP over the network.

## Ingestion Errors
- **Parsing Failures**: If logs appear in Kibana but are not parsed into individual fields, check the `error.message` field.
- **Journald Version Mismatch**: In Docker environments, if the host journal files use a format newer than the `journalctl` binary inside the `elastic-agent-complete` image, the agent will be unable to read the logs. Check the version using:
  `docker run --rm -it --entrypoint journalctl docker.elastic.co/elastic-agent/elastic-agent-complete:<VERSION> --version`.
- **Permission Denied**: For Logfile input, ensure the Elastic Agent user has read permissions for the specified path.

## Vendor Resources
Refer to the official vendor website for additional resources.

# Documentation sites
- [Elastic Iptables Integration Reference](https://www.elastic.co/docs/reference/integrations/iptables)
- Refer to the official vendor website for further documentation.
