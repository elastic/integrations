# Service Info

## Common use cases
The Juniper SRX integration enables the following use cases:

- **Network Security Monitoring**: Monitor firewall events including session creation, closure, and denial to track network traffic patterns and identify potential security issues.
- **Threat Detection and Response**: Collect and analyze intrusion detection (IDS), intrusion prevention (IDP), and advanced anti-malware (AAMW) events to detect and respond to security threats in real-time.
- **Compliance and Auditing**: Centralize security logs for compliance reporting and audit trails of network access and security policy enforcement.
- **Unified Threat Management (UTM) Monitoring**: Track web filtering, antivirus, antispam, and content filtering events to maintain visibility into application-layer threats.
- **Security Intelligence Analysis**: Analyze security intelligence (SECINTEL) events to identify connections to known malicious sources and take proactive security measures.

## Data types collected
The integration collects the following log types from Juniper SRX devices via syslog:

- **RT_FLOW logs**: Session create, close, and deny events including NAT translations and routing instance information
- **RT_IDS logs**: Intrusion detection system events including screen attacks (TCP, UDP, ICMP, IP)
- **RT_UTM logs**: Unified threat management events including web filtering (permitted/blocked URLs), antivirus detections, content filtering, and antispam
- **RT_IDP logs**: Intrusion detection and prevention events including attack logs and DDoS application state events
- **RT_AAMW logs**: Advanced anti-malware events including malware detections and infected host information
- **RT_SECINTEL logs**: Security intelligence events tracking connections to known malicious sources
- **System logs**: General system-level events from the SRX device

All logs are collected in syslog format using the "structured-data + brief" format.

## Compatibility

The integration supports various SRX Series models including branch office devices, mid-range firewalls (e.g., SRX1500), and data center appliances.

## Scaling and Performance
- **Log Volume**: The integration can handle high volumes of syslog messages. Performance depends on the Elastic Agent host specifications and network bandwidth.
- **Multiple Devices**: The integration supports collecting logs from multiple Juniper SRX devices to a single Elastic Agent or multiple agents for horizontal scaling.
- **Input Methods**: Supports UDP (recommended for high-volume environments with acceptable packet loss), TCP (reliable delivery), and file-based collection.
- **Buffer Recommendations**: For UDP input, consider configuring read buffers (default: 100MiB) and max message size (default: 50KiB) based on log volume.
- **Network Considerations**: Ensure adequate network bandwidth between SRX devices and Elastic Agent. A dedicated management network is recommended for production environments.

# Set Up Instructions

## Vendor prerequisites
- Juniper SRX firewall running Junos OS 19.x or later
- Administrator access to the SRX device to configure system logging
- Network connectivity between the SRX device and the Elastic Agent (ensure appropriate firewall rules allow syslog traffic on the configured port)
- The SRX device must be configured to send syslog messages in the "structured-data + brief" format
- The syslog format on the SRX device should be set to "Default"

## Elastic prerequisites
- Elastic Stack version 8.11.0 or higher
- Elastic Agent installed and running on a host that can receive syslog messages from the SRX device
- Sufficient storage capacity in Elasticsearch to accommodate the expected log volume
- Network connectivity from the Elastic Agent to the Elasticsearch cluster

## Vendor set up steps

### Configure syslog on Juniper SRX

1. **Access the SRX device CLI** via SSH or console

2. **Configure structured-data format**:
   ```
   set system syslog structured-data
   ```

3. **Configure remote syslog destination** (replace `<ELASTIC_AGENT_IP>` and `<PORT>` with your values):
   ```
   set system syslog host <ELASTIC_AGENT_IP> port <PORT>
   set system syslog host <ELASTIC_AGENT_IP> facility-override local0
   set system syslog host <ELASTIC_AGENT_IP> log-prefix <hostname>
   ```

4. **Configure which log types to send**:
   ```
   set system syslog host <ELASTIC_AGENT_IP> any any
   ```
   
   Or configure specific severity levels for specific facilities:
   ```
   set system syslog host <ELASTIC_AGENT_IP> authorization any
   set system syslog host <ELASTIC_AGENT_IP> daemon any
   set system syslog host <ELASTIC_AGENT_IP> kernel any
   ```

5. **For security event logs**, ensure the following are enabled:
   ```
   set security log mode stream
   set security log format sd-syslog
   set security log stream <stream-name> host <ELASTIC_AGENT_IP>
   set security log stream <stream-name> port <PORT>
   ```

6. **Commit the configuration**:
   ```
   commit
   ```

For detailed instructions, refer to the [Juniper Knowledge Base article KB16502](https://kb.juniper.net/InfoCenter/index?page=content&id=kb16502) on configuring system logging.

## Kibana set up steps

1. **Navigate to Integrations** in Kibana (Management → Integrations)

2. **Search for "Juniper SRX"** and select the integration

3. **Click "Add Juniper SRX"** to add the integration

4. **Configure the integration**:
   - **Integration name**: Provide a descriptive name
   - **Input type**: Choose to collect logs from Juniper SRX via UDP, TCP, or file depending on your setup
     - **UDP** (recommended for most systems with acceptable packet loss):
       - Syslog Host: The IP address to listen on (default: localhost)
       - Syslog Port: The port to listen on (default: 9006)
     - **TCP** (for reliable delivery):
       - Syslog Host: The IP address to listen on (default: localhost)
       - Syslog Port: The port to listen on (default: 9006)
     - **file** (for reading from log files available on the agent host):
       - Paths: Specify the path to log files (default: /var/log/juniper-srx.log)
   - **Preserve original event**: Enable if you want to keep the raw log message in `event.original` field

5. **Advanced options** (optional):
   - Configure custom processors for data enrichment or filtering
   - For TCP: Configure SSL/TLS settings if encryption is required
   - For UDP: Adjust buffer sizes and timeout values if needed

6. **Select an agent policy** or create a new one

7. **Click "Save and continue"** to deploy the integration

8. **Verify the integration** is added to your agent policy

# Validation Steps

1. **Generate test traffic on the SRX device** to create log events (e.g., initiate a network connection, access a website through the firewall)

2. **Check Elastic Agent status**:
   - Navigate to Fleet → Agents in Kibana
   - Verify the agent status is "Healthy"
   - Check for any error messages related to the Juniper SRX integration

3. **Verify log ingestion in Kibana**:
   - Navigate to Discover in Kibana
   - Select the data view for `logs-*` or create a data view for `logs-juniper_srx.log-*`
   - Add a time filter for the last 15 minutes
   - Search for `data_stream.dataset: "juniper_srx.log"`
   - Verify that events are appearing.

4. **Test specific log types**:
   - For RT_FLOW logs: Filter by `juniper.srx.tag: RT_FLOW_SESSION_CREATE`
   - For RT_IDS logs: Filter by `juniper.srx.tag: RT_SCREEN_*`
   - For RT_UTM logs: Filter by `juniper.srx.tag: WEBFILTER_URL_*`

# Troubleshooting

## Common Configuration Issues

**Issue**: No logs appearing in Elasticsearch

**Solutions**:
- Verify the Elastic Agent is running: Check Fleet → Agents status in Kibana
- Confirm the SRX device can reach the Elastic Agent: Test connectivity using `ping` or `telnet <ELASTIC_AGENT_IP> <PORT>` from the SRX CLI
- Check firewall rules: Ensure the port configured for syslog (default 9006) is open on the Elastic Agent host
- Verify syslog configuration on SRX: Use `show configuration system syslog` to confirm settings
- Check Elastic Agent logs: View agent logs for connection errors or parsing issues

**Issue**: Integration showing as "Unhealthy" in Fleet

**Solutions**:
- Review agent logs for error messages
- Verify the agent policy is correctly assigned
- Ensure the agent has connectivity to the Elasticsearch cluster
- Check for resource constraints (CPU, memory, disk) on the agent host

## Ingestion Errors

**Issue**: Events have `error.message` field populated

**Solutions**:
- Check the syslog format on the SRX device - must be "structured-data + brief" format
- Verify the syslog format is set to "Default" on the SRX device
- Examine the `event.original` field (if preserved) to see the raw message format
- Check for unsupported log types or tags - refer to the README for supported JunOS processes and tags
- Review the ingest pipeline logs in Elasticsearch for detailed parsing errors

**Issue**: Some fields are not being parsed correctly

**Solutions**:
- Verify the Junos OS version is 19.x or later
- Check if log format has been customized on the SRX (custom formats may not parse correctly)
- Review the specific log type - some fields may be optional depending on the event type
- Update the integration to the latest version as parsing improvements may have been added


## Vendor Resources

- [Juniper SRX Series Documentation](https://www.juniper.net/documentation/en_US/release-independent/junos/information-products/pathway-pages/srx-series/product/)
- [JunOS Structured Data Configuration](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/structured-data-edit-system.html)
- [KB16502: SRX Getting Started - Configure System Logging](https://kb.juniper.net/InfoCenter/index?page=content&id=kb16502)
- [Juniper Security Logging and Reporting](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/security-log-reporting.html)

# Documentation sites

- [Elastic Juniper SRX Integration](https://www.elastic.co/docs/reference/integrations/juniper_srx)
- [Juniper SRX Series Product Page](https://www.juniper.net/documentation/en_US/release-independent/junos/information-products/pathway-pages/srx-series/product/)
- [JunOS Documentation - System Logging](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/system-syslog.html)
- [JunOS Structured Data Reference](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/structured-data-edit-system.html)
- [Juniper Knowledge Base](https://kb.juniper.net/)

