# Service Info

## Common use cases

- **Network Security Monitoring**: Monitor network device logs for security events such as access control list (ACL) violations, unauthorized access attempts, and configuration changes
- **Compliance Reporting**: Collect and analyze logs from Cisco IOS devices to meet regulatory compliance requirements
- **Network Operations Management**: Track configuration changes, system events, and device health across Cisco routers and switches
- **Troubleshooting**: Analyze device logs to diagnose network connectivity issues, hardware failures, and configuration problems

## Data types collected

The integration collects syslog messages from Cisco IOS network devices including:

- **System Messages**: Configuration changes, system restarts, and administrative actions
- **Security Events**: Access control list (ACL) denials and permits, authentication failures
- **Network Events**: Interface status changes, routing protocol messages
- **IPv4 and IPv6 Traffic**: Network traffic logs with source/destination IP addresses and ports
- **Protocol-specific Messages**: ICMP, IGMP, TCP, UDP, and other protocol events

The integration captures fields such as:
- Facility and severity levels
- Sequence numbers and message counts
- Interface names
- Source and destination IP addresses and ports
- Network protocols and actions taken

## Compatibility

The Cisco IOS integration supports devices running Cisco IOS software including:
- Cisco routers
- Cisco switches
- Other Cisco network devices running IOS

The integration expects logs to include hostname and timestamp fields. The syslog format should be compatible with standard Cisco IOS syslog output.

**Elastic Stack Requirements:**
- Kibana version 8.11.0 or higher

# Set Up Instructions

## Vendor prerequisites

- Cisco IOS device with network connectivity to the Elastic Agent
- Administrative access to the Cisco device to configure syslog settings
- Network connectivity from Cisco device to Elastic Agent (TCP port 9002 or UDP port 9002 by default, or custom port)

**Important**: Enable timestamps on Cisco IOS devices using the command `service timestamps log datetime` as timestamps are not enabled by default.

## Elastic prerequisites

- Elastic Agent must be installed on a host that can receive syslog messages from Cisco devices
- The host running Elastic Agent must have the specified port (default 9002) available and accessible from Cisco devices
- Proper firewall rules to allow syslog traffic from Cisco devices to the Elastic Agent host

## Vendor set up steps

### Configuring Syslog on Cisco IOS Devices

1. **Enable timestamp logging** (required):
   ```
   configure terminal
   service timestamps log datetime
   exit
   ```

2. **Optional: Enable sequence numbers**:
   ```
   configure terminal
   service sequence-numbers
   exit
   ```
   This will populate the `event.sequence` field in the logs.

3. **Configure syslog destination**:
   
   For UDP (recommended for most deployments):
   ```
   configure terminal
   logging host <ELASTIC_AGENT_IP> transport udp port 9002
   exit
   ```
   
   For TCP (for reliable delivery):
   ```
   configure terminal
   logging host <ELASTIC_AGENT_IP> transport tcp port 9002
   exit
   ```

4. **Set logging level** (optional, adjust as needed):
   ```
   configure terminal
   logging trap informational
   exit
   ```

5. **Save the configuration**:
   ```
   write memory
   ```

For detailed Cisco IOS syslog configuration, refer to [Cisco's System Message Logging documentation](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html).

### File-based Collection

If collecting logs from files, ensure logs are written to a file path accessible by the Elastic Agent (e.g., `/var/log/cisco-ios.log`).

## Kibana set up steps

1. **Navigate to Integrations**:
   - In Kibana, go to Management → Integrations
   
2. **Find and Add Cisco IOS Integration**:
   - Search for "Cisco IOS"
   - Click on the Cisco IOS integration
   - Click "Add Cisco IOS"

3. **Configure the Integration**:
   - **Integration name**: Provide a descriptive name
   - **Select input type**: Choose TCP, UDP, or Logfile based on your configuration
   
   For TCP/UDP inputs:
   - **Host to listen on**: Set to `0.0.0.0` to listen on all interfaces, or `localhost` for local only
   - **Syslog Port**: Default is 9002 (must match the port configured on Cisco devices)
   Advanced Options:
   - **Timezone**: Set to `UTC` or specify your timezone (default: UTC)
   - **Timezone Map**: Configure if you have logs from multiple timezones (advanced)
   - **Preserve original event**: Enable to keep the raw log in `event.original` field
   
   For Logfile input:
   - **Paths**: Specify the file path(s) where Cisco IOS logs are stored (default: `/var/log/cisco-ios.log`)
     - You can specify multiple file paths
     - Supports wildcards (e.g., `/var/log/cisco-*.log`)
   Advanced Options:
   - **Timezone**: Set to `UTC` or specify your timezone (default: UTC)
   - **Timezone Map**: Configure if you have logs from multiple timezones (advanced)
   - **Preserve original event**: Enable to keep the raw log in `event.original` field

4. **Select Agent Policy**:
   - Choose an existing agent policy or create a new one
   - The agent must be running on a host accessible to your Cisco devices

5. **Save and Deploy**:
   - Click "Save and continue"
   - Follow prompts to enroll agents if needed

# Validation Steps

1. **Verify Cisco device is sending logs**:
   - On the Cisco device, trigger a log event (e.g., make a configuration change):
     ```
     configure terminal
     ! Make a harmless change
     description Test log message
     exit
     ```
   - Check that syslog is configured correctly:
     ```
     show logging
     ```

2. **Check data in Kibana**:
   - Go to Analytics → Discover in Kibana
   - Select the `logs-cisco_ios.log-*` data view
   - Filter for recent time range
   - Verify that events are appearing with proper fields populated

3. **Validate parsed fields**:
   - Check that key fields are populated:
     - `@timestamp`
     - `observer.vendor` should be "Cisco"
     - `observer.product` should be "IOS"
     - `cisco.ios.facility` should contain the facility name
     - `message` should contain the log message
     - `event.severity` should contain the severity level

4. **Test specific event types**:
   - Configuration changes should appear with facility "SYS"
   - ACL events should show source and destination IPs in `source.ip` and `destination.ip`

# Troubleshooting

## Common Configuration Issues

**Issue**: No data appearing in Kibana

**Solutions**:
- Verify network connectivity from Cisco device to Elastic Agent host
- Check that firewall rules allow traffic on the configured port
- Verify the Elastic Agent is running: `elastic-agent status`
- Check Agent logs for errors: Review logs in Kibana under Fleet → Agents
- Confirm the listening port matches what's configured on Cisco devices
- Verify the Cisco device is sending logs: `show logging` on the device

**Issue**: Timestamps are not parsing correctly

**Solutions**:
- Ensure `service timestamps log datetime` is configured on Cisco IOS device
- Configure the correct timezone in the integration settings
- For non-standard timezones, use the Timezone Map configuration option
- Check that the system clock is set correctly on Cisco devices

**Issue**: Logs contain additional syslog headers from relay servers

**Solutions**:
- If logs are relayed through intermediate syslog servers, extra headers may be added
- Use Beats processors to remove or parse additional headers before ingestion
- Configure processors in the integration's advanced settings

## Ingestion Errors

**Issue**: Parsing errors in `error.message` field

**Solutions**:
- Verify the log format matches expected Cisco IOS syslog format
- Ensure hostname and timestamp are present in logs
- Check if custom configuration on Cisco device has modified the log format
- Review the ingest pipeline processing to identify parsing issues

**Issue**: Timezone parsing failures

**Solutions**:
- Configure explicit timezone in integration settings (default is UTC)
- Use Timezone Map for devices with abbreviated timezone names (e.g., AEST, CET)
- Ensure the timezone format from Cisco device is recognized

## API Authentication Errors

This integration does not use API authentication as it receives logs via syslog.

## Vendor Resources

- [Cisco IOS System Message Logging](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html)
- [Cisco Developer Documentation](https://developer.cisco.com/docs/)

# Documentation sites

- [Cisco IOS System Message Logging Guide](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html) - Configuration guide for syslog on Cisco IOS devices
- [Cisco Developer Documentation](https://developer.cisco.com/docs/) - General Cisco documentation and API references
- [Elastic Cisco IOS Integration Documentation](https://www.elastic.co/docs) - Official Elastic integration documentation

