# Service Info

## Common use cases
- Network security monitoring and threat detection
- Firewall log analysis and compliance reporting
- Malware detection and file transfer monitoring
- VPN connection tracking and analysis
- Access control rule monitoring
- SSL/TLS inspection and policy enforcement
- URL filtering and web application identification
- DNS query monitoring
- Network flow analysis and connection tracking

## Data types collected
- Security events (malware detection, file transfers, threat intelligence)
- Access control events (rule matches, connection allows/blocks)
- VPN events (connection establishment, termination, user authentication)
- SSL/TLS inspection events
- DNS query and response events
- Network flow information (source/destination IPs, ports, protocols)
- File transfer events (uploads, downloads, file analysis results)
- User authentication and authorization events (AAA)
- System events (failover, updates, configuration changes)

## Compatibility
- Compatible with Cisco Firepower Threat Defense (FTD) devices
- Supports syslog message collection using TCP, UDP, or logfile input
- Tested with various Cisco Firepower device models and FTD software versions
- Requires Elastic Stack version ^8.11.0 || ^9.0.0

## Scaling and Performance
- Supports high-volume syslog ingestion using TCP and UDP inputs
- Can handle multiple concurrent connections when using TCP input
- UDP input provides low-latency log collection suitable for high-throughput environments
- Logfile input allows reading from local log files for batch processing or archival data
- Performance depends on network bandwidth, Elastic Agent resources, and Elasticsearch cluster capacity
- For high-volume deployments, consider using multiple Elastic Agents with load balancing

# Set Up Instructions

## Vendor prerequisites
- Cisco Firepower Threat Defense (FTD) device configured and operational
- Network connectivity between FTD device and Elastic Agent host
- Syslog logging enabled on the FTD device
- Appropriate firewall rules to allow syslog traffic from FTD to Elastic Agent (if applicable)
- Access to FTD management interface for configuration changes

## Elastic prerequisites
- Elastic Stack version ^8.11.0 || ^9.0.0
- Elastic Agent installed and configured
- Sufficient network bandwidth and system resources for log ingestion
- Appropriate Elasticsearch cluster capacity for expected log volume

## Vendor set up steps

### TCP Input Configuration
1. Log into the FTD management interface (Firepower Management Center or FDM)
2. Navigate to the device-specific configuration page
3. Search for or navigate to "FTD Logging" or "Configure Logging on FTD" page
4. Configure syslog server settings:
   - Set the syslog server IP address to the Elastic Agent host IP
   - Set the syslog port (default: 9003 for TCP)
   - Select TCP as the transport protocol
   - Enable the appropriate log types (security events, connection events, etc.)
5. Save and deploy the configuration to the FTD device
6. Verify syslog connectivity by checking for test messages

### UDP Input Configuration
1. Log into the FTD management interface
2. Navigate to the device-specific configuration page
3. Search for or navigate to "FTD Logging" or "Configure Logging on FTD" page
4. Configure syslog server settings:
   - Set the syslog server IP address to the Elastic Agent host IP
   - Set the syslog port (default: 9003 for UDP)
   - Select UDP as the transport protocol
   - Enable the appropriate log types (security events, connection events, etc.)
5. Save and deploy the configuration to the FTD device
6. Verify syslog connectivity by checking for test messages

### Logfile Input Configuration
1. Ensure FTD device is configured to write logs to a file system accessible by Elastic Agent
2. Identify the log file path(s) on the system (for example, `/var/log/cisco-ftd.log`)
3. Ensure Elastic Agent has read permissions for the log file(s)
4. Configure log rotation if needed to prevent disk space issues

Note: Cisco provides a range of Firepower devices, which may have different configuration steps. We recommend users navigate to the device specific configuration page, and search for/go to the "FTD Logging" or "Configure Logging on FTD" page for the specific device.

## Kibana set up steps
1. Log into Kibana
2. Navigate to **Integrations** > **Browse integrations**
3. Search for "Cisco FTD" and select the integration
4. Click **Add Cisco FTD**
5. Configure the integration:
   - **Name**: Provide a name for the integration instance
   - **Data stream**: Select "Cisco FTD logs"
   - **Input type**: Choose TCP, UDP, or Log file based on your configuration
   - **TCP/UDP Configuration**:
     - Set the host and port to match your Elastic Agent configuration
     - Configure timezone offset if needed (default: UTC)
     - Enable "Preserve original event" if you want to keep raw log messages
     - Configure internal/external zones if needed for network direction detection
   - **Logfile Configuration**:
     - Specify the log file path(s)
     - Configure timezone offset if needed
     - Set internal/external zones if applicable
6. Click **Save and continue**
7. Add the integration to an agent policy or create a new agent policy
8. Deploy the agent policy to your Elastic Agents
9. Verify the agent is receiving data by checking the agent status in Kibana

# Validation Steps
1. **Verify Agent Status**:
   - In Kibana, navigate to **Management** > **Fleet** > **Agents**
   - Confirm the Elastic Agent shows as "Healthy" and has the Cisco FTD integration assigned
   - Check the agent logs for any connection errors

2. **Trigger Test Events**:
   - Generate test network traffic through the FTD device (for example, web browsing, file download)
   - Or trigger a security event by accessing a known malicious URL or downloading a test file
   - Verify the FTD device is sending syslog messages (check FTD logs or management interface)

3. **Verify Data Ingestion**:
   - In Kibana, navigate to **Discover**
   - Select the `logs-cisco_ftd.log-*` data stream
   - Verify events are appearing with recent timestamps
   - Check that events contain expected fields such as `cisco.ftd.*`, `source.ip`, `destination.ip`, etc.

4. **Validate Event Fields**:
   - Open a sample event and verify:
     - `@timestamp` is correctly parsed
     - `cisco.ftd.message_id` is present
     - Network fields (`source.ip`, `destination.ip`, `source.port`, `destination.port`) are populated
     - Security event fields are present for security-related events
     - `event.original` contains the raw syslog message (if preserve_original_event is enabled)

5. **Check for Parsing Errors**:
   - Filter for `event.outcome: failure` or check for `error.message` fields
   - Review any events with parsing issues
   - Verify timezone configuration if timestamps appear incorrect

# Troubleshooting

## Common Configuration Issues

**Issue**: No data appearing in Kibana Discover
- **Solution**: 
  - Verify Elastic Agent is running and healthy
  - Check network connectivity between FTD device and Elastic Agent
  - Verify syslog server configuration on FTD device matches Elastic Agent host/port
  - Check firewall rules allow syslog traffic
  - Review Elastic Agent logs for connection errors
  - Verify the integration is properly assigned to the agent policy

**Issue**: Service failed to start
- **Solution**:
  - Check Elastic Agent logs for specific error messages
  - Verify port is not already in use by another service
  - Ensure Elastic Agent has necessary permissions (especially for logfile input)
  - Check system resources (CPU, memory, disk space)

**Issue**: Incorrect timezone in events
- **Solution**:
  - Configure the `tz_offset` parameter in the integration settings
  - Use IANA timezone format (for example, "America/New_York") or offset format (for example, "+0500")
  - Verify FTD device timezone settings match your configuration

**Issue**: Network direction not correctly identified
- **Solution**:
  - Configure internal and external zones in the integration settings
  - Ensure zone names match exactly with FTD device zone configuration
  - Verify `private_is_internal` setting matches your network topology
  - Check that `cisco.ftd.ingress_zone` and `cisco.ftd.egress_zone` fields are present in events

## Ingestion Errors

**Issue**: Events showing parsing errors or missing fields
- **Solution**:
  - Check `event.original` field to see the raw syslog message
  - Verify FTD device is sending logs in expected syslog format
  - Review Elastic Agent logs for parsing error details
  - Ensure FTD device software version is compatible with the integration
  - Check if custom message formats require pipeline modifications

**Issue**: `cisco.ftd.security` field contains flattened data but aggregations fail
- **Solution**:
  - Starting from version 2.21.0, known security fields are moved to `cisco.ftd.security_event` for better aggregation support
  - Use `cisco.ftd.security_event.*` fields for aggregations instead of `cisco.ftd.security.*`
  - To add more fields to `cisco.ftd.security_event`, create a custom ingest pipeline:
    1. Navigate to **Stack Management** > **Ingest Pipelines**
    2. Create pipeline named `logs-cisco_ftd.log@custom`
    3. Add Rename processors to move fields from `cisco.ftd.security.*` to `cisco.ftd.security_event.*`
    4. Optionally add Convert processors to set correct data types

**Issue**: Missing or incorrect field mappings
- **Solution**:
  - Review the exported fields documentation in the integration README
  - Verify FTD message IDs are supported by checking sample events
  - Some fields may be vendor-specific and require custom mapping
  - Check integration version changelog for recent field additions

## API Authentication Errors
- **Not applicable**: This integration uses syslog protocol and does not require API authentication

## Vendor Resources
- [Cisco Secure Firewall Management Center Examples](https://www.cisco.com/c/en/us/support/security/defense-center/products-configuration-examples-list.html)
- [Configure Logging on FTD through FMC](https://www.cisco.com/c/en/us/support/docs/security/firepower-ngfw/200479-Configure-Logging-on-FTD-via-FMC.html)
- [Configure FMC to Send Audit Logs to a Syslog Server](https://www.cisco.com/c/en/us/support/docs/security/secure-firewall-management-center/221019-configure-fmc-to-send-audit-logs-to-a-sy.html)

# Documentation sites
- [Cisco Secure Firewall Management Center Examples](https://www.cisco.com/c/en/us/support/security/defense-center/products-configuration-examples-list.html)
- [Cisco Firepower Threat Defense Product Page](https://www.cisco.com/c/en/us/support/security/firepower-ngfw/series.html)
- [Cisco FTD Software Release and Sustaining Bulletin](https://www.cisco.com/c/en/us/products/collateral/security/firewalls/bulletin-c25-743178.html)
- [Elastic Integrations Documentation](https://www.elastic.co/guide/en/integrations/index.html)
- [Elastic Agent Documentation](https://www.elastic.co/guide/en/fleet/current/index.html)
- [Elastic Ingest/Fleet Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems)
