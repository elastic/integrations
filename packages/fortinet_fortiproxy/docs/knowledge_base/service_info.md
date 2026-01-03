# Service Info

## Common use cases

- **Secure Web Gateway**: FortiProxy serves as a high-performance secure web gateway, protecting users from online threats through advanced URL filtering, SSL/SSH inspection, and content analysis.
- **Web Traffic Monitoring**: Monitor and analyze web traffic patterns, user behavior, and application usage across the network.
- **Data Loss Prevention (DLP)**: Prevent sensitive data leakage through web channels using DLP policies with Optical Character Recognition (OCR) capabilities.
- **Application Control**: Block malware and enforce granular web application policies through application control, URL filtering, and antivirus scanning.
- **Security Event Detection**: Detect and respond to security incidents including intrusion attempts, malware detections, and policy violations.

## Data types collected

- **Traffic logs**: Network traffic information including source/destination IPs, ports, protocols, bytes transferred, and session details.
- **HTTP transaction logs**: Detailed HTTP/HTTPS request and response data including URLs, methods, status codes, user agents, and timing information.
- **UTM (Unified Threat Management) logs**: Security-related logs from antivirus, web filtering, application control, DLP, and SSL inspection features.
- **Event logs**: System events, administrative actions, user authentication events, configuration changes, and system performance statistics.
- **Security Rating logs**: Security posture assessment results with audit scores and compliance metrics.

## Compatibility

This integration has been tested against FortiProxy versions 7.x up to 7.4.3. Newer versions are expected to work but have not been tested.

## Scaling and Performance

FortiProxy is designed for high scalability and can handle large volumes of web traffic. For cloud deployments, FortiProxy supports active-passive high availability configurations to ensure continuous protection and uptime.

# Set Up Instructions

## Vendor prerequisites

FortiProxy must be configured to send syslog messages to the Elastic Agent. The syslog configuration should use either UDP or TCP mode with the default format.

## Elastic prerequisites

Elastic Agent must be installed and running on a system that can receive syslog messages from FortiProxy.

## Vendor set up steps

### Configure Syslog on FortiProxy

1. Access the FortiProxy CLI or GUI.

2. Configure the syslog settings:
   ```
   config log syslogd setting
       set status enable
       set server "<Elastic_Agent_IP>"
       set port 514
       set mode <udp|reliable>
       set format default
   end
   ```
   - Replace `<Elastic_Agent_IP>` with the IP address of your Elastic Agent
   - Set `mode` to `udp` for UDP transport or `reliable` for TCP transport
   - Keep `format` set to `default`

3. **Important**: When using TCP input with `reliable` mode, the TCP framing in the Elastic Agent configuration should be set to `rfc6587`.

### Configure Log Settings (Optional)

To control which logs are sent and their verbosity:

1. Navigate to **Log & Report** > **Log Settings** in the FortiProxy GUI.

2. Enable logging for the desired event types (traffic, security events, system events).

3. Set the appropriate severity level for each log type.

## Kibana set up steps

1. Navigate to **Integrations** in Kibana.

2. Search for "Fortinet FortiProxy" and select the integration.

3. Click **Add Fortinet FortiProxy**.

4. Choose the appropriate input type:
   - **TCP input**: For reliable syslog transmission
     - Set **Listen Address** (default: `localhost`, or `0.0.0.0` to bind to all interfaces)
     - Set **Listen Port** (default: `514`)
     - Ensure TCP framing is set to `rfc6587` if FortiProxy is configured with `mode reliable`
   - **UDP input**: For standard syslog transmission
     - Set **Listen Address** (default: `localhost`, or `0.0.0.0` to bind to all interfaces)
     - Set **Listen Port** (default: `514`)
   - **Filestream input**: For reading logs from a file
     - Specify the path to the log file

5. Configure optional settings:
   - Enable **Preserve original event** to keep a copy of the raw log in `event.original`
   - Add custom tags if needed
   - Configure SSL/TLS settings for encrypted TCP connections (if required)

6. Save and deploy the integration.

# Validation Steps

1. **Verify FortiProxy is sending logs**:
   - Generate some web traffic through the FortiProxy device
   - Check the FortiProxy logs to confirm syslog is enabled and active
   - Verify network connectivity between FortiProxy and the Elastic Agent (check firewall rules, port accessibility)

2. **Check data ingestion in Kibana**:
   - Navigate to **Discover** in Kibana
   - Select the `logs-fortinet_fortiproxy.log-*` index pattern
   - Confirm that logs are appearing with recent timestamps
   - Verify that fields are being parsed correctly (check `fortinet.proxy.*`, `source.ip`, `destination.ip`, etc.)

3. **Review the dashboard**:
   - Navigate to **Dashboards** in Kibana
   - Open the "Fortinet FortiProxy" dashboard
   - Verify that visualizations are displaying data correctly
   - Check that traffic patterns, top sources/destinations, and security events are visible

4. **Test with specific log types**:
   - Generate traffic logs by accessing websites through the proxy
   - Trigger security events (e.g., blocked URLs) to verify UTM log collection
   - Perform administrative actions to verify system event logs are collected

# Troubleshooting

## Common Configuration Issues

**Issue**: No data collected / Logs not appearing in Kibana

*Solutions*:
- Verify that syslog is enabled on FortiProxy: `show log syslogd setting`
- Check network connectivity between FortiProxy and Elastic Agent (ping, telnet to the syslog port)
- Verify firewall rules allow traffic on the configured syslog port
- Confirm the Elastic Agent is listening on the correct IP address and port
- Check the Elastic Agent logs for connection errors or parsing issues
- Ensure the FortiProxy server IP and Elastic Agent IP are correctly configured

**Issue**: TCP framing errors

*Solutions*:
- When using FortiProxy in `reliable` mode (TCP), ensure the TCP input framing is set to `rfc6587`
- Check the Elastic Agent configuration file for the correct `framing` setting under `tcp_options`

**Issue**: Incomplete or malformed log messages

*Solutions*:
- Verify that FortiProxy syslog format is set to `default`
- Check for network packet loss or truncation issues
- Increase the `max_message_size` setting in the input configuration if logs are being truncated

## Ingestion Errors

**Issue**: Parsing errors in `error.message` field

*Solutions*:
- Check the `event.original` field to see the raw log format
- Verify that the log format matches what the integration expects (syslog format with key=value pairs)
- Check for recent FortiProxy firmware updates that may have changed the log format
- Report parsing issues with sample logs to the integration maintainers

**Issue**: Missing fields or incorrect field mappings

*Solutions*:
- Verify that the FortiProxy log contains the expected fields
- Check the ingest pipeline processing for any dropped fields
- Review the Elastic Agent logs for pipeline processing errors

## API Authentication Errors

This integration collects logs via syslog and does not use API authentication. If you see API-related errors, they may be from a different integration or misconfiguration.

## Vendor Resources

- **FortiProxy Administration Guide**: Official documentation for configuring and managing FortiProxy
  - https://docs.fortinet.com/product/fortiproxy
- **FortiProxy CLI Reference**: Command-line interface reference for configuration
  - https://docs.fortinet.com/document/fortiproxy/7.4.3/cli-reference/

# Documentation sites

- **Fortinet FortiProxy Product Page**: https://www.fortinet.com/products/secure-web-gateway
- **FortiProxy Documentation Portal**: https://docs.fortinet.com/product/fortiproxy
- **FortiProxy 7.4.3 Administration Guide**: https://docs.fortinet.com/document/fortiproxy/7.4.3/administration-guide
- **FortiProxy 7.4.3 CLI Reference**: https://docs.fortinet.com/document/fortiproxy/7.4.3/cli-reference/294620/config-log-syslogd-setting
- **Elastic Fortinet FortiProxy Integration**: https://www.elastic.co/guide/en/integrations/current/fortinet_fortiproxy.html
- **Fortinet Community Forums**: https://community.fortinet.com/

