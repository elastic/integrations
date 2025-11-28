# Service Info

## Common use cases

- **Web Traffic Monitoring and Control**: ProxySG provides secure web gateway functionality to monitor, filter, and control web traffic, ensuring compliance with organizational policies and enhancing security.

- **Data Loss Prevention (DLP)**: By inspecting outbound traffic, ProxySG helps prevent sensitive data from leaving the organization without authorization.

- **Malware Protection**: ProxySG integrates with threat protection solutions to scan web traffic for malware, blocking malicious content before it reaches end-users.

- **Bandwidth Management**: ProxySG optimizes and controls bandwidth usage by caching frequently accessed content and managing streaming media, ensuring efficient network performance.

- **SSL Inspection**: ProxySG performs SSL/TLS inspection to identify and block malicious activities hidden in encrypted traffic.

## Data types collected

- **Access Logs**: Detailed records of web traffic, including URLs accessed, HTTP methods, user information, timestamps, status codes, bytes transferred, and actions taken by the proxy (e.g., TCP_MISS, TCP_HIT).

- **User Authentication Data**: Information on user authentication events, including usernames, authentication groups, and user agent details.

- **Security Events**: Logs related to security activities such as blocked sites, malware detection, threat risk scores, SSL certificate validation status, and filter results.

- **Performance Metrics**: Time taken for requests, connection details, and cache hit/miss statistics.

The integration supports the following log formats:
- `main`
- `bcreportermain_v1`
- `bcreporterssl_v1`
- `ssl`

## Compatibility


## Scaling and Performance

- **Appliance Models**: ProxySG is available in various hardware models (e.g., S400, S500, SG300, SG600, SG900) and can be deployed as physical appliances, virtual appliances, or in the cloud, each designed to handle different performance and scalability requirements.

- **Clustered Deployments**: For large-scale deployments, multiple ProxySG appliances can be managed centrally using the Blue Coat Management Center, allowing for efficient scaling and centralized policy enforcement.

- **Log Volume Considerations**: ProxySG appliances can generate significant log volumes in high-traffic environments. Ensure adequate network bandwidth and storage capacity for log collection and retention.

# Set Up Instructions

## Vendor prerequisites

- **Administrative Access**: Administrative credentials to access the ProxySG Management Console.

- **Network Connectivity**: Network path between the ProxySG appliance and the Elastic Agent host for syslog transmission (TCP/UDP) or file transfer (for file-based collection).

- **Log Format Selection**: Determine which log format to use based on your requirements. The `main` format is the default, while specialized formats like `bcreportermain_v1`, `bcreporterssl_v1`, and `ssl` provide additional fields for reporting or SSL-specific data.


## Vendor set up steps

### For Syslog Collection (TCP/UDP)

1. **Access ProxySG Management Console**: Log in to the ProxySG Management Console with administrative credentials.

2. **Configure Access Logging**:
   - Navigate to **Configuration** > **Access Logging** > **Logs**.
   - Create a new log facility or modify an existing one.
   - Select the desired **Log Format** (e.g., `main`, `bcreportermain_v1`, `bcreporterssl_v1`, or `ssl`).

3. **Set Up Log Destination**:
   - Under **Log Hosts**, add the IP address of the server where the Elastic Agent is running.
   - Specify the port number:
     - Default UDP port: 514
     - Default TCP port: 601 (or as configured in the integration)
   - Select the protocol (TCP or UDP) based on your preference and network requirements.

4. **Enable and Apply Configuration**:
   - Ensure that logging is enabled for the desired policies and rules.
   - Apply and save the configuration changes.

### For File-Based Collection

1. **Configure ProxySG File Upload**:
   - In the ProxySG Management Console, navigate to **Configuration** > **Access Logging**.
   - Configure ProxySG to upload access logs to a remote server on a schedule.
   - Specify the file upload location and schedule.

2. **Select Log Format**: Choose the appropriate log format that matches what you'll configure in the integration.

## Kibana set up steps

1. **Add the ProxySG Integration**:
   - In Kibana, navigate to **Management** > **Integrations**.
   - Search for "ProxySG" and select the **Broadcom ProxySG** integration.
   - Click **Add Broadcom ProxySG**.

2. **Configure the Integration**:
   - Select the appropriate input type:
     - **Collect logs from ProxySG via UDP**: For UDP syslog collection
     - **Collect logs from ProxySG via TCP**: For TCP syslog collection
     - **Collect access logs from ProxySG via logging server file**: For file-based collection

3. **Configure Input Settings**:
   
   **For UDP/TCP:**
   - Set the **Listen Address** (default: `localhost`, use `0.0.0.0` to bind to all interfaces).
   - Set the **Listen Port** (UDP default: 514, TCP default: 601).
   - In **Advanced options**, select the **Access Log Format** that matches the format configured on the ProxySG appliance.
   
   **For File-based:**
   - Set **Paths** to the file pattern matching the location where ProxySG uploads logs on the remote server (e.g., `/var/log/proxysg-log.log`).
   - In **Advanced options**, select the **Access Log Format** that matches the format configured on the ProxySG appliance.

4. **Configure Optional Settings**:
   - Enable **Preserve original event** if you want to keep a raw copy of the original log in the `event.original` field.
   - Configure any additional processors or custom options as needed.

5. **Save and Deploy**:
   - Save the integration configuration.
   - Select the agent policy to add this integration to, or create a new policy.
   - Deploy the configuration to your Elastic Agent.

# Validation Steps

1. **Generate Test Traffic**:
   - Access various websites through the ProxySG appliance to generate log entries.
   - Try accessing both allowed and blocked sites to test different policy actions.

2. **Verify Log Transmission**:
   - **For syslog**: Check that the ProxySG appliance is successfully sending logs to the configured destination. You can verify this in the ProxySG console under logging statistics or status.
   - **For file-based**: Confirm that log files are being uploaded to the expected location.

3. **Check Data in Kibana**:
   - In Kibana, navigate to **Discover**.
   - Select the `logs-*` data view or create a data view for `proxysg.log`.
   - Search for recent ProxySG logs using a time filter.
   - Verify that logs are appearing with correct timestamps.

4. **Validate Field Mapping**:
   - Examine sample events to ensure fields are correctly parsed.
   - Check that key fields are populated: `client.ip`, `url.domain`, `http.request.method`, `http.response.status_code`, `user.name`, etc.

5. **Review Dashboards**:
   - Navigate to **Dashboards** in Kibana.
   - Open the ProxySG dashboard to view visualizations of the ingested data.
   - Verify that visualizations are displaying data correctly.

# Troubleshooting

## Common Configuration Issues

- **Issue**: No logs are appearing in Kibana.
  - **Solution**: Verify that the ProxySG appliance is configured to send logs to the correct IP address and port. Check network connectivity between ProxySG and the Elastic Agent host (firewall rules, routing). Verify that the Elastic Agent is running and the integration is properly configured.

- **Issue**: Logs are being received but not parsed correctly.
  - **Solution**: Ensure that the **Access Log Format** selected in the integration configuration matches the log format configured on the ProxySG appliance. Review the format options: `main`, `bcreportermain_v1`, `bcreporterssl_v1`, and `ssl`.

- **Issue**: Missing or empty fields in parsed logs.
  - **Solution**: Some fields may only be populated with certain log formats. For example, SSL-specific fields require the `ssl` or `bcreporterssl_v1` format. Verify that the log format includes the fields you need.

## Ingestion Errors

- **Issue**: Pipeline processing failures.
  - **Solution**: Verify that the ProxySG appliance is sending logs in the expected format. Check for custom log format modifications on the appliance that might not match the standard formats. Consider enabling "Preserve original event" to review the raw log data.

- **Issue**: Timestamp parsing errors.
  - **Solution**: Ensure that the ProxySG appliance and Elastic Agent are synchronized to a reliable time source (NTP). Verify that timezone settings are correct on both systems.

## Vendor Resources

- **ProxySG Logging Configuration**: Consult the ProxySG Administration Guide for detailed instructions on configuring access logging and syslog facilities.
- **Log Format Specifications**: Refer to the Broadcom documentation for detailed specifications of each log format and the fields they include.

# Documentation sites

- **Broadcom ProxySG Log Formats**: https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-3/getting-started/page-help-administration/page-help-logging/log-formats/default-formats.html
- **Blue Coat Systems Product Use Guide**: https://docs.broadcom.com/doc/blue-coat-systems-product-use-guide-en
- **SGOS Administration Guide**: https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg.html
- **Elastic Integration Documentation**: https://www.elastic.co/guide/en/integrations/current/index.html
- **Filebeat Filestream Input**: https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-filestream.html
- **SSL Configuration for Elastic Agent**: https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html