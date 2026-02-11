# Service Info

## Common use cases

The Fortinet FortiManager integration allows you to monitor and analyze logs from FortiManager and FortiAnalyzer devices, providing centralized visibility into network operations and security events for enhanced management and security posture.
-   **Centralized Security Monitoring:** Aggregate security events and alerts from multiple FortiManager/FortiAnalyzer instances into a single Elastic Stack for comprehensive threat detection, incident response, and forensic analysis across your Fortinet Security Fabric.
-   **Compliance and Auditing:** Collect detailed system, device management, and logging status logs to meet regulatory compliance requirements and perform security audits, ensuring accountability for administrative actions and system changes.
-   **Operational Visibility:** Monitor administrative actions, configuration changes (`objcfg`), firmware updates (`fmwmgr`), and device management events (`devmgr`) across the Fortinet Security Fabric to maintain operational awareness, troubleshoot issues, and track system health.
-   **Log Management and Archiving:** Centralize FortiManager and FortiAnalyzer logs for long-term storage, enabling historical analysis, trending, and ensuring log availability for incident investigation beyond the devices' local storage capabilities.

## Data types collected

This integration can collect the following types of data:
-   **Fortinet FortiManager logs** (type: logs, input: filestream): Collect Fortinet FortiManager logs via Filestream input. This stream includes various FortiManager event subtypes such as System Manager (system), FortiGuard Service (fgd), Security Console (scply), Firmware Manager (fmwmgr), Log Daemon (logd), Debug IO Log (iolog), FortiGate-FortiManager Protocol (fgfm), Device Manager (devmgr/dvm), Deployment Manager (dm), Object Changes (objcfg), and Script Manager (scrmgr) from active log files. The data is parsed from Syslog format.
-   **Fortinet FortiManager logs** (type: logs, input: tcp): Collect Fortinet FortiManager logs via TCP input. This stream includes various FortiManager and FortiAnalyzer event subtypes, including System Manager, FortiGuard Service, Log Files, Logging Status, and Reports, pushed directly to an Elastic Agent via a TCP port. The data is parsed from Syslog format.
-   **Fortinet FortiManager logs** (type: logs, input: udp): Collect Fortinet FortiManager logs via UDP input. This stream includes various FortiManager and FortiAnalyzer event subtypes, including System Manager, Log Files, Logging Status, and Reports, pushed directly to an Elastic Agent via a UDP port. The data is parsed from Syslog format.

## Compatibility

**Fortinet FortiManager** and **FortiAnalyzer**: 7.2.2 and above. This integration has been tested against FortiManager & FortiAnalyzer version 7.2.2. Versions above this are expected to work but have not been tested.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:
-   **Transport/Collection Considerations:** When collecting logs via Syslog, the choice between TCP and UDP is crucial. TCP offers reliable, ordered delivery, which is ideal for critical security logs where data integrity is paramount, though it may introduce slightly more overhead. UDP provides faster, connectionless delivery, making it suitable for high-volume, less critical logs where some occasional packet loss is acceptable. For filestream, ensure the Elastic Agent has efficient access to log file paths and proper handling of log rotations to prevent data gaps or performance bottlenecks.
-   **Data Volume Management:** To optimize the performance of both the FortiManager/FortiAnalyzer and the Elastic Stack, configure the FortiManager/FortiAnalyzer to filter or limit the types and severity of logs forwarded to the Elastic Agent. Only forward logs essential for your security monitoring, compliance, or operational analysis needs. While setting the minimum severity to `information` ensures comprehensive logging, it can be adjusted to `warning` or `error` if data volume becomes unmanageably high.
-   **Elastic Agent Scaling:** A single Elastic Agent can handle a significant volume of logs, but for very high-throughput FortiManager/FortiAnalyzer environments, consider deploying multiple Elastic Agents. Each agent can be configured to listen on a dedicated port or monitor specific subsets of log files, thereby distributing the ingestion load. Ensure the agents are adequately resourced with CPU, memory, and disk I/O, and are placed strategically (e.g., on the same network segment) to minimize network latency to the FortiManager/FortiAnalyzer devices.

# Set Up Instructions

## Vendor prerequisites

-   Administrative access to the FortiManager or FortiAnalyzer device to configure log forwarding settings via both the web-based GUI and the command-line interface (CLI).
-   Network connectivity between the FortiManager/FortiAnalyzer device and the Elastic Agent's host. This requires allowing traffic on the specific Syslog port (e.g., TCP/UDP 514 or 9022) in any intervening firewalls.
-   Knowledge of the Elastic Agent's IP address (or fully qualified domain name) and the specific TCP or UDP port number it will be configured to listen on for incoming Syslog messages.
-   If utilizing the filestream input method, ensure the Elastic Agent has appropriate read permissions to access the FortiManager/FortiAnalyzer log files stored locally on the Agent's host or an accessible network-mounted filesystem.

## Elastic prerequisites

-   An installed and enrolled Elastic Agent running on a host machine that is network-accessible from the FortiManager/FortiAnalyzer devices.
-   Network connectivity between the Elastic Agent and your Elasticsearch cluster to successfully send collected data for indexing and analysis.
-   Sufficient system resources (CPU, memory, disk I/O) on the host running the Elastic Agent to efficiently process and forward the anticipated volume of FortiManager/FortiAnalyzer logs.
-   Elastic Stack 8.x or newer.

## Vendor set up steps

### For Syslog (TCP/UDP) Collection:
Configuring Fortinet FortiManager to send local event logs to Elastic Agent involves a two-part process. First, you define the Elastic Agent as a syslog server destination in the FortiManager GUI. Second, you enable the log forwarding to that server using the FortiManager command-line interface (CLI).

#### Part 1: Add the Elastic Agent as a Syslog Server (GUI)
This step registers the Elastic Agent as a valid log destination.

1.  Log in to the FortiManager web UI using your administrative credentials.
2.  Navigate to **System Settings > Advanced > Syslog Server**. In some older versions, this option may be found under **System Settings > Syslog Server**.
3.  In the Syslog Server pane, click **Create New** to add a new syslog server entry.
4.  Configure the syslog server with the following settings:
    *   **Name**: Provide a descriptive name for the server, for example, `elastic-agent-syslog`.
    *   **IP address (or FQDN)**: Enter the IP address or fully qualified domain name of the server where the Elastic Agent is running and listening for logs.
    *   **Syslog Server Port**: Enter the port number that the Elastic Agent is configured to listen on. The standard default syslog port is `514`, but `9022` is a common alternative.
    *   **Reliable Connection**:
        *   To send logs via **UDP** (the default syslog protocol), leave this option disabled.
        *   To send logs via **TCP** (for guaranteed delivery), enable this option. This setting **must** match the protocol configured in the Elastic Agent integration.
5.  Click **OK** to save the syslog server configuration.

#### Part 2: Enable Log Forwarding to the Syslog Server (CLI)
This step activates the sending of logs to the server you just configured. This can only be done via the CLI.

1.  Open the FortiManager CLI console. You can typically access this from the top-right corner of the FortiManager web GUI or via SSH.
2.  Enter the following commands to configure the local log syslog daemon settings:
    ```shell
    config system locallog syslogd setting
    ```
3.  Set the syslog server name to the one you created in Part 1 of the GUI steps:
    ```shell
    set syslog-name "elastic-agent-syslog"
    ```
4.  Set the minimum severity level of logs to be sent. To ensure all relevant logs are forwarded, it is recommended to set this to `information`:
    ```shell
    set severity information
    ```
5.  Enable the syslog service to start forwarding logs:
    ```shell
    set status enable
    ```
6.  Apply the configuration changes:
    ```shell
    end
    ```
7.  (Optional) You can verify the connection from the FortiManager GUI. Navigate back to **System Settings > Advanced > Syslog Server**, select your configured server, and click the **Test** button to send a test message.

### For Logfile Collection:
For filestream collection, FortiManager or FortiAnalyzer must be configured to store logs locally on the system where the Elastic Agent is running, or on a network-mounted filesystem accessible by the Agent.
Specific vendor steps for configuring FortiManager/FortiAnalyzer to write logs to local files for filestream collection are not explicitly provided in the integration context. Users should refer to Fortinet's official documentation regarding local log storage, retention, and file paths on their FortiManager or FortiAnalyzer device.
Common log paths may include `/var/log/fortinet/fortimanager.log*`. Ensure that the Elastic Agent has the necessary file system read permissions to access these log files.

### Vendor Set up Resources

-   [Syslog Server | FortiManager 7.6.4 | Fortinet Document Library](https://docs.fortinet.com/document/fortimanager/7.6.4/administration-guide/374190/syslog-server) - Provides official documentation on configuring syslog servers within FortiManager.
-   [Send local logs to syslog server | FortiManager 7.4.5 | Fortinet Document Library](https://docs.fortinet.com/document/fortimanager/7.4.5/administration-guide/414141/send-local-logs-to-syslog-server) - Details the process of sending local logs from FortiManager to a syslog server.
-   [Technical tip: Configure FortiManager to send logs to a syslog server - Fortinet Community](https://community.fortinet.com/t5/FortiManager/Technical-tip-Configure-FortiManager-to-send-logs-to-a-syslog/ta-p/191412) - A community-provided technical tip for configuring syslog forwarding on FortiManager.

## Kibana set up steps

1.  In Kibana, navigate to **Integrations**.
2.  Search for "Fortinet FortiManager" and click on the integration.
3.  Click **Add Fortinet FortiManager**.
4.  Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
5.  Proceed to configure the specific input types based on your FortiManager/FortiAnalyzer deployment:

### Collecting logs from Fortinet FortiManager instances via filestream input.
1.  Select the **Collecting logs from Fortinet FortiManager instances via filestream input.** input type in Kibana.
2.  Configure the following fields:
    -   **Paths**: A list of glob-based paths that will be crawled and fetched. Default: `/var/log/fortinet/fortimanager.log*`.
    -   **Timezone Offset**: By default, datetimes in the logs will be interpreted as relative to the timezone configured in the host where the agent is running. If ingesting logs from a host on a different timezone, use this field to set the timezone offset so that datetimes are correctly parsed. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00") from UCT. Default: `local`.
    -   **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
    -   **Tags**: Default: `['forwarded', 'fortinet_fortimanager-log']`.
    -   **Preserve duplicate custom fields**: Preserve fortinet_fortimanager.log fields that were copied to Elastic Common Schema (ECS) fields. Default: `False`.
    -   **Processors**: Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
3.  Save and deploy the integration.

### Collecting logs from Fortinet FortiManager instances via tcp input.
1.  Select the **Collecting logs from Fortinet FortiManager instances via tcp input.** input type in Kibana.
2.  Configure the following fields:
    -   **Listen Address**: The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
    -   **Listen Port**: The TCP port number to listen on. Default: `9022`.
    -   **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
    -   **Custom TCP Options**: Specify custom configuration options for the TCP input. Default: `
#framing: delimiter
#max_message_size: 50KiB
#max_connections: 1
#line_delimiter: "\n"
`.
    -   **SSL Configuration**: SSL configuration options. See [documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details. Default: `
#certificate_authorities:
#  - |
#    -----BEGIN CERTIFICATE-----
#    MIIDCjCCAfKgAwIBAgITJ706Mu2wJlKckpIvkWxEHvEyijANBgkqhkiG9w0BAQsF
#    ADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwIBcNMTkwNzIyMTkyOTA0WhgPMjExOTA2
#    MjgxOTI5MDRaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEB
#    BQADggEPADCCAQoCggEBANce58Y/JykI58iyOXpxGfw0/gMvF0hUQAcUrSMxEO6n
#    fZRA49b4OV4SwWmA3395uL2eB2NB8y8qdQ9muXUdPBWE4l9rMZ6gmfu90N5B5uEl
#    94NcfBfYOKi1fJQ9i7WKhTjlRkMCgBkWPkUokvBZFRt8RtF7zI77BSEorHGQCk9t
#    /D7BS0GJyfVEhftbWcFEAG3VRcoMhF7kUzYwp+qESoriFRYLeDWv68ZOvG7eoWnP
#    PsvZStEVEimjvK5NSESEQa9xWyJOmlOKXhkdymtcUd/nXnx6UTCFgnkgzSdTWV41
#    CI6B6aJ9svCTI2QuoIq2HxX/ix7OvW1huVmcyHVxyUECAwEAAaNTMFEwHQYDVR0O
#    BBYEFPwN1OceFGm9v6ux8G+DZ3TUDYxqMB8GA1UdIwQYMBaAFPwN1OceFGm9v6ux
#    8G+DZ3TUDYxqMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAG5D
#    874A4YI7YUwOVsVAdbWtgp1d0zKcPRR+r2OdSbTAV5/gcS3jgBJ3i1BN34JuDVFw
#    3DeJSYT3nxy2Y56lLnxDeF8CUTUtVQx3CuGkRg1ouGAHpO/6OqOhwLLorEmxi7tA
#    H2O8mtT0poX5AnOAhzVy7QW0D/k4WaoLyckM5hUa6RtvgvLxOwA0U+VGurCDoctu
#    8F4QOgTAWyh8EZIwaKCliFRSynDpv3JTUwtfZkxo6K6nce1RhCWFAsMvDZL8Dgc0
#    yvgJ38BRsFOtkRuAGSf6ZUwTO8JJRRIFnpUzXflAnGivK9M13D5GEQMmIl6U9Pvk
#    sxSmbIUfc2SGJGCJD4I=
#    -----END CERTIFICATE-----
`.
    -   **Tags**: Default: `['forwarded', 'fortinet_fortimanager-log']`.
    -   **Preserve duplicate custom fields**: Preserve fortinet_fortimanager.log fields that were copied to Elastic Common Schema (ECS) fields. Default: `False`.
    -   **Processors**: Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
3.  Save and deploy the integration.

### Collecting logs from Fortinet FortiManager instances via udp input.
1.  Select the **Collecting logs from Fortinet FortiManager instances via udp input.** input type in Kibana.
2.  Configure the following fields:
    -   **Listen Address**: The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
    -   **Listen Port**: The UDP port number to listen on. Default: `9022`.
    -   **Preserve original event**: Preserves a raw copy of the original event, added to the field `event.original`. Default: `False`.
    -   **Tags**: Default: `['forwarded', 'fortinet_fortimanager-log']`.
    -   **Preserve duplicate custom fields**: Preserve fortinet_fortimanager.log fields that were copied to Elastic Common Schema (ECS) fields. Default: `False`.
    -   **Processors**: Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. This executes in the agent before the logs are parsed. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.
    -   **Custom UDP Options**: Specify custom configuration options for the UDP input. Default: `
#max_message_size: 50KiB
#timeout: 300s
`.
3.  Save and deploy the integration.

# Validation Steps

After configuration is complete, follow these steps to verify data is flowing correctly from Fortinet FortiManager to the Elastic Stack.

### 1. Trigger Data Flow on Fortinet FortiManager:
1.  **Generate a configuration event:** Log in to the FortiManager web GUI using your administrative account. Navigate to a configuration section, make a minor, non-impactful change (e.g., add a comment to an unused address object), save the change, and then revert it. These actions typically generate `objcfg` or `devmgr` logs.
2.  **Trigger a system event:** Access the FortiManager CLI console and execute a simple system diagnostic command, such as `diagnose sys top` or `show system status`.
3.  **Perform a login/logout:** Explicitly log out of the FortiManager web GUI and then log back in. This will generate authentication and system access logs.
4.  **Initiate a report (if FortiAnalyzer is connected):** If your FortiManager is managing a FortiAnalyzer, navigate to the FortiAnalyzer features and run a quick, small report to generate `report` related logs.

### 2. Check Data in Kibana:
1.  Navigate to **Analytics > Discover** in Kibana.
2.  Select the `logs-*` data view or the specific integration data view.
3.  Enter the following KQL filter: `data_stream.dataset : "fortinet_fortimanager.log"`
4.  Verify logs appear in the results. Expand a log entry and confirm these fields are populated:
    -   `event.dataset` (should be `fortinet_fortimanager.log`)
    -   `source.ip` (IP address of the FortiManager/FortiAnalyzer device)
    -   `event.action` or `event.outcome` (e.g., `login`, `logout`, `change`, `report`)
    -   `fortinet.fortimanager.type` (e.g., `event`, `traffic`)
    -   `fortinet.fortimanager.subtype` (e.g., `system`, `objcfg`, `devmgr`, `report`)
    -   `message` (containing the raw log payload)
5.  Navigate to **Analytics > Dashboards** and search for "Fortinet FortiManager" to view pre-built visualizations and dashboards.

# Troubleshooting

## Common Configuration Issues

-   **No logs received by Elastic Agent**:
    -   **Cause**: The FortiManager/FortiAnalyzer is not configured to send logs to the correct IP address or port, or a network firewall is blocking the traffic. The Elastic Agent might also not be listening on the expected address or port.
    -   **Solution**:
        1.  Verify the `IP address (or FQDN)` and `Syslog Server Port` in the FortiManager GUI (**System Settings > Advanced > Syslog Server**) match the `Listen Address` and `Listen Port` configured in the Elastic Agent integration.
        2.  Check for any network firewalls between the FortiManager/FortiAnalyzer and the Elastic Agent host that might be blocking the Syslog port (e.g., 514 or 9022).
        3.  On the Elastic Agent host, use `netstat -tulnp | grep <port>` (Linux) or similar commands to confirm the Elastic Agent is actively listening on the configured port.
-   **Incorrect protocol configuration (TCP vs UDP)**:
    -   **Cause**: A mismatch between the protocol configured on the FortiManager/FortiAnalyzer and the Elastic Agent's input type. If FortiManager sends via TCP, but Agent expects UDP, no logs will be processed.
    -   **Solution**: Ensure the `Reliable Connection` option in the FortiManager GUI Syslog Server settings (under **System Settings > Advanced > Syslog Server**) is enabled if you are using the Elastic Agent's **TCP input**, or disabled if you are using the **UDP input**. Update the Elastic Agent integration input accordingly to match.
-   **Log forwarding not enabled or severity too low**:
    -   **Cause**: The CLI commands to enable log forwarding (`set status enable`) or the configured severity level (`set severity information`) were not correctly applied or are too restrictive.
    -   **Solution**: Re-access the FortiManager CLI and verify the configuration settings in `config system locallog syslogd setting`. Ensure `set status enable` is active and `set severity information` is set to `information` (or a level appropriate for your logging needs) to capture sufficient logs.
-   **Filestream input permission issues**:
    -   **Cause**: If using the filestream input, the Elastic Agent process lacks the necessary read permissions to access the FortiManager/FortiAnalyzer log files specified in the `Paths` variable.
    -   **Solution**: On the host where the log files reside, verify that the user account running the Elastic Agent has read and execute permissions for the log file directory and read permissions for the log files themselves. Adjust file system permissions (`chmod`, `chown`) as required.

## Ingestion Errors

-   **Parsing failures or incomplete events**:
    -   **Cause**: Logs received by the Elastic Agent are not in the expected Syslog format, are malformed, or are truncated due to message size limits, leading to errors in the parsing pipeline.
    -   **Solution**:
        1.  In Kibana Discover, apply a filter like `error.message : *` to identify events that failed to parse.
        2.  If the `preserve_original_event` setting is enabled in your integration, examine the `event.original` field for these erroring events to see the raw log content received by the Agent. This can help identify formatting issues at the source.
        3.  If logs appear truncated, consider increasing the `max_message_size` in the `Custom TCP Options` or `Custom UDP Options` within your Elastic Agent integration configuration to accommodate larger log messages.
-   **Missing or incorrect fields**:
    -   **Cause**: Some expected ECS fields (e.g., `source.ip`, `event.action`) or Fortinet-specific fields are not populated, or their values are incorrect, indicating a potential issue with the processing pipeline's field extraction.
    -   **Solution**:
        1.  Ensure that FortiManager/FortiAnalyzer is sending logs with complete information, including source IP, event type, and other relevant details.
        2.  If specific custom fields are expected to be copied to ECS, verify the `preserve_duplicate_custom_fields` setting in the Kibana integration configuration.
        3.  For advanced cases, custom processors can be added to the Elastic Agent integration configuration to apply additional parsing logic or field manipulations.

## Vendor Resources

-   [FortiManager & FortiAnalyzer Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/5a0d548a-12b0-11ed-9eba-fa163e15d75b/FortiManager_%26_FortiAnalyzer_7.2.1_Log_Reference.pdf) - A comprehensive guide detailing the log messages generated by FortiManager and FortiAnalyzer.
-   [Fortinet FortiManager VM Install Guide](https://help.fortinet.com/fmgr/vm-install/56/Resources/HTML/0000_OnlineHelp%20Cover.htm) - Provides instructions and resources for installing FortiManager as a virtual machine.

# Documentation sites

-   [FortiManager & FortiAnalyzer Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/5a0d548a-12b0-11ed-9eba-fa163e15d75b/FortiManager_%26_FortiAnalyzer_7.2.1_Log_Reference.pdf) - Detailed log reference documentation for FortiManager and FortiAnalyzer.
-   [Fortinet FortiManager VM Install Guide](https://help.fortinet.com/fmgr/vm-install/56/Resources/HTML/0000_OnlineHelp%20Cover.htm) - Official installation guide for FortiManager virtual machines.