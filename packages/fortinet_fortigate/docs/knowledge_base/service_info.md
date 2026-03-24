# Service Info

## Common use cases
- Security monitoring and threat detection from FortiGate firewall logs
- Network traffic analysis and monitoring
- Firewall policy compliance and auditing
- Intrusion detection and prevention system (IPS) event monitoring
- VPN connection monitoring and troubleshooting
- Web filtering and application control monitoring

## Data types collected
- Traffic logs (firewall allow/deny decisions)
- UTM logs (antivirus, web filter, application control, IPS, DNS filter)
- Event logs (system events, HA events, configuration changes)
- Authentication logs (VPN, admin, and user authentication events)

## Compatibility
This integration has been tested against FortiOS versions 6.x and 7.x up to 7.4.1. Newer versions are expected to work but have not been tested.

## Scaling and Performance


# Set Up Instructions

## Vendor prerequisites
- FortiGate firewall with access to configure syslog settings
- Network connectivity between FortiGate and Elastic Agent


## Vendor set up steps

### Syslog Configuration
You can configure FortiGate to send logs to the Elastic Agent using either the GUI or the CLI.

**GUI Configuration:**

1.  Log in to the FortiGate web-based manager (GUI).
2.  Navigate to **Log & Report -> Log Settings**.
3.  Enable **Send Logs to Syslog**.
4.  In the IP address field, enter the IP address of the host where the Elastic Agent is installed.
5.  Click **Apply**.
6.  Under **Log Settings**, ensure that **Event Logging** and all desired log subtypes are enabled to generate and send the necessary logs.

**CLI Configuration:**

1.  Log in to the FortiGate CLI.
2.  Use the following commands to configure the syslog server settings:

    ```sh
    config log syslogd setting
        set status enable
        set server "<elastic_agent_ip>"
        set port <port>  // Default syslog ports are 514 for UDP and TCP
        // For TCP with reliable syslog mode, ensure framing is set to rfc6587
        set mode reliable
        set format rfc6587
    end
    ```

3.  Configure the appropriate log types and severity levels to be sent to the syslog server. For example:

    ```sh
    config log syslogd filter
        set severity information
        set forward-traffic enable
        set local-traffic enable
        set web enable
        set antivirus enable
        // Enable other UTM and event logs as needed
    end
    ```

For more detailed information, refer to the [FortiGate CLI reference](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/405620/config-log-syslogd-setting).

## Kibana set up steps
1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "Fortinet FortiGate Firewall Logs" and select the integration.
3.  Click **Add Fortinet FortiGate Firewall Logs**.
4.  Configure the integration by selecting an input type and providing the necessary settings. This integration supports `TCP`, `UDP`, and `Log file` inputs.

#### TCP Input Configuration

This input collects logs over a TCP socket.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address for the TCP listener (e.g., `localhost`, `0.0.0.0`). |
| **Listen Port** | The TCP port number to listen on (e.g., `9004`). |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced Options**, you can configure the following optional parameters:

| Setting | Description |
|---|---|
| **Internal/External interfaces** | Define your network interfaces to correctly map network direction. |
| **Internal networks** | Specify your internal network ranges (defaults to private address spaces). Supports CIDR notation and named ranges like `private`. |
| **SSL Configuration** | Configure SSL options for encrypted communication. See the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details. |
| **Custom TCP Options** | `framing`: Specifies how messages are framed. Defaults to `rfc6587`, which is required for FortiGate's reliable syslog mode. <br> `max_message_size`: The maximum size of a log message (e.g., `50KiB`). <br> `max_connections`: The maximum number of simultaneous connections. |
| **Timezone** | Specify an IANA timezone or offset (e.g., `+0200`) for logs with no timezone information. |
| **Timezone Map** | A mapping of timezone strings from logs to standard IANA timezone formats. |
| **Processors** | Add custom processors to enhance or reduce event fields before parsing. |

#### UDP Input Configuration

This input collects logs over a UDP socket.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address for the UDP listener (e.g., `localhost`, `0.0.0.0`). |
| **Listen Port** | The UDP port number to listen on (e.g., `9004`). |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced Options**, you can configure the following optional parameters:

| Setting | Description |
|---|---|
| **Internal/External interfaces** | Define your network interfaces to correctly map network direction. |
| **Internal networks** | Specify your internal network ranges (defaults to private address spaces). |
| **Custom UDP Options** | `read_buffer`: The size of the read buffer for the UDP socket (e.g., `100MiB`). <br> `max_message_size`: The maximum size of a log message (e.g., `50KiB`). <br> `timeout`: The read timeout for the UDP socket (e.g., `300s`). |
| **Timezone** | Specify an IANA timezone or offset (e.g., `+0200`) for logs with no timezone information. |
| **Timezone Map** | A mapping of timezone strings from logs to standard IANA timezone formats. |
| **Processors** | Add custom processors to enhance or reduce event fields before parsing. |

#### Log file Input Configuration

This input collects logs directly from log files on the host where the Elastic Agent is running.

| Setting | Description |
|---|---|
| **Paths** | A list of file paths to monitor (e.g., `/var/log/fortinet-firewall.log`). |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |

Under **Advanced Options**, you can configure the following optional parameters:

| Setting | Description |
|---|---|
| **Internal/External interfaces** | Define your network interfaces to correctly map network direction. |
| **Internal networks** | Specify your internal network ranges (defaults to private address spaces). |
| **Timezone** | Specify an IANA timezone or offset (e.g., `+0200`) for logs with no timezone information. |
| **Timezone Map** | A mapping of timezone strings from logs to standard IANA timezone formats. |
| **Processors** | Add custom processors to enhance or reduce event fields before parsing. |

After configuring the input, assign the integration to an agent policy and click **Save and continue**.

# Validation Steps
1. Verify logs are being sent from FortiGate by checking the syslog configuration
2. In Kibana, navigate to Discover and search for `data_stream.dataset: "fortinet_fortigate.log"`
3. Verify that events are appearing with recent timestamps
4. Check the dashboards provided by the integration (Management > Dashboards > "Fortinet FortiGate Overview")
5. Generate test traffic on FortiGate (e.g., web browsing, firewall hits) and verify corresponding logs appear in Kibana

# Troubleshooting

## Common Configuration Issues
- **No data collected**: Verify network connectivity between FortiGate and Elastic Agent. Check that the configured listen port matches the port configured on FortiGate.
- **TCP framing issues**: When using TCP with reliable syslog mode, ensure framing is set to `rfc6587` in both FortiGate configuration and the integration settings.

## Vendor Resources
- [FortiGate CLI Reference - Syslog Settings](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/405620/config-log-syslogd-setting)

# Documentation sites
- [Fortinet Documentation Library](https://docs.fortinet.com/)
- [FortiGate Administration Guide](https://docs.fortinet.com/product/fortigate)
- [Technical Tip: How to configure syslog on FortiGate](https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-to-configure-syslog-on-FortiGate/ta-p/331959)
