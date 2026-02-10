# Cisco Nexus Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Cisco Nexus integration for Elastic enables you to collect and parse system messages and error logs from Cisco Nexus series switches running NX-OS. These modular and fixed-port network switches are designed for data center environments, and this integration provides critical visibility into the operational health and security status of your networking infrastructure.

This integration facilitates:
- Infrastructure health monitoring: Monitor system-level events such as hardware failures, environmental alarms (temperature, power), and module status changes to ensure high availability.
- Network troubleshooting: Analyze interface flaps, spanning tree (STP) changes, and routing protocol updates to identify and resolve connectivity issues quickly within the fabric.
- Security auditing and compliance: Track user authentication attempts, configuration changes, and access control list (ACL) hits for security auditing.
- Performance analysis: Review system resource warnings and buffer utilization logs to proactively address potential bottlenecks before they impact network performance.

### Compatibility

This integration is compatible with the following Cisco Nexus products and operating systems:
- Cisco Nexus series switches: Tested against 9000 Series, 3172T, and 3048 models.
- Cisco NX-OS: Verified against NX-OS Release 6.x and is expected to work with later versions.
- Virtual Routing and Forwarding (VRF): Supports management and default VRF instances for log forwarding.

### How it works

This integration collects data from your switches by receiving syslog messages over the network via UDP or TCP, or by reading from local log files. You'll deploy an Elastic Agent on a host that's configured as a syslog receiver or has access to the log files. The agent ingests the raw data, parses it into Elastic Common Schema (ECS) fields, and forwards it to your Elastic deployment where you can monitor, search, and visualize it.

## What data does this integration collect?

The Cisco Nexus integration collects log messages of the following types:
* System messages: High-level operational logs including system start up information, module status, and process events.
* Error logs: Detailed error messages categorized by severity levels 0 through 7, which cover everything from emergency system failures to informational debugging data.
* Configuration events: Logs capturing when you enter configuration mode and any specific changes you've made to the switch running configuration.

Logs are primarily collected in Syslog format using RFC 3164 or RFC 5424.

### Supported use cases

Integrating Cisco Nexus logs with the Elastic Stack helps you monitor your network infrastructure more effectively. Key use cases include:
* System health monitoring to track module status and system processes.
* Troubleshooting and diagnostics using error logs across all severity levels to resolve issues quickly.
* Audit and compliance by monitoring configuration changes to maintain a record of switch modifications.
* Operational visibility to gain a centralized view of network events and correlate data with other system logs.

## What do I need to use this integration?

Before you can collect data, ensure your environment meets these requirements:

### Vendor requirements

To collect logs from your Cisco Nexus devices, you'll need to ensure:
- You have administrative access with `network-admin` or equivalent CLI access to the Cisco Nexus switch using SSH or console.
- The switch has a network path to the Elastic Agent. If you're using a management VRF, you'll need to ensure routing is correctly configured.
- Your firewalls permit traffic on the configured port, which defaults to `9506`.
- You've synchronized switch clocks using NTP to ensure log timestamps are accurate for correlation in Kibana.
- Basic system management features are available, which are typically included in standard NX-OS images.

### Elastic requirements

On the Elastic side, you'll need the following:
- An active Elastic Agent installed and enrolled in Fleet.
- An Elastic Stack deployment running Kibana version `8.11.0` or higher.
- Connectivity between the Elastic Agent and the Cisco Nexus switch over the designated syslog port using TCP or UDP.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that can receive syslog data or has access to the log files from the Cisco Nexus switch. For details on installation, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events are processed via the integration's ingest pipelines.

### Set up steps in Cisco Nexus

You can configure your Cisco Nexus switch to send logs to the Elastic Agent using syslog (UDP or TCP) or by writing messages to a local file.

#### Syslog collection

To configure syslog for UDP or TCP collection, follow these steps:

1. Log in to the Cisco Nexus switch CLI using SSH or console.
2. Enter global configuration mode:
   ```bash
   switch# configure terminal
   ```
3. Set the timestamp granularity to milliseconds:
   ```bash
   switch(config)# logging timestamp milliseconds
   ```
4. Configure the remote logging server pointing to the Elastic Agent IP:
   *   For UDP (Standard):
       ```bash
       switch(config)# logging server <ELASTIC_AGENT_IP> 6 use-vrf <vrf_name>
       ```
   *   For Secure TCP/TLS (NX-OS 9.2(1) and later):
       ```bash
       switch(config)# logging server <ELASTIC_AGENT_IP> 6 port 6514 secure use-vrf <vrf_name>
       ```
       Note: NX-OS does not support standard (unencrypted) TCP syslog. The `secure` keyword enables TLS-encrypted syslog on port `6514`. Ensure SSL is configured on the Elastic Agent TCP input to accept TLS connections, and update the integration's listen port to `6514` accordingly.
5. Specify the source interface for syslog traffic:
   ```bash
   switch(config)# logging source-interface loopback 0
   ```
6. Verify the logging configuration:
   ```bash
   switch(config)# show logging server
   ```
7. Save the configuration:
   ```bash
   switch(config)# copy running-config startup-config
   ```

#### Log file collection

To configure log file collection, follow these steps:

1. Log in to the Cisco Nexus switch CLI.
2. Configure the switch to write system messages to a local file:
   ```bash
   switch# configure terminal
   switch(config)# logging logfile <FILENAME> <SEVERITY_LEVEL>
   ```
3. Ensure the Elastic Agent has file system access to the directory where the log file is stored.

#### Vendor resources

For more information, refer to the Cisco documentation:
- [Cisco Nexus 9000 Series NX-OS System Management Configuration Guide - Configuring System Message Logging](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/system_management/configuration/guide/b_Cisco_Nexus_9000_Series_NX-OS_System_Management_Configuration_Guide/sm_5syslog.html)

### Set up steps in Kibana

To set up the integration in Kibana, follow these steps:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Cisco Nexus** and select the integration.
3. Click **Add Cisco Nexus**.
4. Configure the integration by selecting an input type and providing the necessary settings. This integration supports `TCP`, `UDP`, and `Log file` inputs.

Choose the setup instructions below that match your configuration:

#### TCP input configuration

This input collects logs over a TCP socket. Configure the following settings:

*   `Listen Address` (`listen_address`): The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
*   `Listen Port` (`listen_port`): The TCP port number to listen on. Default: `9506`.
*   `Timezone Map` (`tz_map`): A collection of timezones found in Cisco Nexus logs (as defined in each `tz_short`), and the replacement value (as defined in each `tz_long`) which should be the full proper IANA Timezone format. This is used to override vendor-provided timezone formats not supported by Elasticsearch [Date Processors](https://www.elastic.co/docs/reference/enrich-processor/date-processor#date-processor-timezones).
*   `Timezone Offset` (`tz_offset`): When interpreting syslog timestamps without a time zone, use this timezone offset. Datetimes recorded in logs are by default interpreted in relation to the timezone set up on the host where the agent is operating.
*   `Preserve original event` (`preserve_original_event`): Preserves a raw copy of the original event, added to the field `event.original`. Default: `false`.
*   `Custom TCP Options` (`tcp_options`): Specify custom configuration options for the TCP input, such as `framing`, `max_message_size`, or `max_connections`.
*   `SSL Configuration` (`ssl`): SSL configuration options for secure transmission. Refer to the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details.
*   `Tags` (`tags`): Custom tags to add to the events. Default: `['forwarded', 'cisco_nexus-log']`.
*   `Preserve duplicate custom fields` (`preserve_duplicate_custom_fields`): Preserve `cisco_nexus.log` fields that were copied to Elastic Common Schema (ECS) fields. Default: `false`.
*   `Processors` (`processors`): Processors are used to reduce the number of fields in the exported event or to enhance the event with metadata. Refer to [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

#### UDP input configuration

This input collects logs over a UDP socket. Configure the following settings:

*   `Listen Address` (`listen_address`): The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
*   `Listen Port` (`listen_port`): The UDP port number to listen on. Default: `9506`.
*   `Timezone Map` (`tz_map`): A collection of timezones found in Cisco Nexus logs, and the replacement value which should be the full proper IANA Timezone format.
*   `Timezone Offset` (`tz_offset`): When interpreting syslog timestamps without a time zone, use this timezone offset.
*   `Preserve original event` (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `false`.
*   `Custom UDP Options` (`udp_options`): Specify custom configuration options for the UDP input, such as `max_message_size` and `timeout`.
*   `Tags` (`tags`): Custom tags to add to the events. Default: `['forwarded', 'cisco_nexus-log']`.
*   `Preserve duplicate custom fields` (`preserve_duplicate_custom_fields`): Preserve `cisco_nexus.log` fields that were copied to ECS fields. Default: `false`.
*   `Processors` (`processors`): Processors used for agent-side filtering and metadata enhancement. Refer to [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

#### Log file input configuration

This input collects logs directly from files using the filestream input. Configure the following settings:

*   `Paths` (`paths`): A list of glob-based file paths to monitor.
*   `Timezone Map` (`tz_map`): A collection of timezones found in Cisco Nexus logs, and the replacement value which should be the full proper IANA Timezone format.
*   `Timezone Offset` (`tz_offset`): When interpreting syslog timestamps without a time zone, use this timezone offset.
*   `Preserve original event` (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `false`.
*   `Tags` (`tags`): Custom tags to add to the events. Default: `['forwarded', 'cisco_nexus-log']`.
*   `Preserve duplicate custom fields` (`preserve_duplicate_custom_fields`): Preserve `cisco_nexus.log` fields that were copied to ECS fields. Default: `false`.
*   `Processors` (`processors`): Define agent-side processing rules. Refer to [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

After configuring the input, click **Save and continue** to deploy the integration.

### Validation

To verify that the integration is working and data is flowing, follow these steps:

1.  Trigger data flow on the Cisco Nexus device using one of the following methods:
    *   Configuration event: Enter and exit global configuration mode by running `configure terminal` followed by `exit` to generate a `SYS-5-CONFIG_I` log message.
    *   Interface event: Perform a `shutdown` and `no shutdown` command on a test interface (for example, `interface Ethernet1/1`) to generate interface status change logs.
    *   Authentication event: Log out of the current SSH session and log back in to generate an AAA/User login message.
2.  In Kibana, navigate to **Analytics > Discover**.
3.  Select the `logs-*` data view.
4.  Enter the following KQL filter in the search bar: `data_stream.dataset : "cisco_nexus.log"`
5.  Verify that logs appear in the results with recent timestamps. Expand a log entry and confirm the presence of these fields:
    *   `event.dataset` (should be `cisco_nexus.log`)
    *   `source.ip` (should match the management IP of the Nexus switch)
    *   `event.code` (the NX-OS mnemonic, for example, `VSHD_SYSLOG_CONFIG_I` or `IF_UP`)
    *   `message` (the raw log payload)
6.  Navigate to **Analytics > Dashboards** and search for "Cisco Nexus" to view the pre-built dashboards and confirm visualization of the events.

## Troubleshooting

For help with Elastic ingest tools, check the [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation.

### Common configuration issues

You can resolve common connectivity and parsing issues by following these troubleshooting steps:

- No data is being collected:
    * Verify that the port specified in the integration (default `9506`) isn't being used by another service on the Elastic Agent host. You can check for active listeners on Linux using a command like `netstat -ano | grep 9506`.
    * Confirm that local firewalls on the Elastic Agent host, such as `iptables` or `firewalld`, and network access control lists (ACLs) allow traffic on the configured TCP or UDP port.
    * Ensure the Cisco Nexus switch has a valid network path to the Elastic Agent IP address.
- Virtual Routing and Forwarding (VRF) configuration issues:
    * On Cisco Nexus switches, logging often occurs over a specific VRF instance, such as the `management` VRF. If the switch can't reach the agent, ensure you've specified the correct VRF in the logging command.
    * Update the logging command on the switch to include the VRF, for example: `logging server <ELASTIC_AGENT_IP> 6 use-vrf management`.
- TCP connection failures:
    * Note that NX-OS doesn't support standard unencrypted TCP syslog. The `secure` keyword is required on the switch to enable TLS-encrypted syslog, which typically uses port `6514`. 
    * If you're using TCP, ensure you have configured SSL/TLS settings in the integration and that the switch is configured with the `secure` parameter: `logging server <ELASTIC_AGENT_IP> 6 port 6514 secure use-vrf <vrf_name>`.
- Timestamp and timezone parsing errors:
    * If events appear with the wrong time or fail to parse, verify that the switch is configured for millisecond precision using the command `logging timestamp milliseconds`.
    * Check the switch's system time and NTP synchronization settings.
    * Use the `Timezone Offset` or `Timezone Map` parameters in the integration settings to align the switch's local time with the Elastic Stack.
- Ingestion and field mapping errors:
    * Check the `error.message` field in Kibana Discover for specific details about parsing failures.
    * Verify the switch is using the standard NX-OS logging format, as custom log formats might not be compatible with the integration's processors.
    * Avoid forwarding debug-level logs (level 7) unless necessary, as these can vary significantly in format and volume, potentially causing mapping issues.

### Vendor resources

For more information about configuring and troubleshooting Cisco Nexus logging, refer to the following vendor documentation:

- [Cisco Nexus 9000 Series NX-OS System Management Configuration Guide - Configuring System Message Logging](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/system_management/configuration/guide/b_Cisco_Nexus_9000_Series_NX-OS_System_Management_Configuration_Guide/sm_5syslog.html)
- [Cisco Nexus Series Switches Support Home](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/series.html)
- [Cisco NX-OS System Message Guides](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-system-message-guides-list.html)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure optimal performance in high-volume data center environments, you should consider the following configuration and deployment factors:
- While UDP's faster for syslog transmission, you should use TCP for Cisco Nexus logs in environments where you need delivery guarantees. TCP ensures you don't lose log messages due to network congestion, though it introduces slightly higher overhead on the switch's control plane.
- Configure your Cisco Nexus appliance to forward only necessary events by setting the `logging level` at the source. It's recommended to use level `5` (Notifications) or level `6` (Informational) for production monitoring. You should avoid forwarding debug-level logs (level `7`) unless you're troubleshooting specific issues, as they can significantly increase CPU load on the switch and ingest volume in the Elastic Stack.
- For high-throughput environments with hundreds of switches, you can deploy multiple Elastic Agents behind a network load balancer to distribute the `log` data stream traffic evenly across instances. Place your agents close to the data source within the same management VRF to minimize latency and potential packet loss.

## Reference

### Inputs used

These inputs can be used with this integration:
<details>
<summary>filestream</summary>

## Setup

For more details about the Filestream input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-filestream).


### Collecting logs from Filestream

To collect logs via Filestream, select **Collect logs via Filestream** and configure the following parameters:

- Filestream paths: The full path to the related log file.
</details>
<details>
<summary>tcp</summary>

## Setup

For more details about the TCP input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-tcp).

### Collecting logs from TCP

To collect logs via TCP, select **Collect logs via TCP** and configure the following parameters:

**Required Settings:**
- Host
- Port

**Common Optional Settings:**
- Max Message Size - Maximum size of incoming messages
- Max Connections - Maximum number of concurrent connections
- Timeout - How long to wait for data before closing idle connections
- Line Delimiter - Character(s) that separate log messages

## SSL/TLS Configuration

To enable encrypted connections, configure the following SSL settings:

**SSL Settings:**
- Enable SSL - Toggle to enable SSL/TLS encryption
- Certificate - Path to the SSL certificate file (`.crt` or `.pem`)
- Certificate Key - Path to the private key file (`.key`)
- Certificate Authorities - Path to CA certificate file for client certificate validation (optional)
- Client Authentication - Require client certificates (`none`, `optional`, or `required`)
- Supported Protocols - TLS versions to support (e.g., `TLSv1.2`, `TLSv1.3`)

**Example SSL Configuration:**
```yaml
ssl.enabled: true
ssl.certificate: "/path/to/server.crt"
ssl.key: "/path/to/server.key"
ssl.certificate_authorities: ["/path/to/ca.crt"]
ssl.client_authentication: "optional"
```
</details>
<details>
<summary>udp</summary>

## Setup

For more details about the UDP input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-udp).

### Collecting logs from UDP

To collect logs via UDP, select **Collect logs via UDP** and configure the following parameters:

**Required Settings:**
- Host
- Port

**Common Optional Settings:**
- Max Message Size - Maximum size of UDP packets to accept (default: 10KB, max: 64KB)
- Read Buffer - UDP socket read buffer size for handling bursts of messages
- Read Timeout - How long to wait for incoming packets before checking for shutdown
</details>


### Data streams

The Cisco Nexus integration includes the following data stream:

#### log

The `log` data stream collects system messages and operational logs from Cisco Nexus switches. These logs provide information about device status, configuration changes, interface states, and other network events handled by the NX-OS software.

##### log fields

The following fields are exported by this data stream:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_nexus.log.command |  | keyword |
| cisco_nexus.log.description |  | keyword |
| cisco_nexus.log.euid |  | keyword |
| cisco_nexus.log.facility |  | keyword |
| cisco_nexus.log.interface.mode |  | keyword |
| cisco_nexus.log.interface.name |  | keyword |
| cisco_nexus.log.ip_address |  | ip |
| cisco_nexus.log.line_protocol_state |  | keyword |
| cisco_nexus.log.logname |  | keyword |
| cisco_nexus.log.network.egress_interface |  | keyword |
| cisco_nexus.log.network.ingress_interface |  | keyword |
| cisco_nexus.log.operating_value |  | keyword |
| cisco_nexus.log.operational.duplex_mode |  | keyword |
| cisco_nexus.log.operational.receive_flow_control_state |  | keyword |
| cisco_nexus.log.operational.speed |  | keyword |
| cisco_nexus.log.operational.transmit_flow_control_state |  | keyword |
| cisco_nexus.log.priority_number |  | long |
| cisco_nexus.log.pwd |  | keyword |
| cisco_nexus.log.rhost |  | keyword |
| cisco_nexus.log.ruser |  | keyword |
| cisco_nexus.log.sequence_number |  | long |
| cisco_nexus.log.severity |  | long |
| cisco_nexus.log.slot_number |  | long |
| cisco_nexus.log.standby |  | keyword |
| cisco_nexus.log.state |  | keyword |
| cisco_nexus.log.switch_name |  | keyword |
| cisco_nexus.log.syslog_time |  | date |
| cisco_nexus.log.terminal |  | keyword |
| cisco_nexus.log.threshold_value |  | keyword |
| cisco_nexus.log.time |  | date |
| cisco_nexus.log.timezone |  | keyword |
| cisco_nexus.log.tty |  | keyword |
| cisco_nexus.log.type |  | keyword |
| cisco_nexus.log.uid |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| tags | User defined tags. | keyword |


##### log sample event

A sample event for this data stream is as follows:

An example event for `log` looks as following:

```json
{
    "@timestamp": "2023-04-26T09:08:48.000Z",
    "agent": {
        "ephemeral_id": "520a22ce-a7c9-4d1d-83df-a6abd00f7f74",
        "id": "13671cfa-49ce-4139-8d65-90166401d5f5",
        "name": "elastic-agent-83602",
        "type": "filebeat",
        "version": "9.0.3"
    },
    "cisco_nexus": {
        "log": {
            "description": "last message repeated 3 time",
            "priority_number": 187,
            "switch_name": "switchname",
            "time": "2023-04-26T09:08:48.000Z",
            "timezone": "UTC"
        }
    },
    "data_stream": {
        "dataset": "cisco_nexus.log",
        "namespace": "90551",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "13671cfa-49ce-4139-8d65-90166401d5f5",
        "snapshot": false,
        "version": "9.0.3"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "cisco_nexus.log",
        "ingested": "2025-07-11T13:14:05Z",
        "kind": "event",
        "module": "cisco_nexus",
        "original": "<187>switchname: 2023 Apr 26 09:08:48 UTC: last message repeated 3 time",
        "timezone": "UTC"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.22.0.3:46916"
        },
        "syslog": {
            "priority": 187
        }
    },
    "message": "last message repeated 3 time",
    "observer": {
        "name": "switchname",
        "product": "Nexus",
        "type": "switches",
        "vendor": "Cisco"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cisco_nexus-log"
    ]
}
```

### Vendor documentation links

You can find more information about Cisco Nexus logs and system messages in the following resources:
- [Cisco Nexus Series Switches Support Home](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/series.html)
- [Cisco NX-OS System Message Guides](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-system-message-guides-list.html)
- [Configuring System Message Logging](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/system_management/configuration/guide/b_Cisco_Nexus_9000_Series_NX-OS_System_Management_Configuration_Guide/sm_5syslog.html)
