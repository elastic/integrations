# Cisco Nexus Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview
The Cisco Nexus integration for Elastic enables you to collect and parse system messages and error logs from Cisco Nexus series switches running NX-OS. These modular and fixed-port network switches are designed for data center environments, and this integration provides critical visibility into the operational health and security status of your networking infrastructure.

This integration facilitates:
- Infrastructure health monitoring: Monitors system-level events such as hardware failures, environmental alarms (temperature, power), and module status changes to ensure high availability.
- Network troubleshooting: Analyzes interface flaps, spanning tree (STP) changes, and routing protocol updates to identify and resolve connectivity issues within the fabric.
- Security auditing and compliance: Tracks user authentication attempts, configuration changes, and access control list (ACL) hits.
- Performance analysis: Reviews system resource warnings and buffer utilization logs to proactively address potential bottlenecks before they impact performance.

### Compatibility
This integration is compatible with the following Cisco Nexus products and operating systems:
- Cisco Nexus Series Switches: Tested against 9000 Series, 3172T, and 3048 models.
- Cisco NX-OS: Verified against NX-OS Release 6.x and is expected to work with later versions.
- Virtual Routing and Forwarding (VRF): Supports management and default VRF instances for log forwarding.

### How it works
The Cisco Nexus integration collects data from your switches by receiving syslog messages over the network (via UDP or TCP) or by reading from local log files. You'll deploy an Elastic Agent on a host that's configured as a syslog receiver or has access to the stored logs. The agent ingests the raw data, parses it into Elastic Common Schema (ECS) fields, and forwards it to your Elastic deployment where you can monitor, search, and visualize it.

## What data does this integration collect?

The Cisco Nexus integration collects log messages of the following types:
* System messages including high-level operational logs like system boot information, module status, and process events.
* Error logs providing detailed error messages categorized by severity levels 0 through 7, which cover everything from emergency system failures to informational debugging data.
* Configuration events that capture when you enter configuration mode and any specific changes you've made to the switch running configuration.

Logs are primarily collected in Syslog format using RFC 3164 or RFC 5424.

### Supported use cases

Integrating Cisco Nexus logs with the Elastic Stack helps you monitor your network infrastructure more effectively. You can use this integration for the following:
* System health monitoring to track module status and system processes.
* Troubleshooting and diagnostics using error logs across all severity levels to resolve issues quickly.
* Audit and compliance by monitoring configuration changes to maintain a record of switch modifications.
* Operational visibility to gain a centralized view of network events and correlate data with other system logs.

## What do I need to use this integration?

Before you begin, ensure your environment meets the following requirements:

### Vendor requirements

To collect logs from your Cisco Nexus devices, you'll need:
- Administrative access to the Cisco Nexus switch with `network-admin` or equivalent CLI privileges via SSH or console.
- Network connectivity from the switch to the Elastic Agent. If you use a management VRF, ensure you've configured the routing correctly.
- Firewall rules that permit traffic on the configured port, which defaults to `9506`.
- Clocks synchronized across your switches using NTP to ensure log timestamps are accurate for correlation in Kibana.
- A standard NX-OS image that includes basic system management features.

### Elastic requirements

On the Elastic Stack side, you'll need the following:
- An active Elastic Agent installed and enrolled in Fleet.
- The Elastic Stack running with Kibana version `8.11.0` or higher.
- Connectivity between the Elastic Agent and the Cisco Nexus switch over the designated syslog port using TCP or UDP.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that can receive syslog data or has access to the log files from the Cisco Nexus switch. For details on installation, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events are processed via the integration's ingest pipelines.

### Set up steps in Cisco Nexus

You can configure your Cisco Nexus switch to send logs to the Elastic Agent using syslog or by writing messages to a local file.

#### Syslog configuration

To configure syslog for UDP or TCP collection, use the following steps:

1. Log in to the Cisco Nexus switch CLI via SSH or console.
2. Enter global configuration mode:
```bash
switch# configure terminal
```
3. Set the timestamp granularity to milliseconds:
```bash
switch(config)# logging timestamp milliseconds
```
4. Configure the remote logging server pointing to the Elastic Agent IP:
   - For UDP (Standard):
     ```bash
     switch(config)# logging server <ELASTIC_AGENT_IP> 6 use-vrf <vrf_name>
     ```
   - For Secure TCP/TLS (NX-OS 9.2(1) and later):
     ```bash
     switch(config)# logging server <ELASTIC_AGENT_IP> 6 port 6514 secure use-vrf <vrf_name>
     ```
     > **Note:** NX-OS does not support standard (unencrypted) TCP syslog. The `secure` keyword enables TLS-encrypted syslog on port `6514`. You must configure SSL on the Elastic Agent TCP input to accept TLS connections and update the integration's listen port to `6514`.
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

#### Log file configuration

To configure log file collection, use the following steps:

1. Log in to the Cisco Nexus switch CLI.
2. Configure the switch to write system messages to a local file:
```bash
switch# configure terminal
switch(config)# logging logfile <FILENAME> <SEVERITY_LEVEL>
```
3. Ensure the Elastic Agent has file system access to the directory where the log file is stored.

#### Vendor resources

For more detailed information, refer to the following:
- [Cisco Nexus 9000 Series NX-OS System Management Configuration Guide - Configuring System Message Logging](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/system_management/configuration/guide/b_Cisco_Nexus_9000_Series_NX-OS_System_Management_Configuration_Guide/sm_5syslog.html)

### Set up steps in Kibana

To set up the integration in Kibana, follow these steps:

1. In Kibana, navigate to Management > Integrations.
2. Search for Cisco Nexus and select the integration.
3. Click Add Cisco Nexus.
4. Configure the integration by selecting an input type and providing the necessary settings. This integration supports TCP, UDP, and Log file inputs.

Choose the setup instructions below that match your configuration.

#### TCP input configuration

This input collects logs over a TCP socket. Configure the following settings:

- Listen address (`listen_address`): The bind address for the TCP listener (e.g., `0.0.0.0`). Default: `localhost`.
- Listen port (`listen_port`): The TCP port number to listen on. Default: `9506`.
- Timezone map (`tz_map`): A mapping of timezone strings found in logs to standard IANA timezone formats.
- Timezone offset (`tz_offset`): The offset to use when timestamps lack timezone information.
- Preserve original event (`preserve_original_event`): If enabled, a raw copy of the log is stored in `event.original`. Default: `false`.
- SSL configuration (`ssl`): Options for secure transmission. For more details, see the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config).
- Custom TCP options (`tcp_options`): Options such as `framing`, `max_message_size`, or `max_connections`.
- Tags (`tags`): Custom tags to add to the events. Default: `['forwarded', 'cisco_nexus-log']`.
- Preserve duplicate custom fields (`preserve_duplicate_custom_fields`): Whether to keep fields that were copied to ECS fields. Default: `false`.
- Processors (`processors`): Custom rules to enhance or filter events. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

#### UDP input configuration

This input collects logs over a UDP socket. Configure the following settings:

- Listen address (`listen_address`): The bind address for the UDP listener (e.g., `0.0.0.0`). Default: `localhost`.
- Listen port (`listen_port`): The UDP port number to listen on. Default: `9506`.
- Timezone map (`tz_map`): A mapping of timezone strings to standard IANA formats.
- Timezone offset (`tz_offset`): The offset used when no timezone is present in the log.
- Preserve original event (`preserve_original_event`): If enabled, stores a raw copy in `event.original`. Default: `false`.
- Custom UDP options (`udp_options`): Options such as `max_message_size` and `timeout`.
- Tags (`tags`): Custom tags to add to the events. Default: `['forwarded', 'cisco_nexus-log']`.
- Preserve duplicate custom fields (`preserve_duplicate_custom_fields`): Whether to keep fields copied to ECS. Default: `false`.
- Processors (`processors`): Rules for agent-side filtering and enhancement. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

#### Log file input configuration

This input collects logs directly from files. Configure the following settings:

- Paths (`paths`): A list of glob-based file paths to monitor.
- Timezone map (`tz_map`): A mapping of timezone strings to standard IANA formats.
- Timezone offset (`tz_offset`): The offset used when no timezone is present in the log.
- Preserve original event (`preserve_original_event`): If enabled, stores a raw copy in `event.original`. Default: `false`.
- Tags (`tags`): Custom tags to add to the events. Default: `['forwarded', 'cisco_nexus-log']`.
- Preserve duplicate custom fields (`preserve_duplicate_custom_fields`): Whether to keep fields copied to ECS. Default: `false`.
- Processors (`processors`): Rules for agent-side filtering and enhancement. See [Processors](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details.

After configuring the input, click Save and continue to deploy the integration.

### Validation

To verify the integration is working and data is flowing, follow these steps:

1. Navigate to Management > Fleet > Agents and verify that the Elastic Agent status is "Healthy".
2. On your Cisco Nexus device, trigger data flow using one of the following methods:
   - Enter and exit global configuration mode by running `configure terminal` followed by `exit` to generate a `SYS-5-CONFIG_I` log message.
   - Perform a `shutdown` and `no shutdown` command on a test interface (e.g., `interface Ethernet1/1`) to generate status change logs.
   - Log out and log back in to generate AAA/User login messages.
3. In Kibana, navigate to Analytics > Discover.
4. Select the `logs-*` data view and search for `data_stream.dataset: "cisco_nexus.log"`.
5. Verify that logs appear with recent timestamps and that fields such as `event.dataset`, `source.ip`, and `event.code` are correctly populated.
6. Navigate to Analytics > Dashboards and search for "Cisco Nexus" to confirm that the pre-built dashboards are populated with your data.

## Troubleshooting

For help with Elastic ingest tools, check the [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation.

### Common configuration issues

- No data is being collected:
  You can troubleshoot connectivity and listener issues by:
  - Verifying that the port specified in the integration (default `9506`) isn't being used by another service on the Elastic Agent host using a command like `netstat -ano | grep 9506`.
  - Checking that local firewalls on the Elastic Agent host (like `iptables` or `firewalld`) and network ACLs allow traffic on the configured TCP or UDP port.
  - Ensuring the Cisco Nexus switch has a valid network path to the Elastic Agent IP address.
- VRF configuration issues:
  You should verify the Virtual Routing and Forwarding (VRF) settings on the switch because logging often occurs over a specific instance:
  - Confirm if the switch is using the `management` VRF or a custom VRF to reach the network.
  - Update the logging command on the switch to include the correct VRF, for example: `logging server <ELASTIC_AGENT_IP> 6 use-vrf management`.
- Timestamp and timezone parsing errors:
  You can fix issues where events appear with the wrong time or fail to parse by:
  - Configuring the switch to use millisecond precision with the command `logging timestamp milliseconds`.
  - Verifying the switch's system time and NTP synchronization settings.
  - Using the `Timezone Offset` or `Timezone Map` parameters in the integration settings to align the switch's local time with the Elastic Stack.
- Ingestion and field mapping errors:
  You can identify why specific fields aren't appearing or are failing to map by:
  - Checking the `error.message` field in Kibana Discover for specific details about parsing failures.
  - Verifying the switch is using the standard NX-OS logging format, as custom log formats might not be compatible with the integration's processors.
  - Confirming that you aren't forwarding debug-level logs (level 7) unless necessary, as these can vary significantly in format and volume.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure optimal performance in high-volume data center environments, you should consider the following configuration and deployment factors:
- While UDP's faster for transmission, you should use TCP for Cisco Nexus logs in environments where you need delivery guarantees. TCP ensures you don't lose log messages due to network congestion, though it introduces slightly higher overhead on the switch's control plane.
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
- [Cisco Nexus 9000 Series Switches Support Home](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/series.html)
- [Cisco NX-OS System Message Guides](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-system-message-guides-list.html)
- [Configuring System Message Logging](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/system_management/configuration/guide/b_Cisco_Nexus_9000_Series_NX-OS_System_Management_Configuration_Guide/sm_5syslog.html)