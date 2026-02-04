# Cisco IOS Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The Cisco IOS integration for Elastic enables you to collect system logs from Cisco routers and switches, providing centralized visibility into network health and security events. By ingesting these logs into the Elastic Stack, you can monitor infrastructure stability, respond to critical events in real-time, and maintain historical records of system activity for your network environment.

This integration facilitates:
- Security monitoring and auditing: Track unauthorized access attempts, configuration changes, and privilege escalations across the entire network fabric by analyzing system message logs.
- Network troubleshooting: Rapidly identify and diagnose hardware failures, interface flapping, or routing protocol changes such as EIGRP or OSPF state transitions using centralized log data.
- Compliance and reporting: Maintain long-term historical records of system events to meet regulatory requirements for network logging and audit trails.
- Performance visibility: Monitor system-level notifications regarding resource exhaustion, such as high CPU or memory utilization alerts, to proactively manage device health.

### Compatibility

This integration is compatible with Cisco IOS and Cisco IOS-XE network devices that support standard syslog output over TCP, UDP, or local file logging. It's generally applicable to all modern Cisco IOS versions that support the `logging host` command and `service timestamps` configuration. Note that older versions of IOS might not support TCP transport for syslog; UDP is the most universally compatible method.

### How it works

This integration collects logs from Cisco IOS devices by receiving syslog data over TCP or UDP, or by reading directly from log files. You'll deploy an Elastic Agent on a host that's configured as a syslog receiver or has access to the log files. The agent collects the `log` data stream, parses the messages, and forwards them to your Elastic deployment where they're mapped to the Elastic Common Schema (ECS) for analysis.

## What data does this integration collect?

The Cisco IOS integration collects log messages of the following types:
* System message logs: Standard Cisco IOS logging messages including facility, severity, mnemonic, and descriptive text.
* Authentication logs: Events related to user logins, logouts, and command execution when you've enabled AAA logging on your devices.
* Interface logs: Status updates regarding physical and logical interfaces, including up/down state transitions.
* Protocol events: Log entries from routing protocols and network services like DHCP, VPN, and Spanning Tree.

This integration uses the `log` data stream to organize the collected information. This stream supports standard Cisco syslog formats and includes fields for sequencing and millisecond timestamps. You can collect these logs using the following methods:
* Network inputs: Collect logs directly via `UDP` or `TCP` inputs.
* File inputs: Collect logs from files for environments where logs are written to a local disk or an intermediate log aggregator.

### Supported use cases

Integrating your Cisco IOS logs with the Elastic Stack provides several benefits:
* Real-time security monitoring: You'll detect and respond to potential threats by monitoring authentication events and command execution across your network.
* Network performance analysis: You can use Kibana dashboards to visualize and analyze network traffic patterns, which helps you identify anomalies and optimize performance.
* Rapid incident response: When issues occur, you'll have a centralized location to correlate Cisco IOS data with other security and observability sources.
* Compliance and auditing: You'll maintain a searchable, long-term archive of logs to meet regulatory requirements and conduct thorough security audits.

## What do I need to use this integration?

Before you start collecting logs from your Cisco IOS devices, you'll need to ensure your environment meets these requirements.

### Vendor prerequisites

To configure your Cisco hardware, you must meet these prerequisites:
- You'll need privileged EXEC mode (`enable`) access to the Cisco device CLI to perform the necessary configuration.
- Your device needs a clear network path to the Elastic Agent. You'll also need to ensure firewall rules allow traffic on the configured port (the default is `9002`).
- You must enable the `service timestamps` feature on the device to ensure that logs are formatted correctly for the integration to parse.
- You'll need to configure a hostname on the device because the integration expects this field to be present in the syslog header.
- You'll need a stable source interface, such as a Loopback address, to ensure that logs are sent from a consistent IP address.

### Elastic prerequisites

To prepare your Elastic Stack environment, you'll need the following:
- You'll need an active Elastic Agent installed and enrolled in Fleet.
- It's recommended that you use Elastic Stack version `8.11.0` or later for full support of this integration's data streams.
- Ensure the Cisco devices can reach the Elastic Agent over the network via the specified TCP or UDP ports.
- You'll need the necessary roles and permissions in Kibana to manage integrations and Fleet policies.

## How do I deploy this integration?

### Agent-based deployment

You must install Elastic Agent on a host that can receive syslog data or access the log files from your Cisco IOS devices. For detailed instructions, see the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You only need one Elastic Agent per host.

You'll need Elastic Agent to stream data from the syslog or log file receiver and ship it to Elastic, where the integration's ingest pipelines process the events.

### Set up steps in Cisco IOS

To set up **UDP** or **TCP** syslog collection, follow these steps:

1.  Log in to your Cisco IOS device via SSH, Telnet, or a Console cable and enter privileged EXEC mode using the `enable` command.

2.  Access global configuration mode by typing `configure terminal`.

3.  Enable timestamps for log messages to ensure Elastic Agent can parse the events:

    ```bash
    service timestamps log datetime
    ```
    For higher precision, you can use `service timestamps log datetime msec show-timezone`.

4.  Direct the device to the IP address of the Elastic Agent. Replace `<ELASTIC_AGENT_IP>` (replace with your actual value) with your Agent's IP and use the default port `9002`:
    ```bash
    logging <ELASTIC_AGENT_IP>
    logging trap <ELASTIC_AGENT_IP> transport udp port 9002
    ```
    *Note: Change `udp` to `tcp` and update the port if you've customized the Kibana input settings.*

5.  Define which logs to send to the Agent. Level 6 (informational) is a common starting point:
    ```bash
    logging trap informational
    ```

6.  Ensure all logs originate from a consistent IP address, such as `Loopback0`:
    ```bash
    logging source-interface Loopback0
    ```

7.  Exit configuration mode and save the changes to the startup configuration:
    ```bash
    end
    write memory
    ```

8.  Run the `show logging` command to confirm the remote host is configured and logs are being generated.

To set up **log file** collection, follow these steps:

1.  Log in to your device and enter global configuration mode.

2.  Ensure logs are being written to a local buffer or a file that the Elastic Agent can access:

    ```bash
    logging buffered 16384
    ```

3.  If the Elastic Agent is running on a host that mounts a filesystem from the Cisco device or receives files via SCP/FTP, ensure the Agent service has read permissions for the target log file path. The default path is `/var/log/cisco-ios.log`.

#### Vendor resources

For more information, refer to the following Cisco documentation:
- [Configuring System Message Logs - Cisco IOS XE 17.17.x](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-17/configuration_guide/sys_mgmt/b_1717_sys_mgmt_9300_cg/configuring_system_message_logs.html)
- [How to configure logging in Cisco IOS - Cisco Community](https://community.cisco.com/t5/networking-knowledge-base/how-to-configure-logging-in-cisco-ios/ta-p/3132434)
- [Cisco Syslog Configuration Step-by-Step](https://www.auvik.com/franklyit/blog/configure-syslog-cisco/)

### Set up steps in Kibana

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for **Cisco IOS** and select the integration.
3.  Click **Add Cisco IOS**.
4.  Configure the integration by selecting an input type and providing the necessary settings. This integration supports `TCP`, `UDP`, and `Log file` inputs.

Choose the configuration steps below that match your environment.

#### Collecting logs from Cisco IOS via TCP

This input collects logs over a TCP socket. Configure the following variables:

| Setting                 | Description                                                                                    |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| Host to listen on       | The interface address the agent should bind to (e.g., `0.0.0.0`).                              |
| Syslog Port             | The TCP port to listen for Cisco logs (e.g., `9002`).                                          |
| Preserve original event | If you check this, a raw copy of the original event is added to the `event.original` field.    |
| Tags                    | List of tags to add to the events (e.g., `cisco-ios`, `forwarded`).                            |
| Timezone                | IANA time zone or offset (e.g., `+0200`) to use when syslog timestamps don't have a time zone. |
| Timezone Map            | A mapping of timezones as they appear in Cisco IOS logs to standard IANA formats.              |
| Processors              | Add custom processors to reduce or enhance event fields.                                       |
| SSL Configuration       | Configure SSL options for encrypted communication.                                             |
| Custom TCP Options      | Specify custom configuration options for the TCP input.                                        |

#### Collecting logs from Cisco IOS via UDP

This input collects logs over a UDP socket. Configure the following variables:

| Setting                 | Description                                                                                    |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| Host to listen on       | The interface address the agent should bind to (e.g., `0.0.0.0`).                              |
| Syslog Port             | The UDP port to listen for Cisco logs (e.g., `9002`).                                          |
| Preserve original event | If you check this, a raw copy of the original event is added to the `event.original` field.    |
| Tags                    | List of tags to add to the events (e.g., `cisco-ios`, `forwarded`).                            |
| Timezone                | IANA time zone or offset (e.g., `+0200`) to use when syslog timestamps don't have a time zone. |
| Timezone Map            | A mapping of timezones as they appear in Cisco IOS logs to standard IANA formats.              |
| Custom UDP Options      | Specify custom configuration options for the UDP input.                                        |
| Processors              | Add custom processors to reduce or enhance event fields.                                       |

#### Collecting logs from Cisco IOS via file

This input collects logs directly from log files on the host where the Elastic Agent is running. Configure the following variables:

| Setting                 | Description                                                                                    |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| Paths                   | List of file paths to monitor (e.g., `/var/log/cisco-ios.log`).                                |
| Preserve original event | If you check this, a raw copy of the original event is added to the `event.original` field.    |
| Tags                    | List of tags to add to the events (e.g., `cisco-ios`, `forwarded`).                            |
| Timezone                | IANA time zone or offset (e.g., `+0200`) to use when syslog timestamps don't have a time zone. |
| Timezone Map            | A mapping of timezones as they appear in Cisco IOS logs to standard IANA formats.              |
| Processors              | Add custom processors to reduce or enhance event fields.                                       |

After you finish configuring the input, assign the integration to an agent policy and click **Save and continue**.

### Validation

To ensure your integration works correctly, you can trigger specific events on your Cisco IOS device using these commands:

- Trigger a configuration event by entering and exiting global configuration mode:
  ```bash
  configure terminal
  exit
  ```
- Trigger an interface event by toggling a non-critical interface:
  ```bash
  interface Loopback99
  shutdown
  no shutdown
  ```
- Trigger an authentication event by logging out and logging back in to your SSH or Console session.

Next, verify the data in Kibana:

1.  Navigate to **Analytics > Discover**.
2.  Select the `logs-*` data view.
3.  Enter the following KQL filter in the search bar: `data_stream.dataset : "cisco_ios.log"`.
4.  Confirm that logs appear with recent timestamps.
5.  Check for the following fields to confirm data is mapped correctly:
    - `event.dataset` should be `cisco_ios.log`.
       - `event.severity` or `event.sequence` should be populated.
       - `observer.vendor` should be `Cisco`.
       - `message` should contain the raw Cisco log payload.
6.  Navigate to **Analytics > Dashboards** and search for **Cisco IOS** to view the pre-built dashboards populated with your data.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

You might encounter the following issues when configuring or using the Cisco IOS integration:

- **No data is being collected**: Verify network connectivity between the Cisco device and the Elastic Agent host. Ensure there are no firewalls or network ACLs blocking the syslog port. Confirm that the listening port configured in the Elastic integration matches the destination port configured on the device.
- **Log format requirements**: Your Cisco appliance might be configured to include or exclude various fields. This integration expects the hostname and timestamp to be present in the logs. If `sequence-number` is configured, it populates the `event.sequence` field; otherwise, `message-count` is used if available.
- **Missing timestamps**: Timestamps and timezones aren't enabled by default for Cisco IOS logging. You can enable them by using the `service timestamps log datetime` command on your device. Without this, the integration can't accurately determine the event time.
- **Timezone configuration**: Cisco IOS logs often use non-standard timezone formats. You can use the `Timezone` option to specify a single offset for all logs or use the `Timezone Map` setting for more complex environments with multiple timezones.
- **Port conflict**: If the Elastic Agent fails to start the input, check if another service is already using port `9002`. You can verify this on the host using a command like `netstat -ano | grep 9002`.
- **Firewall blockage**: If you see that messages are being logged on the Cisco device but no data reaches Kibana, ensure that the UDP or TCP port `9002` is open on any intermediate firewalls and the Elastic Agent host's local firewall.
- **Relayed log headers**: If you send logs to a central syslog server (like `syslog-ng` or `rsyslog`) before they reach the Elastic Agent, that server might add its own headers. You can use a processor in your configuration to strip these extra prefixes before ingestion.
- **Timezone mapping failures**: If your logs show an incorrect time that's offset by several hours, ensure your `Timezone Map` is configured to correctly translate Cisco's short-form timezone strings (like `AEST`) to standard IANA formats.
- **Incomplete log parsing**: Check the `error.message` field in Kibana Discover. If it contains `pattern not found`, verify that your Cisco device isn't using a custom log format that deviates from the standard `facility-severity-mnemonic` structure.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure you get the best performance from Cisco IOS in high-volume networking environments, consider these recommendations for the `log` data stream:
- Use `UDP` for low overhead in high-volume log streams, or use `TCP` in environments that require guaranteed delivery to prevent data loss during network congestion.
- Use the `logfile` input for the most reliable collection method if you co-locate the Elastic Agent on a management server that has access to device logs.
- Manage data volume by using the `logging trap <level>` (replace `<level>` with your actual value) command on your Cisco devices to filter logs by severity at the source.
- Collect levels 0 (emergencies) through 5 (notifications) for standard monitoring.
- Avoid using level 7 (debugging) in production unless you're troubleshooting, as it can generate excessive volume that impacts both device performance and ingest pipelines.
- Deploy multiple Elastic Agents behind a network load balancer like F5 or HAProxy to distribute `UDP` or `TCP` traffic in high-throughput environments receiving logs from thousands of interfaces.
- Ensure your Elastic Agent host has enough CPU resources for the parsing overhead associated with `grok` patterns and `tz_map` translations.

## Reference

### Inputs used

These inputs can be used with this integration:
<details>
<summary>logfile</summary>

## Setup
For more details about the logfile input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-log).

### Collecting logs from logfile

To collect logs via logfile, select **Collect logs via the logfile input** and configure the following parameter:

- Paths: List of glob-based paths to crawl and fetch log files from. Supports glob patterns like
  `/var/log/*.log` or `/var/log/*/*.log` for subfolder matching. Each file found starts a
  separate harvester.
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

#### log

The `log` data stream provides events from Cisco IOS devices of the following types:
- System messages
- Configuration changes
- Interface status updates

##### log fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cisco.ios.access_list | Name of the IP access list. | keyword |
| cisco.ios.action | Action taken by the device | keyword |
| cisco.ios.facility | The facility to which the message refers (for example, SNMP, SYS, and so forth). A facility can be a hardware device, a protocol, or a module of the system software. It denotes the source or the cause of the system message. | keyword |
| cisco.ios.interface.name | The name of the network interface. | keyword |
| cisco.ios.message_count | Message count number provided by the device when the device's service message-counter global configuration is set. | long |
| cisco.ios.outcome | The result of the event | keyword |
| cisco.ios.pim.group.ip | Multicast group IP | ip |
| cisco.ios.pim.source.ip | Multicast source IP | ip |
| cisco.ios.sequence | Sequence number provided by the device when the device's service sequence-numbers global configuration is set. | keyword |
| cisco.ios.session.number | Session ID | integer |
| cisco.ios.session.type | Session type | keyword |
| cisco.ios.tableid | The tableid associated with badauth errors | keyword |
| cisco.ios.uptime | The uptime for the device. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| elastic.agent.id |  | keyword |
| elastic.agent.snapshot |  | boolean |
| elastic.agent.version |  | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| hostname | Hostname from syslog header. | keyword |
| icmp.code | ICMP code. | keyword |
| icmp.type | ICMP type. | keyword |
| igmp.type | IGMP type. | keyword |
| input.type |  | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset |  | long |
| log.source.address |  | keyword |
| log.syslog.hostname | The hostname, FQDN, or IP of the machine that originally sent the Syslog message. This is sourced from the hostname field of the syslog header. Depending on the environment, this value may be different from the host that handled the event, especially if the host handling the events is acting as a collector. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.program | Process from syslog header. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |


##### log sample event

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-01-06T20:52:12.861Z",
    "agent": {
        "ephemeral_id": "960a0fda-a7b7-4362-9018-34b1d0d119c4",
        "id": "f00ff835-626e-4a18-a8a2-0bb3ebb7503f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "cisco": {
        "ios": {
            "facility": "SYS",
            "message_count": 2360957
        }
    },
    "data_stream": {
        "dataset": "cisco_ios.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "f00ff835-626e-4a18-a8a2-0bb3ebb7503f",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "code": "CONFIG_I",
        "dataset": "cisco_ios.log",
        "ingested": "2023-07-13T09:20:48Z",
        "original": "<189>2360957: Jan  6 2022 20:52:12.861: %SYS-5-CONFIG_I: Configured from console by akroh on vty0 (10.100.11.10)",
        "provider": "firewall",
        "sequence": 2360957,
        "severity": 5,
        "timezone": "+00:00",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "level": "notification",
        "source": {
            "address": "172.25.0.4:46792"
        },
        "syslog": {
            "priority": 189
        }
    },
    "message": "Configured from console by akroh on vty0 (10.100.11.10)",
    "observer": {
        "product": "IOS",
        "type": "firewall",
        "vendor": "Cisco"
    },
    "tags": [
        "preserve_original_event",
        "cisco-ios",
        "forwarded"
    ]
}
```

### Vendor documentation links

For more information about Cisco IOS logging and troubleshooting, refer to these resources:
- [Cisco System Message Logging Guide](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html)
- [Configuring System Message Logs - Cisco IOS XE 17.17.x](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-17/configuration_guide/sys_mgmt/b_1717_sys_mgmt_9300_cg/configuring_system_message_logs.html)
- [How to configure logging in Cisco IOS - Cisco Community](https://community.cisco.com/t5/networking-knowledge-base/how-to-configure-logging-in-cisco-ios/ta-p/3132434)
- [Cisco Syslog Configuration Step-by-Step | Auvik](https://www.auvik.com/franklyit/blog/configure-syslog-cisco/)
