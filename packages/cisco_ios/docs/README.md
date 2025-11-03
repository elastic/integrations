# Cisco IOS Integration for Elastic

## Overview

The Cisco IOS integration for Elastic collects logs from Cisco IOS devices, enabling real-time visibility into network activity, security events, and operational health. This integration facilitates network security monitoring, compliance reporting, and troubleshooting by parsing and visualizing syslog messages from Cisco routers and switches.

### How it works

This integration receives syslog messages from Cisco IOS devices through the Elastic Agent. It can be configured to listen for logs over TCP or UDP, or to read them directly from a log file. The Elastic Agent processes these logs, parsing them into structured fields, and securely sends them to your Elastic deployment for analysis and visualization.

### Compatibility

This integration is compatible with a wide range of Cisco devices running Cisco IOS software, including routers and switches.

**Elastic Stack Requirements:**
- Elastic Stack version 8.11.0 or higher

## What data does this integration collect?

The Cisco IOS integration collects various types of log messages, including:

*   **System Messages**: Captures administrative actions, configuration changes, and system restarts.
*   **Security Events**: Monitors for access control list (ACL) violations, authentication failures, and other security-related events.
*   **Network Events**: Tracks interface status changes (up/down), routing protocol updates, and other network-related messages.
*   **Traffic Logs**: Collects data on IPv4 and IPv6 traffic, including source/destination IP addresses and ports.
*   **Protocol-specific Messages**: Logs events related to protocols like ICMP, TCP, UDP, and IGMP.

### Supported use cases

*   **Network Security Monitoring**: Actively monitor network device logs for security threats like unauthorized access attempts and ACL violations.
*   **Compliance Reporting**: Collect and archive logs to meet regulatory compliance requirements (e.g., PCI DSS, SOX).
*   **Network Operations Management**: Gain visibility into the health and status of network devices, track configuration changes, and monitor system events.
*   **Troubleshooting**: Quickly diagnose and resolve network issues, hardware failures, and configuration problems by analyzing detailed device logs.

## What do I need to use this integration?

### Vendor Prerequisites

*   A Cisco IOS device with network connectivity to the host running the Elastic Agent.
*   Administrative access to the Cisco device to configure syslog settings.
*   **Important**: Timestamps must be enabled on the Cisco IOS device, as they are not on by default. Use the command `service timestamps log datetime`.

### Elastic Prerequisites

*   Elastic Agent must be installed on a host that can receive syslog messages from your Cisco devices.
*   The host running the Elastic Agent must have the specified listening port (e.g., 9002) open and accessible from the Cisco devices.
*   Firewall rules must be configured to allow syslog traffic from your network devices to the Elastic Agent host.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent is required to stream data from the syslog receiver or log file and ship it to Elastic, where the events will be processed by the integration's ingest pipelines. You can install only one Elastic Agent per host. For detailed instructions, see the Elastic Agent [installation guide](docs-content://reference/fleet/install-elastic-agents.md).

### Onboard / configure

#### 1. Configure Syslog on Cisco IOS Devices

Log into your Cisco IOS device to perform the following steps.

1.  **Enable Timestamp Logging (Required)**:
    This ensures that logs have the correct timestamp.
    ```shell
    configure terminal
    service timestamps log datetime
    exit
    ```

2.  **Enable Sequence Numbers (Optional)**:
    This adds a sequence number to each log message, which populates the `event.sequence` field.
    ```shell
    configure terminal
    service sequence-numbers
    exit
    ```

3.  **Configure Syslog Destination**:
    Point your Cisco device to the Elastic Agent's IP address and port. Replace `<ELASTIC_AGENT_IP>` with the actual IP address of your agent host.

    *   **For UDP**:
        ```shell
        configure terminal
        logging host <ELASTIC_AGENT_IP> transport udp port 9002
        exit
        ```
    *   **For TCP**:
        ```shell
        configure terminal
        logging host <ELASTIC_AGENT_IP> transport tcp port 9002
        exit
        ```

4.  **Set Logging Severity Level (Optional)**:
    Adjust the logging level to control the verbosity of the logs. `informational` (level 6) is a common choice.
    ```shell
    configure terminal
    logging trap informational
    exit
    ```

5.  **Save Configuration**:
    ```shell
    write memory
    ```

For more details, refer to [Cisco's System Message Logging documentation](https://www.cisco.com/c/en/us/td/docs/routers/access/wireless/software/guide/SysMsgLogging.html).

#### 2. Add and Configure the Integration in Kibana

1.  In Kibana, navigate to **Management → Integrations**.
2.  Search for "Cisco IOS" and click on it.
3.  Click **Add Cisco IOS**.
4.  Provide a descriptive **Integration name**.
5.  Choose your desired **Input Type** (TCP, UDP, or Log file) and configure its settings.

##### TCP Input Configuration

Collect logs via a TCP syslog listener.

**Basic Options**

| Setting | Description | Default Value |
|---|---|---|
| **Host to listen on** | The IP address or hostname for the Elastic Agent to listen on. Use `0.0.0.0` to listen on all interfaces or `localhost` for local-only. | `localhost` |
| **Syslog Port** | The port for the Elastic Agent to listen on for syslog messages. Must match the port configured on the Cisco device. | `9002` |
| **Preserve original event** | If enabled, the original, raw log message is stored in the `event.original` field. | `false` |

**Advanced Options**

| Setting | Description | Default Value |
|---|---|---|
| **Timezone** | The IANA time zone or time offset (e.g., `+0200`) to use when parsing timestamps that do not include a timezone. | `UTC` |
| **Timezone Map** | A map of timezone abbreviations (e.g., AEST) to their corresponding IANA timezone names (e.g., Australia/Sydney). | (empty) |
| **SSL Configuration** | Configuration for SSL/TLS settings. See [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html) for details. | (empty) |
| **Custom TCP Options** | Advanced TCP settings such as `max_connections`, `framing`, and `line_delimiter`. See the [Filebeat TCP input documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-tcp.html) for details. | (empty) |
| **Processors** | Processors to apply to the data before it is sent to Elasticsearch. See the [Processors documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details. | (empty) |

##### UDP Input Configuration

Collect logs via a UDP syslog listener.

**Basic Options**

| Setting | Description | Default Value |
|---|---|---|
| **Host to listen on** | The IP address or hostname for the Elastic Agent to listen on. Use `0.0.0.0` to listen on all interfaces or `localhost` for local-only. | `localhost` |
| **Syslog Port** | The port for the Elastic Agent to listen on for syslog messages. Must match the port configured on the Cisco device. | `9002` |
| **Preserve original event** | If enabled, the original, raw log message is stored in the `event.original` field. | `false` |

**Advanced Options**

| Setting | Description | Default Value |
|---|---|---|
| **Timezone** | The IANA time zone or time offset (e.g., `+0200`) to use when parsing timestamps that do not include a timezone. | `UTC` |
| **Timezone Map** | A map of timezone abbreviations (e.g., AEST) to their corresponding IANA timezone names (e.g., Australia/Sydney). | (empty) |
| **Custom UDP Options** | Advanced UDP settings such as `read_buffer`, `max_message_size`, and `timeout`. See the [Filebeat UDP input documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-udp.html) for details. | (empty) |
| **Processors** | Processors to apply to the data before it is sent to Elasticsearch. See the [Processors documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details. | (empty) |

##### Log File Input Configuration

Collect logs from one or more log files.

**Basic Options**

| Setting | Description | Default Value |
|---|---|---|
| **Paths** | A list of file paths to monitor for logs. Wildcards are supported (e.g., `/var/log/cisco-*.log`). | `/var/log/cisco-ios.log` |
| **Preserve original event** | If enabled, the original, raw log message is stored in the `event.original` field. | `false` |

**Advanced Options**

| Setting | Description | Default Value |
|---|---|---|
| **Timezone** | The IANA time zone or time offset (e.g., `+0200`) to use when parsing timestamps that do not include a timezone. | `UTC` |
| **Timezone Map** | A map of timezone abbreviations (e.g., AEST) to their corresponding IANA timezone names (e.g., Australia/Sydney). | (empty) |
| **Processors** | Processors to apply to the data before it is sent to Elasticsearch. See the [Processors documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filtering-and-enhancing-data.html) for details. | (empty) |

6.  Select an **Agent policy**. The Elastic Agent must be running on a host that is accessible to your Cisco devices.
7.  Click **Save and continue** to save your configuration and deploy the changes to the specified agent policy.

### Validation

1.  **Verify Logs on Cisco Device**:
    *   Trigger a log event, for example, by entering and exiting configuration mode.
    *   Run `show logging` on the Cisco device to confirm that logs are being generated and sent.

2.  **Check Data in Kibana**:
    *   Navigate to **Analytics → Discover**.
    *   Select the `logs-cisco_ios.log-*` data view.
    *   Verify that log events from your device are appearing. Check that key fields like `@timestamp`, `observer.vendor`, `cisco.ios.facility`, and `message` are correctly populated.

## Troubleshooting

For help with Elastic ingest tools, see [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

**Issue: No data in Kibana**
*   Verify network connectivity between the Cisco device and the Elastic Agent host.
*   Check that firewall rules on the agent host and any network firewalls allow traffic on the configured syslog port.
*   Confirm the Elastic Agent is running (`elastic-agent status`) and check its logs for errors.
*   Ensure the listening port in the integration settings matches the destination port configured on the Cisco device.

**Issue: Incorrect timestamps**
*   Confirm that `service timestamps log datetime` is configured on the Cisco IOS device.
*   In the integration's advanced settings, ensure the correct **Timezone** is configured (default is UTC).

## Reference

### log

The `log` data stream provides logs from Cisco IOS.

#### log fields

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
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
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
- Enable SSL*- Toggle to enable SSL/TLS encryption
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

