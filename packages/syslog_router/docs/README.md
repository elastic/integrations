# Syslog Router Integration for Elastic

> Note: This AI-assisted guide was validated by our engineers. You may need to adjust the steps to match your environment.

## Overview

The Syslog router integration for Elastic enables you to route incoming syslog events to the correct Elastic integration data stream using regex pattern matching on the `message` field. It acts as a centralized traffic controller for syslog messages, allowing a single Elastic Agent to receive a mixed stream of logs from multiple network devices and forward each event to its appropriate integration-specific data stream for parsing.

### Compatibility

This integration requires Kibana versions ^8.14.3 or ^9.0.0, and a basic Elastic subscription.

This integration supports routing events from the following 22 pre-configured integrations out of the box:

- Arista NG Firewall
- Check Point
- Cisco ASA
- Cisco FTD
- Cisco IOS
- Cisco ISE
- Cisco Secure Email Gateway
- Citrix WAF (CEF format only)
- Fortinet FortiEDR
- Fortinet FortiGate
- Fortinet FortiMail
- Fortinet FortiManager
- Fortinet FortiProxy
- Imperva SecureSphere (CEF format only)
- Iptables
- Juniper SRX
- Palo Alto Next-Gen Firewall
- QNAP NAS
- Snort
- Sonicwall Firewall
- Sophos XG
- Stormshield

Due to subtle differences in how devices emit syslog events, the default patterns may not work in all cases. Some integrations that support syslog are not listed here because their patterns would be too complex or could overlap with other integrations, which might cause false matches. You may need to create custom patterns for those cases.

### How it works

The integration receives syslog events through TCP, UDP, or filestream inputs. You deploy Elastic Agent on a host that is configured as a syslog receiver or has access to the log files. The integration evaluates each incoming event against an ordered list of regex patterns defined in the reroute configuration. When a pattern matches the `message` field, the integration sets the `_conf.dataset` field to the target integration's data stream name (for example, `cisco_asa.log`). The integration's routing rules then reroute the event to that target data stream, where the target integration's ingest pipeline handles the actual parsing.

Events that do not match any pattern remain in the `syslog_router.log` data stream. We recommend you create a custom integration (for example, with Automatic Import) and route to it if you need to handle unmatched events in production.

## What data does this integration collect?

The Syslog Router integration collects log messages of the following types:

- Syslog events (TCP): You can listen for incoming TCP syslog connections on a configurable address and port (default: `localhost:9514`).
- Syslog events (UDP): You can listen for incoming UDP syslog packets on a configurable address and port (default: `localhost:9514`).
- Syslog events (Filestream): You can monitor local log files (default: `/var/log/syslog.log`). This input is turned off by default.

This integration acts as a transit layer that collects raw syslog events and routes them to other Elastic integrations for parsing. Events that are not matched and rerouted are processed by a minimal ingest pipeline that sets `ecs.version` and handles errors. The actual parsing of routed events is performed by the target integration's ingest pipeline.

The routing mechanism works as follows:

1. Each event is matched against ordered regex patterns on the `message` field.
2. When a match is found, the `_conf.dataset` field is set to the target integration's data stream (for example, `cisco_asa.log` or `fortinet_fortigate.log`).
3. The `routing_rules.yml` configuration then reroutes the event to the target data stream defined in `_conf.dataset`.

Based on your routing configuration, data is directed toward specialized integrations including:

- Network security logs: Firewall traffic and security policy events (for example, `cisco_asa.log`, `panw.panos`, `fortinet_fortigate.log`, or `arista_ngfw.log`).
- Web application security logs: Web application firewall events (for example, `citrix_waf.log`).
- Authentication and identity logs: Identity services and access logs (for example, `cisco_ise.log`).
- Intrusion detection alerts: IDS/IPS signatures (for example, `snort.log` or `fortinet_fortiedr.log`).

### Supported use cases

You can use this integration for the following use cases:

- Centralized syslog ingestion: Receive syslog from many different network devices on a single port and automatically route each event to its corresponding integration for parsing.
- Multi-vendor firewall environments: Consolidate syslog collection through a single Elastic Agent policy rather than deploying separate inputs per vendor.
- Rapid onboarding of syslog sources: Add support for new device types by adding a single `if/then` block with a regex pattern, without needing to deploy additional agents or inputs.

## What do I need to use this integration?

The Syslog Router is an Elastic-built tool and not a third-party vendor product, so you don't have vendor-side prerequisites. To use this integration, you'll need the following:

- An Elastic Agent installed and enrolled in a Fleet policy on a host that can receive syslog traffic from network devices.
- Kibana and Elasticsearch version `8.14.3` or `9.0.0` and later, with at least a basic subscription.
- Target integration assets for each specific data stream installed in Kibana so that events parse correctly (for example, you'll need to install the Cisco ASA integration assets before routing Cisco ASA syslog events).
- Network connectivity that allows syslog-sending devices to reach the Elastic Agent host on the configured listen port, which defaults to `9514` for TCP and UDP.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed using the integration's ingest pipelines.

### Set up steps in Syslog Router

This integration acts as a central hub. You first need to prepare the target integrations and then configure your network devices to point to the host running the Elastic Agent.

#### Install target integration assets

Before you add the Syslog Router, you can install the assets for each integration you want to route data to:

1. In Kibana, navigate to **Management > Integrations**.
2. Find the relevant integration by searching or browsing the catalog. For example, search for "Cisco ASA".
   ![Cisco ASA Integration](../img/catalog-cisco-asa.png)
3. Select the integration, navigate to the **Settings** tab, and click **Install \<Integration Name\> assets**. Confirm the installation in the popup.
   ![Install Cisco ASA assets](../img/install-assets.png)
4. Repeat these steps for every integration whose syslog events you expect to receive and route.

#### Configure syslog on network devices

Configure each network device to forward its syslog stream to the Elastic Agent host on the port you plan to use (default is `9514`). Refer to each vendor's documentation for detailed syslog forwarding instructions.

### Set up steps in Kibana

After your devices are ready to send data, you can set up the integration in Kibana:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Syslog Router** and select it.
3. Click **Add Syslog Router**.
4. Enable and configure the inputs you need:
    - **TCP input**: Set the **Listen Address** (for example, `0.0.0.0`) and **Listen Port** (for example, `9514`). You can also configure SSL settings if your devices support encrypted syslog.
    - **UDP input**: Set the **Listen Address** and **Listen Port**.
    - **Filestream input**: Specify the **Paths** to the syslog files on the host if the agent is reading from local logs.
5. Review the **Reroute configuration** section. You'll find a list of patterns used to match incoming logs to specific integrations. You can modify these YAML patterns to match the specific log formats in your environment.
6. Select the **Elastic Agent policy** where you want to deploy the integration.
7. Click **Save and continue**.

### Configuring routing patterns

#### Pattern definition

The integration uses [Beats conditionals and processors](https://www.elastic.co/guide/en/beats/filebeat/current/defining-processors.html) to match incoming syslog messages to target data streams. Pattern definitions are evaluated in the order they appear. Each pattern is an `if/then` block:

```yaml
- if:
    and:
      - not.has_fields: _conf.dataset
      - regexp.message: "%ASA-"
  then:
    - add_fields:
        target: ""
        fields:
          _conf.dataset: "cisco_asa.log"
          _conf.tz_offset: "UTC"
          _temp_.internal_zones: ["trust"]
          _temp_.external_zones: ["untrust"]
```

The `not.has_fields: _conf.dataset` condition ensures only the first matching pattern sets the routing target.

#### Reordering patterns

Move the entire `if/then` block up or down in the YAML list. Place stricter patterns before more relaxed ones, and high-traffic integrations near the top.

#### Disabling a pattern

Remove the block entirely, or comment it out with `#`:

```yaml
# - if:
#     and:
#       - not.has_fields: _conf.dataset
#       - regexp.message: "%ASA-"
#   then:
#     - add_fields:
#         target: ''
#         fields:
#           _conf.dataset: "cisco_asa.log"
#           _conf.tz_offset: "UTC"
#           _temp_.internal_zones: ['trust']
#           _temp_.external_zones: ['untrust']
```

#### Adding a new pattern

At minimum, an `add_fields` processor must set `_conf.dataset` to the target integration's dataset name (`integration.data_stream`):

```yaml
- if:
    and:
      - not.has_fields: _conf.dataset
      - regexp.message: "MY_PATTERN"
  then:
    - add_fields:
        target: ""
        fields:
          _conf.dataset: "my_integration.my_data_stream"
```

Multiple regex patterns can be combined with `or`:

```yaml
- if:
    and:
      - not.has_fields: _conf.dataset
      - or:
          - regexp.message: <PATTERN_1>
          - regexp.message: <PATTERN_2>
```

Additional processors such as `decode_cef` or `syslog` may be added in the `then` block if the target integration requires light pre-processing. However, for any complex processing of custom logs, we recommend creating a separate integration and routing to it.

### Validation

To ensure your deployment is working correctly, follow these steps:

1. Verify the agent is receiving data by checking the Elastic Agent logs for the configured input (TCP/UDP) to confirm it is listening. You can send a test syslog message from the agent host to itself to confirm the port is open:

   ```bash
   echo 'Oct 10 2018 12:34:56 localhost CiscoASA[999]: %ASA-4-106023: Deny tcp src outside:192.168.19.254/80 dst inside:172.31.98.44/8277 by access-group "inbound" [0x0, 0x0]' | nc localhost 9514
   ```

2. In Kibana, navigate to **Analytics > Discover**.
3. Select the `logs-*` data view.
4. Search for routed events using KQL. For example, to check for routed Cisco ASA logs, use: `data_stream.dataset : "cisco_asa.log"`.
5. Verify that the events are correctly parsed and that fields from the target integration are present.
6. To find events that didn't match any routing pattern, search for: `data_stream.dataset : "syslog_router.log"`.
7. Examine the `message` field of these unmatched events to determine if you need to add or adjust your reroute patterns.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

If you encounter issues while using this integration, check the following common configuration problems:

- Port binding failure: If the Elastic Agent fails to start the listener, verify the configured port, for example `9514`, isn't already in use by another syslog service. On Linux, use `ss -tulpn | grep <port>` (replace `<port>` with your actual port) to identify conflicts.
- Events routed to the wrong integration: Check the order of `if/then` blocks in your routing configuration. Stricter patterns, such as CEF headers or vendor-specific strings, should appear before more relaxed patterns that might match multiple vendors.
- Events remain in `syslog_router.log` instead of the target data stream: This happens when an event doesn't match any pattern. Examine the `message` field against the configured regex patterns. You might need to add a custom pattern for your device's specific syslog format.
- Routed events aren't parsed correctly: Ensure the target integration's assets are installed in Kibana. The Syslog Router only routes events; it doesn't parse them. The target integration's ingest pipeline handles the parsing.
- Error message is present on routed events: The target integration's ingest pipeline encountered a parsing error. Verify that the syslog format matches what the target integration expects. Some integrations require specific formats, such as Citrix WAF which requires CEF format.
- Missing `_conf.dataset` field: If this field is absent, the event defaults to the `syslog_router.log` stream. Review the `message` field and verify it matches a regex defined in your routing configuration.
- High volume of unmatched events: Review the unmatched events in the `syslog_router.log` stream to identify their source. You might need to add custom routing patterns for device types that aren't covered by the default patterns.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To optimize the performance and scaling of the Syslog Router, you should follow these best practices:

- Pattern ordering: You should place stricter and more specific patterns before broader ones to avoid false matches. You'll also get better performance if you place your highest-traffic integrations at the top of your configuration to reduce the number of regex evaluations performed for each event.
- Regex complexity: You should keep your patterns as straightforward as possible. Avoid using broad patterns like `.*` because they can cause excessive backtracking and increase CPU overhead on the ingestion nodes.
- Transport selection: You can use UDP for higher throughput with lower overhead, but you should use TCP when you need guaranteed delivery. When you use TCP, you can tune advanced settings like `max_connections` and `max_message_size` in the custom TCP options to match your environment's requirements.
- Agent scaling: For high-throughput environments, you can deploy multiple Elastic Agents behind a network load balancer to distribute the ingestion load across multiple instances.
- Routing efficiency: This integration routes all events through the `syslog_router.log` data stream. Because the rerouting rules happen at the Elasticsearch level rather than the agent level, you won't experience data duplication at rest, which keeps your storage and processing usage efficient.
- Input buffers: When you use the UDP input in high-traffic environments, you can increase the `read_buffer` size in the custom UDP options to help prevent packet loss during bursts of network traffic.

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


### Vendor documentation links

The following documentation provides information on the configuration options for the inputs and processors used by this integration:

- [Beats Processors and Conditionals](https://www.elastic.co/guide/en/beats/filebeat/current/defining-processors.html)
- [TCP input configuration](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-tcp.html)
- [UDP input configuration](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-udp.html)
- [Filestream input configuration](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-filestream.html)
- [SSL configuration](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config)

### Data streams

#### log

The `log` data stream provides events from syslog of the following types: system logs, application logs, and other syslog-formatted messages. It's the transit data stream for all syslog events collected by the integration. You use pattern matching configuration to route these events from this data stream to their target integration data stream.

##### log fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| _conf.dataset | Target data stream | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
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
| input.type | Input type | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | Log contents. | match_only_text |

