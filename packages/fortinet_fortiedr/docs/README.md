# Fortinet FortiEDR Logs Integration for Elastic

## Overview

The Fortinet FortiEDR logs integration for Elastic enables you to collect and analyze endpoint security telemetry from your FortiEDR environment. By ingesting these logs into the Elastic Stack, you'll centralize monitoring, maintain long-term retention, and perform advanced threat hunting across your fleet.

This integration facilitates:
- Endpoint threat monitoring: You'll monitor real-time security events detected by FortiEDR to identify and respond to malware, ransomware, and unauthorized access attempts across your fleet.
- Audit and compliance: You'll maintain a comprehensive audit trail of administrative actions and user activities within the FortiEDR console to satisfy regulatory compliance requirements.
- Incident investigation: You'll leverage detailed process and network telemetry from FortiEDR logs to perform root cause analysis and reconstruct the timeline of security incidents.
- Operational health oversight: You'll track system-level events and operational status changes within the FortiEDR environment to ensure your security infrastructure is functioning optimally.

### Compatibility

This integration is compatible with the following vendor versions:
- Fortinet FortiEDR version 5.0.0 and higher.

### How it works

You collect telemetry from Fortinet FortiEDR instances using several transport methods. You can configure the integration to receive logs via a syslog listener using TCP or UDP, or you can set it up to monitor local log files where FortiEDR events are persisted. The data is processed in a semicolon-separated key-value format. For proper parsing, you'll need to set the FortiEDR export format to `Semicolon`.

This integration processes several types of telemetry within the `log` data stream:
- Security events: You'll receive detailed logs regarding detected threats, blocked processes, and suspicious behaviors identified by EDR agents.
- System events: You'll see logs related to the health and operational status of FortiEDR components, including Central Manager and Collector status updates.
- Audit trail: You'll have comprehensive records of administrative changes, policy modifications, and user login activity within the FortiEDR console.

The integration assigns `event.category: malware` to all events by default. You can identify the specific log type by inspecting fields such as `fortinet.edr.classification` and `fortinet.edr.severity`. Once you deploy the Elastic Agent with this integration, it collects these logs and forwards them to your Elastic deployment, where the data is parsed and mapped to the Elastic Common Schema (ECS) for analysis.

## What data does this integration collect?

The integration collects telemetry within a single `log` data stream. The types of log messages and how they are processed are described in the [How it works](#how-it-works) section above.

### Supported use cases

Integrating Fortinet FortiEDR logs with the Elastic Stack provides centralized visibility into your endpoint security posture. You can use this data for several key use cases:
*   Real-time threat detection: You use Elastic Security to alert on threats identified by FortiEDR, allowing you to respond quickly to potential compromises.
*   Security investigation: You correlate your endpoint logs with other security events in the Elastic Stack to perform deep-dive investigations into complex attacks.
*   Compliance and auditing: You maintain a searchable history of administrative actions and user activity to satisfy regulatory and internal compliance requirements.
*   Infrastructure health monitoring: You track the operational status of your EDR management components to ensure your protection remains active and healthy.

## What do I need to use this integration?

You must meet the following vendor and Elastic prerequisites before you can use this integration:

### Vendor prerequisites

Before you configure the integration, ensure your Fortinet FortiEDR environment meets these requirements:
- You must have a user account with administrative privileges for the Fortinet FortiEDR Central Manager console to modify export settings and playbook policies.
- The FortiEDR Central Manager must be able to reach the Elastic Agent host over the configured syslog port (the default is `9509`). Ensure any intermediate firewalls allow TCP or UDP traffic on the selected port.
- A functional playbook must be assigned to the target devices to trigger the generation and transmission of security event notifications.
- You must set the FortiEDR export format to `Semicolon` to ensure the Elastic Agent can correctly parse the key-value pairs into ECS-compliant fields.

### Elastic prerequisites

Before you collect data, ensure you have the following Elastic Stack components ready:
- Elastic Stack version `8.11.0` or later (version `9.0.0` is also supported).
- An Elastic Agent installed on a host reachable by the FortiEDR Central Manager and enrolled in Fleet.
- Port `9509` (or your custom configured port) open on the Elastic Agent host's firewall to accept incoming TCP or UDP traffic.
- The Fortinet FortiEDR integration added to an Elastic Agent policy via Fleet.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in Fortinet FortiEDR Logs

To configure Fortinet FortiEDR to send data to Elastic, follow the instructions for your preferred collection method.

#### Syslog (TCP/UDP) collection

Configure the FortiEDR Central Manager to export logs via syslog using these steps:

1. Log in to the **Fortinet FortiEDR Central Manager** console.
2. Navigate to **Administration > Export Settings**.
3. Select the **Syslog** tab to view existing configurations.
4. Click the **Add** (+) button to create a new syslog destination.
5. Configure the destination parameters:
    * **Syslog Name**: Enter a unique name, such as `Elastic_Agent_EDR`.
    * **Host**: Enter the IP address of the machine running the Elastic Agent.
    * **Port**: Enter the port configured in the Elastic integration (default is `9509`).
    * **Protocol**: Choose `TCP` or `UDP` (`TCP` is recommended for reliability).
    * **Format**: Select **Semicolon**. This is critical for proper parsing of the logs.
6. Click **Save** to finalize the destination.
7. Locate the newly created destination in the list and find the **Notifications** pane.
8. Use the toggle sliders to enable the specific categories you wish to export:
    * **Security Events**
    * **System Events**
    * **Audit Trail**
9. Navigate to **Security Settings > Playbooks**.
10. Select the Playbook policy assigned to your monitored devices.
11. In the policy actions, ensure the **Send Syslog Notification** checkbox is enabled for relevant triggers.
12. Click **Save** to apply the policy changes across your environment.

#### Logfile collection

If you prefer to collect logs from a file, follow these steps:

1. Configure the FortiEDR console or a secondary forwarder to write logs to a local directory accessible by the Elastic Agent.
2. Identify the absolute path where the logs are being rotated, such as `/var/log/fortinet-edr.log` (replace with your actual value).
3. Ensure the Elastic Agent user has read permissions for the log files and the directory containing them using `chmod` or `chown` as necessary.
4. Verify that the log rotation mechanism, such as `logrotate`, does not delete files before the Elastic Agent has finished ingesting them.

#### Vendor resources

For more information, refer to the following Fortinet documentation:
- [Fortinet FortiEDR Administration Guide: Syslog](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/109591/syslog)
- [Fortinet FortiEDR Administration Guide: Export Settings](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/918407/export-settings)
- [Fortinet FortiEDR Administration Guide: Playbooks](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/419440/automated-incident-response-playbooks-page)

### Set up steps in Kibana

To configure the integration in Kibana, follow these steps:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Fortinet FortiEDR** and select the integration.
3. Click **Add Fortinet FortiEDR Logs**.
4. Configure the integration by selecting an input type and providing the necessary settings.

Choose the setup instructions below that match your configuration:

#### Log file input configuration

Select the **Collecting logs from Fortinet FortiEDR instances (input: logfile)** input type and configure these variables:

* **Paths** (`paths`): The list of paths to the log files. Default: `['/var/log/fortinet-edr.log']`.
* **Timezone offset (+HH:mm format)** (`tz_offset`): The timezone offset for the logs. Default: `local`.
* **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `false`.
* **Tags** (`tags`): Custom tags to add to the events. Default: `['fortinet-fortiedr', 'forwarded']`.
* **Enable debug logging** (`debug`): Enable debug logging for the input. Default: `false`.
* **Processors** (`processors`): Add custom processors to reduce fields or enhance metadata.

#### TCP input configuration

Select the **Collecting logs from Fortinet FortiEDR instances (input: tcp)** input type and configure these variables:

* **Listen Address** (`tcp_host`): The bind address to listen for TCP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
* **Listen Port** (`tcp_port`): The TCP port number to listen on. Default: `9509`.
* **Timezone offset (+HH:mm format)** (`tz_offset`): The timezone offset for the logs. Default: `local`.
* **Add non-ECS fields** (`rsa_fields`): Whether to add RSA fields that are not part of ECS. Default: `true`.
* **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `false`.
* **Tags** (`tags`): Custom tags to add to the events. Default: `['fortinet-fortiedr', 'forwarded']`.
* **Keep raw parser fields** (`keep_raw_fields`): If `true`, the integration keeps the original fields from the parser. Default: `false`.
* **Enable debug logging** (`debug`): Enable debug logging for the input. Default: `false`.
* **Processors** (`processors`): Add custom processors to reduce fields or enhance metadata.

#### UDP input configuration

Select the **Collecting logs from Fortinet FortiEDR instances (input: udp)** input type and configure these variables:

* **Listen Address** (`udp_host`): The bind address to listen for UDP connections. Set to `0.0.0.0` to bind to all available interfaces. Default: `localhost`.
* **Listen Port** (`udp_port`): The UDP port number to listen on. Default: `9509`.
* **Timezone offset (+HH:mm format)** (`tz_offset`): The timezone offset for the logs. Default: `local`.
* **Add non-ECS fields** (`rsa_fields`): Whether to add RSA fields that are not part of ECS. Default: `true`.
* **Preserve original event** (`preserve_original_event`): Preserves a raw copy of the original event in `event.original`. Default: `false`.
* **Tags** (`tags`): Custom tags to add to the events. Default: `['fortinet-fortiedr', 'forwarded']`.
* **Keep raw parser fields** (`keep_raw_fields`): If `true`, the integration keeps the original fields from the parser. Default: `false`.
* **Enable debug logging** (`debug`): Enable debug logging for the input. Default: `false`.
* **Custom UDP Options** (`udp_options`): Specify custom configuration options such as `read_buffer` or `max_message_size`.
* **Processors** (`processors`): Add custom processors to reduce fields or enhance metadata.

After configuring the input, assign the integration to an agent policy and click **Save and continue**.

### Validation

After configuration is complete, verify that data is flowing correctly with these steps:

1. Navigate to **Management > Fleet > Agents** and verify that the Elastic Agent status is **Healthy**.
2. Trigger data flow on Fortinet FortiEDR:
    * **Test Connection**: In the FortiEDR Console under **Administration > Export Settings**, select the Elastic Agent syslog destination and click the **Test** button to send a synthetic test message.
    * **Trigger Audit Event**: Log out of the FortiEDR Administration Console and log back in to generate an administrative login event.
    * **Modify Settings**: Briefly toggle a non-critical notification setting in the **Security Settings** to generate an audit trail event.
    * **Trigger Security Event**: If in a test environment, execute a script in a protected directory or trigger a known-safe behavioral rule to generate a "Suspicious" or "Malicious" notification.
3. Check data in Kibana:
    * Navigate to **Analytics > Discover**.
    * Select the `logs-*` data view.
    * Enter the KQL filter: `data_stream.dataset : "fortinet_fortiedr.log"`
    * Verify logs appear and confirm fields like `event.dataset`, `event.action`, `fortinet.edr.severity`, `fortinet.edr.classification`, `process.name`, and `host.hostname`.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

If you encounter issues while setting up or using the Fortinet FortiEDR Logs integration, check the following common scenarios:

- No data is being collected:
    Verify that you've enabled the **Send Syslog Notification** checkbox within the specific active Playbook in the FortiEDR console. Defining the Syslog Export server is a global setting, but alerts are triggered via Playbooks in **Security Settings > Playbooks**. You can verify this by checking the following:
    * Go to **Security Settings > Playbooks** and ensure the specific active Playbook has syslog notifications enabled.
    * Confirm that the FortiEDR Central Manager can reach the Elastic Agent host over the network.
- Port conflicts:
    Verify that no other service is using the port assigned to the Elastic Agent (default is `9509`). You can check for existing bindings on the Agent host using the following command:
    ```bash
    netstat -ano | grep 9509
    ```
- Firewall obstructions:
    Verify that intermediate firewalls or local host firewalls, such as `iptables`, `firewalld`, or Windows Firewall, are allowing traffic from the FortiEDR Manager IP address to the Elastic Agent on the configured port.
- Incorrect listen address:
    If the Elastic Agent isn't receiving data from a remote source, ensure the **Listen Address** is set to `0.0.0.0` instead of `localhost` in the integration settings.
- Parsing failures:
    Check the `error.message` field in Discover. This often indicates the syslog format doesn't match the integration's expectations. Ensure the FortiEDR export format is set to `Semicolon` in the **Administration > Export Settings** menu.
- Timezone misalignment:
    If logs appear in the past or future, verify the `Timezone offset` variable in the Kibana integration settings to ensure it matches the FortiEDR Central Manager's timezone.
- Message truncation:
    For large security events sent via UDP, logs might be truncated. Increase the `max_message_size` and `read_buffer` in the **Custom UDP Options** if you notice incomplete payloads.

For vendor documentation links, see the [Vendor documentation links](#vendor-documentation-links) section.

## Performance and scaling

To ensure optimal performance in high-volume environments, consider these strategies:

*   Transport and collection considerations: While `UDP` provides lower overhead for syslog transmission, you should use `TCP` in environments where you need delivery guarantees to prevent packet loss during traffic spikes. If you use `UDP`, ensure that you tune the `read_buffer` (for example, `100MiB`) and `max_message_size` (for example, `50KiB`) variables within the `Custom UDP Options` to handle high throughput without dropping packets at the kernel level.
*   Data volume management: You can manage the volume of data ingested into Elasticsearch by using FortiEDR Playbook policies to selectively enable the "Send Syslog Notification" option only for critical event categories. Filtering at the source reduces the processing load on the Elastic Agent and helps minimize storage costs associated with high-noise system events.
*   Elastic Agent scaling: For large-scale deployments with high event rates, you'll want to deploy multiple Elastic Agents behind a network load balancer to distribute the syslog traffic evenly. Place agents close to the FortiEDR Central Manager to minimize network latency and ensure horizontal scalability.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

This reference guide provides details about the inputs and data streams used by the Fortinet FortiEDR Logs integration.

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


### Data streams

#### log

The `log` data stream provides events from Fortinet FortiEDR of the following types: security alerts, incident details, and endpoint logs.

##### log fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| fortinet.edr.action |  | keyword |
| fortinet.edr.autonomous_system |  | keyword |
| fortinet.edr.certificate |  | keyword |
| fortinet.edr.classification |  | keyword |
| fortinet.edr.count |  | keyword |
| fortinet.edr.country |  | keyword |
| fortinet.edr.destination |  | keyword |
| fortinet.edr.device_name |  | keyword |
| fortinet.edr.event_id |  | keyword |
| fortinet.edr.first_seen |  | date |
| fortinet.edr.last_seen |  | date |
| fortinet.edr.mac_address |  | keyword |
| fortinet.edr.operating_system |  | keyword |
| fortinet.edr.organization |  | keyword |
| fortinet.edr.organization_id |  | keyword |
| fortinet.edr.process_name |  | keyword |
| fortinet.edr.process_path |  | keyword |
| fortinet.edr.process_type |  | keyword |
| fortinet.edr.raw_data_id |  | keyword |
| fortinet.edr.rules_list |  | keyword |
| fortinet.edr.script |  | keyword |
| fortinet.edr.script_path |  | keyword |
| fortinet.edr.severity |  | keyword |
| fortinet.edr.users |  | keyword |
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
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Full path to the log file this event came from. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.appname | The device or application that originated the Syslog message, if available. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.hostname | The hostname, FQDN, or IP of the machine that originally sent the Syslog message. This is sourced from the hostname field of the syslog header. Depending on the environment, this value may be different from the host that handled the event, especially if the host handling the events is acting as a collector. | keyword |
| log.syslog.msgid | An identifier for the type of Syslog message, if available. Only applicable for RFC 5424 messages. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.procid | The process name or ID that originated the Syslog message, if available. | keyword |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| log.syslog.version | The version of the Syslog protocol specification. Only applicable for RFC 5424 messages. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |


##### log sample event

An example event for `log` looks as following:

```json
{
    "@timestamp": "2019-09-18T06:42:18.000Z",
    "agent": {
        "ephemeral_id": "a328c9b6-3f49-4e0a-bc08-181d13ad6b77",
        "id": "e2f57999-9659-45c8-a03c-c5bf85dc5124",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.3"
    },
    "data_stream": {
        "dataset": "fortinet_fortiedr.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "e2f57999-9659-45c8-a03c-c5bf85dc5124",
        "snapshot": false,
        "version": "8.3.3"
    },
    "event": {
        "action": "blocked",
        "agent_id_status": "verified",
        "category": "malware",
        "dataset": "fortinet_fortiedr.log",
        "end": "2019-09-18T02:42:18.000Z",
        "id": "458478",
        "ingested": "2022-08-26T07:24:21Z",
        "original": "<133>1 2019-09-18T06:42:18.000Z 1.1.1.1 enSilo - - - Organization: Demo;Organization ID: 156646;Event ID: 458478; Raw Data ID: 1270886879;Device Name: WIN10-VICTIM;Operating System: Windows 10 Pro N; Process Name: svchost.exe;Process Path: \\Device\\HarddiskVolume4\\Windows\\System32\\svchost.exe; Process Type: 64bit;Severity: Critical;Classification: Suspicious;Destination: File Creation; First Seen: 18-Sep-2019, 02:42:18;Last Seen: 18-Sep-2019, 02:42:18;Action: Blocked;Count: 1; Certificate: yes;Rules List: File Encryptor - Suspicious file modification;Users: WIN10-VICTIM\\U; MAC Address: 00-0C-29-D4-75-EC;Script: N/A;Script Path: N/A;Autonomous System: N/A;Country: N/A",
        "start": "2019-09-18T02:42:18.000Z",
        "timezone": "+00:00"
    },
    "fortinet": {
        "edr": {
            "action": "Blocked",
            "autonomous_system": "N/A",
            "certificate": "yes",
            "classification": "Suspicious",
            "count": "1",
            "country": "N/A",
            "destination": "File Creation",
            "device_name": "WIN10-VICTIM",
            "event_id": "458478",
            "first_seen": "2019-09-18T02:42:18.000Z",
            "last_seen": "2019-09-18T02:42:18.000Z",
            "mac_address": "00-0C-29-D4-75-EC",
            "operating_system": "Windows 10 Pro N",
            "organization": "Demo",
            "organization_id": "156646",
            "process_name": "svchost.exe",
            "process_path": "\\Device\\HarddiskVolume4\\Windows\\System32\\svchost.exe",
            "process_type": "64bit",
            "raw_data_id": "1270886879",
            "rules_list": "File Encryptor - Suspicious file modification",
            "script": "N/A",
            "script_path": "N/A",
            "severity": "Critical",
            "users": "WIN10-VICTIM\\U"
        }
    },
    "host": {
        "hostname": "WIN10-VICTIM",
        "mac": [
            "00-0C-29-D4-75-EC"
        ],
        "os": {
            "full": "Windows 10 Pro N"
        }
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "192.168.48.4:47582"
        },
        "syslog": {
            "appname": "enSilo",
            "facility": {
                "code": 16
            },
            "hostname": "1.1.1.1",
            "priority": 133,
            "severity": {
                "code": 5
            },
            "version": "1"
        }
    },
    "observer": {
        "product": "FortiEDR",
        "type": "edr",
        "vendor": "Fortinet"
    },
    "process": {
        "executable": "\\Device\\HarddiskVolume4\\Windows\\System32\\svchost.exe",
        "name": "svchost.exe"
    },
    "related": {
        "hosts": [
            "WIN10-VICTIM",
            "1.1.1.1"
        ],
        "user": [
            "WIN10-VICTIM\\U"
        ]
    },
    "tags": [
        "preserve_original_event",
        "fortinet-fortiedr",
        "forwarded"
    ],
    "user": {
        "id": "WIN10-VICTIM\\U"
    }
}
```

### Vendor documentation links

You can find additional information about Fortinet FortiEDR logs in the following resources:
- [FortiEDR Administration Guide: Syslog](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/109591/syslog)
- [FortiEDR Administration Guide: Export Settings](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/918407/export-settings)
- [FortiEDR Administration Guide: Automated Incident Response - Playbooks](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide/419440/automated-incident-response-playbooks-page)
- [Fortinet FortiEDR Administration Guide](https://docs.fortinet.com/document/fortiedr/7.2.0/administration-guide)
- [Fortinet Documentation Library](https://docs.fortinet.com/)
- [Elastic Fortinet FortiEDR Integration Reference](https://www.elastic.co/docs/reference/integrations/fortinet_fortiedr)
