# QNAP NAS Integration for Elastic

> **Note**: This documentation was generated using AI and should be reviewed for accuracy.

## Overview

The QNAP NAS integration for Elastic enables you to collect and analyze Event and Access logs from your QNAP devices. By ingesting these logs into the Elastic Stack, you'll improve your security posture, monitor system health, and maintain audit trails for compliance.

This integration facilitates:
- Security monitoring: Monitor for unauthorized access attempts, failed logins, successful user authentications, and changes to user permissions to detect potential threats and malicious activity.
- Operational insight: Track critical system events such as device reboots, firmware updates, service starts or stops, and storage volume health to manage device status effectively.
- Compliance auditing: Maintain a comprehensive and immutable record of system and user activities on the QNAP NAS, which is essential for meeting regulatory requirements and internal auditing processes.
- Troubleshooting and diagnostics: Use detailed event and access logs to diagnose system problems, identify performance bottlenecks, and resolve configuration issues affecting the NAS device and its users.

### Compatibility

This integration has been tested against QNAP NAS QTS 4.5.4 and is expected to work with versions later than QTS 4.5.4. It's only compatible with logs sent using the "Send to Syslog Server" option, which uses the RFC-3164 syslog format.

### How it works

This integration collects logs by receiving syslog data over TCP or UDP. You configure your QNAP NAS device to forward its logs to an Elastic Agent running on a host that is reachable from your NAS. The agent acts as a syslog receiver, processes the RFC-3164 formatted logs from the `log` data stream, and forwards them to your Elastic deployment for monitoring and analysis.

## What data does this integration collect?

You can use the QNAP NAS integration to collect various system and activity logs from your NAS devices. It's designed to collect the following types of log messages:
- QNAP NAS logs (TCP): This data stream collects QNAP NAS event and access logs using the TCP protocol. It processes logs formatted according to RFC-3164, providing you with detailed records of system events and user activities.
- QNAP NAS logs (UDP): This data stream collects QNAP NAS event and access logs using the UDP protocol. It also processes RFC-3164 formatted logs, offering you an alternative for collecting event and access data.

You'll find these logs processed and stored in the `log` data stream.

### Supported use cases

Integrating your QNAP NAS logs with the Elastic Stack gives you visibility into your storage environment and helps you improve your security posture. You can use this integration for the following use cases:
- Security monitoring: You can monitor user authentication, file access, and administrative changes to identify unauthorized activity or potential security breaches.
- System health tracking: You'll be able to review system events, hardware status, and service logs to ensure your NAS infrastructure is performing optimally and to receive early warnings of hardware issues.
- Compliance and auditing: You'll maintain a searchable, long-term archive of access and system logs to satisfy regulatory requirements and simplify your internal audits.
- Troubleshooting: You can quickly identify the root cause of service interruptions or configuration issues by analyzing detailed system event logs.

## What do I need to use this integration?

You'll need to satisfy several vendor and Elastic prerequisites before you can use this integration.

### Vendor prerequisites

You'll need administrative access and specific applications configured on your QNAP NAS:
- You'll need full administrator access to the QNAP QTS web administration interface to configure log forwarding using the `QuLog Center`.
- You must install the `QuLog Center` application on your QNAP NAS. If it's not present, you can install it from the App Center.
- Ensure you have network connectivity between the QNAP NAS and the Elastic Agent host using your chosen protocol (`TCP`, `UDP`, or `TLS`) and port (for example, `9301`). Check that no firewalls are blocking communication between the NAS and the agent.
- You'll need the IP address of the server where the Elastic Agent is running so you can configure it as the syslog server destination.
- Decide on the protocol and port number the Elastic Agent will listen on; your choice must match the configuration on both the QNAP NAS and the Elastic Agent.

### Elastic prerequisites

You'll need to have your Elastic environment prepared:
- You must have an Elastic Agent installed and successfully enrolled in Fleet, connected to your Elastic Stack instance.
- Ensure the Elastic Agent host is reachable from the QNAP NAS on the configured syslog port (for example, `9301`) and protocol (`TCP`, `UDP`, or `TLS`). You should verify that any host-based firewalls on the Elastic Agent server or network firewalls allow inbound connections on the specified port.
- Use an Elastic Stack (Elasticsearch and Kibana) version that is compatible with the version of the Elastic Agent you're using.

## How do I deploy this integration?

### Agent-based deployment

You must install Elastic Agent to use this integration. For detailed installation instructions, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can only install one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog receiver and ship the data to Elastic, where the events are then processed using the integration's ingest pipelines.

### Set up steps in QNAP NAS

Follow these steps to configure your QNAP NAS device to send logs to the Elastic Agent:

1.  Log in to your QNAP QTS web administration interface using an administrator account.
2.  Open the **QuLog Center** application. If it's not installed, navigate to the **App Center** and install it.
3.  In QuLog Center, navigate to **QuLog Service** using the left-hand menu.
4.  Click the **Log Sender** tab to manage log forwarding settings.
5.  Select the checkbox next to **Send logs to a syslog server** to enable the log forwarding service.
6.  Click **Add a log sending rule** to initiate the configuration of a new syslog destination for the Elastic Agent.
7.  In the rule creation window, configure the following settings:
    *   Server: Enter the IP address of the server where your Elastic Agent is running.
    *   Protocol: Choose the protocol (`UDP`, `TCP`, or `TLS`) that precisely matches the syslog input configuration of your Elastic Agent.
    *   Port: Specify the port number (for example, `9301`) that your Elastic Agent is configured to listen on for syslog messages.
    *   Log Format: Select `RFC-3164` as the log format. This is critical for the integration to correctly parse the logs.
8.  Under Log Type, choose the types of logs you wish to send. It's recommended to select both **Event Log** and **Access Log** for comprehensive monitoring.
9.  Click the **Test** button to send a test message from the QNAP NAS to the configured Elastic Agent and verify that the connection is successful.
10. If the test is successful, click **Apply** to save the log sending rule.

#### Vendor resources

For more information about configuring your device, you can refer to the following documentation:

- [QNAP QTS 5.0.x User Manual](https://docs.qnap.com/operating-system/qts/5.0.x/en-us/configuring-samba-microsoft-networking-settings-7447174D.html)

### Set up steps in Kibana

To set up the integration in Kibana, follow these steps:

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for QNAP NAS and select the integration.
3.  Click **Add QNAP NAS**.
4.  Follow the prompts to add the integration to an existing Elastic Agent policy or create a new one.
5.  Choose the setup instructions below that match your QNAP NAS syslog configuration.

#### Collecting logs from QNAP NAS using TCP

This input collects logs over a TCP socket. Configure the following fields:

- Syslog Host: The host address to listen on for syslog messages (for example, `0.0.0.0` or `localhost`).
- Syslog Port: The port number to listen on (for example, `9301`).
- Timezone Offset: By default, log timestamps are interpreted based on the agent host's timezone. Use this field to set the correct offset (for example, `Europe/Amsterdam` or `-05:00`) if the logs come from a different timezone.
- SSL Configuration: Configure SSL options for encrypted communication. Refer to the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details.
- Preserve original event: If enabled, a raw copy of the original log is stored in the `event.original` field.
- Tags: Add custom tags to your events (defaults to `qnap-nas` and `forwarded`).
- Processors: Add custom processors to enhance or reduce event fields before parsing.

#### Collecting logs from QNAP NAS using UDP

This input collects logs over a UDP socket. Configure the following fields:

- Syslog Host: The host address to listen on for syslog messages (for example, `0.0.0.0` or `localhost`).
- Syslog Port: The port number to listen on (for example, `9301`).
- Timezone Offset: Use this to set the correct timezone offset if the QNAP NAS is in a different timezone than the agent host.
- Preserve original event: If enabled, the raw log is saved in the `event.original` field.
- Tags: Add custom tags to your events (defaults to `qnap-nas` and `forwarded`).
- Custom UDP Options: Specify advanced configuration options for the UDP input, such as:
  ```yaml
  read_buffer: 100MiB
  max_message_size: 50KiB
  timeout: 300s
  ```
- Processors: Add custom processors to modify the events before the agent sends them.

After configuring the settings, click **Save and Deploy** to update your agent policy.

### Validation

Follow these steps to verify that the integration is working and data is flowing to the Elastic Stack:

1.  Trigger data flow on the QNAP NAS by performing any of the following actions:
    - Log out of the QNAP QTS web administration interface and then log back in to generate authentication events.
    - Access a shared folder and create or delete a file to generate access logs.
    - Change a system setting like Date & Time or network settings to trigger configuration events.
    - Access a shared folder from a client device using SMB/CIFS or NFS to generate additional access logs.
2.  Check the data in Kibana using these steps:
    - Navigate to **Analytics > Discover**.
    - Select the `logs-*` data view.
    - Enter the following KQL filter: `data_stream.dataset : "qnap_nas.log"`.
    - Verify that logs appear in the results and confirm that fields like `event.dataset`, `source.ip`, and `message` are populated.
    - Navigate to **Analytics > Dashboards** and search for QNAP NAS to view the pre-built visualizations.

## Troubleshooting

For help with Elastic ingest tools, check the [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems) documentation.

### Common configuration issues

If you encounter problems with the integration, check these common issues:
- No logs appearing in Kibana: Verify that the server IP address you configured in the QNAP QuLog Center's Send to Syslog Server tab matches the IP address of the Elastic Agent host. Make sure the port number matches the `syslog_port` you configured in your integration (the default is `9301`). You'll also want to confirm that the protocol (UDP, TCP, or TLS) on the QNAP NAS matches the input type you selected in the integration. Also, check firewall rules on both the NAS and the Agent host to ensure traffic can pass through. You can use a utility like `tcpdump` on the Agent host to verify reception: `tcpdump -i any port 9301`.
- Logs are present but unparsed or missing fields: In the QNAP QuLog Center, confirm that you've set the log format to `RFC-3164`, as other formats aren't supported. Check the `error.message` field in Kibana Discover for specific parsing error details. If you've enabled the `preserve_original_event` setting, check the `event.original` field to view the raw log payload. Additionally, verify that you've correctly configured the `Timezone Offset` if the NAS is in a different timezone than the Elastic Agent host.
- Parsing failures for specific log types: If you receive certain logs but they aren't processed correctly, inspect the `error.message` field for clues. This often happens if the log content deviates from the expected `RFC-3164` standard. You can compare the raw log in `event.original` with the standard format to identify discrepancies.

### Vendor resources

For more information about QNAP NAS logging and configuration, you can refer to these resources:
- [QNAP QTS 5.0.x User Manual](https://docs.qnap.com/operating-system/qts/5.0.x/en-us/configuring-samba-microsoft-networking-settings-7447174D.html)
- [QNAP NAS Official Website](https://qnap.com)

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

### Transport protocol considerations

When you're configuring syslog collection from QNAP NAS devices, consider these trade-offs between `UDP` and `TCP`:
- `UDP` offers faster, connectionless transmission. It's suitable for high-volume logs where occasional packet loss is acceptable.
- `TCP` provides reliable, ordered delivery. It ensures all logs are received and is preferred for critical security and audit events, though it has more overhead.
- `TLS` can be used with `TCP` for encrypted transport. It adds security but increases the processing load on both the NAS and the Elastic Agent.

### Data volume management

To optimize performance and reduce the amount of data you're sending to the Elastic Stack, configure the QNAP NAS device in the `QuLog Center` to send only necessary log types:
- Limit forwarding to `Event Log` and `Access Log`.
- Avoid sending unnecessary log categories if they're available in your QNAP software version.
- Be careful about high log volumes, as they can impact the performance of your NAS device.

### Elastic Agent scaling

A single Elastic Agent can handle a significant volume of syslog traffic. For high-throughput environments or when you're collecting from multiple QNAP NAS devices, consider these strategies:
- Deploy multiple Elastic Agents to distribute the log forwarding load.
- Assign each agent to listen on a unique port or IP address.
- Ensure the host running the Elastic Agent has enough CPU, memory, and disk I/O resources to process and forward logs efficiently.

## Reference

### Inputs used

These inputs can be used with this integration:
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

The `log` data stream provides events from QNAP NAS of the following types: system activities and connection details for protocols such as `Samba`, `FTP`, `HTTP`, `HTTPS`, and `SSH`.

##### log fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| group.name | Name of the group. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| qnap.nas.application | QNAP application that generated the event | keyword |
| qnap.nas.category | Sub-component of the QNAP application that generated the event | keyword |
| qnap.nas.connection_type | Connection type (ex. Samba) | keyword |
| qnap.nas.file.new_path | Renamed/Moved path of accessed resource | keyword |
| qnap.nas.file.path | Path of accessed resource | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


##### log sample event

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-10-30T20:24:24.000Z",
    "agent": {
        "ephemeral_id": "d78177be-a52f-47d7-ab88-ce74c24bde53",
        "id": "8ad7c85d-9943-4b05-b50f-ccab228ad581",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "qnap_nas.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "8ad7c85d-9943-4b05-b50f-ccab228ad581",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "action": "create-directory",
        "agent_id_status": "verified",
        "category": [
            "file"
        ],
        "created": "2022-10-30T20:24:24.000Z",
        "dataset": "qnap_nas.log",
        "ingested": "2022-11-24T09:21:53Z",
        "kind": "event",
        "provider": "conn-log",
        "timezone": "+00:00",
        "type": [
            "creation"
        ]
    },
    "file": {
        "path": "path/to/files/New folder"
    },
    "host": {
        "name": "qnap-nas01"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.24.0.4:35244"
        },
        "syslog": {
            "priority": 30
        }
    },
    "observer": {
        "product": "NAS",
        "type": "nas",
        "vendor": "QNAP"
    },
    "process": {
        "name": "qulogd",
        "pid": 14629
    },
    "qnap": {
        "nas": {
            "connection_type": "Samba",
            "file": {
                "path": "path/to/files/New folder"
            }
        }
    },
    "related": {
        "hosts": [
            "user-laptop"
        ],
        "ip": [
            "10.50.36.33"
        ],
        "user": [
            "admin.user"
        ]
    },
    "source": {
        "address": "10.50.36.33",
        "domain": "user-laptop",
        "ip": "10.50.36.33"
    },
    "tags": [
        "qnap-nas",
        "forwarded"
    ],
    "user": {
        "name": "admin.user"
    }
}
```

### Vendor documentation links

This resource provides additional information about QNAP NAS:
- [QNAP NAS Official Website](https://qnap.com)
