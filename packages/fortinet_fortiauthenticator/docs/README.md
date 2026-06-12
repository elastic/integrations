# Fortinet FortiAuthenticator Logs Integration for Elastic

## Overview

The Fortinet FortiAuthenticator Logs integration for Elastic enables the collection of logs from Fortinet FortiAuthenticator. This allows for system and security monitoring. By ingesting FortiAuthenticator logs, users can gain visibility into radius, and tacacs+ activity.

### Compatibility

This integration has been tested against FortiAuthenticator version 8.0.2, this version has important bugfix for log messages. Version 7.x or any version below 8.0.2 may not work with this integration!

This integration is compatible with Elastic Stack version 9.0.0 or higher.

### How it works

This integration collects logs from FortiAuthenticator by receiving syslog data via TCP/UDP or by reading directly from log files. An Elastic Agent is deployed on a host that is configured as a syslog receiver or has access to the log files. The agent forwards the logs to your Elastic deployment, where they can be monitored or analyzed.

## What data does this integration collect?

The Fortinet FortiAuthenticator Logs integration collects the following types of logs:
*   **System Event logs**: System-level events, license, firmware, high-availability (HA) events, and configuration changes.
*   **Authentication logs**: Records of radius, tacacs+, administrator, and user authentication events

## What do I need to use this integration?

- A FortiAuthenticator with version 8.0.2 or higher and administrative access to configure syslog settings.
- Elastic Stack version 9.0.0 or higher.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that will receive the syslog data or has access to the log files from the FortiAuthenticator. For detailed installation instructions, refer to the Elastic Agent [installation guide](docs-content://reference/fleet/install-elastic-agents.md). Only one Elastic Agent is needed per host.

### Vendor set up steps

#### Syslog Configuration

You can configure FortiAuthenticator to send logs to the Elastic Agent using either the GUI or the CLI.

**GUI Configuration:**

1.  Log in to the Fortinet FortiAuthenticator
2.  Navigate to **Logging -> Log Config -> Syslog Servers**.
3.  Create new syslog-server. In the IP address field, enter the IP address of the host where the Elastic Agent is installed.
4.  Navigate to **Logging -> Log COnfig -> Log Settings**.
5.  Enable **Send system logs to remote Syslog servers**.
6.  Select your newly created syslog-server and click the right arrow to move to list of "chosen syslog servers"
7.  Click **Save**.

### Onboard / configure in Kibana

1.  In Kibana, navigate to **Management > Integrations**.
2.  Search for "Fortinet FortiAuthenticator" and select the integration.
3.  Click **Add Fortinet FortiAuthenticator Logs**.
4.  Configure the integration by selecting an input type and providing the necessary settings. This integration supports `TCP`, `UDP`, and `Log file` inputs.

#### TCP Input Configuration

This input collects logs over a TCP socket.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address for the TCP listener (e.g., `localhost`, `0.0.0.0`). |
| **Listen Port** | The TCP port number to listen on (e.g., `9004`). |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |
| **Preserve duplicate custom fields** | Check this to preserve fields that were copied to ECS fields. Default: false. |

Under **Advanced Options**, you can configure the following optional parameters:

| Setting | Description |
|---|---|
| **Internal/External interfaces** | Define your network interfaces to correctly map network direction. |
| **Internal networks** | Specify your internal network ranges (defaults to private address spaces). Supports CIDR notation and named ranges like `private`. |
| **SSL Configuration** | Configure SSL options for encrypted communication. See the [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config) for details. |
| **Custom TCP Options** | `max_message_size`: The maximum size of a log message (e.g., `50KiB`). <br> `max_connections`: The maximum number of simultaneous connections. |
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
| **Preserve duplicate custom fields** | Check this to preserve fields that were copied to ECS fields. Default: false. |

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
| **Paths** | A list of file paths to monitor (e.g., `/var/log/fortinet-fortiauthenticatgor.log`). |
| **Preserve original event** | If checked, a raw copy of the original log is stored in the `event.original` field. |
| **Preserve duplicate custom fields** | Check this to preserve fields that were copied to ECS fields. Default: false. |

Under **Advanced Options**, you can configure the following optional parameters:

| Setting | Description |
|---|---|
| **Internal/External interfaces** | Define your network interfaces to correctly map network direction. |
| **Internal networks** | Specify your internal network ranges (defaults to private address spaces). |
| **Timezone** | Specify an IANA timezone or offset (e.g., `+0200`) for logs with no timezone information. |
| **Timezone Map** | A mapping of timezone strings from logs to standard IANA timezone formats. |
| **Processors** | Add custom processors to enhance or reduce event fields before parsing. |

After configuring the input, assign the integration to an agent policy and click **Save and continue**.

### Validation

1.  First, verify on the FortiAuthenticator device that logs are being actively sent to the configured Elastic Agent host.
2.  In Kibana, navigate to **Discover**.
3.  In the search bar, enter `data_stream.dataset: "fortinet_fortiauthenticator.log"` and check for incoming documents.
4.  Verify that events are appearing with recent timestamps.
5.  Navigate to **Management > Dashboards** and search for "Fortinet FortiAuthenticator Overview" to see if the visualizations are populated with data.
6.  Generate some test traffic that would be logged by the FortiAuthenticator and confirm that the corresponding logs appear in Kibana.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common Configuration Issues

-   **No data is being collected**:
    *   Verify network connectivity (e.g., using `ping` or `netcat`) between the FortiAuthenticator and the Elastic Agent host.
    *   Ensure there are no firewalls or network ACLs blocking the syslog port.
    *   Confirm that the syslog listening port configured in the Elastic integration matches the destination port configured on the FortiAuthenticator.

### Vendor Resources

-   [Fortinet Fortiauthenticator - Log configuration](https://docs.fortinet.com/document/fortiauthenticator/8.0.2/administration-guide/964220/log-configuration)
-   [Fortinet Documentation Library](https://docs.fortinet.com/)
-   [Fortiauthenticator Guide](https://docs.fortinet.com/product/fortiauthenticator)

## Performance and Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### log

The `log` data stream collects all log types from the FortiAuthenticator.

#### log fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.action | The event action as described in FortiAuthenticator documentation. (e.g "FortiAuthenticator-admin-gui-login") | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| fortinet.fortiauthenticator.log.action | Action field from the log (e.g., "EAP Login", "Authentication", "Login"). | keyword |
| fortinet.fortiauthenticator.log.category | Log category (e.g., "Event"). | keyword |
| fortinet.fortiauthenticator.log.changes | Fields that were modified in a user edit operation (e.g., "email address and password", "FortiToken", "enabled and FortiToken"). | keyword |
| fortinet.fortiauthenticator.log.level | Log severity level (e.g., "information", "notice", "warning", "error"). | keyword |
| fortinet.fortiauthenticator.log.mfa_method | MFA or authentication method used (e.g., "FortiToken", "no token"). | keyword |
| fortinet.fortiauthenticator.log.msg | Additional message field present in some system log lines. | keyword |
| fortinet.fortiauthenticator.log.nas | Network Access Server (NAS) identifier or IP address. | keyword |
| fortinet.fortiauthenticator.log.reason | Reason or detail message for the authentication outcome. | keyword |
| fortinet.fortiauthenticator.log.status | Status of the event (e.g., "Success", "Failed", "Start"). | keyword |
| fortinet.fortiauthenticator.log.subcategory | Log subcategory (e.g., "Authentication", "System", "Admin Configuration", "High Availability"). | keyword |
| fortinet.fortiauthenticator.log.typeid | Numeric event type identifier. | integer |
| fortinet.fortiauthenticator.log.user | Username associated with the event. | keyword |
| fortinet.fortiauthenticator.log.userip | IP address of the end-user device. | ip |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was received. | keyword |
| tags | User defined tags. | keyword |


#### log sample event

An example event for `log` looks as following:

```json
{
    "@timestamp": "2026-04-07T16:34:36.000Z",
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "action": "FortiAuthenticator-admin-gui-authentication",
        "category": [
            "authentication",
            "iam"
        ],
        "code": "20994",
        "kind": "event",
        "original": "Apr  7 16:34:36 fortiauthenticator category=\"Event\" subcategory=\"Authentication\" typeid=20994 level=\"information\" user=\"admin\" nas=\"\" userip=\"192.0.2.100\" action=\"Login\" status=\"Success\" Local administrator authentication from 192.0.2.100  with no token successful",
        "outcome": "success",
        "type": [
            "admin",
            "info"
        ]
    },
    "fortinet": {
        "fortiauthenticator": {
            "log": {
                "action": "Login",
                "category": "Event",
                "level": "information",
                "mfa_method": "no token",
                "status": "Success",
                "subcategory": "Authentication",
                "typeid": 20994,
                "user": "admin",
                "userip": "192.0.2.100"
            }
        }
    },
    "log": {
        "level": "information"
    },
    "message": "Local administrator authentication from 192.0.2.100  with no token successful",
    "observer": {
        "hostname": "fortiauthenticator",
        "product": "FortiAuthenticator",
        "type": "authentication-server",
        "vendor": "Fortinet"
    },
    "related": {
        "ip": [
            "192.0.2.100"
        ],
        "user": [
            "admin"
        ]
    },
    "source": {
        "ip": "192.0.2.100",
        "user": {
            "name": "admin"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields"
    ],
    "user": {
        "name": "admin"
    }
}
```

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

