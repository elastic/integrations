# Broadcom ProxySG Integration for Elastic

## Overview

The Broadcom ProxySG integration for Elastic enables the collection of access logs from Broadcom ProxySG appliances. This allows for comprehensive monitoring of web traffic, security events, and user activities within the Elastic Stack. By ingesting ProxySG logs, organizations can gain visibility into web usage patterns, enforce compliance policies, and detect security threats.

This integration facilitates:
- **Web Traffic Monitoring and Control**: Monitor, filter, and control web traffic to ensure compliance and enhance security.
- **Data Loss Prevention (DLP)**: Inspect outbound traffic to help prevent sensitive data exfiltration.
- **Malware Protection**: Scan web traffic for malware and block malicious content.
- **SSL Inspection**: Identify and block malicious activities hidden in encrypted traffic.
- **Bandwidth Management**: Optimize network performance by analyzing bandwidth usage.

### Compatibility

This integration is compatible with Broadcom ProxySG appliances that support the following access log formats:
- `main`
- `bcreportermain_v1`
- `bcreporterssl_v1`
- `ssl`

### How it works

This integration collects logs from ProxySG appliances using two primary methods:
1.  **Syslog (UDP/TCP)**: The ProxySG appliance is configured to stream access logs via syslog to the Elastic Agent.
2.  **File-based Collection**: The ProxySG appliance uploads log files to a server where the Elastic Agent is installed and configured to read them.

The Elastic Agent receives the logs, parses them according to the selected format, and forwards them to Elasticsearch for storage and analysis.

## What data does this integration collect?

The Broadcom ProxySG integration collects **Access Logs**, which provide detailed records of web traffic processed by the proxy. Depending on the log format configured, this data includes:

-   **Traffic Details**: URLs accessed, HTTP methods, bytes transferred, status codes, and action taken (e.g., TCP_HIT, TCP_MISS).
-   **User Information**: Usernames, authentication groups, and client IP addresses.
-   **Security Events**: Blocked sites, malware detection events, threat risk scores, and SSL validation status.
-   **Performance Metrics**: Request duration and connection details.

### Supported use cases

Integrating Broadcom ProxySG with Elastic enables several critical security and operational use cases:

-   **Security Auditing**: maintain a complete audit trail of all web access to investigate security incidents and policy violations.
-   **Threat Detection**: Correlate proxy logs with other security data to identify complex threats and compromised hosts.
-   **Usage Analytics**: Analyze web traffic trends to optimize network resources and user productivity.
-   **Compliance Reporting**: Generate reports on web usage and blocked content to meet regulatory requirements.

## What do I need to use this integration?

-   **Broadcom ProxySG Appliance**: Admin access to configure access logging and log transmission.
-   **Elastic Agent**: Installed on a host that is reachable by the ProxySG appliance (for syslog) or has access to the uploaded log files.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that will receive the syslog data or has access to the log files. For detailed installation instructions, refer to the Elastic Agent [installation guide](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Set up steps in Broadcom ProxySG

You can configure Broadcom ProxySG to send logs using either Syslog (recommended for real-time monitoring) or File Upload.

#### For Syslog Collection (TCP/UDP)

1.  **Log in to the Management Console**: Access the ProxySG Management Console with administrative credentials.
2.  **Configure Access Logging**:
    -   Navigate to **Configuration** > **Access Logging** > **Logs**.
    -   Create a new log facility or select an existing one.
    -   Set the **Log Format** to one of the supported formats: `main`, `bcreportermain_v1`, `bcreporterssl_v1`, or `ssl`. *Note: This must match the configuration in the Elastic integration.*
3.  **Set Up Log Destination**:
    -   Navigate to **Log Hosts**.
    -   Add the IP address of the server where the Elastic Agent is running.
    -   Specify the port number (Default UDP: 514, Default TCP: 601).
    -   Select the protocol (UDP or TCP).
4.  **Apply Configuration**:
    -   Ensure logging is enabled for your active policies.
    -   Click **Apply** to save the changes.

#### For File-Based Collection

1.  **Configure File Upload**:
    -   In the Management Console, navigate to **Configuration** > **Access Logging**.
    -   Configure the appliance to upload access logs to the server where Elastic Agent is running.
    -   Define the schedule and the destination directory.
2.  **Select Log Format**:
    -   Ensure the log format for the uploaded files is set to one of the supported formats (`main`, `bcreportermain_v1`, `bcreporterssl_v1`, or `ssl`).

### Set up steps in Kibana

1.  In Kibana, navigate to **Management** > **Integrations**.
2.  Search for "Broadcom ProxySG" and select the integration.
3.  Click **Add Broadcom ProxySG**.
4.  Select the appropriate **Input type** based on your ProxySG configuration:
    -   **Collect logs from ProxySG via UDP**
    -   **Collect logs from ProxySG via TCP**
    -   **Collect access logs from ProxySG via logging server file**

#### Input Configuration

**For UDP/TCP Inputs:**
-   **Listen Address**: Enter the address the agent should listen on (default `localhost`). Use `0.0.0.0` to listen on all interfaces.
-   **Listen Port**: Enter the port configured on the ProxySG appliance (UDP default `514`, TCP default `601`).
-   **Access Log Format**: Select the format that matches your ProxySG configuration (`main`, `bcreportermain_v1`, `bcreporterssl_v1`, or `ssl`).

**For File-based Input:**
-   **Paths**: Specify the path pattern to the log files uploaded by ProxySG (e.g., `/var/log/proxysg/*.log`).
-   **Access Log Format**: Select the format that matches the logs (`main`, `bcreportermain_v1`, `bcreporterssl_v1`, or `ssl`).

#### Common Options
-   **Preserve original event**: Enable this to store the raw log message in `event.original`. This is useful for troubleshooting parsing issues.
-   **Tags**: Add custom tags to your events (e.g., `proxysg`, `forwarded`).

5.  **Save and Deploy**: Click **Save and continue**, then select the agent policy to deploy the integration.

## Troubleshooting

### Common Configuration Issues

-   **No logs appearing in Kibana**:
    -   **Check Connectivity**: Ensure the ProxySG appliance can reach the Elastic Agent on the configured IP and Port. Check firewalls and routing.
    -   **Verify Agent Status**: Ensure the Elastic Agent is healthy and the integration policy is applied.
    -   **Check Listen Interface**: If sending from a remote appliance, ensure Listen Address is set to `0.0.0.0`, not `localhost`.

-   **Parsing Errors / Incorrect Fields**:
    -   **Format Mismatch**: The most common cause is a mismatch between the **Access Log Format** selected in the integration and the actual format configured on the ProxySG appliance. Verify both are set to the same standard format (e.g., both set to `main`).
    -   **Custom Formats**: This integration supports the standard vendor formats. If you have customized the log string on the ProxySG, parsing may fail. Revert to a standard format or use the `preserve_original_event` option to debug.

-   **Missing SSL Fields**:
    -   If SSL-related fields are empty, ensure you are using a log format that supports them, such as `ssl` or `bcreporterssl_v1`.

### Ingestion Errors

-   **Timestamp Issues**: Ensure the ProxySG appliance and the Elastic Agent host are synchronized with a reliable NTP source to prevent timestamp skews.

## Performance and scaling

-   **Log Volume**: ProxySG appliances can generate high volumes of logs. Ensure your network bandwidth and the Elastic Agent host resources (CPU/RAM) are sufficient to handle the load.
-   **Load Balancing**: For high-availability and scaling, you can place a load balancer in front of multiple Elastic Agents and configure the ProxySG to send logs to the load balancer VIP.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### log

The `log` data stream collects access logs from the ProxySG appliance.

#### log fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Count of bytes sent by the client. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Type of input. | keyword |
| log.file.device_id | Log file device ID. | keyword |
| log.file.inode | Log file inode. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address for the log. | keyword |
| proxysg.client.ip |  | keyword |
| proxysg.client_to_server.auth_group |  | keyword |
| proxysg.client_to_server.auth_groups |  | keyword |
| proxysg.client_to_server.bytes |  | keyword |
| proxysg.client_to_server.categories |  | keyword |
| proxysg.client_to_server.certificate_subject |  | keyword |
| proxysg.client_to_server.connection_negotiated_cipher |  | keyword |
| proxysg.client_to_server.connection_negotiated_cipher_size |  | keyword |
| proxysg.client_to_server.connection_negotiated_ssl_version |  | keyword |
| proxysg.client_to_server.host |  | keyword |
| proxysg.client_to_server.icap_error_details |  | keyword |
| proxysg.client_to_server.icap_status |  | keyword |
| proxysg.client_to_server.method |  | keyword |
| proxysg.client_to_server.ocsp_error |  | keyword |
| proxysg.client_to_server.referer |  | keyword |
| proxysg.client_to_server.rs_content_type |  | keyword |
| proxysg.client_to_server.threat_id |  | keyword |
| proxysg.client_to_server.threat_risk |  | keyword |
| proxysg.client_to_server.threat_source |  | keyword |
| proxysg.client_to_server.uri_extension |  | keyword |
| proxysg.client_to_server.uri_path |  | keyword |
| proxysg.client_to_server.uri_port |  | long |
| proxysg.client_to_server.uri_query |  | keyword |
| proxysg.client_to_server.uri_scheme |  | keyword |
| proxysg.client_to_server.user_agent |  | keyword |
| proxysg.client_to_server.userdn |  | keyword |
| proxysg.client_to_server.username |  | keyword |
| proxysg.client_to_server.x_requested_with |  | keyword |
| proxysg.remote.ip |  | keyword |
| proxysg.remote.supplier_country |  | keyword |
| proxysg.remote_to_server.certificate_hostection_negotname |  | keyword |
| proxysg.remote_to_server.certificate_hostection_negotnamecategory |  | keyword |
| proxysg.remote_to_server.certificate_hostname |  | keyword |
| proxysg.remote_to_server.certificate_hostname_category |  | keyword |
| proxysg.remote_to_server.certificate_hostname_threat_risk |  | keyword |
| proxysg.remote_to_server.certificate_observed_errors |  | keyword |
| proxysg.remote_to_server.certificate_validate_status |  | keyword |
| proxysg.remote_to_server.connection_negotiated_cipher |  | keyword |
| proxysg.remote_to_server.connection_negotiated_cipher_size |  | keyword |
| proxysg.remote_to_server.connection_negotiated_cipher_strength |  | keyword |
| proxysg.remote_to_server.connection_negotiated_ssl_version |  | keyword |
| proxysg.remote_to_server.content_type |  | keyword |
| proxysg.remote_to_server.icap_error_details |  | keyword |
| proxysg.remote_to_server.icap_status |  | keyword |
| proxysg.remote_to_server.ocsp_error |  | keyword |
| proxysg.remote_to_server.threat_id |  | keyword |
| proxysg.remote_to_server.threat_source |  | keyword |
| proxysg.server.action |  | keyword |
| proxysg.server.hierarchy |  | keyword |
| proxysg.server.ip |  | keyword |
| proxysg.server.sitename |  | keyword |
| proxysg.server.supplier_country |  | keyword |
| proxysg.server.supplier_failures |  | keyword |
| proxysg.server.supplier_ip |  | keyword |
| proxysg.server.supplier_name |  | keyword |
| proxysg.server_to_client.bytes |  | keyword |
| proxysg.server_to_client.filter_result |  | keyword |
| proxysg.server_to_client.status |  | keyword |
| proxysg.time_taken |  | long |
| proxysg.x_bluecoat.access_security_policy_action |  | keyword |
| proxysg.x_bluecoat.access_security_policy_reason |  | keyword |
| proxysg.x_bluecoat.access_type |  | keyword |
| proxysg.x_bluecoat.appliance_name |  | keyword |
| proxysg.x_bluecoat.application_groups |  | keyword |
| proxysg.x_bluecoat.application_name |  | keyword |
| proxysg.x_bluecoat.application_operation |  | keyword |
| proxysg.x_bluecoat.location_id |  | keyword |
| proxysg.x_bluecoat.location_name |  | keyword |
| proxysg.x_bluecoat.placeholder |  | keyword |
| proxysg.x_bluecoat.reference_id |  | keyword |
| proxysg.x_bluecoat.request_tenant_id |  | keyword |
| proxysg.x_bluecoat.transaction_uuid |  | keyword |
| proxysg.x_client_agent_sw |  | keyword |
| proxysg.x_client_agent_type |  | keyword |
| proxysg.x_client_device_id |  | keyword |
| proxysg.x_client_device_name |  | keyword |
| proxysg.x_client_device_type |  | keyword |
| proxysg.x_client_os |  | keyword |
| proxysg.x_client_security_posture_details |  | keyword |
| proxysg.x_client_security_posture_risk_score |  | keyword |
| proxysg.x_cloud_rs |  | keyword |
| proxysg.x_cs_certificate_subject |  | keyword |
| proxysg.x_cs_client_ip_country |  | keyword |
| proxysg.x_cs_connection_negotiated_cipher |  | keyword |
| proxysg.x_cs_connection_negotiated_cipher_size |  | keyword |
| proxysg.x_cs_connection_negotiated_ssl_version |  | keyword |
| proxysg.x_cs_ocsp_error |  | keyword |
| proxysg.x_data_leak_detected |  | keyword |
| proxysg.x_exception_id |  | keyword |
| proxysg.x_icap_reqmod_header_x_icap_metadata |  | keyword |
| proxysg.x_icap_respmod_header_x_icap_metadata |  | keyword |
| proxysg.x_random_ipv6 |  | keyword |
| proxysg.x_rs_certificate_hostname |  | keyword |
| proxysg.x_rs_certificate_hostname_categories |  | keyword |
| proxysg.x_rs_certificate_hostname_threat_risk |  | keyword |
| proxysg.x_rs_certificate_observed_errors |  | keyword |
| proxysg.x_rs_certificate_signature_algorithm |  | keyword |
| proxysg.x_rs_certificate_validate_status |  | keyword |
| proxysg.x_rs_connection_negotiated_cipher |  | keyword |
| proxysg.x_rs_connection_negotiated_cipher_size |  | keyword |
| proxysg.x_rs_connection_negotiated_ssl_version |  | keyword |
| proxysg.x_rs_ocsp_error |  | keyword |
| proxysg.x_sc_connection_issuer_keyring |  | keyword |
| proxysg.x_sc_connection_issuer_keyring_alias |  | keyword |
| proxysg.x_virus_id |  | keyword |
| server.bytes | Count of bytes sent by the server. | long |


#### log sample event

An example event for `log` looks as following:

```json
{
    "@timestamp": "2024-03-22T16:16:01Z",
    "agent": {
        "ephemeral_id": "c62f5fcb-3497-49a3-988a-a076cc2b9dd6",
        "id": "d4460588-94a9-4ddb-8a40-c80a3b7db55a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "client": {
        "bytes": 969,
        "ip": "10.82.255.36",
        "user": {
            "name": "aeinstein"
        }
    },
    "data_stream": {
        "dataset": "proxysg.log",
        "namespace": "55535",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "d4460588-94a9-4ddb-8a40-c80a3b7db55a",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "proxysg.log",
        "duration": 48000000,
        "ingested": "2024-09-12T22:16:57Z",
        "original": "2024-03-22 16:16:01 48 10.82.255.36 302 TCP_NC_MISS 1242 969 GET https pixel.tapad.com 443 /idsync/ex/push ?partner_id=2499&partner_device_id=aeb66687-eabe-442e-b11e-79494b740d0d-640ba437-5553&partner_url=https%3A%2F%2Fa.vidoomy.com%2Fapi%2Frtbserver%2Fpbscookie%3Fuid%3Daeb66687-eabe-442e-b11e-79494b740d0d-640ba437-5553%26vid%3D280fa751e99651c4193ef92f6dab0f92%26dspid%3DCEN aeinstein - - pixel.tapad.com - https://vid.vidoomy.com/ OBSERVED \"FastwebRes_CallCntr;Web Ads/Analytics\" - 142.182.19.21 34.111.113.62 \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36\" sha256WithRSAEncryption",
        "timezone": "+00:00"
    },
    "http": {
        "request": {
            "method": "GET",
            "referrer": "-"
        },
        "response": {
            "status_code": 302
        }
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "172.19.0.6:47495"
        },
        "syslog": {
            "appname": "serverd",
            "facility": {
                "code": 1,
                "name": "user-level"
            },
            "hostname": "srvr",
            "priority": 13,
            "severity": {
                "code": 5,
                "name": "Notice"
            },
            "version": "1"
        }
    },
    "observer": {
        "product": "ProxySG",
        "vendor": "Broadcom"
    },
    "proxysg": {
        "client": {
            "ip": "10.82.255.36"
        },
        "client_to_server": {
            "auth_group": "-",
            "bytes": "969",
            "categories": "FastwebRes_CallCntr;Web Ads/Analytics",
            "host": "pixel.tapad.com",
            "method": "GET",
            "referer": "-",
            "uri_path": "/idsync/ex/push",
            "uri_port": 443,
            "uri_query": "?partner_id=2499&partner_device_id=aeb66687-eabe-442e-b11e-79494b740d0d-640ba437-5553&partner_url=https%3A%2F%2Fa.vidoomy.com%2Fapi%2Frtbserver%2Fpbscookie%3Fuid%3Daeb66687-eabe-442e-b11e-79494b740d0d-640ba437-5553%26vid%3D280fa751e99651c4193ef92f6dab0f92%26dspid%3DCEN",
            "uri_scheme": "https",
            "user_agent": "https://vid.vidoomy.com/",
            "username": "aeinstein"
        },
        "remote_to_server": {
            "content_type": "pixel.tapad.com"
        },
        "server": {
            "action": "TCP_NC_MISS",
            "ip": "142.182.19.21",
            "supplier_name": "-"
        },
        "server_to_client": {
            "bytes": "1242",
            "filter_result": "OBSERVED",
            "status": "302"
        },
        "time_taken": 48,
        "x_virus_id": "-"
    },
    "server": {
        "bytes": 1242,
        "ip": "142.182.19.21"
    },
    "tags": [
        "preserve_original_event",
        "forwarded"
    ],
    "url": {
        "domain": "pixel.tapad.com",
        "path": "/idsync/ex/push",
        "port": 443,
        "query": "?partner_id=2499&partner_device_id=aeb66687-eabe-442e-b11e-79494b740d0d-640ba437-5553&partner_url=https%3A%2F%2Fa.vidoomy.com%2Fapi%2Frtbserver%2Fpbscookie%3Fuid%3Daeb66687-eabe-442e-b11e-79494b740d0d-640ba437-5553%26vid%3D280fa751e99651c4193ef92f6dab0f92%26dspid%3DCEN",
        "registered_domain": "tapad.com",
        "scheme": "https",
        "subdomain": "pixel",
        "top_level_domain": "com"
    },
    "user_agent": {
        "device": {
            "name": "Generic Feature Phone"
        },
        "name": "Other",
        "original": "https://vid.vidoomy.com/"
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

