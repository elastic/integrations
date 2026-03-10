# Broadcom ProxySG Integration for Elastic

> **Note**: This AI-assisted guide was validated by our engineers. You may need to adjust the steps to match your environment.

## Overview

The Broadcom ProxySG integration for Elastic allows you to ingest and analyze web traffic data from your Broadcom ProxySG (formerly Symantec) appliances. By collecting and centralizing these logs, you gain deep visibility into user activity, security threats, and network performance across your infrastructure.

### Compatibility

This integration is compatible with Broadcom ProxySG and Edge SWG appliances. It has been specifically tested and documented for ProxySG / Edge SWG version 7.3 and later.

The integration currently supports the following log formats as defined in the appliance configuration:
- `main`
- `bcreportermain_v1`
- `bcreporterssl_v1`
- `ssl`

This integration is compatible with Elastic Stack version 8.11.0 or later.

### How it works

This integration collects ProxySG access logs by acting as a receiver for data sent from the appliance or by reading logs from a file. You can deploy an Elastic Agent and configure it to collect data through several methods:
- File collection: Use this method when logs are uploaded from the ProxySG appliance to a central logging server where the Elastic Agent is running.
- TCP: Use this method for reliable real-time log transmissions, ensuring delivery for sensitive security audits.
- UDP: Use this method to capture real-time syslog-style transmissions from the appliance, which is suitable for high-velocity environments, and where possible log message loss is acceptable.

Once the logs are ingested, the integration parses the data into the Elastic Common Schema (ECS), making it ready for analysis in Kibana dashboards or for use with Elastic Security.

## What data does this integration collect?

This integration collects ProxySG access logs, which contain detailed records of web traffic passing through your ProxySG appliance. These logs include:

- **Request and response details**: URLs, HTTP methods, status codes, content types, and bytes transferred.
- **Client information**: Source IP addresses, user identities (when authenticated), and user agent strings.
- **Timing data**: Request timestamps, response times, and connection durations.
- **Security context**: SSL/TLS inspection results, certificate details, and threat categories.
- **Policy decisions**: Actions taken (allowed, denied, or observed), matched policy rules, and URL categories.
- **Caching metrics**: Cache hit or miss status and origin server response information.

### Supported use cases

Integrating your Broadcom ProxySG logs with the Elastic Stack provides several benefits for monitoring and securing your network:
- Security monitoring: You can use the logs to detect unauthorized access attempts or suspicious traffic patterns in real time.
- Network traffic analysis: You'll be able to visualize and analyze your network traffic patterns using Kibana dashboards to identify performance issues or optimize resources.
- Compliance and auditing: You can maintain a searchable history of access logs to meet your organization's regulatory requirements for data retention and auditing.
- Incident response: You'll accelerate your investigations by correlating ProxySG data with other security and observability data sources within Elastic.

## What do I need to use this integration?

### Elastic prerequisites
To use this integration, you need:
- An Elastic Agent installed and enrolled in Fleet on a host that can receive network traffic from your Broadcom ProxySG appliance.
- The required TCP or UDP ports open in the host's local firewall to receive log data, when using the network data collection methods.ß

### Vendor prerequisites
You'll need the following from your Broadcom ProxySG environment:
- Administrative credentials for the ProxySG Management Console with permissions to modify access logging and upload client settings.
- Network connectivity between the ProxySG appliance and the Elastic Agent host on the configured ports.
- A supported log configuration on the appliance.
- Permission to install or modify policies in the Visual Policy Manager (VPM) to ensure traffic is written to the access log.
- A destination server for FTP, SFTP, or SCP that the Elastic Agent can access locally if you're using the file upload method.

## How do I deploy this integration?

### Agent-based deployment

You'll need to install the Elastic Agent on a host that can receive syslog data or access the log files from your Broadcom ProxySG appliance. For detailed instructions, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can only install one Elastic Agent per host.

You'll use the Elastic Agent to stream data from your syslog or log file receiver and ship it to Elastic. Once there, the integration's ingest pipelines will process your events.

### Set up steps in Broadcom ProxySG

You'll need to configure your ProxySG appliance to send logs to the host where your Elastic Agent is running. You can choose between syslog collection or file upload.

#### Syslog (TCP/UDP) collection

To send logs using syslog, follow these steps:

1. Log in to your **ProxySG Management Console**.
2. Navigate to **Configuration > Access Logging > Logs > General**.
3. Select the log object you want to collect and ensure the **Log Format** is set to a supported format.
4. Navigate to **Configuration > Access Logging > Logs > Upload Client**.
5. Select the same log object from the list.
6. Change the **Client type** to `Custom Client`.
7. Click **Settings** and configure the following:
    - **Primary Host**: Enter the IP address of your Elastic Agent.
    - **Port**: Enter `514` for UDP or `601` for TCP (replace with your actual port if different).
    - **Protocol**: Select `UDP` or `TCP` depending on your transport preference.
8. Click **OK**, then click **Apply**.
9. Navigate to the **Upload Schedule** tab.
10. Select the log object and set the **Upload type** to `Continuously`.
11. Optionally, set the **Wait time before upload** to `5` seconds for near real-time delivery.
12. Click **Apply**.

#### File upload collection

To upload logs as files, follow these steps:

1. Log in to your **ProxySG Management Console**.
2. Navigate to **Configuration > Access Logging > Logs > Upload Client**.
3. Select the log object you want to collect.
4. Set the **Client type** to `FTP Client`, `SFTP Client`, or `SCP Client` depending on your logging server.
5. Click **Settings** and enter the destination server details where your Elastic Agent can access the files.
6. Under **Save the log file as**, select `text file`.
7. Navigate to the **Upload Schedule** tab and set the **Upload type** to `Periodically` or `Continuously`.
8. Click **Apply**.

#### Enable logging in policy

You'll also need to ensure your policies are configured to log traffic:

1. Launch the **Visual Policy Manager (VPM)** from your ProxySG Console.
2. Create or edit a **Web Access Layer**.
3. Locate or create a rule for the traffic you want to monitor.
4. Right-click the **Action** column and select **Set > New > Modify Access Logging**.
5. Select the log object (for example, `main`) you configured in the previous steps.
6. Click **OK**, then click **Install Policy**.

#### Vendor resources

For more information, refer to these Broadcom resources:

- [Sending Access Logs to a Syslog server - Broadcom Knowledge Base](https://knowledge.broadcom.com/external/article/166529/sending-access-logs-to-a-syslog-server.html)
- [Configure access logging on ProxySG to an FTP server - Broadcom Knowledge Base](https://knowledge.broadcom.com/external/article/165586/configure-access-logging-on-proxysg-or-a.html)

### Set up steps in Kibana

You'll need to add the integration to an Elastic Agent policy in Kibana.

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Broadcom ProxySG** and select it.
3. Click **Add Broadcom ProxySG**.
4. Configure the integration settings based on the input method that matches your ProxySG setup.

#### Collecting access logs via logging server file

Use this input if your ProxySG uploads files to a server that the Elastic Agent can access.

| Setting | Description |
|---|---|
| **Paths** | The file pattern matching the location of your log files (for example, `/var/log/proxysg-log.log`). |
| **Preserve original event** | If you want to keep a raw copy of the event in the `event.original` field, toggle this to `true`. |
| **Access Log Format** | The log configuration type. Supported formats include `main`, `ssl`, `bcreportermain_v1`, and `bcreporterssl_v1`. |

Under **Advanced options**, you'll find these settings:

| Setting | Description |
|---|---|
| **Tags** | Custom tags to append to your events (for example, `proxysg-access-log`). |
| **Custom Filestream Options** | Specify custom configuration for the Filestream input. |
| **Processors** | Add processors to reduce or enhance your events before they're parsed. |

#### Collecting logs via UDP

Use this input if you configured ProxySG to send logs using UDP syslog.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address to listen for UDP connections. Use `0.0.0.0` to bind to all available interfaces. |
| **Listen Port** | The UDP port number to listen on (for example, `514`). |
| **Preserve original event** | If you want to keep a raw copy of the event in the `event.original` field, toggle this to `true`. |
| **Access Log Format** | The log configuration type. Supported formats include `main`, `ssl`, `bcreportermain_v1`, and `bcreporterssl_v1`. |

Under **Advanced options**, you'll find these settings:

| Setting | Description |
|---|---|
| **Tags** | Custom tags to append to your events. |
| **Custom UDP Options** | Specify custom configuration like `read_buffer` or `max_message_size`. |
| **Processors** | Add processors to execute in the agent before logs are parsed. |

#### Collecting logs via TCP

Use this input if you configured ProxySG to send logs using TCP syslog.

| Setting | Description |
|---|---|
| **Listen Address** | The bind address to listen for TCP connections. Use `0.0.0.0` to bind to all available interfaces. |
| **Listen Port** | The TCP port number to listen on (for example, `601`). |
| **Preserve original event** | If you want to keep a raw copy of the event in the `event.original` field, toggle this to `true`. |
| **Access Log Format** | The log configuration type. Supported formats include `main`, `ssl`, `bcreportermain_v1`, and `bcreporterssl_v1`. |

Under **Advanced options**, you'll find these settings:

| Setting | Description |
|---|---|
| **Tags** | Custom tags to append to your events. |
| **Custom TCP Options** | Specify custom configuration for the TCP input. |
| **SSL Configuration** | Configure encrypted transmission using `certificate` and `key` paths. |
| **Processors** | Add processors to execute in the agent before logs are parsed. |

After you've finished configuring your input, click **Save and continue** to add the integration to your agent policy.

### Validation

You'll want to verify that your data is flowing correctly from the ProxySG appliance to Elasticsearch.

#### Trigger data flow on ProxySG

You can generate logs by performing these actions:

- **Generate Web Traffic**: Browse several public websites from a workstation using the ProxySG as a gateway.
- **Trigger Policy Events**: Try to access a URL category that's restricted by your policy to generate "denied" or "blocked" entries.
- **Force Log Upload**: In the Management Console, navigate to **Access Logging > Logs > [Your Log] > Upload Now** and click the button to manually trigger a log push.

#### Check data in Kibana

You can verify the incoming data by following these steps:

1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Enter the KQL filter: `data_stream.dataset : "proxysg.log"`
4. Confirm that logs appear and verify that fields like `event.dataset`, `source.ip`, and `message` are correctly populated.
5. Navigate to **Analytics > Dashboards** and search for "ProxySG" to see if the pre-built dashboards are showing your data.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

If you encounter issues with the Broadcom ProxySG integration, review these common problems and solutions:

- Log format mismatch: Ensure the ProxySG appliance is explicitly using a format supported by the integration. If a custom format is defined on the appliance, the Elastic Agent will fail to parse the fields correctly. Check the settings in **Configuration > Access Logging > Logs > General**.
- Upload schedule delay: If data appears delayed, check the **Upload Schedule** on the ProxySG. Ensure it's set to `Continuously` rather than `Periodically` or `On-Demand`.
- Custom client port conflict: If you're using the syslog method, ensure no other service on the Elastic Agent host is using the configured TCP or UDP port. You can use `netstat -ano` or `ss -tuln` to verify port availability.
- VPM policy not applied: If no logs are appearing, verify that the **Modify Access Logging** action is correctly applied to the relevant rules in the Visual Policy Manager and that the policy has been successfully installed.
- Parsing failures: If logs appear in Kibana but contain a `_grokparsefailure` or `_jsonparseerror` tag, verify that the raw message in the `event.original` field matches the expected structure of the configured ProxySG format.
- Timezone mismatch: If logs appear to be delayed or from the future, check that the ProxySG appliance and the Elastic Agent host are synchronized using NTP and that timezone offsets are correctly handled in the integration settings.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

To ensure optimal performance in high-volume environments, consider the following:
- Transport and collection: For real-time requirements, TCP is the recommended transport protocol to ensure delivery reliability using the `ProxySG logs (via TCP)` input. You can use UDP for high-velocity environments where occasional packet loss is acceptable for reduced overhead. When you use the `ProxySG Access logs` (`filestream`) method, make sure the disk I/O on the logging server can handle the write and read operations of the incoming log files.
- Data volume management: In high-traffic environments, you should use the ProxySG's Web Access Policy to filter out unnecessary logs—such as specific health checks or trusted internal traffic—at the source before you send them to the Elastic Agent. This significantly reduces the processing load on both the appliance and the Elastic Stack ingest pipelines.
- Elastic Agent scaling: If you're working in high-throughput environments exceeding 10,000 events per second, deploy multiple Elastic Agents behind a network load balancer to distribute the Syslog (TCP/UDP) ingestion load. Make sure the host machine for the Agent has enough CPU resources to handle the concurrent parsing of the ProxySG logs across multiple data streams.

## Reference

This reference section provides technical details about the inputs and data streams used by this integration.

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

The following resources provide additional information about Broadcom ProxySG log formats and configuration:
* [Sending Access Logs to a Syslog server - Broadcom Knowledge Base](https://knowledge.broadcom.com/external/article/166529/sending-access-logs-to-a-syslog-server.html)
* [Configure access logging on ProxySG to an FTP server - Broadcom Knowledge Base](https://knowledge.broadcom.com/external/article/165586/configure-access-logging-on-proxysg-or-a.html)
* [Broadcom ProxySG Log Formats Documentation](https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-3/getting-started/page-help-administration/page-help-logging/log-formats/default-formats.html)

### Data streams

The Broadcom ProxySG integration collects the following data stream:

#### log

The `log` data stream provides events from Broadcom ProxySG of the following types: access logs, SSL session logs, and security policy events. It supports logs in the `main`, `ssl`, `bcreportermain_v1`, and `bcreporterssl_v1` formats.

##### log fields

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


##### log sample event

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


