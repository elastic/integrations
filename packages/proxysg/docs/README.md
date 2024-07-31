# Broadcom ProxySG

ProxySG is a secure web gateway solution that enhances the security, performance, and management of web traffic for enterprises by providing URL
filtering, advanced threat protection, and SSL inspection to identify and block malicious activities. It improves web application performance and
reduces bandwidth usage by caching frequently accessed content, while supporting user authentication and access control policies based on various
attributes. Additionally, ProxySG offers detailed reporting and analytics tools for insights into web usage patterns, security incidents, and policy
compliance. Deployed as a physical or virtual appliance or in the cloud, ProxySG serves as a proxy server that inspects, filters, and manages web
traffic to strengthen an organization's network security posture.

## Data streams

The ProxySG integration collects access logs from an appliance. Log can be provided with syslog or files uploaded from the appliance.

Log formats supported by ProxySG are available [here](https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-3/getting-started/page-help-administration/page-help-logging/log-formats/default-formats.html).
Currently the ProxySG integration supports the following formats:

* main

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

ProxySG access logs can be exported from the appliance via syslog or file upload; the integration supports both.

### Syslog

Configure ProxySG to send access logs via syslog to a remote server.

Add the integration, and configure it with "Collect logs from ProxySG via UDP" or "Collect logs from ProxySG via TCP".

In advanced options, select the "Access Log Format" value that matches the configured appliance access log format. 

### File Upload

Configure ProxySG to upload access logs to a remove server on a schedule.

Add the integration, and configure it with "Collect access logs from ProxySG via logging server file"

In advanced options, set "Paths" to the file pattern that matches the location files will be uploaded to on the remote server.
Select the "Access Log Format" value that matches the configured appliance access log format.

### Access Logs

An example event for `log` looks as following:

```json
{
    "@timestamp": "2024-03-22T16:16:01Z",
    "agent": {
        "ephemeral_id": "499ed581-571a-430b-9ef9-5721f68ca7c7",
        "id": "912d13a0-558b-4372-b8cb-7256333c3f5a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "client": {
        "bytes": 969,
        "ip": "10.82.255.36",
        "user": {
            "id": "aeinstein"
        }
    },
    "data_stream": {
        "dataset": "proxysg.log",
        "namespace": "22366",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "912d13a0-558b-4372-b8cb-7256333c3f5a",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "proxysg.log",
        "ingested": "2024-07-30T22:05:31Z",
        "original": "2024-03-22 16:16:01 48 10.82.255.36 302 TCP_NC_MISS 1242 969 GET https pixel.tapad.com 443 /idsync/ex/push ?partner_id=2499&partner_device_id=aeb66687-eabe-442e-b11e-79494b740d0d-640ba437-5553&partner_url=https%3A%2F%2Fa.vidoomy.com%2Fapi%2Frtbserver%2Fpbscookie%3Fuid%3Daeb66687-eabe-442e-b11e-79494b740d0d-640ba437-5553%26vid%3D280fa751e99651c4193ef92f6dab0f92%26dspid%3DCEN aeinstein - - pixel.tapad.com - https://vid.vidoomy.com/ OBSERVED \"FastwebRes_CallCntr;Web Ads/Analytics\" - 142.182.19.21 34.111.113.62 \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36\" sha256WithRSAEncryption",
        "timezone": "+00:00"
    },
    "http": {
        "request": {
            "referrer": "-"
        }
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.19.0.5:47150"
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
        "time_taken": "48",
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
        "path": "/idsync/ex/push",
        "port": 443,
        "query": "?partner_id=2499&partner_device_id=aeb66687-eabe-442e-b11e-79494b740d0d-640ba437-5553&partner_url=https%3A%2F%2Fa.vidoomy.com%2Fapi%2Frtbserver%2Fpbscookie%3Fuid%3Daeb66687-eabe-442e-b11e-79494b740d0d-640ba437-5553%26vid%3D280fa751e99651c4193ef92f6dab0f92%26dspid%3DCEN",
        "scheme": "https"
    },
    "user_agent": {
        "original": "https://vid.vidoomy.com/"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.user.id | Unique identifier of the user. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.duration | Duration of the event in nanoseconds. If `event.start` and `event.end` are known this value should be the difference between the end and start time. | long |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| input.type | Type of input. | keyword |
| log.file.device_id | Log file device ID. | keyword |
| log.file.inode | Log file inode. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address for the log. | keyword |
| log.syslog.appname | The device or application that originated the Syslog message, if available. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.facility.name | The Syslog text-based facility of the log event, if available. | keyword |
| log.syslog.hostname | The hostname, FQDN, or IP of the machine that originally sent the Syslog message. This is sourced from the hostname field of the syslog header. Depending on the environment, this value may be different from the host that handled the event, especially if the host handling the events is acting as a collector. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| log.syslog.severity.name | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different severity value (e.g. firewall, IDS), your source's text severity should go to `log.level`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `log.level`. | keyword |
| log.syslog.version | The version of the Syslog protocol specification. Only applicable for RFC 5424 messages. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| proxysg.client.ip |  | keyword |
| proxysg.client_to_server.auth_group |  | keyword |
| proxysg.client_to_server.auth_groups |  | keyword |
| proxysg.client_to_server.bytes |  | keyword |
| proxysg.client_to_server.categories |  | keyword |
| proxysg.client_to_server.host |  | keyword |
| proxysg.client_to_server.icap_error_details |  | keyword |
| proxysg.client_to_server.icap_status |  | keyword |
| proxysg.client_to_server.method |  | keyword |
| proxysg.client_to_server.referer |  | keyword |
| proxysg.client_to_server.threat_risk |  | keyword |
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
| proxysg.remote_to_server.content_type |  | keyword |
| proxysg.remote_to_server.icap_error_details |  | keyword |
| proxysg.remote_to_server.icap_status |  | keyword |
| proxysg.server.action |  | keyword |
| proxysg.server.hierarchy |  | keyword |
| proxysg.server.ip |  | keyword |
| proxysg.server.supplier_country |  | keyword |
| proxysg.server.supplier_failures |  | keyword |
| proxysg.server.supplier_ip |  | keyword |
| proxysg.server.supplier_name |  | keyword |
| proxysg.server_to_client.bytes |  | keyword |
| proxysg.server_to_client.filter_result |  | keyword |
| proxysg.server_to_client.status |  | keyword |
| proxysg.time_taken |  | keyword |
| proxysg.x_bluecoat_access_type |  | keyword |
| proxysg.x_bluecoat_appliance_name |  | keyword |
| proxysg.x_bluecoat_application_name |  | keyword |
| proxysg.x_bluecoat_application_operation |  | keyword |
| proxysg.x_bluecoat_location_id |  | keyword |
| proxysg.x_bluecoat_location_name |  | keyword |
| proxysg.x_bluecoat_placeholder |  | keyword |
| proxysg.x_bluecoat_reference_id |  | keyword |
| proxysg.x_bluecoat_request_tenant_id |  | keyword |
| proxysg.x_bluecoat_transaction_uuid |  | keyword |
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
| server.bytes | Bytes sent from the server to the client. | long |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |

