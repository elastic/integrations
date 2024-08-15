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

