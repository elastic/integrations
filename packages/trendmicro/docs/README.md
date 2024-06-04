# Trendmicro Integration

## Overview

Trend Micro Deep Security provides advanced server security for physical, virtual, and cloud servers. It protects enterprise applications and data from breaches and business disruptions without requiring emergency patching. The Trend Micro Deep Security integration collects and parses data received from [Deep Security](https://www.trendmicro.com/en_gb/business/products/hybrid-cloud/deep-security.html) via syslog server.

## Data Streams

This integration supports **deep_security** data stream. See more details from Deep Security logging documentation [here](https://help.deepsecurity.trendmicro.com/20_0/on-premise/events.html).

## Requirements

Elastic Agent is required to ingest data from Deep Security. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.11.0**.

This integration has been tested against Deep Security 20. Please note if you have a Trend Micro Vision One XDR license, we recommend using the [Vision One](https://docs.elastic.co/integrations/trend_micro_vision_one) integration to ingest Deep Security events. For steps on how to configure Deep Security events with Vision One, please see [here](https://help.deepsecurity.trendmicro.com/aws/xdr.html).

## Setup

Follow the [setup guide](https://help.deepsecurity.trendmicro.com/20_0/on-premise/event-syslog.html) to forward deep security events to a syslog server.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Trend Micro.
3. Click on the "Trend Micro" integration from the search results.
4. Click on the "Add Trend Micro" button to add the integration.
5. Add all the required integration configuration parameters according to the enabled input type.
6. Click on "Save and Continue" to save the integration.

## Logs

### Deep Security Logs

Deep Security logs collect the trendmicro deep security logs.

An example event for `deep_security` looks as following:

```json
{
    "@timestamp": "2020-09-21T07:21:11.000Z",
    "agent": {
        "ephemeral_id": "2ea89e49-a391-4415-a8c4-c0ad743e691b",
        "id": "e87ecfdf-7336-4275-96c5-a4ab24a8facc",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.11.0"
    },
    "data_stream": {
        "dataset": "trendmicro.deep_security",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e87ecfdf-7336-4275-96c5-a4ab24a8facc",
        "snapshot": false,
        "version": "8.11.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "code": "5000000",
        "dataset": "trendmicro.deep_security",
        "ingested": "2024-03-20T09:48:02Z",
        "kind": "event",
        "original": "194 <86>2020-09-21T13:51:11+06:30 DeepSec Logs CEF:0|Trend Micro|Deep Security Agent|10.2.229|5000000|WebReputation|5|cn1=1 cn1Label=Host ID dvchost=hostname request=example.com msg=Blocked By Admin",
        "severity": 5,
        "timezone": "UTC",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "1"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "192.168.224.7:54066"
        },
        "syslog": {
            "priority": 86
        }
    },
    "message": "Blocked By Admin",
    "observer": {
        "hostname": "hostname",
        "product": "Deep Security Agent",
        "vendor": "Trend Micro",
        "version": "10.2.229"
    },
    "related": {
        "hosts": [
            "1"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trendmicro.deep_security"
    ],
    "trendmicro": {
        "deep_security": {
            "device": {
                "custom_number1": {
                    "label": "Host ID"
                }
            },
            "event_category": "web-reputation-event",
            "signature_id": 5000000,
            "version": "0"
        }
    },
    "url": {
        "original": "example.com"
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
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| source.process.name | Source process name. | keyword |
| tags | User defined tags. | keyword |
| trendmicro.deep_security.action | The action detected by the integrity rule. | keyword |
| trendmicro.deep_security.aggregation_type | An integer that indicates how the event is aggregated:. | keyword |
| trendmicro.deep_security.base_event_count | Base event count. | long |
| trendmicro.deep_security.bytes_in | Number of inbound bytes read. | long |
| trendmicro.deep_security.computer_name | The computer name. | keyword |
| trendmicro.deep_security.destination.address | IP address of the destination computer. | ip |
| trendmicro.deep_security.destination.mac_address | Destination MAC Address. | keyword |
| trendmicro.deep_security.destination.port | Port number of the destination computer's connection or session. | long |
| trendmicro.deep_security.destination.user_name | Destination user name. | keyword |
| trendmicro.deep_security.device.custom_number1.label | The name label for the field cn1. | keyword |
| trendmicro.deep_security.device.custom_number1.value | The value for the field cn1. | keyword |
| trendmicro.deep_security.device.custom_number2.label | The name label for the field cn2. | keyword |
| trendmicro.deep_security.device.custom_number2.value | The value for the field cn2. | long |
| trendmicro.deep_security.device.custom_number3.label | The name label for the field cn3. | keyword |
| trendmicro.deep_security.device.custom_number3.value | The value for the field cn3. | long |
| trendmicro.deep_security.device.custom_string1.label | The name label for the field cs1. | keyword |
| trendmicro.deep_security.device.custom_string1.value | The value for the field cs1. | keyword |
| trendmicro.deep_security.device.custom_string2.label | The name label for the field cs2. | keyword |
| trendmicro.deep_security.device.custom_string2.value | The value for the field cs2. | keyword |
| trendmicro.deep_security.device.custom_string3.label | The name label for the field cs3. | keyword |
| trendmicro.deep_security.device.custom_string3.value | The value for the field cs3. | keyword |
| trendmicro.deep_security.device.custom_string4.label | The name label for the field cs4. | keyword |
| trendmicro.deep_security.device.custom_string4.value | The value for the field cs4. | keyword |
| trendmicro.deep_security.device.custom_string5.label | The name label for the field cs5. | keyword |
| trendmicro.deep_security.device.custom_string5.value | The value for the field cs5. | keyword |
| trendmicro.deep_security.device.custom_string6.label | The name label for the field cs6. | keyword |
| trendmicro.deep_security.device.custom_string6.value | The value for the field cs6. | keyword |
| trendmicro.deep_security.device.custom_string7.label | The name label for the field cs7. | keyword |
| trendmicro.deep_security.device.custom_string7.value | The value for the field cs7. | keyword |
| trendmicro.deep_security.device.product | Product name. | keyword |
| trendmicro.deep_security.device.vendor | Vendor name. | keyword |
| trendmicro.deep_security.device.version | Product version. | keyword |
| trendmicro.deep_security.deviceHostName | The hostname for cn1. | keyword |
| trendmicro.deep_security.domain_name | The domain name. | keyword |
| trendmicro.deep_security.event_category | Event category of deep security event. | keyword |
| trendmicro.deep_security.event_class_id | Event Class ID. | keyword |
| trendmicro.deep_security.file.hash | The SHA 256 hash that identifies the software file. | keyword |
| trendmicro.deep_security.file.size | The file size in bytes. | long |
| trendmicro.deep_security.file_path | The location of the malware file. | keyword |
| trendmicro.deep_security.filename | The file name that was accessed. | keyword |
| trendmicro.deep_security.message | A list of changed attribute names. | keyword |
| trendmicro.deep_security.model | The product name of the device. | keyword |
| trendmicro.deep_security.name | CEF event containing message. | keyword |
| trendmicro.deep_security.permission | The block reason of the access. | keyword |
| trendmicro.deep_security.process.name | The process name. | keyword |
| trendmicro.deep_security.repeat_count | The number of occurrences of the event. | keyword |
| trendmicro.deep_security.request_url | The URL of the request. | keyword |
| trendmicro.deep_security.result | The result of the failed Anti-Malware action. | keyword |
| trendmicro.deep_security.serial | The serial number of the device. | keyword |
| trendmicro.deep_security.severity | Severity of the Event. | long |
| trendmicro.deep_security.signature_id | Signature ID of event. | long |
| trendmicro.deep_security.source.address | Source computer IP address. | ip |
| trendmicro.deep_security.source.host_name | Source computer hostname. | keyword |
| trendmicro.deep_security.source.mac_address | MAC address of the source computer's network interface. | keyword |
| trendmicro.deep_security.source.port | Port number of the source computer's connection or session. | long |
| trendmicro.deep_security.source.process_name | The name of the event's source process. | keyword |
| trendmicro.deep_security.source.user_id | Source user ID. | keyword |
| trendmicro.deep_security.source.user_name | Account of the user who changed the file being monitored. | keyword |
| trendmicro.deep_security.target.id | The identifier added in the manager. | keyword |
| trendmicro.deep_security.target.value | The subject of the event. It can be the administrator account logged into Deep Security Manager, or a computer. | keyword |
| trendmicro.deep_security.transport_protocol | Name of the transport protocol used. | keyword |
| trendmicro.deep_security.trendmicro.ds_behavior.rule_id | The behavior monitoring rule ID for internal malware case tracking. | keyword |
| trendmicro.deep_security.trendmicro.ds_behavior.type | The type of behavior monitoring event detected. | keyword |
| trendmicro.deep_security.trendmicro.ds_command_line | The commands that the subject process executes. | keyword |
| trendmicro.deep_security.trendmicro.ds_cve | The CVE information, if the process behavior is identified in one of Common Vulnerabilities and Exposures. | keyword |
| trendmicro.deep_security.trendmicro.ds_detection_confidence | Indicates how closely the file matched the malware model. | long |
| trendmicro.deep_security.trendmicro.ds_file.md5 | The MD5 hash of the file. | keyword |
| trendmicro.deep_security.trendmicro.ds_file.sha1 | The SHA1 hash of the file. | keyword |
| trendmicro.deep_security.trendmicro.ds_file.sha256 | The SHA256 hash of the file. | keyword |
| trendmicro.deep_security.trendmicro.ds_frame_type | Connection ethernet frame type. | keyword |
| trendmicro.deep_security.trendmicro.ds_malware_target.count | The number of target files. | long |
| trendmicro.deep_security.trendmicro.ds_malware_target.type | The type of system resource that this malware was trying to affect. | keyword |
| trendmicro.deep_security.trendmicro.ds_malware_target.value | The file, process, or registry key (if any) that the malware was trying to affect. | keyword |
| trendmicro.deep_security.trendmicro.ds_mitre | The MITRE information, if the process behavior is identified in one of MITRE attack scenarios. | keyword |
| trendmicro.deep_security.trendmicro.ds_packet_data | The packet data, represented in Base64. | keyword |
| trendmicro.deep_security.trendmicro.ds_process | Name of ds process. | keyword |
| trendmicro.deep_security.trendmicro.ds_relevant_detection_names | Probable Threat Type. | keyword |
| trendmicro.deep_security.trendmicro.ds_tenant | Deep Security tenant. | keyword |
| trendmicro.deep_security.trendmicro.ds_tenant_id | Deep Security tenant ID. | keyword |
| trendmicro.deep_security.type | The device type of the device. | keyword |
| trendmicro.deep_security.version | Deep Security version. | keyword |
| trendmicro.deep_security.xff | The IP address of the last hub in the X-Forwarded-For header. | ip |

