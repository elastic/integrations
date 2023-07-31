# Cisco Nexus

## Overview

The [Cisco Nexus](https://www.cisco.com/c/en_my/products/switches/data-center-switches/index.html) integration allows users to monitor Errors and System Messages. The Cisco Nexus series switches are modular and fixed port network switches designed for the data center. All switches in the Nexus range run the modular NX-OS firmware/operating system on the fabric. NX-OS has some high-availability features compared to the well-known Cisco IOS. This platform is optimized for high-density 10 Gigabit Ethernet.

Use the Cisco Nexus integration to collect and parse data from Syslog and log files. Then visualize that data through search, correlation and visualization within Elastic Security.

## Data streams

The Cisco Nexus integration collects one type of data: log.

**Log** consists of errors and system messages. See more details about [errors and system messages](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-system-message-guides-list.html)

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.7.0**.

This module has been tested against the **Cisco Nexus Series 9000, 3172T and 3048 Switches**.

## Setup

### To collect data from Cisco Nexus, follow the below steps:

- [Logging System Messages to a File](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/system_management/configuration/guide/b_Cisco_Nexus_9000_Series_NX-OS_System_Management_Configuration_Guide/sm_5syslog.html#task_AADF73ACC611470A8FCB903A51A438AD)

- [Configuring Syslog Servers](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/system_management/configuration/guide/b_Cisco_Nexus_9000_Series_NX-OS_System_Management_Configuration_Guide/sm_5syslog.html#task_5793349949823830091)

**NOTE:**
- Configuration steps can vary from switch to switch. We have mentioned steps for the configuration of the 9K series of switches.
- Use the Timezone Offset parameter, if the timezone is not present in the log messages.

## Logs Reference

### Log

This is the `Log` dataset.

#### Example

An example event for `log` looks as following:

```json
{
    "@timestamp": "2023-04-26T09:08:48.000Z",
    "agent": {
        "ephemeral_id": "777b3d32-4639-4d5d-bc3e-fa5e4053d335",
        "id": "ae8acf2b-2fd5-4ab9-921c-e92bc69cd32c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.7.0"
    },
    "cisco_nexus": {
        "log": {
            "description": "last message repeated 3 time",
            "priority_number": 187,
            "switch_name": "switchname",
            "time": "2023-04-26T09:08:48.000Z",
            "timezone": "UTC"
        }
    },
    "data_stream": {
        "dataset": "cisco_nexus.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.8.0"
    },
    "elastic_agent": {
        "id": "ae8acf2b-2fd5-4ab9-921c-e92bc69cd32c",
        "snapshot": false,
        "version": "8.7.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "cisco_nexus.log",
        "ingested": "2023-06-15T06:21:25Z",
        "kind": "event",
        "original": "\u003c187\u003eswitchname: 2023 Apr 26 09:08:48 UTC: last message repeated 3 time"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "192.168.251.1:37485"
        },
        "syslog": {
            "priority": 187
        }
    },
    "message": "last message repeated 3 time",
    "observer": {
        "name": "switchname",
        "product": "Nexus",
        "type": "switches",
        "vendor": "Cisco"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cisco_nexus-log"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_nexus.log.command |  | keyword |
| cisco_nexus.log.description |  | keyword |
| cisco_nexus.log.euid |  | keyword |
| cisco_nexus.log.facility |  | keyword |
| cisco_nexus.log.interface.mode |  | keyword |
| cisco_nexus.log.interface.name |  | keyword |
| cisco_nexus.log.ip_address |  | ip |
| cisco_nexus.log.line_protocol_state |  | keyword |
| cisco_nexus.log.logname |  | keyword |
| cisco_nexus.log.network.egress_interface |  | keyword |
| cisco_nexus.log.network.ingress_interface |  | keyword |
| cisco_nexus.log.operating_value |  | keyword |
| cisco_nexus.log.operational.duplex_mode |  | keyword |
| cisco_nexus.log.operational.receive_flow_control_state |  | keyword |
| cisco_nexus.log.operational.speed |  | keyword |
| cisco_nexus.log.operational.transmit_flow_control_state |  | keyword |
| cisco_nexus.log.priority_number |  | long |
| cisco_nexus.log.pwd |  | keyword |
| cisco_nexus.log.rhost |  | keyword |
| cisco_nexus.log.ruser |  | keyword |
| cisco_nexus.log.sequence_number |  | long |
| cisco_nexus.log.severity |  | long |
| cisco_nexus.log.slot_number |  | long |
| cisco_nexus.log.standby |  | keyword |
| cisco_nexus.log.state |  | keyword |
| cisco_nexus.log.switch_name |  | keyword |
| cisco_nexus.log.syslog_time |  | date |
| cisco_nexus.log.terminal |  | keyword |
| cisco_nexus.log.threshold_value |  | keyword |
| cisco_nexus.log.time |  | date |
| cisco_nexus.log.timezone |  | keyword |
| cisco_nexus.log.tty |  | keyword |
| cisco_nexus.log.type |  | keyword |
| cisco_nexus.log.uid |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| tags | User defined tags. | keyword |
