# Imperva

This integration is for Imperva device logs. It includes the
datasets for receiving logs over syslog or read from a file:
- `securesphere` dataset: supports Imperva SecureSphere logs.

## Data streams

The Imperva integration collects one type of data: securesphere.

**Securesphere** consists of alerts, violations, and system events. See more details about [alerts, violations, and events](https://docs.imperva.com/bundle/v14.7-web-application-firewall-user-guide/page/1024.htm)

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent, and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.10.1**.

## Setup

### To collect data from Imperva, follow the required steps:

1. The gateway and management server (MX) should have the relevant connectivity for sending logs using the Syslog server.

2. To send all security violations from the gateway to Elastic:

- Create a custom action set:

  - From a 'security violation–all', type and add the gateway security system log > gateway log security event to system log (syslog) using the CEF standard.
  - Configure the relevant name and parameters for the action set.

- Assign a followed action to a security - > policy rule.

3. To send all security alerts (aggregated violations) from the gateway to Elastic:

- Create a custom action set:

  - From an 'any event type', type and add the server system log > log security event to system log (syslog) using the CEF standard.
  - Configure the relevant name and parameters for the action set.

- Assign a followed action to a security - > policy rule.

4. To send all system events from the gateway to Elastic:

- Create a custom action set:

   - From an 'any event type', type and add the server system log > log system event to system log (syslog) using the CEF standard.
   - Configure the relevant name and parameters for the action set.

- Create system events policy.
- Assign a followed action to a system event policy.

For more information on working with action sets and followed actions, refer to the Imperva relevant [documentation]( https://docs.imperva.com/bundle/v15.0-waf-management-server-manager-user-guide/page/Working_with_Action_Sets_and_Followed_Actions.htm).

### Enabling the integration in Elastic:

1. In Kibana, go to Management > Integrations
2. In the "Search for integrations" search bar, type Imperva.
3. Click on the "Imperva" integration from the search results.
4. Click on the "Add Imperva" button to add the integration.
5. Enable the data collection mode from the following: Filestream, TCP, or UDP.
6. Add all the required configuration parameters, such as paths for the filestream or listen address and listen port for the TCP and UDP.

## Logs Reference

### SecureSphere

This is the `Securesphere` dataset.

#### Example

An example event for `securesphere` looks as following:

```json
{
    "@timestamp": "2023-10-05T18:33:02.000Z",
    "agent": {
        "ephemeral_id": "94608df6-6778-4ec4-99dc-d0cd37d583d8",
        "id": "0412638f-dd94-4c0e-b349-e99a0886d9f0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "imperva.securesphere",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "0412638f-dd94-4c0e-b349-e99a0886d9f0",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "code": "User logged in",
        "dataset": "imperva.securesphere",
        "ingested": "2023-12-01T09:10:18Z",
        "kind": "event",
        "original": "<14>CEF:0|Imperva Inc.|SecureSphere|15.1.0|User logged in|User admin logged in from 81.2.69.142.|High|suser=admin rt=Oct 05 2023 18:33:02 cat=SystemEvent",
        "severity": 7
    },
    "imperva": {
        "securesphere": {
            "device": {
                "event": {
                    "category": "SystemEvent",
                    "class_id": "User logged in"
                },
                "product": "SecureSphere",
                "receipt_time": "2023-10-05T18:33:02.000Z",
                "vendor": "Imperva Inc.",
                "version": "15.1.0"
            },
            "name": "User admin logged in from 81.2.69.142.",
            "severity": "High",
            "source": {
                "user_name": "admin"
            },
            "version": "0"
        }
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "192.168.249.7:48857"
        }
    },
    "message": "User admin logged in from 81.2.69.142.",
    "observer": {
        "product": "SecureSphere",
        "vendor": "Imperva Inc.",
        "version": "15.1.0"
    },
    "related": {
        "user": [
            "admin"
        ]
    },
    "source": {
        "user": {
            "name": "admin"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "imperva.securesphere"
    ]
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
| imperva.securesphere.destination.address |  | ip |
| imperva.securesphere.destination.port |  | long |
| imperva.securesphere.destination.user_name |  | keyword |
| imperva.securesphere.device.action |  | keyword |
| imperva.securesphere.device.custom_string1.label |  | keyword |
| imperva.securesphere.device.custom_string1.value |  | keyword |
| imperva.securesphere.device.custom_string10.label |  | keyword |
| imperva.securesphere.device.custom_string10.value |  | keyword |
| imperva.securesphere.device.custom_string11.label |  | keyword |
| imperva.securesphere.device.custom_string11.value |  | keyword |
| imperva.securesphere.device.custom_string12.label |  | keyword |
| imperva.securesphere.device.custom_string12.value |  | keyword |
| imperva.securesphere.device.custom_string13.label |  | keyword |
| imperva.securesphere.device.custom_string13.value |  | keyword |
| imperva.securesphere.device.custom_string14.label |  | keyword |
| imperva.securesphere.device.custom_string14.value |  | keyword |
| imperva.securesphere.device.custom_string15.label |  | keyword |
| imperva.securesphere.device.custom_string15.value |  | keyword |
| imperva.securesphere.device.custom_string16.label |  | keyword |
| imperva.securesphere.device.custom_string16.value |  | keyword |
| imperva.securesphere.device.custom_string17.label |  | keyword |
| imperva.securesphere.device.custom_string17.value |  | keyword |
| imperva.securesphere.device.custom_string18.label |  | keyword |
| imperva.securesphere.device.custom_string18.value |  | keyword |
| imperva.securesphere.device.custom_string19.label |  | keyword |
| imperva.securesphere.device.custom_string19.value |  | keyword |
| imperva.securesphere.device.custom_string2.label |  | keyword |
| imperva.securesphere.device.custom_string2.value |  | keyword |
| imperva.securesphere.device.custom_string20.label |  | keyword |
| imperva.securesphere.device.custom_string20.value |  | keyword |
| imperva.securesphere.device.custom_string21.label |  | keyword |
| imperva.securesphere.device.custom_string21.value |  | keyword |
| imperva.securesphere.device.custom_string3.label |  | keyword |
| imperva.securesphere.device.custom_string3.value |  | keyword |
| imperva.securesphere.device.custom_string4.label |  | keyword |
| imperva.securesphere.device.custom_string4.value |  | keyword |
| imperva.securesphere.device.custom_string5.label |  | keyword |
| imperva.securesphere.device.custom_string5.value |  | keyword |
| imperva.securesphere.device.custom_string6.label |  | keyword |
| imperva.securesphere.device.custom_string6.value |  | keyword |
| imperva.securesphere.device.custom_string7.label |  | keyword |
| imperva.securesphere.device.custom_string7.value |  | keyword |
| imperva.securesphere.device.custom_string8.label |  | keyword |
| imperva.securesphere.device.custom_string8.value |  | keyword |
| imperva.securesphere.device.custom_string9.label |  | keyword |
| imperva.securesphere.device.custom_string9.value |  | keyword |
| imperva.securesphere.device.event.category |  | keyword |
| imperva.securesphere.device.event.class_id |  | keyword |
| imperva.securesphere.device.product |  | keyword |
| imperva.securesphere.device.receipt_time |  | date |
| imperva.securesphere.device.vendor |  | keyword |
| imperva.securesphere.device.version |  | keyword |
| imperva.securesphere.name |  | keyword |
| imperva.securesphere.severity |  | keyword |
| imperva.securesphere.source.address |  | ip |
| imperva.securesphere.source.port |  | long |
| imperva.securesphere.source.user_name |  | keyword |
| imperva.securesphere.transport_protocol |  | keyword |
| imperva.securesphere.version |  | keyword |
| input.type | Type of filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| tags | User defined tags. | keyword |
