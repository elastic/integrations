# Nozomi Networks

## Overview

[Nozomi Networks](https://www.nozominetworks.com/) is a global leader in OT and IoT cybersecurity, delivering unmatched visibility, real-time threat detection, and AI-powered analysis to safeguard critical infrastructure. Trusted across industries, Nozomi helps organizations protect mission-critical environments by combining deep network and endpoint visibility with rapid, intelligent incident response—ensuring security, compliance, and operational resilience.

For this integration, data should be collected from Nozomi’s Vantage platform via REST APIs.

## Data streams

The Nozomi Networks integration collects logs for eight types of events.

**Alert:** Alert allows collecting Alert Log Events, which are generated when the system detects unusual or potentially harmful activity. These events are categorized by severity and help monitor network security and operations.

**Asset:** Asset allows collecting Asset Log Events, which are generated to capture details of all physical components and systems in the local network, including their attributes, types, and relationships for improved visibility and management.

**Audit:** Audit allows collecting Audit Log Events, which are generated whenever a user performs actions such as login, logout, or configuration changes, capturing the IP address and username of the user for tracking and accountability.

**Health:** Health allows collecting Health Log Events, which provide status updates and condition changes of sensors to monitor their operational state and ensure system reliability.

**Node:** Node allows collecting Node Log Events, which are generated to capture details of individual network entities, such as computers or controllers, providing insights into their communication protocols and roles within the network.

**Node CVE:** Node CVE allows collecting vulnerability events by matching network nodes against current Common Vulnerabilities and Exposures (CVEs), helping to identify security risks.

**Session:** Sessions allow collecting session events, capturing the start and end of connections between network nodes, including detailed information about the messages exchanged during these sessions.

**Variable:** Variables allow collecting data extracted via deep packet inspection (DPI) from monitored systems, providing detailed insights into the variables associated with each asset.

## Requirements

### Agentless-enabled integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation
Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Compatibility

For Rest API, this module has been tested against the **N2OS 25.1.0** version.

## Setup

### Collect data from the Nozomi Networks API:

1. Navigate to your **Profile > API Keys** in the Vantage UI (top-right corner).
2. Click on **Add** API Keys.
3. Optionally Add a **Description** and **Allowed IPs**.
4. Select the appropriate **Organization**.
5. Click **Generate**.
6. Copy **Key Name** and **Key Token**.

**Required Roles by Endpoint:**

| **Endpoint**   | **Role**                                                  |
|----------------|-----------------------------------------------------------|
| Audit          | Superobserver                                             |
| Alert          | Alerts Operator, Observer, Superobserver                  |
| Asset          | Assets Operator, Observer, Superobserver                  |
| Health         | Superobserver                                             |
| Node           | Superobserver                                             |
| Node CVE       | Vulnerabilities Operator, Observer, Superobserver         |
| Session        | Superobserver                                             |
| Variable       | Superobserver                                             |

For more details, see [Nozomi Vantage API Key](https://technicaldocs.nozominetworks.com/products/vantage/topics/administration/teams/t_vantage_admin_teams_api-keys_generate-1.html) and [Role Documentation](https://technicaldocs.nozominetworks.com/products/vantage/topics/administration/teams/r_vantage_admin_teams_groups_roles-permissions.html).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Nozomi Networks**.
3. Select the **Nozomi Networks** integration and add it.
4. Add all the required integration configuration parameters: URL, Username and Password.
5. Save the integration.

## Logs reference

### Alert

This is the `Alert` dataset.

#### Example

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2025-05-21T22:13:30.343Z",
    "agent": {
        "ephemeral_id": "64ad927e-8705-44ce-aaf5-5a0d9501df90",
        "id": "06f85d75-2919-4003-983b-8bff8fe5eb44",
        "name": "elastic-agent-50013",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "nozomi_networks.alert",
        "namespace": "52588",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.112",
        "mac": "F4-54-33-9F-22-3D",
        "port": 44818,
        "user": {
            "roles": [
                "producer"
            ]
        }
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "06f85d75-2919-4003-983b-8bff8fe5eb44",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2025-05-16T12:35:06.110Z",
        "dataset": "nozomi_networks.alert",
        "id": "6dbf93f8-d8da-4ae3-bf1a-e91a82fc3041",
        "ingested": "2025-06-24T06:58:13Z",
        "kind": "alert",
        "original": "{\"ack\":false,\"appliance_host\":\"Sandbox-TAE-Guardian3\",\"appliance_id\":\"d5ab7eaa-9a4b-4b4b-9a4b-4b4b9a4b4b4b\",\"appliance_ip\":\"1.128.0.0\",\"appliance_site\":\"Sandbox\",\"bpf_filter\":\"(ip host 1.128.0.11 and ip host 1.128.0.0 and tcp port 58679 and tcp port 44818) or (vlan and ip host 1.128.0.11 and ip host 1.128.0.0 and tcp port 58679 and tcp port 44818)\",\"capture_device\":\"base.pcap\",\"close_option\":null,\"closed_time\":0,\"created_time\":1747398906110,\"custom_fields_dst\":{},\"custom_fields_src\":{},\"description\":\"Online edits have been made on the PLC with IP 1.128.0.0. The following steps were executed:\\n[1]- Downloaded project [ C:\\\\USERS\\\\NOZOMI\\\\DESKTOP\\\\LADDERBOMB\\\\PLC_LOGIC_CHALLENGE2\\\\challenge2changed.ACD ] to [ \\\\AB_ETHIP-1\\\\1.128.0.0\\\\C1_1756 ]\\n[2]- Changed Controller [ C1_1756 ] to Run Mode\\n[3]- Changed Controller [ C1_1756 ] to Program Mode\\n[4]- Downloaded project [ C:\\\\USERS\\\\NOZOMI\\\\DESKTOP\\\\LADDERBOMB\\\\PLC_LOGIC_CHALLENGE2\\\\challenge2changed.ACD ] to [ \\\\AB_ETHIP-1\\\\1.128.0.0\\\\C1_1756 ]\\n[5]- Changed Controller [ C1_1756 ] to Run Mode\\n[6]- Changed Controller [ C1_1756 ] to Program Mode\\n[7]- Downloaded project [ C:\\\\USERS\\\\NOZOMI\\\\DESKTOP\\\\LADDERBOMB\\\\PLC_LOGIC_CHALLENGE2\\\\challenge2changed.ACD ] to [ \\\\AB_ETHIP-1\\\\1.128.0.0\\\\C1_1756 ]\\n[8]- Changed Controller [ C1_1756 ] to Run Mode\\n[9]- Changed Controller [ C1_1756 ] to Program Mode\\n[10]- Downloaded project [ C:\\\\USERS\\\\NOZOMI\\\\DESKTOP\\\\LADDERBOMB\\\\PLC_LOGIC_CHALLENGE2\\\\challenge2changed.ACD ] to [ \\\\AB_ETHIP-1\\\\1.128.0.0\\\\C1_1756 ]\\n\",\"dst_roles\":\"producer\",\"grouped_visible\":true,\"id\":\"6dbf93f8-d8da-4ae3-bf1a-e91a82fc3041\",\"id_dst\":\"89.160.20.112\",\"id_src\":\"81.2.69.192\",\"incident_keys\":[],\"ip_dst\":\"89.160.20.112\",\"ip_src\":\"81.2.69.192\",\"is_incident\":false,\"is_security\":true,\"label_dst\":\"private.directinvesting.com1\",\"label_src\":\"private.directinvesting.com2\",\"mac_dst\":\"f4:54:33:9f:22:3d\",\"mac_src\":\"00:0c:29:01:98:be\",\"name\":\"Program change\",\"note\":\"User Defined Note\",\"parents\":[\"id1\"],\"playbook_contents\":null,\"port_dst\":44818,\"port_src\":58679,\"properties\":{\"base_risk\":6,\"from_id\":\"1.128.0.11\",\"is_dst_node_learned\":true,\"is_dst_public\":false,\"is_dst_reputation_bad\":false,\"is_src_node_learned\":true,\"is_src_public\":false,\"is_src_reputation_bad\":false,\"mitre_attack_for_ics\":{\"destination\":{\"levels\":[\"2\"],\"types\":[\"Field Controller/RTU/PLC/IED\"]},\"source\":{\"levels\":[\"2\"],\"types\":[\"Engineering Workstation\"]}},\"n2os_version\":\"25.0.0-03042016_D5AB7\",\"raised_by\":\"n2os_ids\",\"to_id\":\"1.128.0.0\"},\"protocol\":\"ethernetip\",\"record_created_at\":1747865610343,\"replicated\":true,\"risk\":6,\"sec_profile_visible\":true,\"session_id\":\"12eszcd-223cds34\",\"severity\":10,\"src_roles\":\"consumer, engineering_station\",\"status\":\"open\",\"synchronized\":true,\"threat_name\":\"Grizzly Steppe Threat Actor\",\"ti_source\":\"\",\"time\":1747398906110,\"trace_sha1\":null,\"trace_status\":\"state_unavailable_for_alert_type\",\"transport_protocol\":\"tcp\",\"trigger_id\":\"indicator--fb15c96c-eb73-48ac-a48a-15bcab2f0fe3\",\"trigger_type\":\"stix_indicators\",\"type_id\":\"SIGN:PROGRAM:CHANGE\",\"type_name\":\"Program change\",\"zone_dst\":\"Production_B\",\"zone_src\":\"Production_B\"}",
        "risk_score": 6,
        "severity": 73
    },
    "host": {
        "hostname": "Sandbox-TAE-Guardian3",
        "id": "d5ab7eaa-9a4b-4b4b-9a4b-4b4b9a4b4b4b",
        "ip": [
            "1.128.0.0"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "Online edits have been made on the PLC with IP 1.128.0.0. The following steps were executed:\n[1]- Downloaded project [ C:\\USERS\\NOZOMI\\DESKTOP\\LADDERBOMB\\PLC_LOGIC_CHALLENGE2\\challenge2changed.ACD ] to [ \\AB_ETHIP-1\\1.128.0.0\\C1_1756 ]\n[2]- Changed Controller [ C1_1756 ] to Run Mode\n[3]- Changed Controller [ C1_1756 ] to Program Mode\n[4]- Downloaded project [ C:\\USERS\\NOZOMI\\DESKTOP\\LADDERBOMB\\PLC_LOGIC_CHALLENGE2\\challenge2changed.ACD ] to [ \\AB_ETHIP-1\\1.128.0.0\\C1_1756 ]\n[5]- Changed Controller [ C1_1756 ] to Run Mode\n[6]- Changed Controller [ C1_1756 ] to Program Mode\n[7]- Downloaded project [ C:\\USERS\\NOZOMI\\DESKTOP\\LADDERBOMB\\PLC_LOGIC_CHALLENGE2\\challenge2changed.ACD ] to [ \\AB_ETHIP-1\\1.128.0.0\\C1_1756 ]\n[8]- Changed Controller [ C1_1756 ] to Run Mode\n[9]- Changed Controller [ C1_1756 ] to Program Mode\n[10]- Downloaded project [ C:\\USERS\\NOZOMI\\DESKTOP\\LADDERBOMB\\PLC_LOGIC_CHALLENGE2\\challenge2changed.ACD ] to [ \\AB_ETHIP-1\\1.128.0.0\\C1_1756 ]\n",
    "network": {
        "protocol": "ethernetip",
        "transport": "tcp"
    },
    "nozomi_networks": {
        "alert": {
            "ack": false,
            "appliance_host": "Sandbox-TAE-Guardian3",
            "appliance_id": "d5ab7eaa-9a4b-4b4b-9a4b-4b4b9a4b4b4b",
            "appliance_ip": "1.128.0.0",
            "appliance_site": "Sandbox",
            "bpf_filter": "(ip host 1.128.0.11 and ip host 1.128.0.0 and tcp port 58679 and tcp port 44818) or (vlan and ip host 1.128.0.11 and ip host 1.128.0.0 and tcp port 58679 and tcp port 44818)",
            "capture_device": "base.pcap",
            "created_time": "2025-05-16T12:35:06.110Z",
            "description": "Online edits have been made on the PLC with IP 1.128.0.0. The following steps were executed:\n[1]- Downloaded project [ C:\\USERS\\NOZOMI\\DESKTOP\\LADDERBOMB\\PLC_LOGIC_CHALLENGE2\\challenge2changed.ACD ] to [ \\AB_ETHIP-1\\1.128.0.0\\C1_1756 ]\n[2]- Changed Controller [ C1_1756 ] to Run Mode\n[3]- Changed Controller [ C1_1756 ] to Program Mode\n[4]- Downloaded project [ C:\\USERS\\NOZOMI\\DESKTOP\\LADDERBOMB\\PLC_LOGIC_CHALLENGE2\\challenge2changed.ACD ] to [ \\AB_ETHIP-1\\1.128.0.0\\C1_1756 ]\n[5]- Changed Controller [ C1_1756 ] to Run Mode\n[6]- Changed Controller [ C1_1756 ] to Program Mode\n[7]- Downloaded project [ C:\\USERS\\NOZOMI\\DESKTOP\\LADDERBOMB\\PLC_LOGIC_CHALLENGE2\\challenge2changed.ACD ] to [ \\AB_ETHIP-1\\1.128.0.0\\C1_1756 ]\n[8]- Changed Controller [ C1_1756 ] to Run Mode\n[9]- Changed Controller [ C1_1756 ] to Program Mode\n[10]- Downloaded project [ C:\\USERS\\NOZOMI\\DESKTOP\\LADDERBOMB\\PLC_LOGIC_CHALLENGE2\\challenge2changed.ACD ] to [ \\AB_ETHIP-1\\1.128.0.0\\C1_1756 ]\n",
            "destination_ip": "89.160.20.112",
            "dst_roles": "producer",
            "grouped_visible": true,
            "id": "6dbf93f8-d8da-4ae3-bf1a-e91a82fc3041",
            "id_dst": "89.160.20.112",
            "id_src": "81.2.69.192",
            "is_incident": false,
            "is_security": true,
            "label_dst": "private.directinvesting.com1",
            "label_src": "private.directinvesting.com2",
            "mac_dst": "f4:54:33:9f:22:3d",
            "mac_src": "00:0c:29:01:98:be",
            "name": "Program change",
            "note": "User Defined Note",
            "parents": [
                "id1"
            ],
            "port_dst": 44818,
            "port_src": 58679,
            "properties": {
                "base_risk": 6,
                "from_id": "1.128.0.11",
                "is_dst_node_learned": true,
                "is_dst_public": false,
                "is_dst_reputation_bad": false,
                "is_src_node_learned": true,
                "is_src_public": false,
                "is_src_reputation_bad": false,
                "mitre_attack_for_ics": {
                    "destination": {
                        "levels": [
                            "2"
                        ],
                        "types": [
                            "Field Controller/RTU/PLC/IED"
                        ]
                    },
                    "source": {
                        "levels": [
                            "2"
                        ],
                        "types": [
                            "Engineering Workstation"
                        ]
                    }
                },
                "n2os_version": "25.0.0-03042016_D5AB7",
                "raised_by": "n2os_ids",
                "to_id": "1.128.0.0"
            },
            "protocol": "ethernetip",
            "record_created_at": "2025-05-21T22:13:30.343Z",
            "replicated": true,
            "risk": 6,
            "sec_profile_visible": true,
            "session_id": "12eszcd-223cds34",
            "severity": 10,
            "severity_label": "high",
            "source_ip": "81.2.69.192",
            "src_roles": "consumer, engineering_station",
            "status": "open",
            "synchronized": true,
            "threat_name": "Grizzly Steppe Threat Actor",
            "time": "2025-05-16T12:35:06.110Z",
            "trace_status": "state_unavailable_for_alert_type",
            "transport_protocol": "tcp",
            "trigger_id": "indicator--fb15c96c-eb73-48ac-a48a-15bcab2f0fe3",
            "trigger_type": "stix_indicators",
            "type_id": "SIGN:PROGRAM:CHANGE",
            "type_name": "Program change",
            "zone_dst": "Production_B",
            "zone_src": "Production_B"
        }
    },
    "related": {
        "hosts": [
            "Sandbox-TAE-Guardian3",
            "private.directinvesting.com1",
            "private.directinvesting.com2"
        ],
        "ip": [
            "1.128.0.0",
            "89.160.20.112",
            "81.2.69.192"
        ]
    },
    "rule": {
        "id": "indicator--fb15c96c-eb73-48ac-a48a-15bcab2f0fe3",
        "name": "stix_indicators"
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.192",
        "mac": "00-0C-29-01-98-BE",
        "port": 58679,
        "user": {
            "roles": [
                "consumer, engineering_station"
            ]
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "nozomi_networks-alert"
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| nozomi_networks.alert.ack | True if the Alert has been acknowledged. | boolean |
| nozomi_networks.alert.appliance_host | The hostname of the sensor where this entity has been observed. | keyword |
| nozomi_networks.alert.appliance_id | The id of the sensor where this entity has been observed. | keyword |
| nozomi_networks.alert.appliance_ip | The IP address of the sensor where this entity has been observed. | ip |
| nozomi_networks.alert.appliance_site | Site name of the sensor where this alert has been generated. | keyword |
| nozomi_networks.alert.bpf_filter | Berkeley Packet Filter (BPF) filter for the entity, used when performing traces for this entity. | keyword |
| nozomi_networks.alert.capture_device | Name of the interface from which this entity has been detected. | keyword |
| nozomi_networks.alert.close_option |  | keyword |
| nozomi_networks.alert.closed_time | Time in epoch milliseconds when the alert has been closed. 0 if still open. | date |
| nozomi_networks.alert.created_time | Time when the alert record was created. | date |
| nozomi_networks.alert.custom_fields_dst |  | flattened |
| nozomi_networks.alert.custom_fields_src |  | flattened |
| nozomi_networks.alert.description | More details about the alert. | match_only_text |
| nozomi_networks.alert.destination_ip |  | ip |
| nozomi_networks.alert.dst_roles | Roles of the target node. | keyword |
| nozomi_networks.alert.grouped_visible |  | boolean |
| nozomi_networks.alert.id | Primary key of this query source. | keyword |
| nozomi_networks.alert.id_dst | ID of the destination node. | keyword |
| nozomi_networks.alert.id_src | ID of the source node. | keyword |
| nozomi_networks.alert.incident_keys |  | keyword |
| nozomi_networks.alert.ip_dst | Destination IP address. | keyword |
| nozomi_networks.alert.ip_src | Source internet protocol (IP) address. | keyword |
| nozomi_networks.alert.is_incident | True if this Alert is an incident grouping more alerts. | boolean |
| nozomi_networks.alert.is_security | True if the alert is a Cybersecurity alert. | boolean |
| nozomi_networks.alert.label_dst | Label of the destination node. | keyword |
| nozomi_networks.alert.label_src | Label of the source node. | keyword |
| nozomi_networks.alert.mac_dst | Destination MAC address. | keyword |
| nozomi_networks.alert.mac_src | Source media access control (MAC) addres. | keyword |
| nozomi_networks.alert.name | Name of the type ID. It can be updated dynamically by the correlation engine. | keyword |
| nozomi_networks.alert.note | User-defined note about the Alert. | keyword |
| nozomi_networks.alert.parents | ID of parent incidents. | keyword |
| nozomi_networks.alert.playbook_contents |  | keyword |
| nozomi_networks.alert.port_dst | Destination port. | long |
| nozomi_networks.alert.port_src | Source port. | long |
| nozomi_networks.alert.properties.base_risk |  | long |
| nozomi_networks.alert.properties.from_id |  | keyword |
| nozomi_networks.alert.properties.is_dst_node_learned |  | boolean |
| nozomi_networks.alert.properties.is_dst_public |  | boolean |
| nozomi_networks.alert.properties.is_dst_reputation_bad |  | boolean |
| nozomi_networks.alert.properties.is_src_node_learned |  | boolean |
| nozomi_networks.alert.properties.is_src_public |  | boolean |
| nozomi_networks.alert.properties.is_src_reputation_bad |  | boolean |
| nozomi_networks.alert.properties.mitre_attack_for_ics.destination.levels |  | keyword |
| nozomi_networks.alert.properties.mitre_attack_for_ics.destination.types |  | keyword |
| nozomi_networks.alert.properties.mitre_attack_for_ics.source.levels |  | keyword |
| nozomi_networks.alert.properties.mitre_attack_for_ics.source.types |  | keyword |
| nozomi_networks.alert.properties.n2os_version |  | keyword |
| nozomi_networks.alert.properties.raised_by |  | keyword |
| nozomi_networks.alert.properties.to_id |  | keyword |
| nozomi_networks.alert.protocol | The protocol in which this entity has been observed. | keyword |
| nozomi_networks.alert.record_created_at |  | date |
| nozomi_networks.alert.replicated | This is true if the record has been replicated on the replica machine. | boolean |
| nozomi_networks.alert.risk | Risk, between 0 and 10. | double |
| nozomi_networks.alert.sec_profile_visible | True if the alert is visible according to the Security Profile. For alerts that are part of incidents, the field value is set to True when at least one child alert has the field value equal to True. | boolean |
| nozomi_networks.alert.session_id | ID of the Session during which this alert was raised. | keyword |
| nozomi_networks.alert.severity | Syslog-like severity. | long |
| nozomi_networks.alert.severity_label |  | keyword |
| nozomi_networks.alert.source_ip |  | ip |
| nozomi_networks.alert.src_roles | Roles of the source node. | keyword |
| nozomi_networks.alert.status | Status of the alert. | keyword |
| nozomi_networks.alert.synchronized | True if this entity has been synchronized with the upper Central Management Console (CMC) or Vantage. . | boolean |
| nozomi_networks.alert.threat_name | In case of known threat, this holds the threat name. | keyword |
| nozomi_networks.alert.ti_source |  | keyword |
| nozomi_networks.alert.time | Time when the first packet triggers the alert; for incidents, it is the time of the last correlated alert, which updates over time. . | date |
| nozomi_networks.alert.trace_sha1 |  | keyword |
| nozomi_networks.alert.trace_status |  | keyword |
| nozomi_networks.alert.transport_protocol | Name of the transport protocol. | keyword |
| nozomi_networks.alert.trigger_id | ID of the triggering engine entity. | keyword |
| nozomi_networks.alert.trigger_type | Name of the trigger/engine. | keyword |
| nozomi_networks.alert.type_id | The Type identifier (ID) represents a unique "class" of the Alert, that characterizes what the Alert is about in a unique way. | keyword |
| nozomi_networks.alert.type_name | Name of the type ID. It is immutable. | keyword |
| nozomi_networks.alert.zone_dst | Destination zone. | keyword |
| nozomi_networks.alert.zone_src | Source zone. | keyword |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |


### Asset

This is the `Asset` dataset.

#### Example

An example event for `asset` looks as following:

```json
{
    "@timestamp": "2023-04-19T23:50:01.431Z",
    "agent": {
        "ephemeral_id": "a53ac3f3-828d-4d14-ac6f-cf6f54393ffb",
        "id": "68be602e-66c7-43c5-9fc7-84124826be4e",
        "name": "elastic-agent-52238",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "nozomi_networks.asset",
        "namespace": "88522",
        "type": "logs"
    },
    "device": {
        "id": "00000000-54b3-e7c7-0000-0000bffd97"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "68be602e-66c7-43c5-9fc7-84124826be4e",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "nozomi_networks.asset",
        "id": "ca08-ec50-4953-ba47-464013e",
        "ingested": "2025-06-18T06:43:30Z",
        "kind": "event",
        "original": "{\"_asset_kb_id\":\"id123\",\"activity_times\":{\"1746639000000\":1},\"appliance_hosts\":[\"Demo Sensor iq e6ef8db9\"],\"capture_device\":\"demo\",\"created_at\":1681948201431,\"custom_fields\":{},\"device_id\":\"00000000-54b3-e7c7-0000-0000bffd97\",\"end_of_sale_date\":1747994353,\"end_of_sale_date:info\":{\"source\":\"passive\"},\"end_of_support_date\":1747994353,\"end_of_support_date:info\":{\"source\":\"passive\"},\"firmware_version\":\"fv2\",\"firmware_version:info\":{\"source\":\"passive\"},\"has_remediations\":false,\"id\":\"ca08-ec50-4953-ba47-464013e\",\"ip\":[\"0.0.0.0\"],\"is_ai_enriched\":false,\"is_arc_enriched\":true,\"is_sp_enriched\":true,\"is_ti_enriched\":false,\"last_activity_time\":1746638915000,\"latitude\":\"45.505918\",\"level\":\"level1\",\"lifecycle\":\"life-cycle\",\"lifecycle:info\":{\"source\":\"passive\"},\"location:info\":{\"lat\":\"-73.614830\",\"lon\":\"45.505918\"},\"longitude\":\"-73.614830\",\"mac_address\":[\"d9:a8:80:ef:9d:d2\"],\"mac_address_level\":{\"d9:a8:80:ef:9d:d2\":\"unconfirmed\"},\"mac_vendor\":[\"Cisco Systems, Inc\"],\"mobility\":\"static\",\"mobility:info\":{\"confidence\":\"medium\",\"source\":\"asset-kb\"},\"mobility_votes\":{\"asset-kb\":\"unknown\"},\"name\":\"0.0.0.0\",\"nodes\":[\"production_b\"],\"nozomi_risk\":2,\"os\":\"Mac OS X\",\"os:info\":{\"source\":\"passive\"},\"os_or_firmware\":\"fware\",\"os_or_firmware:info\":{\"source\":\"none\"},\"product_name\":\"pname\",\"product_name:info\":{\"source\":\"passive\"},\"properties\":{\"81.2.69.144\":{\"_product_name.enrichment\":\"Desktop/Laptop Computer\",\"_type.enrichment\":\"computer\",\"_type.passive\":\"computer\",\"_vendor.enrichment\":\"Dell\",\"http.last_client_version\":\"Chrome 91.0.4472.124\"}},\"protocols\":[\"smb\",\"http\"],\"record_created_at\":1746643849546,\"remediations_signatures\":[\"sign1\",\"sign2\"],\"risk\":2,\"risk_configuration\":{\"ai_risk_weight\":1,\"alerts_risk_weight\":0.5,\"asset_criticality\":25,\"asset_criticality_factor\":0,\"asset_criticality_weight\":0.5,\"communication_risk_weight\":0.5,\"compensating_control\":0,\"compensating_control_weight\":0.2,\"connection_type_weight\":0.5,\"critical_vulnerabilities_weight\":0.5,\"device_risk_weight\":0.5,\"exploitable_vulnerabilities_epss_score\":0.2,\"exploitable_vulnerabilities_weight\":0.5,\"high_risk_alert_level\":7,\"high_risk_alerts_weight\":0.5,\"high_risk_vulnerabilities_level\":7,\"internet_exposure_weight\":0.5,\"lifecycle_weight\":0.5,\"network_activity_weight\":0.5,\"open_alerts_weight\":0.5,\"open_vulnerabilities_likelihood\":0.7,\"open_vulnerabilities_weight\":0.5,\"risk_mitigation_factor\":0,\"suboptimal_management_weight\":0.5,\"technology_category_weight\":0.5,\"type_weight\":0.5,\"unsafe_countries_list\":[\"china\",\"russia\",\"north korea\",\"ukraine\",\"vietnam\",\"indonesia\"],\"unsafe_countries_weight\":0.5,\"unsafe_protocols_list\":[\"ftp\",\"http\",\"imap\",\"llmnr\",\"ntlm\",\"nfs\",\"pop3\",\"rdp\",\"smb\",\"snmp\",\"smtp\",\"sip\",\"telnet\"],\"unsafe_protocols_weight\":0.5,\"vulnerabilities_risk_weight\":0.5},\"roles\":[\"other\"],\"serial_number\":\"123456789\",\"serial_number:info\":{\"source\":\"passive\"},\"tags\":[\"asset1tag\"],\"technology_category\":\"IT\",\"time\":1746643849541,\"type\":\"typehost\",\"type:info\":{\"source\":\"passive\"},\"vendor\":\"unknown\",\"vendor:info\":{\"source\":\"passive\"},\"vlan_id\":[\"10\"],\"zones\":[\"Undefined\"]}",
        "risk_score": 2,
        "type": [
            "info"
        ]
    },
    "host": {
        "geo": {
            "location": {
                "lat": 45.505918,
                "lon": -73.61483
            }
        },
        "hostname": [
            "Demo Sensor iq e6ef8db9"
        ],
        "ip": [
            "0.0.0.0"
        ],
        "mac": [
            "D9-A8-80-EF-9D-D2"
        ],
        "os": {
            "name": "Mac OS X"
        },
        "uptime": 64690713
    },
    "input": {
        "type": "cel"
    },
    "network": {
        "protocol": [
            "smb",
            "http"
        ],
        "vlan": {
            "id": [
                "10"
            ]
        }
    },
    "nozomi_networks": {
        "asset": {
            "activity_times": {
                "1746639000000": 1
            },
            "appliance_hosts": [
                "Demo Sensor iq e6ef8db9"
            ],
            "asset_kb_id": "id123",
            "capture_device": "demo",
            "created_at": "2023-04-19T23:50:01.431Z",
            "device_id": "00000000-54b3-e7c7-0000-0000bffd97",
            "end_of_sale_date": "1970-01-21T05:33:14.353Z",
            "end_of_sale_date_info": {
                "source": "passive"
            },
            "end_of_support_date": "1970-01-21T05:33:14.353Z",
            "end_of_support_date_info": {
                "source": "passive"
            },
            "firmware_version": "fv2",
            "firmware_version_info": {
                "source": "passive"
            },
            "has_remediations": false,
            "id": "ca08-ec50-4953-ba47-464013e",
            "ip": [
                "0.0.0.0"
            ],
            "is_ai_enriched": false,
            "is_arc_enriched": true,
            "is_sp_enriched": true,
            "is_ti_enriched": false,
            "last_activity_time": "2025-05-07T17:28:35.000Z",
            "latitude": 45.505918,
            "level": "level1",
            "lifecycle": "life-cycle",
            "lifecycle_info": {
                "source": "passive"
            },
            "location_info": {
                "lat": "-73.614830",
                "lon": "45.505918"
            },
            "longitude": -73.61483,
            "mac_address": [
                "d9:a8:80:ef:9d:d2"
            ],
            "mac_address_level": {
                "d9:a8:80:ef:9d:d2": "unconfirmed"
            },
            "mac_vendor": [
                "Cisco Systems, Inc"
            ],
            "mobility": "static",
            "mobility_info": {
                "confidence": "medium",
                "source": "asset-kb"
            },
            "mobility_votes": {
                "asset-kb": "unknown"
            },
            "name": "0.0.0.0",
            "nodes": [
                "production_b"
            ],
            "nozomi_risk": 2,
            "os": "Mac OS X",
            "os_info": {
                "source": "passive"
            },
            "os_or_firmware": "fware",
            "os_or_firmware_info": {
                "source": "none"
            },
            "product_name": "pname",
            "product_name_info": {
                "source": "passive"
            },
            "properties": {
                "81.2.69.144": {
                    "_product_name.enrichment": "Desktop/Laptop Computer",
                    "_type.enrichment": "computer",
                    "_type.passive": "computer",
                    "_vendor.enrichment": "Dell",
                    "http.last_client_version": "Chrome 91.0.4472.124"
                }
            },
            "protocols": [
                "smb",
                "http"
            ],
            "record_created_at": "2025-05-07T18:50:49.546Z",
            "remediations_signatures": [
                "sign1",
                "sign2"
            ],
            "risk": 2,
            "risk_configuration": {
                "ai_risk_weight": 1,
                "alerts_risk_weight": 0.5,
                "asset_criticality": 25,
                "asset_criticality_factor": 0,
                "asset_criticality_weight": 0.5,
                "communication_risk_weight": 0.5,
                "compensating_control": 0,
                "compensating_control_weight": 0.2,
                "connection_type_weight": 0.5,
                "critical_vulnerabilities_weight": 0.5,
                "device_risk_weight": 0.5,
                "exploitable_vulnerabilities_epss_score": 0.2,
                "exploitable_vulnerabilities_weight": 0.5,
                "high_risk_alert_level": 7,
                "high_risk_alerts_weight": 0.5,
                "high_risk_vulnerabilities_level": 7,
                "internet_exposure_weight": 0.5,
                "lifecycle_weight": 0.5,
                "network_activity_weight": 0.5,
                "open_alerts_weight": 0.5,
                "open_vulnerabilities_likelihood": 0.7,
                "open_vulnerabilities_weight": 0.5,
                "risk_mitigation_factor": 0,
                "suboptimal_management_weight": 0.5,
                "technology_category_weight": 0.5,
                "type_weight": 0.5,
                "unsafe_countries_list": [
                    "china",
                    "russia",
                    "north korea",
                    "ukraine",
                    "vietnam",
                    "indonesia"
                ],
                "unsafe_countries_weight": 0.5,
                "unsafe_protocols_list": [
                    "ftp",
                    "http",
                    "imap",
                    "llmnr",
                    "ntlm",
                    "nfs",
                    "pop3",
                    "rdp",
                    "smb",
                    "snmp",
                    "smtp",
                    "sip",
                    "telnet"
                ],
                "unsafe_protocols_weight": 0.5,
                "vulnerabilities_risk_weight": 0.5
            },
            "roles": [
                "other"
            ],
            "serial_number": "123456789",
            "serial_number_info": {
                "source": "passive"
            },
            "tags": [
                "asset1tag"
            ],
            "technology_category": "IT",
            "time": "2025-05-07T18:50:49.541Z",
            "type": "typehost",
            "type_info": {
                "source": "passive"
            },
            "vendor": "unknown",
            "vendor_info": {
                "source": "passive"
            },
            "vlan_id": [
                "10"
            ],
            "zones": [
                "Undefined"
            ]
        }
    },
    "related": {
        "hosts": [
            "Demo Sensor iq e6ef8db9"
        ],
        "ip": [
            "0.0.0.0"
        ]
    },
    "risk": {
        "calculated_score": 2
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "nozomi_networks-asset",
        "asset1tag"
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| nozomi_networks.asset.activity_times |  | flattened |
| nozomi_networks.asset.appliance_hosts | The hostname(s) of the sensor(s) where this entity has been observed. | keyword |
| nozomi_networks.asset.asset_kb_id |  | keyword |
| nozomi_networks.asset.capture_device | Name of the interface from which this entity has been detected. | keyword |
| nozomi_networks.asset.created_at |  | date |
| nozomi_networks.asset.custom_fields | Any additional custom field defined in the Custom fields. | flattened |
| nozomi_networks.asset.device_id |  | keyword |
| nozomi_networks.asset.end_of_sale_date |  | date |
| nozomi_networks.asset.end_of_sale_date_info |  | flattened |
| nozomi_networks.asset.end_of_support_date |  | date |
| nozomi_networks.asset.end_of_support_date_info |  | flattened |
| nozomi_networks.asset.firmware_version | The firmware version of the asset. The field is not present when the os field is available. | keyword |
| nozomi_networks.asset.firmware_version_info | This is a metadata field about the firmware_version field. | flattened |
| nozomi_networks.asset.has_remediations |  | boolean |
| nozomi_networks.asset.id |  | keyword |
| nozomi_networks.asset.ip | internet protocol (IP) address(es) of the asset. It can be either IPv4, IPv6 or empty (in case of L2 node). | ip |
| nozomi_networks.asset.is_ai_enriched | This field is true if this asset has been enriched by Asset Intelligence. | boolean |
| nozomi_networks.asset.is_arc_enriched |  | boolean |
| nozomi_networks.asset.is_sp_enriched |  | boolean |
| nozomi_networks.asset.is_ti_enriched |  | boolean |
| nozomi_networks.asset.last_activity_time |  | date |
| nozomi_networks.asset.latitude |  | double |
| nozomi_networks.asset.level | The purdue-model level of the asset. | keyword |
| nozomi_networks.asset.lifecycle |  | keyword |
| nozomi_networks.asset.lifecycle_info |  | flattened |
| nozomi_networks.asset.location_info |  | flattened |
| nozomi_networks.asset.longitude |  | double |
| nozomi_networks.asset.mac_address | media access control (MAC) address(es) of the asset. It can be missing in some situations (serial nodes). | keyword |
| nozomi_networks.asset.mac_address_level |  | flattened |
| nozomi_networks.asset.mac_vendor | MAC address vendor(s). Is not empty when the MAC address is present and the corresponding Vendor name is known. | keyword |
| nozomi_networks.asset.mobility |  | keyword |
| nozomi_networks.asset.mobility_info |  | flattened |
| nozomi_networks.asset.mobility_votes.asset-kb |  | keyword |
| nozomi_networks.asset.name | Name of the node. | keyword |
| nozomi_networks.asset.nodes | The set of node id(s) that compose this asset. | keyword |
| nozomi_networks.asset.nozomi_risk |  | double |
| nozomi_networks.asset.os | Operating System of the asset, if available. This field is not present when the firmware_version is available. | keyword |
| nozomi_networks.asset.os_info |  | flattened |
| nozomi_networks.asset.os_or_firmware | Since os and firmware cannot be present at the same time, this field allow to get either of the two in a coalesce-like manner. | keyword |
| nozomi_networks.asset.os_or_firmware_info |  | flattened |
| nozomi_networks.asset.product_name | The product name of the asset. | keyword |
| nozomi_networks.asset.product_name_info | This is a metadata field about the product_name field. | flattened |
| nozomi_networks.asset.properties |  | flattened |
| nozomi_networks.asset.protocols | The unique protocols used from and to this asset. | keyword |
| nozomi_networks.asset.record_created_at |  | date |
| nozomi_networks.asset.remediations_signatures |  | keyword |
| nozomi_networks.asset.risk |  | double |
| nozomi_networks.asset.risk_configuration.ai_risk_weight |  | long |
| nozomi_networks.asset.risk_configuration.alerts_risk_weight |  | double |
| nozomi_networks.asset.risk_configuration.asset_criticality |  | long |
| nozomi_networks.asset.risk_configuration.asset_criticality_factor |  | double |
| nozomi_networks.asset.risk_configuration.asset_criticality_weight |  | double |
| nozomi_networks.asset.risk_configuration.communication_risk_weight |  | double |
| nozomi_networks.asset.risk_configuration.compensating_control |  | long |
| nozomi_networks.asset.risk_configuration.compensating_control_weight |  | double |
| nozomi_networks.asset.risk_configuration.connection_type_weight |  | double |
| nozomi_networks.asset.risk_configuration.critical_vulnerabilities_weight |  | double |
| nozomi_networks.asset.risk_configuration.device_risk_weight |  | double |
| nozomi_networks.asset.risk_configuration.exploitable_vulnerabilities_epss_score |  | double |
| nozomi_networks.asset.risk_configuration.exploitable_vulnerabilities_weight |  | double |
| nozomi_networks.asset.risk_configuration.high_risk_alert_level |  | long |
| nozomi_networks.asset.risk_configuration.high_risk_alerts_weight |  | double |
| nozomi_networks.asset.risk_configuration.high_risk_vulnerabilities_level |  | long |
| nozomi_networks.asset.risk_configuration.internet_exposure_weight |  | double |
| nozomi_networks.asset.risk_configuration.lifecycle_weight |  | double |
| nozomi_networks.asset.risk_configuration.network_activity_weight |  | double |
| nozomi_networks.asset.risk_configuration.open_alerts_weight |  | double |
| nozomi_networks.asset.risk_configuration.open_vulnerabilities_likelihood |  | double |
| nozomi_networks.asset.risk_configuration.open_vulnerabilities_weight |  | double |
| nozomi_networks.asset.risk_configuration.risk_mitigation_factor |  | double |
| nozomi_networks.asset.risk_configuration.suboptimal_management_weight |  | double |
| nozomi_networks.asset.risk_configuration.technology_category_weight |  | double |
| nozomi_networks.asset.risk_configuration.type_weight |  | double |
| nozomi_networks.asset.risk_configuration.unsafe_countries_list |  | keyword |
| nozomi_networks.asset.risk_configuration.unsafe_countries_weight |  | double |
| nozomi_networks.asset.risk_configuration.unsafe_protocols_list |  | keyword |
| nozomi_networks.asset.risk_configuration.unsafe_protocols_weight |  | double |
| nozomi_networks.asset.risk_configuration.vulnerabilities_risk_weight |  | double |
| nozomi_networks.asset.roles | The set of application-level roles of the asset. | keyword |
| nozomi_networks.asset.serial_number | The serial number of the asset. | keyword |
| nozomi_networks.asset.serial_number_info | This is a metadata field about the serial_number field. | flattened |
| nozomi_networks.asset.tags |  | keyword |
| nozomi_networks.asset.technology_category |  | keyword |
| nozomi_networks.asset.time |  | date |
| nozomi_networks.asset.type | The type of the asset. . | keyword |
| nozomi_networks.asset.type_info | This is a metadata field about the type field. | flattened |
| nozomi_networks.asset.vendor | Vendor of the asset. | keyword |
| nozomi_networks.asset.vendor_info | This is a metadata field about the vendor field. | flattened |
| nozomi_networks.asset.vlan_id | The virtual local area network (VLAN) identifier (ID)(s) of the asset. It can be absent if the traffic to/from the node is not VLAN-tagged. | keyword |
| nozomi_networks.asset.zones |  | keyword |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |


### Audit

This is the `Audit` dataset.

#### Example

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2025-05-12T05:38:53.580Z",
    "agent": {
        "ephemeral_id": "a6c46f83-823d-427c-aa46-301bb853e305",
        "id": "eb39cad6-2037-4a83-8bd8-eeac01ad5aea",
        "name": "elastic-agent-31721",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "nozomi_networks.audit",
        "namespace": "99538",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "eb39cad6-2037-4a83-8bd8-eeac01ad5aea",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "action": "create",
        "agent_id_status": "verified",
        "dataset": "nozomi_networks.audit",
        "id": "e68f6c04-fe98-4549-abcf-6a2213249c3c",
        "ingested": "2025-06-11T12:08:52Z",
        "kind": "event",
        "original": "{\"action\":\"create\",\"browser\":\"python-requests/2.32.3\",\"controller\":\"api/api_key_sessions\",\"details\":null,\"event\":\"API key signed in with id 7a6534a6-ee49-4cb3-a0ae-1f3a6cac9b26\",\"id\":\"e68f6c04-fe98-4549-abcf-6a2213249c3c\",\"ip_address\":\"81.2.69.192\",\"name\":\"API key signed in\",\"record_created_at\":1747028333580,\"time\":1747028333579,\"username\":\"edward@gmail.com via APIkey AK6eef5d\"}"
    },
    "input": {
        "type": "cel"
    },
    "message": "API key signed in with id 7a6534a6-ee49-4cb3-a0ae-1f3a6cac9b26",
    "nozomi_networks": {
        "audit": {
            "action": "create",
            "browser": "python-requests/2.32.3",
            "controller": "api/api_key_sessions",
            "event": "API key signed in with id 7a6534a6-ee49-4cb3-a0ae-1f3a6cac9b26",
            "id": "e68f6c04-fe98-4549-abcf-6a2213249c3c",
            "ip_address": "81.2.69.192",
            "name": "API key signed in",
            "record_created_at": "2025-05-12T05:38:53.580Z",
            "time": "2025-05-12T05:38:53.579Z",
            "username": "edward@gmail.com via APIkey AK6eef5d"
        }
    },
    "related": {
        "ip": [
            "81.2.69.192"
        ],
        "user": [
            "edward",
            "edward@gmail.com"
        ]
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.192"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "nozomi_networks-audit"
    ],
    "user": {
        "domain": "gmail.com",
        "email": "edward@gmail.com",
        "name": "edward"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Python Requests",
        "original": "python-requests/2.32.3",
        "version": "2.32"
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| nozomi_networks.audit.action |  | keyword |
| nozomi_networks.audit.browser |  | keyword |
| nozomi_networks.audit.controller |  | keyword |
| nozomi_networks.audit.details |  | keyword |
| nozomi_networks.audit.event |  | keyword |
| nozomi_networks.audit.id |  | keyword |
| nozomi_networks.audit.ip_address |  | ip |
| nozomi_networks.audit.name |  | keyword |
| nozomi_networks.audit.record_created_at |  | date |
| nozomi_networks.audit.time |  | date |
| nozomi_networks.audit.username |  | keyword |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |


### Health

This is the `Health` dataset.

#### Example

An example event for `health` looks as following:

```json
{
    "@timestamp": "2025-03-13T12:36:17.517Z",
    "agent": {
        "ephemeral_id": "33fdbb95-78cf-412c-bb24-44f45aeb048c",
        "id": "61d952ea-7718-4c4c-9a32-2476eb5aaf5a",
        "name": "elastic-agent-91000",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "nozomi_networks.health",
        "namespace": "34884",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "61d952ea-7718-4c4c-9a32-2476eb5aaf5a",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "created": "2025-03-13T12:36:17.517Z",
        "dataset": "nozomi_networks.health",
        "id": "f8c3fe6d-6926-4cbe-b51d-08f38a72c593",
        "ingested": "2025-06-18T12:16:25Z",
        "kind": "event",
        "original": "{\"appliance_host\":\"Sandbox-TAE-Guardian3\",\"appliance_id\":\"1c08da2c-e7e9-4030-b956-cada6e0a9a96\",\"id\":\"f8c3fe6d-6926-4cbe-b51d-08f38a72c593\",\"info\":{\"description\":\"Recommended changes. The following items should be changed to support the updates included in version 22.5.0.\\n\\nAlert rules:\\nNothing to change here\\n\\nAssertions:\\nNothing to change here\\n\\nQueries:\\nNothing to change here\\n\\nAlert rules:\\nNothing to change here\\n\\nReports:\\nNothing to change here\\n\\nSee the N2OS release notes for further explanations.\"},\"record_created_at\":1741869377517,\"sensor_appliance_type\":\"guardian\",\"time\":1741868841845}",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "Sandbox-TAE-Guardian3",
        "id": "1c08da2c-e7e9-4030-b956-cada6e0a9a96",
        "name": "Sandbox-TAE-Guardian3"
    },
    "input": {
        "type": "cel"
    },
    "nozomi_networks": {
        "health": {
            "appliance_host": "Sandbox-TAE-Guardian3",
            "appliance_id": "1c08da2c-e7e9-4030-b956-cada6e0a9a96",
            "id": "f8c3fe6d-6926-4cbe-b51d-08f38a72c593",
            "info": {
                "description": "Recommended changes. The following items should be changed to support the updates included in version 22.5.0.\n\nAlert rules:\nNothing to change here\n\nAssertions:\nNothing to change here\n\nQueries:\nNothing to change here\n\nAlert rules:\nNothing to change here\n\nReports:\nNothing to change here\n\nSee the N2OS release notes for further explanations."
            },
            "record_created_at": "2025-03-13T12:36:17.517Z",
            "sensor_appliance_type": "guardian",
            "time": "2025-03-13T12:27:21.845Z"
        }
    },
    "related": {
        "hosts": [
            "Sandbox-TAE-Guardian3",
            "1c08da2c-e7e9-4030-b956-cada6e0a9a96"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "nozomi_networks-health"
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| nozomi_networks.health.appliance_host | The hostname of the sensor where this entity has been observed. | keyword |
| nozomi_networks.health.appliance_id | The id of the sensor where this entity has been observed. | keyword |
| nozomi_networks.health.appliance_ip | The internet protocol (IP) address of the sensor where this entity has been observed. | ip |
| nozomi_networks.health.id | Primary key of this query source. | keyword |
| nozomi_networks.health.info | JavaScript Object Notation (JSON) with the information captured with about the event. | flattened |
| nozomi_networks.health.record_created_at |  | date |
| nozomi_networks.health.replicated | This is true if the record has been replicated on the replica machine. | boolean |
| nozomi_networks.health.sensor_appliance_type |  | keyword |
| nozomi_networks.health.sensor_host |  | keyword |
| nozomi_networks.health.sensor_id |  | keyword |
| nozomi_networks.health.synchronized | True if this entity has been synchronized with the upper Central Management Console (CMC) or Vantage. | boolean |
| nozomi_networks.health.time | Timestamp in epoch milliseconds when this entity was created or updated. | date |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |


### Node

This is the `Node` dataset.

#### Example

An example event for `node` looks as following:

```json
{
    "@timestamp": "2025-05-14T08:15:53.228Z",
    "agent": {
        "ephemeral_id": "2f5e942e-21ab-4372-9fab-0836822fcefb",
        "id": "8617f577-4713-401a-9bcf-c9f79a96ea1c",
        "name": "elastic-agent-42207",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "nozomi_networks.node",
        "namespace": "76268",
        "type": "logs"
    },
    "destination": {
        "bytes": 0,
        "packets": 0
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "8617f577-4713-401a-9bcf-c9f79a96ea1c",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "created": "2024-09-10T09:21:46.182Z",
        "dataset": "nozomi_networks.node",
        "end": "2025-05-14T07:00:00.000Z",
        "id": "9b492faf-5cf2-4b91-b745-f1e903bba5d1",
        "ingested": "2025-06-18T06:45:52Z",
        "kind": "event",
        "original": "{\"_asset_kb_id\":\"123id\",\"_is_licensed\":true,\"_private_status\":\"no\",\"appliance_host\":\"hname\",\"asset_id\":\"54trg\",\"bpf_filter\":\"ip host 81.2.69.144\",\"capture_device\":\"demo\",\"created_at\":1725960106182,\"custom_fields\":{\"field1\":\"value1\"},\"device_id\":\"00000000-54b3-e7c7-0000-000046bffd97\",\"device_modules\":{\"children\":{\"cip\":[{\"attributes\":{\"name\":\"Backplane\",\"type\":\"1\"},\"children\":[{\"attributes\":{\"device_type\":\"Programmable Logic Controller\",\"device_type_id\":\"14\",\"firmware_version\":\"20.055\",\"product_code\":\"54\",\"product_name\":\"1756-L61/B LOGIX5561\",\"serial_number\":\"00112237\",\"vendor\":\"Rockwell Automation/Allen-Bradley\",\"vendor_id\":\"1\"},\"children\":[{\"attributes\":{\"name\":\"Backplane\",\"type\":\"1\"},\"type\":\"port\",\"value\":\"1\"},{\"attributes\":{\"name\":\"Channel 0\",\"type\":\"9\"},\"type\":\"port\",\"value\":\"2\"}],\"type\":\"address\",\"value\":\"0\"},{\"attributes\":{\"device_type\":\"\",\"device_type_id\":\"112\",\"firmware_version\":\"20.004\",\"product_code\":\"3\",\"product_name\":\"1756-RM2/A REDUNDANCY MODULE\",\"serial_number\":\"00010207\",\"vendor\":\"Rockwell Automation/Allen-Bradley\",\"vendor_id\":\"1\"},\"type\":\"address\",\"value\":\"1\"},{\"attributes\":{\"device_type\":\"Communications Adapter\",\"device_type_id\":\"12\",\"firmware_version\":\"18.002\",\"product_code\":\"166\",\"product_name\":\"1756-ENBT/A\",\"serial_number\":\"00112237\",\"vendor\":\"Rockwell Automation/Allen-Bradley\",\"vendor_id\":\"1\"},\"type\":\"address\",\"value\":\"3\"},{\"attributes\":{\"device_type\":\"Communications Adapter\",\"device_type_id\":\"12\",\"firmware_version\":\"10.006\",\"product_code\":\"166\",\"product_name\":\"1756-ENBT/A\",\"serial_number\":\"00445567\",\"vendor\":\"Rockwell Automation/Allen-Bradley\",\"vendor_id\":\"1\"},\"children\":[{\"attributes\":{\"name\":\"Backplane\"},\"type\":\"port\",\"value\":\"1\"}],\"type\":\"address\",\"value\":\"4\"},{\"attributes\":{\"device_type\":\"Communications Adapter\",\"device_type_id\":\"12\",\"firmware_version\":\"5.008\",\"product_code\":\"200\",\"product_name\":\"1756-EN2TR/B\",\"serial_number\":\"00070807\",\"vendor\":\"Rockwell Automation/Allen-Bradley\",\"vendor_id\":\"1\"},\"children\":[{\"attributes\":{\"name\":\"Backplane\",\"type\":\"1\"},\"type\":\"port\",\"value\":\"1\"},{\"attributes\":{\"name\":\"A\",\"type\":\"EtherNet/IP\"},\"type\":\"port\",\"value\":\"2\"},{\"attributes\":{\"name\":\"PCviaUSB\",\"type\":\"107\"},\"type\":\"port\",\"value\":\"3\"}],\"type\":\"address\",\"value\":\"6\"}],\"type\":\"port\",\"value\":\"1\"},{\"attributes\":{\"name\":\"A\",\"type\":\"EtherNet/IP\"},\"type\":\"port\",\"value\":\"2\"},{\"attributes\":{\"name\":\"PCviaUSB\",\"type\":\"107\"},\"type\":\"port\",\"value\":\"3\"}]},\"firmware_version\":\"20.055\",\"product_name\":\"ControlLogix 1756-L61/B LOGIX5561\",\"serial_number\":\"00112237\",\"vendor\":\"Rockwell Automation\"},\"end_of_sale_date\":\"1727740800000\",\"end_of_sale_date:info\":{\"source\":\"none\"},\"end_of_support_date\":\"1727740800000\",\"end_of_support_date:info\":{\"source\":\"none\"},\"firmware_version\":\"18.002\",\"firmware_version:info\":{\"confidence\":\"high\",\"granularity\":\"complete\",\"protocol\":\"ethernetip\",\"source\":\"passive\"},\"first_activity_time\":0,\"id\":\"9b492faf-5cf2-4b91-b745-f1e903bba5d1\",\"ip\":\"ff02::1:ff35:a124\",\"is_ai_enriched\":false,\"is_arc_enriched\":false,\"is_broadcast\":false,\"is_compromised\":false,\"is_confirmed\":true,\"is_disabled\":false,\"is_fully_learned\":true,\"is_learned\":true,\"is_public\":false,\"is_sp_enriched\":false,\"is_ti_enriched\":true,\"label\":\"ACMEincHQ_SW2\",\"label:info\":{\"source\":\"none\"},\"last_activity_time\":1747206000000,\"level\":\"1.5\",\"lifecycle\":\"end_of_sale\",\"lifecycle:info\":{\"source\":\"none\"},\"links\":\"link1\",\"links_count\":\"1\",\"mac_address\":\"00:30:a7:a8:01:65\",\"mac_address:info\":{\"likelihood\":\"0\",\"likelihood_level\":\"unconfirmed\",\"protocol_source\":\"\",\"source\":\"none\"},\"mac_vendor\":\"Schweitzer Engineering Laboratories\",\"name\":\"00112231@81.2.69.144\",\"os\":\"Windows XP SP3\",\"os:info\":{\"source\":\"none\"},\"product_name\":\"ControlLogix 1756-ENBT/A\",\"product_name:info\":{\"confidence\":\"high\",\"granularity\":\"complete\",\"protocol\":\"ethernetip\",\"source\":\"passive\"},\"properties\":{\"_product_name.passive\":\"ControlLogix 1756-ENBT/A\",\"_type.passive\":\"controller\",\"_vendor.passive\":\"Rockwell Automation/Allen-Bradley\",\"ethernetip/device_type\":\"Communications Adapter\",\"ethernetip/device_type_id\":\"12\",\"ethernetip/firmware_version\":\"18.002\",\"ethernetip/product_code\":\"166\",\"ethernetip/product_name\":\"1756-ENBT/A\",\"ethernetip/serial_number\":\"00112231\",\"ethernetip/vendor\":\"Rockwell Automation/Allen-Bradley\",\"ethernetip/vendor_id\":\"1\"},\"protocols\":[\"ethernetip\"],\"received.bytes\":\"0\",\"received.last_15m_bytes\":\"0\",\"received.last_1d_bytes\":\"0\",\"received.last_1h_bytes\":\"0\",\"received.last_1w_bytes\":\"0\",\"received.last_30m_bytes\":\"0\",\"received.last_5m_bytes\":\"0\",\"received.packets\":\"0\",\"record_created_at\":1747210553228,\"reputation\":\"test reputation\",\"roles\":[\"other\"],\"sent.bytes\":\"0\",\"sent.last_15m_bytes\":\"0\",\"sent.last_1d_bytes\":\"0\",\"sent.last_1h_bytes\":\"0\",\"sent.last_1w_bytes\":\"0\",\"sent.last_30m_bytes\":\"0\",\"sent.last_5m_bytes\":\"0\",\"sent.packets\":\"0\",\"serial_number\":\"00112231\",\"serial_number:info\":{\"confidence\":\"high\",\"granularity\":\"complete\",\"protocol\":\"ethernetip\",\"source\":\"passive\"},\"subnet\":\"10.1.1.0/24\",\"tcp_retransmission.bytes\":\"0\",\"tcp_retransmission.last_15m_bytes\":\"0\",\"tcp_retransmission.last_30m_bytes\":\"0\",\"tcp_retransmission.last_5m_bytes\":\"0\",\"tcp_retransmission.packets\":\"0\",\"tcp_retransmission.percent\":0,\"type\":\"controller\",\"type:info\":{\"protocol\":\"ethernetip\",\"source\":\"passive\"},\"variables_count\":\"8\",\"vendor\":\"Rockwell Automation\",\"vendor:info\":{\"confidence\":\"high\",\"granularity\":\"complete\",\"protocol\":\"ethernetip\",\"source\":\"passive\"},\"vlan_id\":\"100\",\"vlan_id:info\":{\"source\":\"none\"},\"zone\":\"Layer2\"}",
        "start": "1970-01-01T00:00:00.000Z",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "hname",
        "os": {
            "full": "Windows XP SP3"
        },
        "uptime": 21245893
    },
    "input": {
        "type": "cel"
    },
    "network": {
        "protocol": [
            "ethernetip"
        ],
        "vlan": {
            "id": "100"
        }
    },
    "nozomi_networks": {
        "node": {
            "appliance_host": "hname",
            "asset_kb_id": "123id",
            "bpf_filter": "ip host 81.2.69.144",
            "capture_device": "demo",
            "created_at": "2024-09-10T09:21:46.182Z",
            "custom_fields": {
                "field1": "value1"
            },
            "device_id": "00000000-54b3-e7c7-0000-000046bffd97",
            "device_modules": {
                "children": {
                    "cip": [
                        {
                            "attributes": {
                                "name": "Backplane",
                                "type": "1"
                            },
                            "children": [
                                {
                                    "attributes": {
                                        "device_type": "Programmable Logic Controller",
                                        "device_type_id": "14",
                                        "firmware_version": "20.055",
                                        "product_code": "54",
                                        "product_name": "1756-L61/B LOGIX5561",
                                        "serial_number": "00112237",
                                        "vendor": "Rockwell Automation/Allen-Bradley",
                                        "vendor_id": "1"
                                    },
                                    "children": [
                                        {
                                            "attributes": {
                                                "name": "Backplane",
                                                "type": "1"
                                            },
                                            "type": "port",
                                            "value": "1"
                                        },
                                        {
                                            "attributes": {
                                                "name": "Channel 0",
                                                "type": "9"
                                            },
                                            "type": "port",
                                            "value": "2"
                                        }
                                    ],
                                    "type": "address",
                                    "value": "0"
                                },
                                {
                                    "attributes": {
                                        "device_type_id": "112",
                                        "firmware_version": "20.004",
                                        "product_code": "3",
                                        "product_name": "1756-RM2/A REDUNDANCY MODULE",
                                        "serial_number": "00010207",
                                        "vendor": "Rockwell Automation/Allen-Bradley",
                                        "vendor_id": "1"
                                    },
                                    "type": "address",
                                    "value": "1"
                                },
                                {
                                    "attributes": {
                                        "device_type": "Communications Adapter",
                                        "device_type_id": "12",
                                        "firmware_version": "18.002",
                                        "product_code": "166",
                                        "product_name": "1756-ENBT/A",
                                        "serial_number": "00112237",
                                        "vendor": "Rockwell Automation/Allen-Bradley",
                                        "vendor_id": "1"
                                    },
                                    "type": "address",
                                    "value": "3"
                                },
                                {
                                    "attributes": {
                                        "device_type": "Communications Adapter",
                                        "device_type_id": "12",
                                        "firmware_version": "10.006",
                                        "product_code": "166",
                                        "product_name": "1756-ENBT/A",
                                        "serial_number": "00445567",
                                        "vendor": "Rockwell Automation/Allen-Bradley",
                                        "vendor_id": "1"
                                    },
                                    "children": [
                                        {
                                            "attributes": {
                                                "name": "Backplane"
                                            },
                                            "type": "port",
                                            "value": "1"
                                        }
                                    ],
                                    "type": "address",
                                    "value": "4"
                                },
                                {
                                    "attributes": {
                                        "device_type": "Communications Adapter",
                                        "device_type_id": "12",
                                        "firmware_version": "5.008",
                                        "product_code": "200",
                                        "product_name": "1756-EN2TR/B",
                                        "serial_number": "00070807",
                                        "vendor": "Rockwell Automation/Allen-Bradley",
                                        "vendor_id": "1"
                                    },
                                    "children": [
                                        {
                                            "attributes": {
                                                "name": "Backplane",
                                                "type": "1"
                                            },
                                            "type": "port",
                                            "value": "1"
                                        },
                                        {
                                            "attributes": {
                                                "name": "A",
                                                "type": "EtherNet/IP"
                                            },
                                            "type": "port",
                                            "value": "2"
                                        },
                                        {
                                            "attributes": {
                                                "name": "PCviaUSB",
                                                "type": "107"
                                            },
                                            "type": "port",
                                            "value": "3"
                                        }
                                    ],
                                    "type": "address",
                                    "value": "6"
                                }
                            ],
                            "type": "port",
                            "value": "1"
                        },
                        {
                            "attributes": {
                                "name": "A",
                                "type": "EtherNet/IP"
                            },
                            "type": "port",
                            "value": "2"
                        },
                        {
                            "attributes": {
                                "name": "PCviaUSB",
                                "type": "107"
                            },
                            "type": "port",
                            "value": "3"
                        }
                    ]
                },
                "firmware_version": "20.055",
                "product_name": "ControlLogix 1756-L61/B LOGIX5561",
                "serial_number": "00112237",
                "vendor": "Rockwell Automation"
            },
            "end_of_sale_date": "2024-10-01T00:00:00.000Z",
            "end_of_sale_date_info": {
                "source": "none"
            },
            "end_of_support_date": "2024-10-01T00:00:00.000Z",
            "end_of_support_date_info": {
                "source": "none"
            },
            "firmware_version": "18.002",
            "firmware_version_info": {
                "confidence": "high",
                "granularity": "complete",
                "protocol": "ethernetip",
                "source": "passive"
            },
            "first_activity_time": "1970-01-01T00:00:00.000Z",
            "id": "9b492faf-5cf2-4b91-b745-f1e903bba5d1",
            "ip": "ff02::1:ff35:a124",
            "is_ai_enriched": false,
            "is_arc_enriched": false,
            "is_broadcast": false,
            "is_compromised": false,
            "is_confirmed": true,
            "is_disabled": false,
            "is_fully_learned": true,
            "is_learned": true,
            "is_licensed": true,
            "is_public": false,
            "is_sp_enriched": false,
            "is_ti_enriched": true,
            "label": "ACMEincHQ_SW2",
            "label_info": {
                "source": "none"
            },
            "last_activity_time": "2025-05-14T07:00:00.000Z",
            "level": 1.5,
            "lifecycle": "end_of_sale",
            "lifecycle_info": {
                "source": "none"
            },
            "links": "link1",
            "links_count": 1,
            "mac_address": "00:30:a7:a8:01:65",
            "mac_address_info": {
                "likelihood": "0",
                "likelihood_level": "unconfirmed",
                "source": "none"
            },
            "mac_vendor": "Schweitzer Engineering Laboratories",
            "name": "00112231@81.2.69.144",
            "os": "Windows XP SP3",
            "os_info": {
                "source": "none"
            },
            "private_status": "no",
            "product_name": "ControlLogix 1756-ENBT/A",
            "product_name_info": {
                "source": {
                    "confidence": "high",
                    "granularity": "complete",
                    "protocol": "ethernetip",
                    "source": "passive"
                }
            },
            "properties": {
                "ethernetip_device_type": "Communications Adapter",
                "ethernetip_device_type_id": "12",
                "ethernetip_firmware_version": "18.002",
                "ethernetip_product_code": "166",
                "ethernetip_product_name": "1756-ENBT/A",
                "ethernetip_serial_number": "00112231",
                "ethernetip_vendor": "Rockwell Automation/Allen-Bradley",
                "ethernetip_vendor_id": "1"
            },
            "protocols": [
                "ethernetip"
            ],
            "received": {
                "bytes": 0,
                "last_15m_bytes": 0,
                "last_1d_bytes": 0,
                "last_1h_bytes": 0,
                "last_1w_bytes": 0,
                "last_30m_bytes": 0,
                "last_5m_bytes": 0,
                "packets": 0
            },
            "record_created_at": "2025-05-14T08:15:53.228Z",
            "reputation": "test reputation",
            "roles": [
                "other"
            ],
            "sent": {
                "bytes": 0,
                "last_15m_bytes": 0,
                "last_1d_bytes": 0,
                "last_1h_bytes": 0,
                "last_1w_bytes": 0,
                "last_30m_bytes": 0,
                "last_5m_bytes": 0,
                "packets": 0
            },
            "serial_number": "00112231",
            "serial_number_info": {
                "confidence": "high",
                "granularity": "complete",
                "protocol": "ethernetip",
                "source": "passive"
            },
            "subnet": "10.1.1.0/24",
            "tcp_retransmission": {
                "bytes": 0,
                "last_15m_bytes": 0,
                "last_30m_bytes": 0,
                "last_5m_bytes": 0,
                "packets": 0,
                "percent": 0
            },
            "type": "controller",
            "type_info": {
                "protocol": "ethernetip",
                "source": "passive"
            },
            "variables_count": 8,
            "vendor": "Rockwell Automation",
            "vendor_info": {
                "confidence": "high",
                "granularity": "complete",
                "protocol": "ethernetip",
                "source": "passive"
            },
            "vlan_id": "100",
            "vlan_id_info": {
                "source": "none"
            },
            "zone": "Layer2"
        }
    },
    "related": {
        "hosts": [
            "hname",
            "Windows XP SP3"
        ],
        "ip": [
            "ff02::1:ff35:a124"
        ]
    },
    "service": {
        "node": {
            "name": "ControlLogix 1756-ENBT/A",
            "roles": [
                "other"
            ]
        },
        "type": "controller"
    },
    "source": {
        "bytes": 0,
        "ip": "ff02::1:ff35:a124",
        "mac": "00-30-A7-A8-01-65",
        "packets": 0
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "nozomi_networks-node"
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| nozomi_networks.node.appliance_host | The hostname of the sensor where this entity has been observed. | keyword |
| nozomi_networks.node.asset_kb_id |  | keyword |
| nozomi_networks.node.bpf_filter | Berkeley Packet Filter (BPF) filter for the node, used when performing traces for this node and as building block for link traces too. | keyword |
| nozomi_networks.node.capture_device | Name of the interface from which this entity has been detected. | keyword |
| nozomi_networks.node.created_at | Timestamp in epoch milliseconds when this node was first observed. | date |
| nozomi_networks.node.custom_fields | Any additional custom field defined in the Custom fields. | flattened |
| nozomi_networks.node.device_id | Internal use. | keyword |
| nozomi_networks.node.device_modules.children.cip.attributes.name |  | keyword |
| nozomi_networks.node.device_modules.children.cip.attributes.type |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.attributes.device_type |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.attributes.device_type_id |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.attributes.firmware_version |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.attributes.product_code |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.attributes.product_name |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.attributes.serial_number |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.attributes.vendor |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.attributes.vendor_id |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.children.attributes.name |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.children.attributes.type |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.children.type |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.children.value |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.type |  | keyword |
| nozomi_networks.node.device_modules.children.cip.children.value |  | keyword |
| nozomi_networks.node.device_modules.children.cip.type |  | keyword |
| nozomi_networks.node.device_modules.children.cip.value |  | keyword |
| nozomi_networks.node.device_modules.firmware_version |  | keyword |
| nozomi_networks.node.device_modules.product_name |  | keyword |
| nozomi_networks.node.device_modules.serial_number |  | keyword |
| nozomi_networks.node.device_modules.vendor |  | keyword |
| nozomi_networks.node.end_of_sale_date |  | date |
| nozomi_networks.node.end_of_sale_date_info |  | flattened |
| nozomi_networks.node.end_of_support_date |  | date |
| nozomi_networks.node.end_of_support_date_info |  | flattened |
| nozomi_networks.node.firmware_version | The firmware version of the node. The field is not present when the os field is available. | keyword |
| nozomi_networks.node.firmware_version_info | This is a metadata field about the firmware_version field. | flattened |
| nozomi_networks.node.first_activity_time | Timestamp in epoch milliseconds when this node send a packet for the first time. | date |
| nozomi_networks.node.id | Primary key of this query source. | keyword |
| nozomi_networks.node.ip | internet protocol (IP) address of the node. It can be either IPv4, IPv6 or empty (in case of L2 node). | ip |
| nozomi_networks.node.is_ai_enriched |  | boolean |
| nozomi_networks.node.is_arc_enriched |  | boolean |
| nozomi_networks.node.is_broadcast | True if this is not a real node but a broadcast or multicast entry. | boolean |
| nozomi_networks.node.is_compromised | This is true for nodes that have been recognised as compromised according to threat indicators. | boolean |
| nozomi_networks.node.is_confirmed | This is true for nodes that are confirmed to exist. Non-existing targets of port scans for instance are not confirmed. | boolean |
| nozomi_networks.node.is_disabled | This is true for nodes that are hidden from graphs because too noisy. | boolean |
| nozomi_networks.node.is_fully_learned | This is true for nodes that were observed also during the learning phase and which properties are not changed since then. | boolean |
| nozomi_networks.node.is_learned | This is true for nodes that were observed during the learning phase. | boolean |
| nozomi_networks.node.is_licensed |  | boolean |
| nozomi_networks.node.is_public | True if this not a local node but an outside, public IP address. | boolean |
| nozomi_networks.node.is_sp_enriched |  | boolean |
| nozomi_networks.node.is_ti_enriched |  | boolean |
| nozomi_networks.node.label | Name of the node. | keyword |
| nozomi_networks.node.label_info |  | flattened |
| nozomi_networks.node.last_activity_time | Timestamp in epoch milliseconds when this node send a packet for the last time. | date |
| nozomi_networks.node.level | The purdue-model level of the node. | double |
| nozomi_networks.node.lifecycle |  | keyword |
| nozomi_networks.node.lifecycle_info |  | flattened |
| nozomi_networks.node.links | The set of links to which this node is related. | keyword |
| nozomi_networks.node.links_count | The total number of links from and to this node. | long |
| nozomi_networks.node.mac_address | media access control (MAC) address of the node. It can be missing in some situations (serial nodes). | keyword |
| nozomi_networks.node.mac_address_info | This is a metadata field about the mac_address field. | flattened |
| nozomi_networks.node.mac_vendor | MAC address vendor. Is not empty when the MAC address is present and the corresponding Vendor name is known. | keyword |
| nozomi_networks.node.name |  | keyword |
| nozomi_networks.node.os | Operating System of the node, if available. This field is not present when the firmware_version is available. | keyword |
| nozomi_networks.node.os_info |  | flattened |
| nozomi_networks.node.private_status |  | keyword |
| nozomi_networks.node.product_name | The product name of the node. | keyword |
| nozomi_networks.node.product_name_info.source | This is a metadata field about the product_name field. | flattened |
| nozomi_networks.node.properties.ethernetip_device_type |  | keyword |
| nozomi_networks.node.properties.ethernetip_device_type_id |  | keyword |
| nozomi_networks.node.properties.ethernetip_firmware_version |  | keyword |
| nozomi_networks.node.properties.ethernetip_product_code |  | keyword |
| nozomi_networks.node.properties.ethernetip_product_name |  | keyword |
| nozomi_networks.node.properties.ethernetip_serial_number |  | keyword |
| nozomi_networks.node.properties.ethernetip_vendor |  | keyword |
| nozomi_networks.node.properties.ethernetip_vendor_id |  | keyword |
| nozomi_networks.node.properties.product_name.passive |  | keyword |
| nozomi_networks.node.properties.type.passive |  | keyword |
| nozomi_networks.node.properties.vendor.passive |  | keyword |
| nozomi_networks.node.protocols | The unique protocols used from and to this node. | keyword |
| nozomi_networks.node.received.bytes | Total number of bytes received. | long |
| nozomi_networks.node.received.last_15m_bytes | Number of bytes received in the last 15 minutes. | long |
| nozomi_networks.node.received.last_1d_bytes |  | long |
| nozomi_networks.node.received.last_1h_bytes |  | long |
| nozomi_networks.node.received.last_1w_bytes |  | long |
| nozomi_networks.node.received.last_30m_bytes | Number of bytes received in the last 30 minutes. | long |
| nozomi_networks.node.received.last_5m_bytes | Number of bytes received in the last 5 minutes. | long |
| nozomi_networks.node.received.packets | Total number of packets received. | long |
| nozomi_networks.node.record_created_at |  | date |
| nozomi_networks.node.reputation | This can be good or bad depending on information coming from STIX indicators. | keyword |
| nozomi_networks.node.roles | The set of application-level roles of the node. Differently from the type, these are behaviors. | keyword |
| nozomi_networks.node.sent.bytes | Total number of bytes sent. | long |
| nozomi_networks.node.sent.last_15m_bytes | Number of bytes sent in the last 15 minutes. | long |
| nozomi_networks.node.sent.last_1d_bytes |  | long |
| nozomi_networks.node.sent.last_1h_bytes |  | long |
| nozomi_networks.node.sent.last_1w_bytes |  | long |
| nozomi_networks.node.sent.last_30m_bytes | Number of bytes sent in the last 30 minutes. | long |
| nozomi_networks.node.sent.last_5m_bytes | Number of bytes sent in the last 5 minutes. | long |
| nozomi_networks.node.sent.packets | Total number of packets sent. | long |
| nozomi_networks.node.serial_number | The serial number of the node. | keyword |
| nozomi_networks.node.serial_number_info | This is a metadata field about the serial_number field. | flattened |
| nozomi_networks.node.subnet | The subnet to which this node belongs, if any. | keyword |
| nozomi_networks.node.tcp_retransmission.bytes | Total amount of bytes for TCP packets that have been retransmitted. | long |
| nozomi_networks.node.tcp_retransmission.last_15m_bytes | Amount of bytes of TCP packets that have been retransmitted in the last 15 minutes. | long |
| nozomi_networks.node.tcp_retransmission.last_30m_bytes | Amount of bytes of TCP packets that have been retransmitted in the last 30 minutes. | long |
| nozomi_networks.node.tcp_retransmission.last_5m_bytes | Amount of bytes of TCP packets that have been retransmitted in the last 5 minutes. | long |
| nozomi_networks.node.tcp_retransmission.packets | Total number of TCP packets that have been retransmitted. | long |
| nozomi_networks.node.tcp_retransmission.percent | Percentage of transmission control protocol (TCP) packets that have been retransmitted. | double |
| nozomi_networks.node.type | The type of the node. | keyword |
| nozomi_networks.node.type_info | This is a metadata field about the type field. | flattened |
| nozomi_networks.node.variables_count | Amount of variables attached to the node. | long |
| nozomi_networks.node.vendor | Vendor of the node. | keyword |
| nozomi_networks.node.vendor_info | This is a metadata field about the vendor field. | flattened |
| nozomi_networks.node.vlan_id | The virtual local area network (VLAN) identifier (ID) of the node. It can be absent if the traffic to/from the node is not VLAN-tagged. | keyword |
| nozomi_networks.node.vlan_id_info | This is a metadata field about the vlan_id field. | flattened |
| nozomi_networks.node.zone | The zone name to which this node belongs to. | keyword |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |


### Node CVE

This is the `Node CVE` dataset.

#### Example

An example event for `node_cve` looks as following:

```json
{
    "@timestamp": "2025-03-13T13:53:37.431Z",
    "agent": {
        "ephemeral_id": "c3a699b3-2a2e-42d8-b179-9eee0e4cbf8d",
        "id": "6e25f3fc-0680-49f1-addb-1416ed6895d8",
        "name": "elastic-agent-28676",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "nozomi_networks.node_cve",
        "namespace": "31345",
        "type": "logs"
    },
    "device": {
        "id": "7d2fd56b-f3e2-4afd-8d3e-9b7480ab6f7d"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "6e25f3fc-0680-49f1-addb-1416ed6895d8",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "nozomi_networks.node_cve",
        "end": "1970-01-01T00:00:00.000Z",
        "id": "4c26-b605-be03f2b5b629",
        "ingested": "2025-06-18T06:59:15Z",
        "kind": "alert",
        "original": "{\"asset_id\":\"7d2fd56b-f3e2-4afd-8d3e-9b7480ab6f7d\",\"cve\":\"CVE-EOL\",\"cve_creation_time\":0,\"cve_epss_score\":null,\"cve_score\":10,\"cve_source\":null,\"cve_summary\":\"The product cannot be updated or patched in order to remove vulnerabilities or significant bugs.\",\"cve_update_time\":0,\"cwe_id\":\"CWE-1329\",\"cwe_name\":\"Reliance on Component That is Not Updatable\",\"firmware_version\":\"5.1.100.13                                 :)\",\"id\":\"4c26-b605-be03f2b5b629\",\"is_kev\":false,\"latest_hotfix\":null,\"likelihood\":1,\"matching_cpes\":[\"cpe:/o:microsoft:windows_xp:-:-:-\"],\"minimum_hotfix\":null,\"name\":\"HMI-A101\",\"nodes\":[\"1.128.0.0\"],\"os\":\"Firmware: 5.1.100.13                                 :)\",\"probability\":\"Confirmed\",\"product_name\":\"AC 800M PM851\",\"record_created_at\":1741874017431,\"references\":[{\"reference_type\":\"Vendor Advisory\",\"source\":\"product-security@xyz.com\",\"url\":\"https://support.xyz.com/en-us\"}],\"resolved\":false,\"time\":1741874017429,\"type\":\"controller\",\"vendor\":\"ABB\",\"zones\":[\"Production_B\"]}",
        "start": "1970-01-01T00:00:00.000Z",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "The product cannot be updated or patched in order to remove vulnerabilities or significant bugs.",
    "nozomi_networks": {
        "node_cve": {
            "asset_id": "7d2fd56b-f3e2-4afd-8d3e-9b7480ab6f7d",
            "cve": "CVE-EOL",
            "cve_creation_time": "1970-01-01T00:00:00.000Z",
            "cve_score": 10,
            "cve_summary": "The product cannot be updated or patched in order to remove vulnerabilities or significant bugs.",
            "cve_update_time": "1970-01-01T00:00:00.000Z",
            "cwe_id": "CWE-1329",
            "cwe_name": "Reliance on Component That is Not Updatable",
            "firmware_version": "5.1.100.13                                 :)",
            "id": "4c26-b605-be03f2b5b629",
            "is_kev": false,
            "likelihood": 1,
            "matching_cpes": [
                "cpe:/o:microsoft:windows_xp:-:-:-"
            ],
            "name": "HMI-A101",
            "nodes_ip": [
                "1.128.0.0"
            ],
            "os": "Firmware: 5.1.100.13                                 :)",
            "probability": "Confirmed",
            "product_name": "AC 800M PM851",
            "record_created_at": "2025-03-13T13:53:37.431Z",
            "references": [
                {
                    "reference_type": "Vendor Advisory",
                    "source": "product-security@xyz.com",
                    "url": "https://support.xyz.com/en-us"
                }
            ],
            "resolved": false,
            "time": "2025-03-13T13:53:37.429Z",
            "type": "controller",
            "vendor": "ABB",
            "zones": [
                "Production_B"
            ]
        }
    },
    "related": {
        "ip": [
            "1.128.0.0"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "nozomi_networks-node_cve"
    ],
    "vulnerability": {
        "category": [
            "Reliance on Component That is Not Updatable"
        ],
        "description": "The product cannot be updated or patched in order to remove vulnerabilities or significant bugs.",
        "enumeration": "CVE",
        "id": "CVE-EOL",
        "published_date": "1970-01-01T00:00:00.000Z",
        "reference": [
            "https://www.cve.org/CVERecord?id=CVE-EOL",
            "https://support.xyz.com/en-us"
        ],
        "scanner": {
            "vendor": [
                "product-security@xyz.com"
            ]
        },
        "score": {
            "base": 10
        }
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| nozomi_networks.node_cve.appliance_host | Host name of the Nozomi Networks sensor where the Common Vulnerabilities and Exposures (CVE) entry is hosted. | keyword |
| nozomi_networks.node_cve.appliance_id | Identifier (ID) of the Nozomi Networks sensor where the CVE entry is hosted. | keyword |
| nozomi_networks.node_cve.appliance_ip | Internet protocol (IP) address of the Nozomi Networks sensor where the CVE entry is hosted. | ip |
| nozomi_networks.node_cve.asset_id | ID of the vulnerable asset. | keyword |
| nozomi_networks.node_cve.cve | CVE ID. | keyword |
| nozomi_networks.node_cve.cve_creation_time | Timestamp for creation of the vulnerability. | date |
| nozomi_networks.node_cve.cve_epss_score |  | double |
| nozomi_networks.node_cve.cve_references | List of references to external websites providing extra information about the vulnerability. | flattened |
| nozomi_networks.node_cve.cve_score | CVSS (Common Vulnerability Scoring System) score assigned to this CVE. | double |
| nozomi_networks.node_cve.cve_source | Entity that provided the original information about the vulnerability. | keyword |
| nozomi_networks.node_cve.cve_summary | Description of the vulnerability. | keyword |
| nozomi_networks.node_cve.cve_update_time | Timestamp for when this vulnerability was last updated. | date |
| nozomi_networks.node_cve.cwe_id | Vulnerability category ID. | keyword |
| nozomi_networks.node_cve.cwe_name | Vulnerability category name. | keyword |
| nozomi_networks.node_cve.firmware_version |  | keyword |
| nozomi_networks.node_cve.id | Primary key for this query source. | keyword |
| nozomi_networks.node_cve.installed_on | (For internal use). | keyword |
| nozomi_networks.node_cve.is_kev |  | boolean |
| nozomi_networks.node_cve.latest_hotfix | Latest and most complete hotfix to install to solve the related CVE (only relevant for Microsoft Windows assets). | keyword |
| nozomi_networks.node_cve.likelihood | Value between 0.1 and 1.0, where 1.0 represents the maximum likelihood that the CVE is present. | double |
| nozomi_networks.node_cve.matching_cpes | List of CPEs that lead to assigning the vulnerability to this node. | keyword |
| nozomi_networks.node_cve.minimum_hotfix | Minimum hotfix to install to solve the related CVE (only relevant for Microsoft Windows assets). | keyword |
| nozomi_networks.node_cve.name |  | keyword |
| nozomi_networks.node_cve.node_firmware_version | Firmware version of the vulnerable node. | keyword |
| nozomi_networks.node_cve.node_id | Node ID for the referenced CVE. | keyword |
| nozomi_networks.node_cve.node_label | Label of the vulnerable node. | keyword |
| nozomi_networks.node_cve.node_os | Operating system of the vulnerable node. | keyword |
| nozomi_networks.node_cve.node_product_name | Product name of the vulnerable node. | keyword |
| nozomi_networks.node_cve.node_type | Type of the vulnerable node. | keyword |
| nozomi_networks.node_cve.node_vendor | Vendor of the vulnerable node. | keyword |
| nozomi_networks.node_cve.nodes_hosts |  | keyword |
| nozomi_networks.node_cve.nodes_ip |  | ip |
| nozomi_networks.node_cve.os |  | keyword |
| nozomi_networks.node_cve.probability |  | keyword |
| nozomi_networks.node_cve.product_name |  | keyword |
| nozomi_networks.node_cve.record_created_at |  | date |
| nozomi_networks.node_cve.references.name |  | keyword |
| nozomi_networks.node_cve.references.reference_type |  | keyword |
| nozomi_networks.node_cve.references.source |  | keyword |
| nozomi_networks.node_cve.references.url |  | keyword |
| nozomi_networks.node_cve.resolution_reason | Specifies the possible resolution reason for a vulnerability. | keyword |
| nozomi_networks.node_cve.resolved | Whether or not the vulnerability has been resolved by an installed patch (only relevant for Microsoft Windows assets). | boolean |
| nozomi_networks.node_cve.resolved_source | Specifies the data source from which the resolution status’ related information could be retrieved (only relevant for Microsoft Windows assets). | keyword |
| nozomi_networks.node_cve.time | Timestamp (in epoch milliseconds) at which the vulnerability has been found on the network node in the user's environment. | date |
| nozomi_networks.node_cve.type |  | keyword |
| nozomi_networks.node_cve.vendor |  | keyword |
| nozomi_networks.node_cve.zone | Network zone to which the vulnerable node belongs. | keyword |
| nozomi_networks.node_cve.zones |  | keyword |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |
| vulnerability.published_date |  | date |


### Session

This is the `Session` dataset.

#### Example

An example event for `session` looks as following:

```json
{
    "@timestamp": "2025-04-29T20:04:04.875Z",
    "agent": {
        "ephemeral_id": "227f705f-7a3c-4a8e-9f71-dd5a4549d644",
        "id": "8deb54fa-cc50-4df1-b80e-e058e6bf4674",
        "name": "elastic-agent-73169",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "nozomi_networks.session",
        "namespace": "85617",
        "type": "logs"
    },
    "destination": {
        "geo": {
            "continent_name": "Europe",
            "country_iso_code": "NO",
            "country_name": "Norway",
            "location": {
                "lat": 62,
                "lon": 10
            }
        },
        "ip": "2a02:cf41:abcd::1234",
        "port": 5355
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "8deb54fa-cc50-4df1-b80e-e058e6bf4674",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "nozomi_networks.session",
        "end": "2025-04-29T20:04:04.875Z",
        "id": "5514f626-10d8-476e-a9ad-d06eef56e5eb",
        "ingested": "2025-06-11T12:12:11Z",
        "kind": "event",
        "original": "{\"bpf_filter\":\"ip6 host 2a02:cf40:: and ip6 host 2a02:cf41:abcd::1234 and udp port 49740 and udp port 5355\",\"direction_is_known\":true,\"first_activity_time\":\"1745957044874\",\"from\":\"2a02:cf40::\",\"from_port\":\"49740\",\"from_zone\":\"Undefined\",\"id\":\"5514f626-10d8-476e-a9ad-d06eef56e5eb\",\"is_broadcast\":false,\"is_from_public\":false,\"is_to_public\":false,\"key\":\"2a02:cf41:abcd::1234;5355;2a02:cf40::;49740;udp;56710\",\"last_activity_time\":1745957044875,\"protocol\":\"llmnr\",\"status\":\"ACTIVE\",\"throughput_speed\":0,\"to\":\"2a02:cf41:abcd::1234\",\"to_port\":\"5355\",\"to_zone\":\"Undefined\",\"transferred.avg_packet_bytes\":90,\"transferred.biggest_packet_bytes\":\"90\",\"transferred.bytes\":\"90\",\"transferred.last_15m_bytes\":\"90\",\"transferred.last_30m_bytes\":\"90\",\"transferred.last_5m_bytes\":\"90\",\"transferred.packets\":\"1\",\"transferred.smallest_packet_bytes\":\"90\",\"transport_protocol\":\"udp\",\"vlan_id\":\"100\"}",
        "start": "2025-04-29T20:04:04.874Z",
        "type": [
            "connection"
        ]
    },
    "input": {
        "type": "cel"
    },
    "network": {
        "bytes": 90,
        "packets": 1,
        "transport": "udp",
        "vlan": {
            "id": "100"
        }
    },
    "nozomi_networks": {
        "session": {
            "bpf_filter": "ip6 host 2a02:cf40:: and ip6 host 2a02:cf41:abcd::1234 and udp port 49740 and udp port 5355",
            "direction_is_known": true,
            "first_activity_time": "2025-04-29T20:04:04.874Z",
            "from_ip": "2a02:cf40::",
            "from_port": 49740,
            "from_zone": "Undefined",
            "id": "5514f626-10d8-476e-a9ad-d06eef56e5eb",
            "is_broadcast": false,
            "is_from_public": false,
            "is_to_public": false,
            "key": "2a02:cf41:abcd::1234;5355;2a02:cf40::;49740;udp;56710",
            "last_activity_time": "2025-04-29T20:04:04.875Z",
            "protocol": "llmnr",
            "status": "ACTIVE",
            "throughput_speed": 0,
            "to_ip": "2a02:cf41:abcd::1234",
            "to_port": 5355,
            "to_zone": "Undefined",
            "transferred": {
                "avg_packet_bytes": 90,
                "biggest_packet_bytes": 90,
                "bytes": 90,
                "last_15m_bytes": 90,
                "last_30m_bytes": 90,
                "last_5m_bytes": 90,
                "packets": 1,
                "smallest_packet_bytes": 90
            },
            "transport_protocol": "udp",
            "vlan_id": "100"
        }
    },
    "related": {
        "ip": [
            "2a02:cf40::",
            "2a02:cf41:abcd::1234"
        ]
    },
    "source": {
        "geo": {
            "continent_name": "Europe",
            "country_iso_code": "NO",
            "country_name": "Norway",
            "location": {
                "lat": 62,
                "lon": 10
            }
        },
        "ip": "2a02:cf40::",
        "port": 49740
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "nozomi_networks-session"
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| nozomi_networks.session.bpf_filter | Berkeley Packet Filter (BPF) filter for the entity, used when performing traces for this entity. | keyword |
| nozomi_networks.session.direction_is_known | True if the session direction has been discovered. If false, from and to may be swapped. | boolean |
| nozomi_networks.session.first_activity_time | Timestamp in epoch milliseconds when this session was found for the first time. | date |
| nozomi_networks.session.from | Client node id. | keyword |
| nozomi_networks.session.from_ip | Client node id. | ip |
| nozomi_networks.session.from_port | Port on the client side. | long |
| nozomi_networks.session.from_zone | Client zone. | keyword |
| nozomi_networks.session.id | Primary key of this query source. | keyword |
| nozomi_networks.session.is_broadcast |  | boolean |
| nozomi_networks.session.is_from_public |  | boolean |
| nozomi_networks.session.is_to_public |  | boolean |
| nozomi_networks.session.key |  | keyword |
| nozomi_networks.session.last_activity_time | Timestamp in epoch milliseconds when this session was detected for the last time. | date |
| nozomi_networks.session.protocol | The protocol in which this entity has been observed. | keyword |
| nozomi_networks.session.status | Tells if the session is ACTIVE, CLOSED, SYN, SYN-ACK. | keyword |
| nozomi_networks.session.throughput_speed | Live throughput for the entity. | double |
| nozomi_networks.session.to | Server node id. | keyword |
| nozomi_networks.session.to_ip | Server node id. | ip |
| nozomi_networks.session.to_port | Port on the server side. | long |
| nozomi_networks.session.to_zone | Server zone. | keyword |
| nozomi_networks.session.transferred.avg_packet_bytes | Average packet size in bytes observed. | double |
| nozomi_networks.session.transferred.biggest_packet_bytes | Biggest packet size in bytes observed. | long |
| nozomi_networks.session.transferred.bytes | Total number of bytes transmitted. | long |
| nozomi_networks.session.transferred.last_15m_bytes | Number of bytes transmitted in the last 15 minutes. | long |
| nozomi_networks.session.transferred.last_30m_bytes | Number of bytes transmitted in the last 30 minutes. | long |
| nozomi_networks.session.transferred.last_5m_bytes | Number of bytes transmitted in the last 5 minutes. | long |
| nozomi_networks.session.transferred.packets | Total number of packets transmitted. | long |
| nozomi_networks.session.transferred.smallest_packet_bytes | Smallest packet size in bytes observed. | long |
| nozomi_networks.session.transport_protocol | Transport protocol of the session. | keyword |
| nozomi_networks.session.vlan_id | The virtual local area network (VLAN) identifier (ID) of the session. It can be absent if the traffic of the session is not VLAN-tagged. | keyword |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |


### Variable

This is the `Variable` dataset.

#### Example

An example event for `variable` looks as following:

```json
{
    "@timestamp": "2025-06-05T12:45:38.000Z",
    "agent": {
        "ephemeral_id": "96b7de3f-4d1d-4237-ae4e-37e8af5ae151",
        "id": "354560f6-d5e5-4795-82d3-4d6a1ac74f15",
        "name": "elastic-agent-88673",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "nozomi_networks.variable",
        "namespace": "75267",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "354560f6-d5e5-4795-82d3-4d6a1ac74f15",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "nozomi_networks.variable",
        "end": "2025-04-13T23:10:07.741Z",
        "id": "e77d717d-4306-49af-9bfe-d49f81aebcef",
        "ingested": "2025-06-18T06:48:08Z",
        "kind": "event",
        "original": "{\"active_checks\":[],\"bit_value\":\"00111011011111000000000000000000\",\"changes_count\":\"4\",\"first_activity_time\":\"1741870170944\",\"flow_anomalies\":\"0\",\"flow_anomaly_in_progress\":false,\"flow_hiccups_percent\":\"0\",\"flow_stats.avg\":300005.2765957447,\"flow_stats.var\":224189.0462307355,\"flow_status\":\"CYCLIC\",\"history_status\":false,\"host\":\"1.128.0.0\",\"host_label\":\"plc095.ACME0.corporationnet.com\",\"id\":\"e77d717d-4306-49af-9bfe-d49f81aebcef\",\"is_numeric\":true,\"label\":\"ioa-2-206 at 6913\",\"last_activity_time\":\"1744585807741\",\"last_cause\":\"read:event\",\"last_client\":\"89.160.20.112\",\"last_function_code\":\"9\",\"last_function_code_info\":\"M_ME_NA_1: Measured value, normalized value\",\"last_range_change_time\":\"1741870170944\",\"last_update_time\":\"1741982102719\",\"last_valid_quality_time\":\"1744585807741\",\"last_value\":0.01318359375,\"last_value_is_valid\":true,\"last_value_quality\":[\"invalid\"],\"latest_bit_change\":\"Bit 5 changed from 0 to 1\",\"max_value\":\"0.013184\",\"min_value\":\"0.013184\",\"name\":\"ioa-2-206\",\"namespace\":\"6913\",\"offset\":\"0.000000\",\"protocol\":\"iec104\",\"record_created_at\":1749127538000,\"request_count\":\"9032\",\"scale\":\"1.000000\",\"type\":\"analog\",\"unit\":\"n/a\",\"value\":0.003814697265625,\"var_key\":\"1.128.0.0/6913/ioa-2-206\"}",
        "start": "2025-03-13T12:49:30.944Z",
        "type": [
            "info"
        ]
    },
    "host": {
        "ip": [
            "1.128.0.0"
        ],
        "name": "plc095.ACME0.corporationnet.com"
    },
    "input": {
        "type": "cel"
    },
    "nozomi_networks": {
        "variable": {
            "bit_value": "00111011011111000000000000000000",
            "changes_count": 4,
            "first_activity_time": "2025-03-13T12:49:30.944Z",
            "flow_anomalies": "0",
            "flow_anomaly_in_progress": false,
            "flow_hiccups_percent": 0,
            "flow_stats": {
                "avg": 300005.2765957447,
                "var": 224189.0462307355
            },
            "flow_status": "CYCLIC",
            "history_status": false,
            "host_ip": "1.128.0.0",
            "host_label": "plc095.ACME0.corporationnet.com",
            "id": "e77d717d-4306-49af-9bfe-d49f81aebcef",
            "is_numeric": true,
            "label": "ioa-2-206 at 6913",
            "last_activity_time": "2025-04-13T23:10:07.741Z",
            "last_cause": "read:event",
            "last_client_ip": "89.160.20.112",
            "last_function_code": "9",
            "last_function_code_info": "M_ME_NA_1: Measured value, normalized value",
            "last_range_change_time": "2025-03-13T12:49:30.944Z",
            "last_update_time": "2025-03-14T19:55:02.719Z",
            "last_valid_quality_time": "2025-04-13T23:10:07.741Z",
            "last_value": 0.01318359375,
            "last_value_is_valid": true,
            "last_value_quality": [
                "invalid"
            ],
            "latest_bit_change": "Bit 5 changed from 0 to 1",
            "max_value": "0.013184",
            "min_value": "0.013184",
            "name": "ioa-2-206",
            "namespace": "6913",
            "offset": "0.000000",
            "protocol": "iec104",
            "record_created_at": "2025-06-05T12:45:38.000Z",
            "request_count": 9032,
            "scale": "1.000000",
            "type": "analog",
            "unit": "n/a",
            "value": 0.003814697265625,
            "var_key": "1.128.0.0/6913/ioa-2-206"
        }
    },
    "related": {
        "hosts": [
            "plc095.ACME0.corporationnet.com"
        ],
        "ip": [
            "1.128.0.0",
            "89.160.20.112"
        ]
    },
    "source": {
        "as": {
            "number": 29518,
            "organization": {
                "name": "Bredband2 AB"
            }
        },
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "ip": "89.160.20.112"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "nozomi_networks-variable"
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
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| nozomi_networks.variable.active_checks | List of active real-time checks on the entity. | keyword |
| nozomi_networks.variable.bit_value | The live, last observed value of the variable, expressed in bits. Upon restart, this value is unknown because it needs to reflect the real time status. | keyword |
| nozomi_networks.variable.changes_count | The number of times this variable has changed. | long |
| nozomi_networks.variable.first_activity_time | Timestamp in epoch milliseconds when this variable was found for the first time. | date |
| nozomi_networks.variable.flow_anomalies | Reports anomalies in the flow, if any. | keyword |
| nozomi_networks.variable.flow_anomaly_in_progress | Reports a flow anomaly is in progress or not. | boolean |
| nozomi_networks.variable.flow_hiccups_percent | Shows the amount if hiccups in the flow. | double |
| nozomi_networks.variable.flow_stats.avg | Shows the average access time. | double |
| nozomi_networks.variable.flow_stats.var | Shows the variance of the access time. | double |
| nozomi_networks.variable.flow_status | Tells the status of the flow, that is if the variable has a cyclic behavior or not. | keyword |
| nozomi_networks.variable.history_status | Tells if the history is eanbled or not on this variable. | boolean |
| nozomi_networks.variable.host |  | keyword |
| nozomi_networks.variable.host_ip | The node to which this variable belongs to. | ip |
| nozomi_networks.variable.host_label | The label of the node to which this variable belongs to. | keyword |
| nozomi_networks.variable.id |  | keyword |
| nozomi_networks.variable.is_numeric | True if it represents a number. | boolean |
| nozomi_networks.variable.label | The human-readable name of the variable. | keyword |
| nozomi_networks.variable.last_activity_time | Timestamp in epoch milliseconds when this variable was detected for the last time. | date |
| nozomi_networks.variable.last_cause | The cause of the last value. | keyword |
| nozomi_networks.variable.last_client_host | The last node that accessed this variable (in read or write mode). | keyword |
| nozomi_networks.variable.last_client_ip |  | ip |
| nozomi_networks.variable.last_function_code | The last value function code. | keyword |
| nozomi_networks.variable.last_function_code_info | The last value function code information. | keyword |
| nozomi_networks.variable.last_range_change_time | Timestamp in epoch milliseconds when this variable's range changed. | date |
| nozomi_networks.variable.last_update_time | Timestamp in epoch milliseconds of the last valid quality. | date |
| nozomi_networks.variable.last_valid_quality_time | Timestamp in epoch milliseconds of the last time quality was valid. | date |
| nozomi_networks.variable.last_value | This is the last observed value, and is persisted on reboots. | double |
| nozomi_networks.variable.last_value_is_valid | True if the last value is valid (has valid quality). | boolean |
| nozomi_networks.variable.last_value_quality | The quality of the last value. | keyword |
| nozomi_networks.variable.latest_bit_change | Indices of the flipped bits during the latest variable change. | keyword |
| nozomi_networks.variable.max_value | The maximum observed value. | keyword |
| nozomi_networks.variable.min_value | The minimum observed value. | keyword |
| nozomi_networks.variable.name | The name of the variable, likely an identifier of the memory area. | keyword |
| nozomi_networks.variable.namespace | It is the identifier of the subsystem in the producer to which the variable belongs. Also known as the remote terminal unit (RTU) identifier (ID) of the variable. | keyword |
| nozomi_networks.variable.offset | The offset of the variable. | keyword |
| nozomi_networks.variable.protocol | The protocol in which this entity has been observed. | keyword |
| nozomi_networks.variable.record_created_at |  | date |
| nozomi_networks.variable.request_count | The number of times this variable has been accessed. | long |
| nozomi_networks.variable.scale | The scale of the variable. | keyword |
| nozomi_networks.variable.type | The type of the value of the variable. | keyword |
| nozomi_networks.variable.unit | The unit for the value of the variable. | keyword |
| nozomi_networks.variable.value | The live, last observed value of the variable. Upon restart, this value is unknown because it needs to reflect the real time status. | double |
| nozomi_networks.variable.var_key | The primary key of this data source. | keyword |
| observer.product |  | constant_keyword |
| observer.vendor |  | constant_keyword |
