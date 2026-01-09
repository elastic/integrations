# Claroty xDome

[Claroty xDome](https://claroty.com/industrial-cybersecurity/xdome) is a modular, SaaS-powered industrial cybersecurity platform designed to protect cyber-physical systems (CPS) in industrial, healthcare, and commercial environments, offering features like asset discovery, exposure management, network protection, threat detection, and secure access.

Use this integration to collect and parse data from your Claroty xDome instance.

## Compatibility

This module has been tested against the Claroty xDome API version **v1**.

## Data streams

The Claroty xDome integration collects three types of logs.

- **Alerts** - Retrieves alerts and their affected devices from Claroty xDome.
- **Events** - Collects events related to Operational Technology activities.
- **Vulnerabilities** - Retrieves vulnerabilities and their affected devices from Claroty xDome.

**NOTE:**

1. The **alert data stream** combines data from the alerts and affected devices endpoints using a chain call. It first retrieves all alerts and then fetches affected devices for each alert ID.

2. The **vulnerability data stream** follows the same approach, retrieving vulnerabilities first and then fetching affected devices for each vulnerability ID.

3. A **data count mismatch** may appear in the **Discover** page for the vulnerability data stream. This occurs because the API retrieves data beyond the current date, while the **Elastic Agent** fetches only up-to-date data during the initial call. The missing data will appear in **Kibana** after the next interval's call.

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect logs through REST API

Login to your Claroty xDome portal, create an API user from **Admin Settings** > **User Management**, and generate an API token.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Claroty xDome**.
3. Select the **Claroty xDome** integration and add it.
4. Add all the required integration configuration parameters, including the URL, API token to enable data collection.
5. Save the integration.

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

An example event for `alert` looks as following:

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2025-03-28T03:07:32.195Z",
    "agent": {
        "ephemeral_id": "d49a05fb-334c-4caf-9829-f048f1f8cf13",
        "id": "df132eff-67ec-4c89-aff4-235636e3a8c5",
        "name": "elastic-agent-95703",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "claroty_xdome": {
        "alert": {
            "category": "Risk",
            "class": "Pre-Defined Alerts",
            "description": "46 Zebra Technologies ZT410 Mobile Printer have been detected that will enter the End-of-Life state in 09/01/25",
            "detected_time": "2025-03-28T03:07:32.195Z",
            "device": {
                "activity_rate": 67,
                "applied_acl": {
                    "list": [
                        "Claroty_ZT410_Wired_Access"
                    ],
                    "type_list": [
                        "Cisco dACL"
                    ]
                },
                "asset_id": "JAKBHWV",
                "assignees": [
                    "Sergei Ridkey"
                ],
                "assignees_data": [
                    {
                        "display_name": "Sergei Ridkey",
                        "id": "sergei.r",
                        "is_active": true,
                        "type": "user"
                    }
                ],
                "authentication_user_list": [
                    "00-0C-C6-01-37-B10"
                ],
                "avg": {
                    "online_per_day": 16.2
                },
                "category": "IoT",
                "collection": {
                    "interfaces": {
                        "seen_reported_from": [
                            "ens142@demo-collection-sv_1",
                            "ens192@demo-collection-sv_1",
                            "ens192@demo-collection-sv_2"
                        ]
                    },
                    "servers": {
                        "seen_reported_from": [
                            "demo-collection-sv_1",
                            "demo-collection-sv_2"
                        ]
                    }
                },
                "combined_os": "Proprietary Link-OS 4",
                "connection": {
                    "type_list": [
                        "Ethernet"
                    ]
                },
                "data_sources_seen_reported_from": [
                    "Passive Collection",
                    "Integration"
                ],
                "effective_likelihood_subscore": {
                    "points": 27.971817,
                    "value": "Very Low"
                },
                "end_of": {
                    "life": {
                        "date": "2025-09-01T00:00:00.000Z",
                        "state": "End-Of-Life Notification"
                    }
                },
                "financial_cost": "$10,000-$100,000",
                "first_seen_list": [
                    "2024-11-23T05:22:38.150Z"
                ],
                "handles_pii": "Yes",
                "impact_subscore": {
                    "points": 53.3,
                    "value": "Medium"
                },
                "insecure_protocols": {
                    "points": 0,
                    "value": "Very Low"
                },
                "integration_types_reported_from": [
                    "Cisco ISE"
                ],
                "integrations_reported_from": [
                    "Cisco ISE (Cisco ISE)"
                ],
                "internet_communication": "Yes",
                "ip": {
                    "assignment_list": [
                        "DHCP"
                    ],
                    "list": [
                        "1.128.0.0"
                    ],
                    "value": "1.128.0.0"
                },
                "is_online": false,
                "is_resolved": false,
                "ise": {
                    "authentication_method_list": [
                        "mab"
                    ],
                    "security_group": {
                        "description_list": [
                            "Printers Group - Exported from xDome"
                        ],
                        "name_list": [
                            "Printers_sgt"
                        ],
                        "tag_list": [
                            "4"
                        ]
                    }
                },
                "known_vulnerabilities": {
                    "points": 18.98562,
                    "value": "Low"
                },
                "labels": [
                    "Exposed & EOL Asset",
                    "Exposed EOL Asset",
                    "OT Internet Klabin",
                    "SL1_Win 7 EWS with Critical KVs"
                ],
                "last": {
                    "seen": {
                        "list": [
                            "2025-02-09T00:30:28.150Z"
                        ],
                        "on_switch_list": [
                            "2025-03-09T09:42:01.150Z"
                        ],
                        "reported": "2025-02-09T00:30:28.150Z"
                    }
                },
                "likelihood_subscore": {
                    "points": 63.57231,
                    "value": "High"
                },
                "mac": {
                    "list": [
                        "00:07:4d:c1:06:20"
                    ],
                    "oui_list": [
                        "Zebra Technologies Corp."
                    ]
                },
                "machine_type": "Physical",
                "manufacturer": "Zebra Technologies",
                "model": {
                    "name": "ZT410"
                },
                "network": {
                    "scope_list": [
                        "Default"
                    ]
                },
                "network_list": [
                    "Industrial"
                ],
                "number_of_nics": 1,
                "organization": {
                    "firewall_group_name": "No Zone"
                },
                "os": {
                    "category": "Proprietary",
                    "name": "Proprietary",
                    "revision": "4",
                    "subcategory": "Link-OS",
                    "version": "Link-OS"
                },
                "purdue_level": {
                    "source": "Auto-Assigned",
                    "value": "Level 3"
                },
                "recommended": {
                    "firewall_group_name": "Printers"
                },
                "retired": {
                    "value": false
                },
                "risk_score": {
                    "points": 38.10309,
                    "value": "Low"
                },
                "serial_number": "18J171636094",
                "site": {
                    "group_name": "No Group",
                    "name": "SV_1"
                },
                "software_or_firmware_version": "V75.20.01Z",
                "subcategory": "General IoT",
                "switch": {
                    "location_list": [
                        "dep JzkRK"
                    ],
                    "mac_list": [
                        "00:12:00:36:4e:5f"
                    ],
                    "port_list": [
                        "Fa/1/12"
                    ]
                },
                "type": {
                    "family": "Mobile Printer",
                    "value": "Mobile Printer"
                },
                "uid": "010510c5-fffd-4aa6-9bc5-51c1c79fa21e",
                "utilization_rate": 0,
                "visibility_score": {
                    "level": "Excellent",
                    "value": 99
                },
                "vlan": {
                    "description_list": [
                        "Bldg1-Flr3"
                    ],
                    "list": [
                        "103"
                    ],
                    "name_list": [
                        "Bldg1-Flr3"
                    ]
                }
            },
            "devices_count": 1,
            "friendly_name": "Device End-of-Life: ZT410",
            "id": "1",
            "iot_devices_count": 46,
            "it_devices_count": 0,
            "medical_devices_count": 0,
            "name": "Device End-of-Life: ZT410",
            "ot_devices_count": 0,
            "status": "Unresolved",
            "type_name": "Device End-of-Life",
            "unresolved_devices_count": 46,
            "updated_time": "2025-03-28T03:07:32.195Z"
        }
    },
    "data_stream": {
        "dataset": "claroty_xdome.alert",
        "namespace": "28431",
        "type": "logs"
    },
    "device": {
        "manufacturer": "Zebra Technologies",
        "model": {
            "identifier": "ZT410"
        },
        "serial_number": "18J171636094"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "df132eff-67ec-4c89-aff4-235636e3a8c5",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "action": "device-endoflife-zt410",
        "agent_id_status": "verified",
        "dataset": "claroty_xdome.alert",
        "ingested": "2025-04-21T11:28:15Z",
        "kind": "alert",
        "original": "{\"activity_rate\":67,\"alert_info\":{\"alert_class\":\"Pre-Defined Alerts\",\"alert_name\":\"Device End-of-Life: ZT410\",\"alert_type_name\":\"Device End-of-Life\",\"category\":\"Risk\",\"description\":\"46 Zebra Technologies ZT410 Mobile Printer have been detected that will enter the End-of-Life state in 09/01/25\",\"detected_time\":\"2025-03-28T03:07:32.195965Z\",\"devices_count\":1,\"id\":1,\"iot_devices_count\":46,\"it_devices_count\":0,\"malicious_ip_tags_list\":null,\"medical_devices_count\":0,\"ot_devices_count\":0,\"status\":\"Unresolved\",\"unresolved_devices_count\":46,\"updated_time\":\"2025-03-28T03:07:32.195965Z\"},\"applied_acl_list\":[\"Claroty_ZT410_Wired_Access\"],\"applied_acl_type_list\":[\"Cisco dACL\"],\"asset_id\":\"JAKBHWV\",\"assignees\":[\"Sergei Ridkey\"],\"assignees_data\":[{\"display_name\":\"Sergei Ridkey\",\"id\":\"sergei.r\",\"is_active\":true,\"type\":\"user\"}],\"authentication_user_list\":[\"00-0C-C6-01-37-B10\"],\"avg_online_per_day\":16.2,\"collection_interfaces_seen_reported_from\":[\"ens142@demo-collection-sv_1\",\"ens192@demo-collection-sv_1\",\"ens192@demo-collection-sv_2\"],\"collection_servers_seen_reported_from\":[\"demo-collection-sv_1\",\"demo-collection-sv_2\"],\"combined_os\":\"Proprietary Link-OS 4\",\"connection_type_list\":[\"Ethernet\"],\"data_sources_seen_reported_from\":[\"Passive Collection\",\"Integration\"],\"device_category\":\"IoT\",\"device_name\":\"1.128.0.0\",\"device_subcategory\":\"General IoT\",\"device_type\":\"Mobile Printer\",\"device_type_family\":\"Mobile Printer\",\"dhcp_fingerprint\":null,\"dhcp_last_seen_hostname\":null,\"domains\":[],\"effective_likelihood_subscore\":\"Very Low\",\"effective_likelihood_subscore_points\":27.971817,\"end_of_life_date\":\"2025-09-01\",\"end_of_life_state\":\"End-Of-Life Notification\",\"financial_cost\":\"$10,000-$100,000\",\"first_seen_list\":[\"2024-11-23T05:22:38.150546+00:00\"],\"handles_pii\":\"Yes\",\"http_hostnames\":[],\"impact_subscore\":\"Medium\",\"impact_subscore_points\":53.3,\"insecure_protocols\":\"Very Low\",\"insecure_protocols_points\":0,\"integration_types_reported_from\":[\"Cisco ISE\"],\"integrations_reported_from\":[\"Cisco ISE (Cisco ISE)\"],\"internet_communication\":\"Yes\",\"ip_assignment_list\":[\"DHCP\"],\"ip_list\":[\"1.128.0.0\"],\"is_online\":false,\"is_resolved\":false,\"ise_authentication_method_list\":[\"mab\"],\"ise_security_group_description_list\":[\"Printers Group - Exported from xDome\"],\"ise_security_group_name_list\":[\"Printers_sgt\"],\"ise_security_group_tag_list\":[4],\"known_vulnerabilities\":\"Low\",\"known_vulnerabilities_points\":18.98562,\"labels\":[\"Exposed \\u0026 EOL Asset\",\"Exposed EOL Asset\",\"OT Internet Klabin\",\"SL1_Win 7 EWS with Critical KVs\"],\"last_seen_list\":[\"2025-02-09T00:30:28.150546+00:00\"],\"last_seen_on_switch_list\":[\"2025-03-09T09:42:01.150629+00:00\"],\"last_seen_reported\":\"2025-02-09T00:30:28.150546+00:00\",\"likelihood_subscore\":\"High\",\"likelihood_subscore_points\":63.57231,\"local_name\":null,\"mac_list\":[\"00:07:4d:c1:06:20\"],\"mac_oui_list\":[\"Zebra Technologies Corp.\"],\"machine_type\":\"Physical\",\"manufacturer\":\"Zebra Technologies\",\"model\":\"ZT410\",\"network_list\":[\"Industrial\"],\"network_scope_list\":[\"Default\"],\"number_of_nics\":1,\"organization_firewall_group_name\":\"No Zone\",\"os_category\":\"Proprietary\",\"os_name\":\"Proprietary\",\"os_revision\":\"4\",\"os_subcategory\":\"Link-OS\",\"os_version\":\"Link-OS\",\"phi\":null,\"purdue_level\":\"Level 3\",\"purdue_level_source\":\"Auto-Assigned\",\"recommended_firewall_group_name\":\"Printers\",\"retired\":false,\"risk_score\":\"Low\",\"risk_score_points\":38.10309,\"serial_number\":\"18J171636094\",\"site_group_name\":\"No Group\",\"site_name\":\"SV_1\",\"software_or_firmware_version\":\"V75.20.01Z\",\"switch_location_list\":[\"dep JzkRK\"],\"switch_mac_list\":[\"00:12:00:36:4e:5f\"],\"switch_port_list\":[\"Fa/1/12\"],\"uid\":\"010510c5-fffd-4aa6-9bc5-51c1c79fa21e\",\"utilization_rate\":0,\"visibility_score\":99,\"visibility_score_level\":\"Excellent\",\"vlan_description_list\":[\"Bldg1-Flr3\"],\"vlan_list\":[103],\"vlan_name_list\":[\"Bldg1-Flr3\"]}",
        "risk_score": 38.10309,
        "severity": 21
    },
    "host": {
        "id": "010510c5-fffd-4aa6-9bc5-51c1c79fa21e",
        "ip": [
            "1.128.0.0"
        ],
        "mac": [
            "00-07-4D-C1-06-20"
        ],
        "os": {
            "family": "Proprietary",
            "full": "Proprietary Link-OS 4",
            "name": "Proprietary",
            "version": "Link-OS"
        },
        "type": "Mobile Printer"
    },
    "input": {
        "type": "cel"
    },
    "message": "46 Zebra Technologies ZT410 Mobile Printer have been detected that will enter the End-of-Life state in 09/01/25",
    "observer": {
        "ingress": {
            "vlan": {
                "id": [
                    "103"
                ],
                "name": [
                    "Bldg1-Flr3"
                ]
            }
        },
        "product": "xDome",
        "vendor": "Claroty"
    },
    "related": {
        "hosts": [
            "Proprietary Link-OS 4",
            "Proprietary",
            "SV_1",
            "010510c5-fffd-4aa6-9bc5-51c1c79fa21e"
        ],
        "ip": [
            "1.128.0.0"
        ],
        "user": [
            "Sergei Ridkey",
            "sergei.r"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "claroty_xdome-alert"
    ]
}
```

#### Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| claroty_xdome.alert.category | Alert category such as Risk or Segmentation. | keyword |
| claroty_xdome.alert.class | The alert class, such as Pre-Defined Alerts and Custom Alerts. | keyword |
| claroty_xdome.alert.description | The alert description, such as SMBv1 Communication was detected by 2 OT Device devices. | keyword |
| claroty_xdome.alert.detected_time | Date and time when the Alert was first detected. | date |
| claroty_xdome.alert.device.active_queries_seen_reported_from | The active query tasks the device was seen or reported from. | keyword |
| claroty_xdome.alert.device.activity_rate | The percentage of time the device was online within the past 90 days. | double |
| claroty_xdome.alert.device.ad.description | The Active Directory device description extracted from the Microsoft Active Directory integration. | keyword |
| claroty_xdome.alert.device.ad.distinguished_name | The Active Directory distinguished device name extracted from the Microsoft Active Directory integration. | keyword |
| claroty_xdome.alert.device.ae_titles | The unique identifier of imaging devices provided by the healthcare organization. | keyword |
| claroty_xdome.alert.device.ap.location_list | The location of the access point the device is connected to, extracted from Network Management integrations. | keyword |
| claroty_xdome.alert.device.ap.name_list | The name of the access point the device is connected to, extracted from Network Management integrations. | keyword |
| claroty_xdome.alert.device.applied_acl.list | The device's applied ACL (Access Control List) extracted from Cisco ISE, Aruba ClearPass, Cisco DNAC, or Cisco Prime integrations. | keyword |
| claroty_xdome.alert.device.applied_acl.type_list | The type of the Applied ACL (Access Control List) extracted from Cisco ISE, Aruba ClearPass, Cisco DNAC, or Cisco Prime integrations: Cisco dACL, ArubaOS-Switch, ArubaOS-CX, ArubaOS, Aruba Instant On, AireOS. | keyword |
| claroty_xdome.alert.device.asset_id | Asset ID. | keyword |
| claroty_xdome.alert.device.assignees | The users and or groups the device is assigned to. | keyword |
| claroty_xdome.alert.device.assignees_data.display_name |  | keyword |
| claroty_xdome.alert.device.assignees_data.id |  | keyword |
| claroty_xdome.alert.device.assignees_data.is_active |  | boolean |
| claroty_xdome.alert.device.assignees_data.type |  | keyword |
| claroty_xdome.alert.device.authentication_user_list | The User name used to authenticate the device to the network using Radius/802.1x is extracted from the NAC integration and the traffic. | keyword |
| claroty_xdome.alert.device.avg.examinations_per_day | The average daily number of examinations performed by the device within the selected time period, during the past 3 months. For Imaging Devices only. | double |
| claroty_xdome.alert.device.avg.in_use_per_day | The average daily hours the device was utilized within the selected time period, during the past 3 months. | double |
| claroty_xdome.alert.device.avg.online_per_day | The average daily hours the device was online within the selected time period, during the past 3 months. | double |
| claroty_xdome.alert.device.battery_level | The battery status of the device. Relevant to Infusion Pumps only. | keyword |
| claroty_xdome.alert.device.bssid_list | The MAC physical address of the access point the device is connected to. | keyword |
| claroty_xdome.alert.device.category | The device category group (see About Device Categorization in the Knowledge Base). | keyword |
| claroty_xdome.alert.device.cmms.asset.purchase_cost | The cost of the devices, as extracted from the CMMS platform. | double |
| claroty_xdome.alert.device.cmms.asset.tag | The designated identifier of the device as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.building | The building in which the device is located, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.campus | The site in which the device is located, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.department | The department of the device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.financial_cost |  | double |
| claroty_xdome.alert.device.cmms.floor | The floor in which the device is located, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.last_pm | The last preventative maintenance as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.location | The device location, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.manufacturer | Manufacturer of the device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.model | The model of the device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.ownership | The ownership type of the device, such as Directly Owned or Leased, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.owning_cost_center | The owning cost center of the device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.room | The room in which the device is located, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.serial_number | A unique identifier assigned to a device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.state | The status of the device, such as In Use or Retired, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.cmms.technician | The technician assigned to the device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.alert.device.collection.interfaces.seen_reported_from | The collection interfaces from which the device was seen or reported through passive collection. | keyword |
| claroty_xdome.alert.device.collection.interfaces.value |  | keyword |
| claroty_xdome.alert.device.collection.servers.seen_reported_from | The collection servers from which the device was seen or reported, either through passive collection or from active queries. | keyword |
| claroty_xdome.alert.device.collection.servers.value |  | keyword |
| claroty_xdome.alert.device.combined_os | The aggregated value of OS name, version and revision, such as Windows XP SP3. | keyword |
| claroty_xdome.alert.device.connection.paths | The connection path list describing the network path to a nested device. | keyword |
| claroty_xdome.alert.device.connection.type_list | The connection types of a device, such as Ethernet. | keyword |
| claroty_xdome.alert.device.consequence_of_failure | Determines the consequence of failure of the device, according to The Joint Commission (TJC). | keyword |
| claroty_xdome.alert.device.cppm.authentication_status_list | The device's Authentication Status extracted from the Aruba ClearPass integration. | keyword |
| claroty_xdome.alert.device.cppm.service_list | The device's Service extracted from the Aruba ClearPass integration. | keyword |
| claroty_xdome.alert.device.data_sources_seen_reported_from | The data sources that the device was seen on or reported from. | keyword |
| claroty_xdome.alert.device.dhcp.fingerprint | Summarized fingerprint of the device's different DHCP messages such as the message type, DHCP options used and DHCP vendor class. | keyword |
| claroty_xdome.alert.device.dhcp.hostnames |  | keyword |
| claroty_xdome.alert.device.dhcp.last_seen_hostname | The most recent unique hostname identifier of the device, extracted from DHCP protocol traffic. | keyword |
| claroty_xdome.alert.device.domains | The domain name of the network that the device belongs to. | keyword |
| claroty_xdome.alert.device.edge.hosts_seen_reported_from | The Device IDs of the Edge hosts where the device was seen or reported from. | keyword |
| claroty_xdome.alert.device.edge.locations |  | keyword |
| claroty_xdome.alert.device.edge.locations_seen_reported_from | The Edge locations associated with the Edge scans where the device was seen or reported. | keyword |
| claroty_xdome.alert.device.edr.is_up_to_date_text | Determines whether the endpoint security application installed on the device is up-to-date. | keyword |
| claroty_xdome.alert.device.edr.last_scan_time | Last date and time the device was scanned by the endpoint security application, extracted from Endpoint Security integrations. | date |
| claroty_xdome.alert.device.effective_likelihood_subscore.points | The calculated effective likelihood subscore points of a device, such as 54.1. | double |
| claroty_xdome.alert.device.effective_likelihood_subscore.value | The calculated effective likelihood subscore level of a device, such as Critical, or High. | keyword |
| claroty_xdome.alert.device.end_of.life.date | The date on which the manufacturer announced it would no longer sell, update, maintain or support the product. | date |
| claroty_xdome.alert.device.end_of.life.state | The phase the product is in within its life cycle, such as: End-Of-Life, End-Of-Life Notification, Or Manufacturer-Supported. | keyword |
| claroty_xdome.alert.device.end_of.sale_date | The date on which the manufacturer announced it will stop selling the product. | date |
| claroty_xdome.alert.device.endpoint_security_names | The names of endpoint security applications installed on the device. | keyword |
| claroty_xdome.alert.device.equipment_class | Determines the equipment class of the device, according to The Joint Commission (TJC). | keyword |
| claroty_xdome.alert.device.fda_class | The FDA class categorization of the device including Class 1, 2, 3 and Unclassified. The FDA class is only relevant to medical devices. | keyword |
| claroty_xdome.alert.device.financial_cost | The cost to purchase a new device. | keyword |
| claroty_xdome.alert.device.first_seen_list | The date and time a device's NIC was first seen. | date |
| claroty_xdome.alert.device.handles_pii | The device storage and transmission capabilities of Personal Identifiable Information. | keyword |
| claroty_xdome.alert.device.http.hostnames |  | keyword |
| claroty_xdome.alert.device.http.last_seen_hostname | The most recent unique hostname identifier of the device, extracted from HTTP protocol traffic. | keyword |
| claroty_xdome.alert.device.hw_version | The hardware version of the device. | keyword |
| claroty_xdome.alert.device.impact_subscore.points | The calculated active impact subscore points of a device, such as 54.1. | double |
| claroty_xdome.alert.device.impact_subscore.value | The calculated active impact subscore level of a device, such as Critical, or High. | keyword |
| claroty_xdome.alert.device.insecure_protocols.points | The calculated points for 'insecure protocols' likelihood factor of a device, such as 54.1. | double |
| claroty_xdome.alert.device.insecure_protocols.value | The calculated level of the device's 'insecure protocols' likelihood factor, such as Critical, or High. | keyword |
| claroty_xdome.alert.device.integration_types_reported_from | The Integration types the device was reported from. | keyword |
| claroty_xdome.alert.device.integrations_reported_from | The Integration names the device was reported from. | keyword |
| claroty_xdome.alert.device.internet_communication | The manner of the device's communication over the internet. | keyword |
| claroty_xdome.alert.device.ip.assignment_list | The device's IP assignment method, extracted from DHCP protocol traffic, such as DHCP, DHCP (Static Lease), or Static. | keyword |
| claroty_xdome.alert.device.ip.list | IP address associated with the device. IPs may be suffixed by a / (annotation), where annotation may be a child device ID or (Last Known IP). | ip |
| claroty_xdome.alert.device.ip.value | The Device Name attribute is set automatically based on the priority of the Auto-Assigned Device attribute. You can also set it manually. The Device Name can be the device's IP, hostname, etc. | ip |
| claroty_xdome.alert.device.is_online | A boolean field indicating whether the device is online or not. | boolean |
| claroty_xdome.alert.device.is_resolved | A boolean field indicating if the alert triggered for a device is resolved or unresolved. | boolean |
| claroty_xdome.alert.device.ise.authentication_method_list | The device's Authentication Method extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.alert.device.ise.endpoint_profile_list | The device's Endpoint Profile extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.alert.device.ise.identity_group_list | The device's Identity Group extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.alert.device.ise.logical_profile_list | The device's Logical Profile extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.alert.device.ise.security_group.description_list | The device's Security Group Description extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.alert.device.ise.security_group.name_list | The device's Security Group Name extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.alert.device.ise.security_group.tag_list | The device's Security Group Tag ID extracted from the Cisco ISE integration or Radius traffic. | keyword |
| claroty_xdome.alert.device.known_vulnerabilities.points | The calculated points for 'known vulnerabilities' likelihood factor of a device, such as 54.1. | double |
| claroty_xdome.alert.device.known_vulnerabilities.value | The calculated level of the device's 'known vulnerabilities' likelihood factor, such as Critical, or High. | keyword |
| claroty_xdome.alert.device.labels | The labels added to the device manually or automatically. | keyword |
| claroty_xdome.alert.device.last.scan_time | The last date and time the device was scanned by a Vulnerability Management platform, extracted from a Vulnerability Management integration. | date |
| claroty_xdome.alert.device.last.seen.list | The date and time a device's NIC was last seen. | date |
| claroty_xdome.alert.device.last.seen.on_switch_list | Last date and time the device was seen on the switch. | date |
| claroty_xdome.alert.device.last.seen.reported | The last date and time the device was either seen on the network or reported. The seen information is updated in real time. | date |
| claroty_xdome.alert.device.last_domain_user.activity | Last seen date and time of the last user logged in to the device, extracted from the Kerberos protocol or the Active Directory integration. | date |
| claroty_xdome.alert.device.last_domain_user.name | The last user seen logged in to the device, extracted from the Kerberos protocol or an Active Directory integration. | keyword |
| claroty_xdome.alert.device.likelihood_subscore.points | The calculated likelihood subscore points of a device, such as 54.1. | double |
| claroty_xdome.alert.device.likelihood_subscore.value | The calculated likelihood subscore level of a device, such as Critical, or High. | keyword |
| claroty_xdome.alert.device.local_name | Similar to hostname, the device name identifier is extracted from protocol traffic. | keyword |
| claroty_xdome.alert.device.mac.list | MAC address associated with the device. | keyword |
| claroty_xdome.alert.device.mac.oui_list | The vendor of the device's NIC, according to the OUI. | keyword |
| claroty_xdome.alert.device.machine_type | Identifies if device is physical or virtual. | keyword |
| claroty_xdome.alert.device.managed_by |  | keyword |
| claroty_xdome.alert.device.management_services | Defines whether the device is managed by Active Directory, Mobile Device Management, or neither. | keyword |
| claroty_xdome.alert.device.manufacturer | Manufacturer of the device, such as Alaris. | keyword |
| claroty_xdome.alert.device.mdm.compliance_status | The compliance status of the mobile device incorporated in the MDM platform, extracted from MDM integrations. | keyword |
| claroty_xdome.alert.device.mdm.enrollment_status | The enrollment status of the mobile device incorporated in the MDM platform, extracted from MDM integrations. | keyword |
| claroty_xdome.alert.device.mdm.ownership | The ownership of the mobile device incorporated in the MDM platform, extracted from MDM integrations. | keyword |
| claroty_xdome.alert.device.mobility | Identifies if device is stationary or portable. | keyword |
| claroty_xdome.alert.device.model.family | Identifies a series encompassing related models. | keyword |
| claroty_xdome.alert.device.model.name | The device's model. | keyword |
| claroty_xdome.alert.device.name | Device name. | keyword |
| claroty_xdome.alert.device.network.scope_list | The device's Network Scope - used to differentiate between internal networks that share the same IP subnets. | keyword |
| claroty_xdome.alert.device.network_list | The network types, Corporate and or Guest, that the device belongs to. | keyword |
| claroty_xdome.alert.device.note | The notes added to the device. | keyword |
| claroty_xdome.alert.device.number_of_nics | The number of network interface cards seen on the network. | long |
| claroty_xdome.alert.device.operating_hours_pattern_name | The Operating Hours pattern of the device, used for utilization calculations. | keyword |
| claroty_xdome.alert.device.organization.firewall_group_name | The device’s organization firewall group, as defined by the user in the Firewall Groups page. Accessible with advanced Network Security Management module permissions. | keyword |
| claroty_xdome.alert.device.organization.zone_name | The device's organization zone, as defined by the user in the Security Zones page. Accessible with advanced Network Security Management module permissions. | keyword |
| claroty_xdome.alert.device.os.category | The device's OS category, such as Windows, Linux or Other. | keyword |
| claroty_xdome.alert.device.os.eol_date | The date on which the operating system becomes unsupported, decided by the operating system manufacturer. | date |
| claroty_xdome.alert.device.os.name | The operating system name, such as Windows or Android. | keyword |
| claroty_xdome.alert.device.os.revision | The operating system revision, such as SP3, M1AJQ. | keyword |
| claroty_xdome.alert.device.os.subcategory | A smaller family of operating systems within each category, such as Windows XP & Equivalent. | keyword |
| claroty_xdome.alert.device.os.version | The operating system version, such as XP or 8.1.0. | keyword |
| claroty_xdome.alert.device.other_hostnames | The unique hostname identifier of the device, extracted from other protocol traffic. | keyword |
| claroty_xdome.alert.device.phi | The device storage and transmission capabilities of Personal Health Information, such as Transmits or Transmits & Stores. | keyword |
| claroty_xdome.alert.device.product.code | A unique identifier provided by the manufacturer, used to specify the exact model and characteristics of a product. This can include values like MLFB, Catalog Numbers, and comparable codes from other vendors. | keyword |
| claroty_xdome.alert.device.protocol.location_list | The location of the device, extracted from device protocol communication. | keyword |
| claroty_xdome.alert.device.purdue_level.source |  | keyword |
| claroty_xdome.alert.device.purdue_level.value | The network layer the device belongs to, based on the Purdue Reference Model for Industrial Control System (ICS). The network segmentation-based model defines OT and IT systems into six levels and the logical network boundary controls for securing these networks. | keyword |
| claroty_xdome.alert.device.recommended.firewall_group_name | The device's recommended firewall group, as defined by the system in the Firewall Groups page. Accessible with advanced Network Security Management module permissions. | keyword |
| claroty_xdome.alert.device.recommended.zone_name | The device's recommended zone, as defined by the system in the Security Zones page. Accessible with advanced Network Security Management module permissions. | keyword |
| claroty_xdome.alert.device.retired.since | The date and time the device was retired. | date |
| claroty_xdome.alert.device.retired.value | A boolean field indicating if the device is retired or not. | boolean |
| claroty_xdome.alert.device.risk_score.points |  | double |
| claroty_xdome.alert.device.risk_score.value |  | keyword |
| claroty_xdome.alert.device.serial_number | The device's serial number. | keyword |
| claroty_xdome.alert.device.site.group_name | The name of the site group within the organization the device is associated with. | keyword |
| claroty_xdome.alert.device.site.name | The name of the site within the organization the device is associated with. | keyword |
| claroty_xdome.alert.device.slot_cards.count |  | long |
| claroty_xdome.alert.device.slot_cards.racks.cards.card_type |  | keyword |
| claroty_xdome.alert.device.slot_cards.racks.cards.ip |  | ip |
| claroty_xdome.alert.device.slot_cards.racks.cards.mac |  | keyword |
| claroty_xdome.alert.device.slot_cards.racks.cards.model |  | keyword |
| claroty_xdome.alert.device.slot_cards.racks.cards.name |  | keyword |
| claroty_xdome.alert.device.slot_cards.racks.cards.serial_number |  | keyword |
| claroty_xdome.alert.device.slot_cards.racks.cards.slot_number |  | long |
| claroty_xdome.alert.device.slot_cards.racks.cards.sw_version |  | keyword |
| claroty_xdome.alert.device.slot_cards.racks.cards.uid |  | keyword |
| claroty_xdome.alert.device.slot_cards.racks.cards.vendor |  | keyword |
| claroty_xdome.alert.device.slot_cards.racks.number_of_slots |  | long |
| claroty_xdome.alert.device.snmp.hostnames |  | keyword |
| claroty_xdome.alert.device.snmp.last_seen_hostname | The most recent unique hostname identifier of the device, extracted from SNMP protocol traffic. | keyword |
| claroty_xdome.alert.device.software_or_firmware_version | The application version running on the device. | keyword |
| claroty_xdome.alert.device.ssid_list | The name of the wireless network the device is connected to, such as Guest. | keyword |
| claroty_xdome.alert.device.subcategory | The device sub-category group (see About Device Categorization in the Knowledge Base). | keyword |
| claroty_xdome.alert.device.suspicious | The reasons for which the device was marked as suspicious. | keyword |
| claroty_xdome.alert.device.switch.group_name_list |  | keyword |
| claroty_xdome.alert.device.switch.ip_list | The IP of the switch the device is connected to, extracted from various integrations. | ip |
| claroty_xdome.alert.device.switch.location_list | The location of the switch the device is connected to. | keyword |
| claroty_xdome.alert.device.switch.mac_list | The MAC address of the switch the device is connected to. | keyword |
| claroty_xdome.alert.device.switch.name_list | The name of the switch the device is connected to. | keyword |
| claroty_xdome.alert.device.switch.port_description_list | The description of the switch port to which the device is connected. | keyword |
| claroty_xdome.alert.device.switch.port_list | The port identifier of the switch the device is connected to. | keyword |
| claroty_xdome.alert.device.type.family | The device type family group. | keyword |
| claroty_xdome.alert.device.type.value | The device type group. | keyword |
| claroty_xdome.alert.device.uid | A universal unique identifier (UUID) for the device. | keyword |
| claroty_xdome.alert.device.utilization_rate | The percentage of time the device was utilized within the past 3 months. | double |
| claroty_xdome.alert.device.visibility_score.level |  | keyword |
| claroty_xdome.alert.device.visibility_score.value |  | long |
| claroty_xdome.alert.device.vlan.description_list | The description of the VLAN, extracted from switch configurations. | keyword |
| claroty_xdome.alert.device.vlan.list | The virtual LAN to which the device belongs. | keyword |
| claroty_xdome.alert.device.vlan.name_list | The name of the VLAN, extracted from switch configurations. | keyword |
| claroty_xdome.alert.device.wifi_last_seen_list | Last date and time the device was seen on the access point. | date |
| claroty_xdome.alert.device.windows.hostnames |  | keyword |
| claroty_xdome.alert.device.windows.last_seen_hostname | The most recent unique hostname identifier of the device, extracted from Windows-specific protocols traffic. | keyword |
| claroty_xdome.alert.device.wireless_encryption_type_list | The encryption method the device uses to connect to the wireless network, such as WEP or WPA2. | keyword |
| claroty_xdome.alert.device.wlc.location_list | The encryption method the device uses to connect to the wireless network, such as WEP or WPA2. | keyword |
| claroty_xdome.alert.device.wlc.name_list | The name of the Wireless LAN Controller that controls access points on the network. | keyword |
| claroty_xdome.alert.devices_count | Number of total affected devices. | long |
| claroty_xdome.alert.friendly_name | Alert Name. | keyword |
| claroty_xdome.alert.id | Platform unique Alert ID. | keyword |
| claroty_xdome.alert.iot_devices_count | Number of affected IoT devices. | long |
| claroty_xdome.alert.it_devices_count | Number of affected IT devices. | long |
| claroty_xdome.alert.malicious_ip_tags_list | The Malicious IP Tags, powered by Anomali, associated with the Attempted Malicious Internet Communication and Malicious Internet Communication alerts. | keyword |
| claroty_xdome.alert.medical_devices_count | Number of affected Medical devices. | long |
| claroty_xdome.alert.mitre_technique.enterprise.ids | MITRE ATT&CK® Enterprise technique IDs mapped to the alert. | keyword |
| claroty_xdome.alert.mitre_technique.enterprise.names | MITRE ATT&CK® Enterprise technique names mapped to the alert. | keyword |
| claroty_xdome.alert.mitre_technique.ics.ids | MITRE ATT&CK® ICS technique IDs mapped to the alert. | keyword |
| claroty_xdome.alert.mitre_technique.ics.names | MITRE ATT&CK® ICS technique names mapped to the alert. | keyword |
| claroty_xdome.alert.name | The alert name, such as Malicious Internet Communication: 62.172.138.35. | keyword |
| claroty_xdome.alert.ot_devices_count | Number of affected OT devices. | long |
| claroty_xdome.alert.status | Alert status such as Resolved or Acknowledged. | keyword |
| claroty_xdome.alert.type_name | An alert type such as Outdated Firmware. | keyword |
| claroty_xdome.alert.unresolved_devices_count | Number of unresolved devices. | long |
| claroty_xdome.alert.updated_time | Date and time of last Alert update. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Event

This is the `event` dataset.

#### Example

An example event for `event` looks as following:

An example event for `event` looks as following:

```json
{
    "@timestamp": "2025-02-02T19:54:13.691Z",
    "agent": {
        "ephemeral_id": "fc9cab9d-9bdd-483d-9f3d-06e307f1507c",
        "id": "767047c3-2256-46ec-b4ec-be06b3aa8fa0",
        "name": "elastic-agent-62457",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "claroty_xdome": {
        "event": {
            "description": "Configuration Upload was detected from 81.2.69.142 (Engineering Station) to 175.16.199.0 (PLC)",
            "destination": {
                "asset_id": "EHBLLGK",
                "device": {
                    "ip": "175.16.199.0",
                    "type": "PLC"
                },
                "ip": "175.16.199.0",
                "network": "Industrial",
                "port": 2222,
                "site_name": "NY-BR-212"
            },
            "detection_time": "2025-02-02T19:54:13.691Z",
            "id": "12",
            "ip_protocol": "UDP",
            "protocol": "CIP",
            "related_alert_ids": [
                "1000039"
            ],
            "source": {
                "asset_id": "MNCYPGV",
                "device": {
                    "name": "DESKTOP-JUFLZS",
                    "type": "Engineering Station"
                },
                "ip": "81.2.69.142",
                "network": "Industrial",
                "port": 56576,
                "site_name": "Houston_Line_1"
            },
            "type": "Configuration Upload"
        }
    },
    "data_stream": {
        "dataset": "claroty_xdome.event",
        "namespace": "43168",
        "type": "logs"
    },
    "destination": {
        "geo": {
            "city_name": "Changchun",
            "continent_name": "Asia",
            "country_iso_code": "CN",
            "country_name": "China",
            "location": {
                "lat": 43.88,
                "lon": 125.3228
            },
            "region_iso_code": "CN-22",
            "region_name": "Jilin Sheng"
        },
        "ip": "175.16.199.0",
        "port": 2222
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "767047c3-2256-46ec-b4ec-be06b3aa8fa0",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "action": "configuration-upload",
        "agent_id_status": "verified",
        "category": [
            "network",
            "host",
            "configuration"
        ],
        "dataset": "claroty_xdome.event",
        "id": "12",
        "ingested": "2025-04-21T11:29:14Z",
        "kind": "event",
        "original": "{\"description\":\"Configuration Upload was detected from 81.2.69.142 (Engineering Station) to 175.16.199.0 (PLC)\",\"dest_asset_id\":\"EHBLLGK\",\"dest_device_name\":\"175.16.199.0\",\"dest_device_type\":\"PLC\",\"dest_ip\":\"175.16.199.0\",\"dest_network\":\"Industrial\",\"dest_port\":2222,\"dest_site_name\":\"NY-BR-212\",\"detection_time\":\"2025-02-02T19:54:13.691489+00:00\",\"event_id\":12,\"event_type\":\"Configuration Upload\",\"ip_protocol\":\"UDP\",\"mode\":null,\"protocol\":\"CIP\",\"related_alert_ids\":[1000039],\"source_asset_id\":\"MNCYPGV\",\"source_device_name\":\"DESKTOP-JUFLZS\",\"source_device_type\":\"Engineering Station\",\"source_ip\":\"81.2.69.142\",\"source_network\":\"Industrial\",\"source_port\":56576,\"source_site_name\":\"Houston_Line_1\",\"source_username\":null}",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "MNCYPGV",
        "name": "DESKTOP-JUFLZS"
    },
    "input": {
        "type": "cel"
    },
    "message": "Configuration Upload was detected from 81.2.69.142 (Engineering Station) to 175.16.199.0 (PLC)",
    "network": {
        "protocol": "cip",
        "transport": "udp"
    },
    "observer": {
        "product": "xDome",
        "vendor": "Claroty"
    },
    "related": {
        "hosts": [
            "EHBLLGK",
            "MNCYPGV",
            "DESKTOP-JUFLZS"
        ],
        "ip": [
            "175.16.199.0",
            "81.2.69.142"
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
        "ip": "81.2.69.142",
        "port": 56576
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "claroty_xdome-event"
    ]
}
```

#### Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| claroty_xdome.event.description | A description of the event. | keyword |
| claroty_xdome.event.destination.asset_id | Dest. asset ID. | keyword |
| claroty_xdome.event.destination.device.ip | The Device Name attribute is set automatically based on the priority of the Auto-Assigned Device attribute. You can also set it manually. The Device Name can be the device's IP, hostname, etc. | ip |
| claroty_xdome.event.destination.device.name | The Device Name attribute is set automatically based on the priority of the Auto-Assigned Device attribute. You can also set it manually. The Device Name can be the device's IP, hostname, etc. | keyword |
| claroty_xdome.event.destination.device.type | The device, such as a PLC, on which the operation associated with the event was performed. | keyword |
| claroty_xdome.event.destination.ip | IP address associated with the dest. device. | ip |
| claroty_xdome.event.destination.network | The network type, "Corporate" or "Guest", that the device belongs to. | keyword |
| claroty_xdome.event.destination.port | The port number to which the network traffic was directed. | long |
| claroty_xdome.event.destination.site_name | The name of the site within the organization the device is associated with. | keyword |
| claroty_xdome.event.detection_time | The date and time at which the event was detected. | date |
| claroty_xdome.event.id | Platform unique Event ID. | keyword |
| claroty_xdome.event.ip_protocol | The IP protocol used, such as TCP. | keyword |
| claroty_xdome.event.mode | The new mode of operation that was changed during the Mode Change event. | keyword |
| claroty_xdome.event.protocol | The protocol used, such as CIP. | keyword |
| claroty_xdome.event.related_alert_ids | The IDs of the alerts that are related to the event. | keyword |
| claroty_xdome.event.source.asset_id | Source asset ID. | keyword |
| claroty_xdome.event.source.device.ip | The Device Name attribute is set automatically based on the priority of the Auto-Assigned Device attribute. You can also set it manually. The Device Name can be the device's IP, hostname, etc. | ip |
| claroty_xdome.event.source.device.name | The Device Name attribute is set automatically based on the priority of the Auto-Assigned Device attribute. You can also set it manually. The Device Name can be the device's IP, hostname, etc. | keyword |
| claroty_xdome.event.source.device.type | The device, such as an Engineering Station, that initiated the operation associated with the event. | keyword |
| claroty_xdome.event.source.ip | IP address associated with the source device. | ip |
| claroty_xdome.event.source.network | The network type, "Corporate" or "Guest", that the device belongs to. | keyword |
| claroty_xdome.event.source.port | The port number from which the network traffic originated. | long |
| claroty_xdome.event.source.site_name | The name of the site within the organization the device is associated with. | keyword |
| claroty_xdome.event.source.username | The username who performed the activity associated with the event. | keyword |
| claroty_xdome.event.type | An event type such as "Configuration Upload". | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


### Vulnerability

This is the `vulnerability` dataset.

#### Example

An example event for `vulnerability` looks as following:

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2025-05-11T01:21:05.359Z",
    "agent": {
        "ephemeral_id": "d49b15e7-6de4-49f5-bbbe-a90dc684d350",
        "id": "0b64b41b-bd31-4d85-8358-98d26da791f6",
        "name": "elastic-agent-93298",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "claroty_xdome": {
        "vulnerability": {
            "adjusted_vulnerability_score": {
                "level": "Medium",
                "value": 5.0070715
            },
            "affected": {
                "confirmed_devices_count": 0,
                "devices_count": 0,
                "fixed_devices_count": 0,
                "iot_devices_count": 0,
                "irrelevant_devices_count": 0,
                "it_devices_count": 0,
                "ot_devices_count": 0,
                "potentially_relevant_devices_count": 0
            },
            "cve_ids": [
                "CVE-2020-26144"
            ],
            "cvss_v2": {
                "exploitability_subscore": 6.5,
                "score": 3.3,
                "vector_string": "AV:A/AC:L/Au:N/C:N/I:P/A:N"
            },
            "cvss_v3": {
                "exploitability_subscore": 2.8,
                "score": 6.5,
                "vector_string": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
            },
            "description": "CVE-2020-26144 - An issue was discovered on Samsung Galaxy S3 i9305 4.4.4 devices. The WEP, WPA, WPA2, and WPA3 implementations accept plaintext A-MSDU frames as long as the first 8 bytes correspond to a valid RFC1042 (i.e., LLC/SNAP) header for EAPOL. An adversary can abuse this to inject arbitrary network packets independent of the network configuration.",
            "device": {
                "activity_rate": 82,
                "asset_id": "JLSXVOK",
                "assignees": [
                    "Jose Alegria",
                    "Kelvin Kan"
                ],
                "assignees_data": [
                    {
                        "display_name": "Jose Alegria",
                        "id": "jose.a",
                        "is_active": true,
                        "type": "user"
                    }
                ],
                "avg": {
                    "online_per_day": 19.7
                },
                "category": "OT",
                "collection": {
                    "interfaces": {
                        "seen_reported_from": [
                            "ens142@demo-collection-sv_2"
                        ]
                    },
                    "servers": {
                        "seen_reported_from": [
                            "demo-collection-sv_1",
                            "demo-collection-sv_2"
                        ]
                    }
                },
                "combined_os": "Nucleus 3.1.1",
                "connection": {
                    "type_list": [
                        "Ethernet"
                    ]
                },
                "data_sources_seen_reported_from": [
                    "Passive Collection"
                ],
                "effective_likelihood_subscore": {
                    "points": 50.071365,
                    "value": "Low"
                },
                "end_of": {
                    "life": {
                        "state": "Manufacturer Supported"
                    }
                },
                "financial_cost": "$1,000-$10,000",
                "first_seen_list": [
                    "2024-12-05T05:08:40.208Z"
                ],
                "hw_version": "PXME V2.8.18",
                "impact_subscore": {
                    "points": 65,
                    "value": "Critical"
                },
                "insecure_protocols": {
                    "points": 0,
                    "value": "Very Low"
                },
                "internet_communication": "No",
                "ip": {
                    "assignment_list": [
                        "Static"
                    ],
                    "list": [
                        "81.2.69.144"
                    ],
                    "value": "81.2.69.144"
                },
                "is_online": true,
                "ise": {
                    "security_group": {
                        "description_list": [
                            "Building Management System Group - Exported from xDome"
                        ],
                        "name_list": [
                            "Building_Management_System_sgt"
                        ],
                        "tag_list": [
                            "3"
                        ]
                    }
                },
                "known_vulnerabilities": {
                    "points": 43.84793,
                    "value": "Medium"
                },
                "labels": [
                    "Asset Owner",
                    "criticality",
                    "OT Internet Klabin"
                ],
                "last": {
                    "seen": {
                        "list": [
                            "2025-03-28T02:54:47.042Z"
                        ],
                        "on_switch_list": [
                            "2025-03-09T09:41:58.208Z"
                        ],
                        "reported": "2025-03-29T02:54:26.262Z"
                    }
                },
                "last_updated": "2025-03-28T03:11:36.632Z",
                "likelihood_subscore": {
                    "points": 50.071365,
                    "value": "Low"
                },
                "mac": {
                    "list": [
                        "00:c0:e4:4b:d4:a8"
                    ],
                    "oui_list": [
                        "Siemens Building"
                    ]
                },
                "machine_type": "Physical",
                "manufacturer": "Siemens",
                "mobility": "Stationary",
                "model": {
                    "name": "PXC100-PE96.A"
                },
                "network": {
                    "scope_list": [
                        "Default"
                    ]
                },
                "network_list": [
                    "Industrial"
                ],
                "number_of_nics": 1,
                "organization": {
                    "firewall_group_name": "No Zone"
                },
                "os": {
                    "category": "Other",
                    "name": "Nucleus",
                    "subcategory": "Nucleus",
                    "version": "3.1.1"
                },
                "purdue_level": {
                    "source": "Auto-Assigned",
                    "value": "Level 1"
                },
                "recommended": {
                    "firewall_group_name": "Building Management System"
                },
                "relevance": "Confirmed",
                "retired": {
                    "value": false
                },
                "risk_score": {
                    "points": 56.04282,
                    "value": "Medium"
                },
                "serial_number": "150214B94630",
                "site": {
                    "group_name": "No Group",
                    "name": "SV_1"
                },
                "source": "Claroty",
                "subcategory": "Building Management",
                "switch": {
                    "mac_list": [
                        "00:11:93:61:e7:e3"
                    ],
                    "port_list": [
                        "Fa/0/3"
                    ]
                },
                "type": {
                    "family": "Building Automation Controller",
                    "value": "Building Automation Controller"
                },
                "uid": "0d4b011f-fe47-46d0-9b9c-b102e3309aaa",
                "visibility_score": {
                    "level": "Excellent",
                    "value": 98
                },
                "vlan": {
                    "description_list": [
                        "Bldg1-Flr8"
                    ],
                    "list": [
                        "108"
                    ],
                    "name_list": [
                        "Bldg1-Flr8"
                    ]
                }
            },
            "epss_score": 0.00119,
            "id": "ALTWZXRU",
            "is_known_exploited": false,
            "name": "CVE-2020-26144",
            "published_date": "2025-05-11T01:21:05.359Z",
            "sources": [
                {
                    "name": "NVD",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-26144"
                }
            ],
            "type": "Platform"
        }
    },
    "data_stream": {
        "dataset": "claroty_xdome.vulnerability",
        "namespace": "49050",
        "type": "logs"
    },
    "device": {
        "manufacturer": "Siemens",
        "model": {
            "identifier": "PXC100-PE96.A"
        },
        "serial_number": "150214B94630"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "0b64b41b-bd31-4d85-8358-98d26da791f6",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "claroty_xdome.vulnerability",
        "ingested": "2025-04-21T11:30:15Z",
        "kind": "state",
        "original": "{\"activity_rate\":82,\"asset_id\":\"JLSXVOK\",\"assignees\":[\"Jose Alegria\",\"Kelvin Kan\"],\"assignees_data\":[{\"display_name\":\"Jose Alegria\",\"id\":\"jose.a\",\"is_active\":true,\"type\":\"user\"}],\"avg_online_per_day\":19.7,\"collection_interfaces_seen_reported_from\":[\"ens142@demo-collection-sv_2\"],\"collection_servers_seen_reported_from\":[\"demo-collection-sv_1\",\"demo-collection-sv_2\"],\"combined_os\":\"Nucleus 3.1.1\",\"connection_type_list\":[\"Ethernet\"],\"data_sources_seen_reported_from\":[\"Passive Collection\"],\"device_category\":\"OT\",\"device_name\":\"81.2.69.144\",\"device_subcategory\":\"Building Management\",\"device_type\":\"Building Automation Controller\",\"device_type_family\":\"Building Automation Controller\",\"effective_likelihood_subscore\":\"Low\",\"effective_likelihood_subscore_points\":50.071365,\"end_of_life_state\":\"Manufacturer Supported\",\"financial_cost\":\"$1,000-$10,000\",\"first_seen_list\":[\"2024-12-05T05:08:40.208303+00:00\"],\"hw_version\":\"PXME V2.8.18\",\"impact_subscore\":\"Critical\",\"impact_subscore_points\":65,\"insecure_protocols\":\"Very Low\",\"insecure_protocols_points\":0,\"internet_communication\":\"No\",\"ip_assignment_list\":[\"Static\"],\"ip_list\":[\"81.2.69.144\"],\"is_online\":true,\"ise_security_group_description_list\":[\"Building Management System Group - Exported from xDome\"],\"ise_security_group_name_list\":[\"Building_Management_System_sgt\"],\"ise_security_group_tag_list\":[3],\"known_vulnerabilities\":\"Medium\",\"known_vulnerabilities_points\":43.84793,\"labels\":[\"Asset Owner\",\"criticality\",\"OT Internet Klabin\"],\"last_seen_list\":[\"2025-03-28T02:54:47.042124+00:00\"],\"last_seen_on_switch_list\":[\"2025-03-09T09:41:58.208337+00:00\"],\"last_seen_reported\":\"2025-03-29T02:54:26.262271+00:00\",\"likelihood_subscore\":\"Low\",\"likelihood_subscore_points\":50.071365,\"mac_list\":[\"00:c0:e4:4b:d4:a8\"],\"mac_oui_list\":[\"Siemens Building\"],\"machine_type\":\"Physical\",\"manufacturer\":\"Siemens\",\"mobility\":\"Stationary\",\"model\":\"PXC100-PE96.A\",\"network_list\":[\"Industrial\"],\"network_scope_list\":[\"Default\"],\"number_of_nics\":1,\"organization_firewall_group_name\":\"No Zone\",\"os_category\":\"Other\",\"os_name\":\"Nucleus\",\"os_subcategory\":\"Nucleus\",\"os_version\":\"3.1.1\",\"purdue_level\":\"Level 1\",\"purdue_level_source\":\"Auto-Assigned\",\"recommended_firewall_group_name\":\"Building Management System\",\"retired\":false,\"risk_score\":\"Medium\",\"risk_score_points\":56.04282,\"serial_number\":\"150214B94630\",\"site_group_name\":\"No Group\",\"site_name\":\"SV_1\",\"switch_mac_list\":[\"00:11:93:61:e7:e3\"],\"switch_port_list\":[\"Fa/0/3\"],\"uid\":\"0d4b011f-fe47-46d0-9b9c-b102e3309aaa\",\"visibility_score\":98,\"visibility_score_level\":\"Excellent\",\"vlan_description_list\":[\"Bldg1-Flr8\"],\"vlan_list\":[108],\"vlan_name_list\":[\"Bldg1-Flr8\"],\"vulnerability_info\":{\"adjusted_vulnerability_score\":5.0070715,\"adjusted_vulnerability_score_level\":\"Medium\",\"affected_confirmed_devices_count\":0,\"affected_devices_count\":0,\"affected_fixed_devices_count\":0,\"affected_iot_devices_count\":0,\"affected_irrelevant_devices_count\":0,\"affected_it_devices_count\":0,\"affected_ot_devices_count\":0,\"affected_potentially_relevant_devices_count\":0,\"cve_ids\":[\"CVE-2020-26144\"],\"cvss_v2_exploitability_subscore\":6.5,\"cvss_v2_score\":3.3,\"cvss_v2_vector_string\":\"AV:A/AC:L/Au:N/C:N/I:P/A:N\",\"cvss_v3_exploitability_subscore\":2.8,\"cvss_v3_score\":6.5,\"cvss_v3_vector_string\":\"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N\",\"description\":\"CVE-2020-26144 - An issue was discovered on Samsung Galaxy S3 i9305 4.4.4 devices. The WEP, WPA, WPA2, and WPA3 implementations accept plaintext A-MSDU frames as long as the first 8 bytes correspond to a valid RFC1042 (i.e., LLC/SNAP) header for EAPOL. An adversary can abuse this to inject arbitrary network packets independent of the network configuration.\",\"epss_score\":0.00119,\"id\":\"ALTWZXRU\",\"is_known_exploited\":false,\"name\":\"CVE-2020-26144\",\"published_date\":\"2025-05-11T01:21:05.359000Z\",\"source_name\":\"NVD\",\"source_url\":\"https://nvd.nist.gov/vuln/detail/CVE-2020-26144\",\"sources\":[{\"name\":\"NVD\",\"url\":\"https://nvd.nist.gov/vuln/detail/CVE-2020-26144\"}],\"vulnerability_type\":\"Platform\"},\"vulnerability_is_user_verdict\":false,\"vulnerability_last_updated\":\"2025-03-28T03:11:36.632383+00:00\",\"vulnerability_relevance\":\"Confirmed\",\"vulnerability_source\":\"Claroty\",\"vulnerability_system_relevance\":\"Confirmed\"}",
        "risk_score": 56.04282,
        "severity": 47,
        "type": [
            "info"
        ]
    },
    "host": {
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
        "id": "0d4b011f-fe47-46d0-9b9c-b102e3309aaa",
        "ip": [
            "81.2.69.144"
        ],
        "mac": [
            "00-C0-E4-4B-D4-A8"
        ],
        "os": {
            "family": "Other",
            "full": "Nucleus 3.1.1",
            "name": "Nucleus",
            "version": "3.1.1"
        },
        "type": "Building Automation Controller"
    },
    "input": {
        "type": "cel"
    },
    "message": "CVE-2020-26144 - An issue was discovered on Samsung Galaxy S3 i9305 4.4.4 devices. The WEP, WPA, WPA2, and WPA3 implementations accept plaintext A-MSDU frames as long as the first 8 bytes correspond to a valid RFC1042 (i.e., LLC/SNAP) header for EAPOL. An adversary can abuse this to inject arbitrary network packets independent of the network configuration.",
    "observer": {
        "ingress": {
            "vlan": {
                "id": [
                    "108"
                ],
                "name": [
                    "Bldg1-Flr8"
                ]
            }
        },
        "product": "xDome",
        "vendor": "Claroty"
    },
    "related": {
        "hosts": [
            "Nucleus 3.1.1",
            "Nucleus",
            "SV_1",
            "0d4b011f-fe47-46d0-9b9c-b102e3309aaa"
        ],
        "ip": [
            "81.2.69.144"
        ],
        "user": [
            "Jose Alegria",
            "Kelvin Kan",
            "jose.a"
        ]
    },
    "resource": {
        "id": "0d4b011f-fe47-46d0-9b9c-b102e3309aaa"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "claroty_xdome-vulnerability"
    ],
    "vulnerability": {
        "classification": "CVSS",
        "description": "CVE-2020-26144 - An issue was discovered on Samsung Galaxy S3 i9305 4.4.4 devices. The WEP, WPA, WPA2, and WPA3 implementations accept plaintext A-MSDU frames as long as the first 8 bytes correspond to a valid RFC1042 (i.e., LLC/SNAP) header for EAPOL. An adversary can abuse this to inject arbitrary network packets independent of the network configuration.",
        "enumeration": "CVE",
        "id": "CVE-2020-26144",
        "package": {
            "published_date": "2025-05-11T01:21:05.359Z"
        },
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-26144",
        "score": {
            "base": 6.5,
            "version": "3.0"
        }
    }
}
```

#### Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| claroty_xdome.vulnerability.adjusted_vulnerability_score.level | The calculated Adjusted vulnerability Score (AVS) level of a vulnerability, such as "Critical", or "High". | keyword |
| claroty_xdome.vulnerability.adjusted_vulnerability_score.value | The Adjusted Vulnerability Score represents the vulnerability score based on its impact and exploitability. | double |
| claroty_xdome.vulnerability.affected.confirmed_devices_count | Count of affected devices with ""Confirmed"" vulnerability relevance value. | long |
| claroty_xdome.vulnerability.affected.devices_count | Count of all devices affected by the vulnerability. | long |
| claroty_xdome.vulnerability.affected.fixed_devices_count | Count of affected devices with ""Fixed"" vulnerability relevance value. | long |
| claroty_xdome.vulnerability.affected.iot_devices_count | Count of all IoT devices affected by the vulnerability. | long |
| claroty_xdome.vulnerability.affected.irrelevant_devices_count | Count of affected devices with ""Irrelevant"" vulnerability relevance value. | long |
| claroty_xdome.vulnerability.affected.it_devices_count | Count of all IT devices affected by the vulnerability. | long |
| claroty_xdome.vulnerability.affected.medical_devices_count | Count of all Medical devices affected by the vulnerability. | long |
| claroty_xdome.vulnerability.affected.ot_devices_count | Count of all OT devices affected by the vulnerability. | long |
| claroty_xdome.vulnerability.affected.potentially_relevant_devices_count | Count of affected devices with ""Potentially Relevant"" vulnerability relevance value. | long |
| claroty_xdome.vulnerability.affected.products | All potential products that could be affected by the vulnerability. | keyword |
| claroty_xdome.vulnerability.assignees | The users and or groups the vulnerability is assigned to. | keyword |
| claroty_xdome.vulnerability.cve_ids | Relevant Common Vulnerability Exploits for the selected vulnerability. | keyword |
| claroty_xdome.vulnerability.cvss_v2.exploitability_subscore | The CVSS v2 exploitability score (0-10). In case of multiple CVEs, the highest Subscore is displayed. | double |
| claroty_xdome.vulnerability.cvss_v2.score | Common Vulnerability Scoring System Version 2 score (0-10). In case of multiple CVEs, the highest Subscore is displayed. | double |
| claroty_xdome.vulnerability.cvss_v2.vector_string | Common Vulnerability Scoring System Version 2 vector. In case of multiple CVEs, the vector of the highest Subscore is displayed. | keyword |
| claroty_xdome.vulnerability.cvss_v3.exploitability_subscore | The CVSS v3 exploitability subscore (0.1-3.9). In case of multiple CVEs, the highest Subscore is displayed. | double |
| claroty_xdome.vulnerability.cvss_v3.score | Common Vulnerability Scoring System Version 3 score (0-10). In case of multiple CVEs, the highest Subscore is displayed. | float |
| claroty_xdome.vulnerability.cvss_v3.vector_string | Common Vulnerability Scoring System Version 3 vector. In case of multiple CVEs, the vector of the highest Subscore is displayed. | keyword |
| claroty_xdome.vulnerability.description | Details about the vulnerability. | keyword |
| claroty_xdome.vulnerability.device.active_queries_seen_reported_from | The active query tasks the device was seen or reported from. | keyword |
| claroty_xdome.vulnerability.device.activity_rate | The percentage of time the device was online within the past 90 days. | double |
| claroty_xdome.vulnerability.device.ad.description | The Active Directory device description extracted from the Microsoft Active Directory integration. | keyword |
| claroty_xdome.vulnerability.device.ad.distinguished_name | The Active Directory distinguished device name extracted from the Microsoft Active Directory integration. | keyword |
| claroty_xdome.vulnerability.device.ae_titles | The unique identifier of imaging devices provided by the healthcare organization. | keyword |
| claroty_xdome.vulnerability.device.ap.location_list | The location of the access point the device is connected to, extracted from Network Management integrations. | keyword |
| claroty_xdome.vulnerability.device.ap.name_list | The name of the access point the device is connected to, extracted from Network Management integrations. | keyword |
| claroty_xdome.vulnerability.device.applied_acl.list | The device's applied ACL (Access Control List) extracted from Cisco ISE, Aruba ClearPass, Cisco DNAC, or Cisco Prime integrations. | keyword |
| claroty_xdome.vulnerability.device.applied_acl.type_list | The type of the Applied ACL (Access Control List) extracted from Cisco ISE, Aruba ClearPass, Cisco DNAC, or Cisco Prime integrations: Cisco dACL, ArubaOS-Switch, ArubaOS-CX, ArubaOS, Aruba Instant On, AireOS. | keyword |
| claroty_xdome.vulnerability.device.asset_id | Asset ID. | keyword |
| claroty_xdome.vulnerability.device.assignees | The users and or groups the device is assigned to. | keyword |
| claroty_xdome.vulnerability.device.assignees_data.display_name |  | keyword |
| claroty_xdome.vulnerability.device.assignees_data.id |  | keyword |
| claroty_xdome.vulnerability.device.assignees_data.is_active |  | boolean |
| claroty_xdome.vulnerability.device.assignees_data.type |  | keyword |
| claroty_xdome.vulnerability.device.authentication_user_list | The User name used to authenticate the device to the network using Radius/802.1x is extracted from the NAC integration and the traffic. | keyword |
| claroty_xdome.vulnerability.device.avg.examinations_per_day | The average daily number of examinations performed by the device within the selected time period, during the past 3 months. For Imaging Devices only. | double |
| claroty_xdome.vulnerability.device.avg.in_use_per_day | The average daily hours the device was utilized within the selected time period, during the past 3 months. | double |
| claroty_xdome.vulnerability.device.avg.online_per_day | The average daily hours the device was online within the selected time period, during the past 3 months. | double |
| claroty_xdome.vulnerability.device.battery_level | The battery status of the device. Relevant to Infusion Pumps only. | keyword |
| claroty_xdome.vulnerability.device.bssid_list | The MAC physical address of the access point the device is connected to. | keyword |
| claroty_xdome.vulnerability.device.category | The device category group (see "About Device Categorization" in the Knowledge Base). | keyword |
| claroty_xdome.vulnerability.device.cmms.asset.purchase_cost | The cost of the devices, as extracted from the CMMS platform. | double |
| claroty_xdome.vulnerability.device.cmms.asset.tag | The designated identifier of the device as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.building | The building in which the device is located, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.campus | The site in which the device is located, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.department | The department of the device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.financial_cost |  | double |
| claroty_xdome.vulnerability.device.cmms.floor | The floor in which the device is located, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.last_pm | The last preventative maintenance as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.location | The device location, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.manufacturer | Manufacturer of the device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.model | The model of the device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.ownership | The ownership type of the device, such as Directly Owned or Leased, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.owning_cost_center | The owning cost center of the device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.room | The room in which the device is located, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.serial_number | A unique identifier assigned to a device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.state | The status of the device, such as In Use or Retired, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.cmms.technician | The technician assigned to the device, as extracted from the CMMS platform. | keyword |
| claroty_xdome.vulnerability.device.collection.interfaces.seen_reported_from | The collection interfaces from which the device was seen or reported through passive collection. | keyword |
| claroty_xdome.vulnerability.device.collection.interfaces.value |  | keyword |
| claroty_xdome.vulnerability.device.collection.servers.seen_reported_from | The collection servers from which the device was seen or reported, either through passive collection or from active queries. | keyword |
| claroty_xdome.vulnerability.device.collection.servers.value |  | keyword |
| claroty_xdome.vulnerability.device.combined_os | The aggregated value of OS name, version and revision, such as "Windows XP SP3". | keyword |
| claroty_xdome.vulnerability.device.connection.paths | The connection path list describing the network path to a nested device. | keyword |
| claroty_xdome.vulnerability.device.connection.type_list | The connection types of a device, such as "Ethernet". | keyword |
| claroty_xdome.vulnerability.device.consequence_of_failure | Determines the consequence of failure of the device, according to The Joint Commission (TJC). | keyword |
| claroty_xdome.vulnerability.device.cppm.authentication_status_list | The device's Authentication Status extracted from the Aruba ClearPass integration. | keyword |
| claroty_xdome.vulnerability.device.cppm.service_list | The device's Service extracted from the Aruba ClearPass integration. | keyword |
| claroty_xdome.vulnerability.device.data_sources_seen_reported_from | The data sources that the device was seen on or reported from. | keyword |
| claroty_xdome.vulnerability.device.dhcp.fingerprint | Summarized fingerprint of the device's different DHCP messages such as the message type, DHCP options used and DHCP vendor class. | keyword |
| claroty_xdome.vulnerability.device.dhcp.hostnames |  | keyword |
| claroty_xdome.vulnerability.device.dhcp.last_seen_hostname | The most recent unique hostname identifier of the device, extracted from DHCP protocol traffic. | keyword |
| claroty_xdome.vulnerability.device.domains | The domain name of the network that the device belongs to. | keyword |
| claroty_xdome.vulnerability.device.edge.hosts_seen_reported_from | The Device IDs of the Edge hosts where the device was seen or reported from. | keyword |
| claroty_xdome.vulnerability.device.edge.locations |  | keyword |
| claroty_xdome.vulnerability.device.edge.locations_seen_reported_from | The Edge locations associated with the Edge scans where the device was seen or reported. | keyword |
| claroty_xdome.vulnerability.device.edr.is_up_to_date_text | Determines whether the endpoint security application installed on the device is up-to-date. | keyword |
| claroty_xdome.vulnerability.device.edr.last_scan_time | Last date and time the device was scanned by the endpoint security application, extracted from Endpoint Security integrations. | date |
| claroty_xdome.vulnerability.device.effective_likelihood_subscore.points | The calculated effective likelihood subscore points of a device, such as "54.1". | double |
| claroty_xdome.vulnerability.device.effective_likelihood_subscore.value | The calculated effective likelihood subscore level of a device, such as "Critical", or "High". | keyword |
| claroty_xdome.vulnerability.device.end_of.life.date | The date on which the manufacturer announced it would no longer sell, update, maintain or support the product. | date |
| claroty_xdome.vulnerability.device.end_of.life.state | The phase the product is in within its life cycle, such as: "End-Of-Life", "End-Of-Life Notification", Or "Manufacturer-Supported"        . | keyword |
| claroty_xdome.vulnerability.device.end_of.sale_date | The date on which the manufacturer announced it will stop selling the product. | date |
| claroty_xdome.vulnerability.device.endpoint_security_names | The names of endpoint security applications installed on the device. | keyword |
| claroty_xdome.vulnerability.device.equipment_class | Determines the equipment class of the device, according to The Joint Commission (TJC). | keyword |
| claroty_xdome.vulnerability.device.fda_class | The FDA class categorization of the device including "Class 1, 2, 3" and "Unclassified". The FDA class is only relevant to medical devices. | keyword |
| claroty_xdome.vulnerability.device.financial_cost | The cost to purchase a new device. | keyword |
| claroty_xdome.vulnerability.device.first_seen_list | The date and time a device's NIC was first seen. | date |
| claroty_xdome.vulnerability.device.handles_pii | The device storage and transmission capabilities of Personal Identifiable Information. | keyword |
| claroty_xdome.vulnerability.device.http.hostnames |  | keyword |
| claroty_xdome.vulnerability.device.http.last_seen_hostname | The most recent unique hostname identifier of the device, extracted from HTTP protocol traffic. | keyword |
| claroty_xdome.vulnerability.device.hw_version | The hardware version of the device. | keyword |
| claroty_xdome.vulnerability.device.impact_subscore.points | The calculated active impact subscore points of a device, such as "54.1". | double |
| claroty_xdome.vulnerability.device.impact_subscore.value | The calculated active impact subscore level of a device, such as "Critical", or "High". | keyword |
| claroty_xdome.vulnerability.device.insecure_protocols.points | The calculated points for 'insecure protocols' likelihood factor of a device, such as "54.1". | double |
| claroty_xdome.vulnerability.device.insecure_protocols.value | The calculated level of the device's 'insecure protocols' likelihood factor, such as "Critical", or "High". | keyword |
| claroty_xdome.vulnerability.device.integration_types_reported_from | The Integration types the device was reported from. | keyword |
| claroty_xdome.vulnerability.device.integrations_reported_from | The Integration names the device was reported from. | keyword |
| claroty_xdome.vulnerability.device.internet_communication | The manner of the device's communication over the internet. | keyword |
| claroty_xdome.vulnerability.device.ip.assignment_list | The device's IP assignment method, extracted from DHCP protocol traffic, such as "DHCP", "DHCP (Static Lease)", or "Static". | keyword |
| claroty_xdome.vulnerability.device.ip.list | IP address associated with the device. IPs may be suffixed by a / (annotation), where annotation may be a child device ID or (Last Known IP). | ip |
| claroty_xdome.vulnerability.device.ip.value | The Device Name attribute is set automatically based on the priority of the Auto-Assigned Device attribute. You can also set it manually. The Device Name can be the device's IP, hostname, etc. | ip |
| claroty_xdome.vulnerability.device.is_online | A boolean field indicating whether the device is online or not. | boolean |
| claroty_xdome.vulnerability.device.ise.authentication_method_list | The device's Authentication Method extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.vulnerability.device.ise.endpoint_profile_list | The device's Endpoint Profile extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.vulnerability.device.ise.identity_group_list | The device's Identity Group extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.vulnerability.device.ise.logical_profile_list | The device's Logical Profile extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.vulnerability.device.ise.security_group.description_list | The device's Security Group Description extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.vulnerability.device.ise.security_group.name_list | The device's Security Group Name extracted from the Cisco ISE integration. | keyword |
| claroty_xdome.vulnerability.device.ise.security_group.tag_list | The device's Security Group Tag ID extracted from the Cisco ISE integration or Radius traffic. | keyword |
| claroty_xdome.vulnerability.device.known_vulnerabilities.points | The calculated points for 'known vulnerabilities' likelihood factor of a device, such as "54.1". | double |
| claroty_xdome.vulnerability.device.known_vulnerabilities.value | The calculated level of the device's 'known vulnerabilities' likelihood factor, such as "Critical", or "High". | keyword |
| claroty_xdome.vulnerability.device.labels | The labels added to the device manually or automatically. | keyword |
| claroty_xdome.vulnerability.device.last.scan_time | The last date and time the device was scanned by a Vulnerability Management platform, extracted from a Vulnerability Management integration. | date |
| claroty_xdome.vulnerability.device.last.seen.list | The date and time a device's NIC was last seen. | date |
| claroty_xdome.vulnerability.device.last.seen.on_switch_list | Last date and time the device was seen on the switch. | date |
| claroty_xdome.vulnerability.device.last.seen.reported | The last date and time the device was either seen on the network or reported. The seen information is updated in real time. | date |
| claroty_xdome.vulnerability.device.last_changed |  | date |
| claroty_xdome.vulnerability.device.last_domain_user.activity | Last seen date and time of the last user logged in to the device, extracted from the Kerberos protocol or the Active Directory integration. | date |
| claroty_xdome.vulnerability.device.last_domain_user.name | The last user seen logged in to the device, extracted from the Kerberos protocol or an Active Directory integration. | keyword |
| claroty_xdome.vulnerability.device.last_updated | The last date and time the vulnerability relevance verdict was updated. | date |
| claroty_xdome.vulnerability.device.likelihood_subscore.points | The calculated likelihood subscore points of a device, such as "54.1". | double |
| claroty_xdome.vulnerability.device.likelihood_subscore.value | The calculated likelihood subscore level of a device, such as "Critical", or "High". | keyword |
| claroty_xdome.vulnerability.device.local_name | Similar to hostname, the device name identifier is extracted from protocol traffic. | keyword |
| claroty_xdome.vulnerability.device.mac.list | MAC address associated with the device. | keyword |
| claroty_xdome.vulnerability.device.mac.oui_list | The vendor of the device's NIC, according to the OUI. | keyword |
| claroty_xdome.vulnerability.device.machine_type | Identifies if device is physical or virtual. | keyword |
| claroty_xdome.vulnerability.device.managed_by |  | keyword |
| claroty_xdome.vulnerability.device.management_services | Defines whether the device is managed by Active Directory, Mobile Device Management, or neither. | keyword |
| claroty_xdome.vulnerability.device.manufacturer | Manufacturer of the device, such as "Alaris". | keyword |
| claroty_xdome.vulnerability.device.mdm.compliance_status | The compliance status of the mobile device incorporated in the MDM platform, extracted from MDM integrations. | keyword |
| claroty_xdome.vulnerability.device.mdm.enrollment_status | The enrollment status of the mobile device incorporated in the MDM platform, extracted from MDM integrations. | keyword |
| claroty_xdome.vulnerability.device.mdm.ownership | The ownership of the mobile device incorporated in the MDM platform, extracted from MDM integrations. | keyword |
| claroty_xdome.vulnerability.device.mobility | Identifies if device is stationary or portable. | keyword |
| claroty_xdome.vulnerability.device.model.family | Identifies a series encompassing related models. | keyword |
| claroty_xdome.vulnerability.device.model.name | The device's model. | keyword |
| claroty_xdome.vulnerability.device.name | Device name. | keyword |
| claroty_xdome.vulnerability.device.network.scope_list | The device's Network Scope - used to differentiate between internal networks that share the same IP subnets. | keyword |
| claroty_xdome.vulnerability.device.network_list | The network types, "Corporate" and or "Guest", that the device belongs to. | keyword |
| claroty_xdome.vulnerability.device.note | The notes added to the device. | keyword |
| claroty_xdome.vulnerability.device.number_of_nics | The number of network interface cards seen on the network. | long |
| claroty_xdome.vulnerability.device.operating_hours_pattern_name | The Operating Hours pattern of the device, used for utilization calculations. | keyword |
| claroty_xdome.vulnerability.device.organization.firewall_group_name | The device’s organization firewall group, as defined by the user in the Firewall Groups page. Accessible with advanced Network Security Management module permissions. | keyword |
| claroty_xdome.vulnerability.device.organization.zone_name | The device's organization zone, as defined by the user in the Security Zones page. Accessible with advanced Network Security Management module permissions. | keyword |
| claroty_xdome.vulnerability.device.os.category | The device's OS category, such as "Windows", "Linux" or "Other". | keyword |
| claroty_xdome.vulnerability.device.os.eol_date | The date on which the operating system becomes unsupported, decided by the operating system manufacturer. | date |
| claroty_xdome.vulnerability.device.os.name | The operating system name, such as "Windows" or "Android". | keyword |
| claroty_xdome.vulnerability.device.os.revision | The operating system revision, such as "SP3", "M1AJQ". | keyword |
| claroty_xdome.vulnerability.device.os.subcategory | A smaller family of operating systems within each category, such as Windows XP & Equivalent. | keyword |
| claroty_xdome.vulnerability.device.os.version | The operating system version, such as "XP" or "8.1.0". | keyword |
| claroty_xdome.vulnerability.device.other_hostnames | The unique hostname identifier of the device, extracted from other protocol traffic. | keyword |
| claroty_xdome.vulnerability.device.phi | The device storage and transmission capabilities of Personal Health Information, such as "Transmits" or "Transmits & Stores". | keyword |
| claroty_xdome.vulnerability.device.product.code | A unique identifier provided by the manufacturer, used to specify the exact model and characteristics of a product. This can include values like MLFB, Catalog Numbers, and comparable codes from other vendors. | keyword |
| claroty_xdome.vulnerability.device.protocol.location_list | The location of the device, extracted from device protocol communication. | keyword |
| claroty_xdome.vulnerability.device.purdue_level.source |  | keyword |
| claroty_xdome.vulnerability.device.purdue_level.value | The network layer the device belongs to, based on the Purdue Reference Model for Industrial Control System (ICS). The network segmentation-based model defines OT and IT systems into six levels and the logical network boundary controls for securing these networks. | keyword |
| claroty_xdome.vulnerability.device.recommended.firewall_group_name | The device's recommended firewall group, as defined by the system in the Firewall Groups page. Accessible with advanced Network Security Management module permissions. | keyword |
| claroty_xdome.vulnerability.device.recommended.zone_name | The device's recommended zone, as defined by the system in the Security Zones page. Accessible with advanced Network Security Management module permissions. | keyword |
| claroty_xdome.vulnerability.device.relevance | The device vulnerability relevance reflects the confidence level of the detection process, corresponding to several components, such as the vulnerability type. | keyword |
| claroty_xdome.vulnerability.device.retired.since | The date and time the device was retired. | date |
| claroty_xdome.vulnerability.device.retired.value | A boolean field indicating if the device is retired or not. | boolean |
| claroty_xdome.vulnerability.device.risk_score.points |  | double |
| claroty_xdome.vulnerability.device.risk_score.value |  | keyword |
| claroty_xdome.vulnerability.device.serial_number | The device's serial number. | keyword |
| claroty_xdome.vulnerability.device.site.group_name | The name of the site group within the organization the device is associated with. | keyword |
| claroty_xdome.vulnerability.device.site.name | The name of the site within the organization the device is associated with. | keyword |
| claroty_xdome.vulnerability.device.slot_cards.count |  | long |
| claroty_xdome.vulnerability.device.slot_cards.racks.cards.card_type |  | keyword |
| claroty_xdome.vulnerability.device.slot_cards.racks.cards.ip |  | ip |
| claroty_xdome.vulnerability.device.slot_cards.racks.cards.mac |  | keyword |
| claroty_xdome.vulnerability.device.slot_cards.racks.cards.model |  | keyword |
| claroty_xdome.vulnerability.device.slot_cards.racks.cards.name |  | keyword |
| claroty_xdome.vulnerability.device.slot_cards.racks.cards.serial_number |  | keyword |
| claroty_xdome.vulnerability.device.slot_cards.racks.cards.slot_number |  | long |
| claroty_xdome.vulnerability.device.slot_cards.racks.cards.sw_version |  | keyword |
| claroty_xdome.vulnerability.device.slot_cards.racks.cards.uid |  | keyword |
| claroty_xdome.vulnerability.device.slot_cards.racks.cards.vendor |  | keyword |
| claroty_xdome.vulnerability.device.slot_cards.racks.number_of_slots |  | long |
| claroty_xdome.vulnerability.device.snmp.hostnames |  | keyword |
| claroty_xdome.vulnerability.device.snmp.last_seen_hostname | The most recent unique hostname identifier of the device, extracted from SNMP protocol traffic. | keyword |
| claroty_xdome.vulnerability.device.software_or_firmware_version | The application version running on the device. | keyword |
| claroty_xdome.vulnerability.device.source | The sources that designated the vulnerability on the device, such as "Rapid7" | keyword |
| claroty_xdome.vulnerability.device.ssid_list | The name of the wireless network the device is connected to, such as "Guest". | keyword |
| claroty_xdome.vulnerability.device.status |  | keyword |
| claroty_xdome.vulnerability.device.subcategory | The device sub-category group (see "About Device Categorization" in the Knowledge Base). | keyword |
| claroty_xdome.vulnerability.device.suspicious | The reasons for which the device was marked as suspicious. | keyword |
| claroty_xdome.vulnerability.device.switch.group_name_list |  | keyword |
| claroty_xdome.vulnerability.device.switch.ip_list | The IP of the switch the device is connected to, extracted from various integrations. | ip |
| claroty_xdome.vulnerability.device.switch.location_list | The location of the switch the device is connected to. | keyword |
| claroty_xdome.vulnerability.device.switch.mac_list | The MAC address of the switch the device is connected to. | keyword |
| claroty_xdome.vulnerability.device.switch.name_list | The name of the switch the device is connected to. | keyword |
| claroty_xdome.vulnerability.device.switch.port_description_list | The description of the switch port to which the device is connected. | keyword |
| claroty_xdome.vulnerability.device.switch.port_list | The port identifier of the switch the device is connected to. | keyword |
| claroty_xdome.vulnerability.device.type.family | The device type family group. | keyword |
| claroty_xdome.vulnerability.device.type.value | The device type group. | keyword |
| claroty_xdome.vulnerability.device.uid | A universal unique identifier (UUID) for the device. | keyword |
| claroty_xdome.vulnerability.device.utilization_rate | The percentage of time the device was utilized within the past 3 months. | double |
| claroty_xdome.vulnerability.device.visibility_score.level |  | keyword |
| claroty_xdome.vulnerability.device.visibility_score.value |  | long |
| claroty_xdome.vulnerability.device.vlan.description_list | The description of the VLAN, extracted from switch configurations. | keyword |
| claroty_xdome.vulnerability.device.vlan.list | The virtual LAN to which the device belongs. | keyword |
| claroty_xdome.vulnerability.device.vlan.name_list | The name of the VLAN, extracted from switch configurations. | keyword |
| claroty_xdome.vulnerability.device.wifi_last_seen_list | Last date and time the device was seen on the access point. | date |
| claroty_xdome.vulnerability.device.windows.hostnames |  | keyword |
| claroty_xdome.vulnerability.device.windows.last_seen_hostname | The most recent unique hostname identifier of the device, extracted from Windows-specific protocols traffic. | keyword |
| claroty_xdome.vulnerability.device.wireless_encryption_type_list | The encryption method the device uses to connect to the wireless network, such as WEP or WPA2. | keyword |
| claroty_xdome.vulnerability.device.wlc.location_list | The encryption method the device uses to connect to the wireless network, such as WEP or WPA2. | keyword |
| claroty_xdome.vulnerability.device.wlc.name_list | The name of the Wireless LAN Controller that controls access points on the network. | keyword |
| claroty_xdome.vulnerability.epss_score | A probability score between 0 to 1 indicating the likelihoodof a vulnerability to be exploited in the wild, based on the Exploit Prediction Scoring System (EPSS) model. | double |
| claroty_xdome.vulnerability.exploits_count | An aggregated numeric field of the number of known exploits based on ExploitDB. | keyword |
| claroty_xdome.vulnerability.friendly_name | Vulnerability Name. | keyword |
| claroty_xdome.vulnerability.id | Unique identifier of the vulnerability. | keyword |
| claroty_xdome.vulnerability.is_known_exploited | A boolean field indicating whether a vulnerability is currently exploited in-the-wild, based on the CISA Catalog of Known Exploited Vulnerabilities. | boolean |
| claroty_xdome.vulnerability.labels | The labels added to the vulnerability manually or automatically. | keyword |
| claroty_xdome.vulnerability.name | Name designated by Claroty's Research team, based on the advisory name or CVE ID. | keyword |
| claroty_xdome.vulnerability.note | The notes added to the vulnerability. | keyword |
| claroty_xdome.vulnerability.priority_group | The Vulnerability Priority Group can be used to prioritize vulnerabilities based on the suggested order of hierarchical groups, determined by each vulnerabilities impact, exploitability characteristics, relevance state and remediation information. Device filters dynamically change the groups. | keyword |
| claroty_xdome.vulnerability.published_date | The date the vulnerability was published. | date |
| claroty_xdome.vulnerability.recommendations | Actionable recommendations retrieved from the vendor, CERT advisory and the platform.Such as security updates, upgrades and additional Workarounds to minimize the risk. | keyword |
| claroty_xdome.vulnerability.sources.name |  | keyword |
| claroty_xdome.vulnerability.sources.url |  | keyword |
| claroty_xdome.vulnerability.type | Type such as "Application", "Clinical", "IoT" or "Platform". | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| resource.id |  | keyword |
| resource.name |  | keyword |
| vulnerability.package.published_date |  | date |

