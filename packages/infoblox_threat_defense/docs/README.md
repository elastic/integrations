# Infoblox Threat Defense

## Overview

[Infoblox Threat Defense](https://www.infoblox.com/products/threat-defense/) is a DNS-based security solution that protects networks from cyber threats by detecting and blocking malicious domain activity in real time. It uses threat intelligence, DNS firewalling, and behavioral analytics to identify threats like malware, phishing, and data exfiltration at the DNS layer — often before they reach endpoints or firewalls. Available as a cloud-native platform (BloxOne Threat Defense), it integrates with security tools (like SIEMs and firewalls) and supports both on-prem and hybrid deployments.

This integration supports CEF-formatted logs transmitted through a syslog server over TCP, UDP, or TLS protocols.

## Data streams

The Infoblox Threat Defense integration collects the following types of events.

- **Audit:** - The audit log reports all administrative activities performed by specific user accounts.

- **Service:** - The Service Log reports all service events.

- **Atlas Notifications:** - Atlas Notifications reports all internal notification events.

- **SOC Insights:** - The SOC Insights log reports information about SOC Insights security events.

- **Threat Defense Query/Response (TD DNS):** - The Threat Defense Query/Response Log reports DNS query requests and responses in Infoblox Threat Defense.

- **Threat Defense Threat Feeds Hit (TD RPZ):** - The Threat Defense Threat Feeds Hit Log reports Infoblox Threat Defense feeds hit information.

- **DDI DHCP Lease (DDI DHCP):** - The DDI DHCP Lease Log reports information about Dynamic Host Configuration Protocol (DHCP) lease assignments and terminations.

- **DDI Query/Response (DDI DNS):** - The DDI Query/Response Log reports DNS query requests and responses in Universal DDI.

**NOTE**: While the Infoblox Threat Defense integration collects logs for various event types, we have consolidated them into a single data stream named `event`.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### To collect data from the Infoblox Threat Defense:

1. To collect logs through the syslog server, you need to deploy a Data Connector VM by following the instructions provided [here](https://docs.infoblox.com/space/BloxOneCloud/35429862/Deploying+the+Data+Connector+Solution).
2. Once the Data Connector is successfully deployed, you need to configure the traffic flow to forward logs to your syslog server. Refer to this [link](https://docs.infoblox.com/space/BloxOneCloud/35397475/Configuring+Traffic+Flows) for guidance.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Infoblox Threat Defense`.
3. Select "Infoblox Threat Defense" integration from the search results.
4. Click on the "Add Infoblox Threat Defense" button to add the integration.
5. Enable the data collection mode from the following: TCP, or UDP.
6. Add all the required configuration parameters, such as listen address and listen port for the TCP and UDP, and ssl for the TLS.
8. Click on "Save and Continue" to save the integration.

## Logs reference

### Event

This is the `Event` dataset.

**NOTE**: The `InfobloxDHCPOptions` field will not be populated because it contains a special pattern with special characters that `decode_cef` cannot parse. As a result, this field will be dropped.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2021-03-03T11:57:45.000Z",
    "agent": {
        "ephemeral_id": "7abd4432-6ec9-40f6-bda3-273b38b55c88",
        "id": "64c9d588-6e7c-45ba-8c8b-4d41b6665cba",
        "name": "elastic-agent-49246",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "infoblox_threat_defense.event",
        "namespace": "13231",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 1221,
            "organization": {
                "name": "Telstra Pty Ltd"
            }
        },
        "ip": "1.128.0.1"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "64c9d588-6e7c-45ba-8c8b-4d41b6665cba",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "action": "delete",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "code": "DHCP-LEASE-DELETE",
        "created": "2021-03-03T11:57:45.000Z",
        "dataset": "infoblox_threat_defense.event",
        "ingested": "2025-07-11T07:33:55Z",
        "kind": "event",
        "original": "CEF:0|Infoblox|Data Connector|2.1.3|DHCP-LEASE-DELETE|DHCP Lease Delete|1|src=175.16.199.0 InfobloxClientID=01:00:1A:2B:3C:4D:5E InfobloxHostID=dhcp/host/1516583 InfobloxFingerprintPr=true InfobloxRangeEnd=67.43.156.10 InfobloxRangeStart=67.43.156.0 smac=00:1A:2B:3C:4D:5E InfobloxIPSpace=ipam/ip_space/1f99d3a6-2982-11f0-b65e-fe20d626f7e6 InfobloxSubnet=175.16.199.0/24 InfobloxFingerprint=VMware::Windows: shost= InfobloxLeaseUUID=a91838a3-4679-11f0-b018-ee5154718d37 InfobloxLifetime=3600 InfobloxLeaseOp=Delete app=DHCP cat=DHCP Lease Delete InfobloxDUID= InfobloxHost= dst=1.128.0.1",
        "severity": 21,
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "1516583"
    },
    "infoblox_threat_defense": {
        "event": {
            "application_protocol": "DHCP",
            "created": "2021-03-03T11:57:45.000Z",
            "destination": {
                "address": "1.128.0.1"
            },
            "device": {
                "event_category": "DHCP Lease Delete",
                "event_class_id": "DHCP-LEASE-DELETE",
                "product": "Data Connector",
                "vendor": "Infoblox",
                "version": "2.1.3"
            },
            "infoblox": {
                "client_id": "01:00:1A:2B:3C:4D:5E",
                "fingerprint": "VMware::Windows:",
                "fingerprint_pr": true,
                "host_id": "dhcp/host/1516583",
                "ip_space": {
                    "value": "ipam/ip_space/1f99d3a6-2982-11f0-b65e-fe20d626f7e6"
                },
                "lease": {
                    "op": "Delete",
                    "uuid": "a91838a3-4679-11f0-b018-ee5154718d37"
                },
                "lifetime": 3600,
                "range": {
                    "end": "67.43.156.10",
                    "start": "67.43.156.0"
                },
                "subnet": "175.16.199.0/24"
            },
            "name": "DHCP Lease Delete",
            "severity": 1,
            "source": {
                "address": "175.16.199.0",
                "mac_address": "00:1a:2b:3c:4d:5e"
            },
            "syslog": {
                "appname": "dataconnector",
                "facility": {
                    "code": 16,
                    "name": "local0"
                },
                "msgid": "DHCP-LEASE-DELETE",
                "priority": 134,
                "severity": {
                    "code": 6,
                    "name": "Informational"
                },
                "version": "1"
            },
            "version": "0"
        }
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "192.168.246.3:38218"
        }
    },
    "network": {
        "application": "dhcp"
    },
    "observer": {
        "product": "Data Connector",
        "vendor": "Infoblox",
        "version": "2.1.3"
    },
    "related": {
        "hosts": [
            "1516583"
        ],
        "ip": [
            "1.128.0.1",
            "67.43.156.10",
            "67.43.156.0",
            "175.16.199.0"
        ]
    },
    "source": {
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
        "mac": "00-1A-2B-3C-4D-5E"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "infoblox_threat_defense-event"
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
| infoblox_threat_defense.event.application_protocol |  | keyword |
| infoblox_threat_defense.event.created |  | date |
| infoblox_threat_defense.event.destination.address |  | ip |
| infoblox_threat_defense.event.destination.dns_domain |  | keyword |
| infoblox_threat_defense.event.device.action |  | keyword |
| infoblox_threat_defense.event.device.address |  | ip |
| infoblox_threat_defense.event.device.event_category |  | keyword |
| infoblox_threat_defense.event.device.event_class_id |  | keyword |
| infoblox_threat_defense.event.device.host_ip |  | ip |
| infoblox_threat_defense.event.device.host_name |  | keyword |
| infoblox_threat_defense.event.device.product |  | keyword |
| infoblox_threat_defense.event.device.vendor |  | keyword |
| infoblox_threat_defense.event.device.version |  | keyword |
| infoblox_threat_defense.event.infoblox.an_count |  | keyword |
| infoblox_threat_defense.event.infoblox.ar_count |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.connection_type |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.dhcp_fingerprint |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.dns_tags |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.feed.name |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.feed.type |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.network |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.oph.ip_address |  | ip |
| infoblox_threat_defense.event.infoblox.b1.oph.name |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.policy.action |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.policy.name |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.region |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.src_os_version |  | keyword |
| infoblox_threat_defense.event.infoblox.b1.threat.indicator |  | keyword |
| infoblox_threat_defense.event.infoblox.c_site_id |  | keyword |
| infoblox_threat_defense.event.infoblox.client_id |  | keyword |
| infoblox_threat_defense.event.infoblox.dhcp_options |  | keyword |
| infoblox_threat_defense.event.infoblox.dns_q.class |  | keyword |
| infoblox_threat_defense.event.infoblox.dns_q.flags |  | keyword |
| infoblox_threat_defense.event.infoblox.dns_q.type |  | keyword |
| infoblox_threat_defense.event.infoblox.dns_r_code |  | keyword |
| infoblox_threat_defense.event.infoblox.dns_view |  | keyword |
| infoblox_threat_defense.event.infoblox.domain.cat |  | keyword |
| infoblox_threat_defense.event.infoblox.duid |  | keyword |
| infoblox_threat_defense.event.infoblox.event.occurred_time |  | date |
| infoblox_threat_defense.event.infoblox.event.version |  | keyword |
| infoblox_threat_defense.event.infoblox.event_occurred_time |  | date |
| infoblox_threat_defense.event.infoblox.fingerprint |  | keyword |
| infoblox_threat_defense.event.infoblox.fingerprint_pr |  | boolean |
| infoblox_threat_defense.event.infoblox.host_id |  | keyword |
| infoblox_threat_defense.event.infoblox.host_name |  | keyword |
| infoblox_threat_defense.event.infoblox.http.req_body |  | flattened |
| infoblox_threat_defense.event.infoblox.http.resp_body |  | flattened |
| infoblox_threat_defense.event.infoblox.insight.description |  | keyword |
| infoblox_threat_defense.event.infoblox.insight.feed_source |  | keyword |
| infoblox_threat_defense.event.infoblox.insight.id |  | keyword |
| infoblox_threat_defense.event.infoblox.insight.status |  | keyword |
| infoblox_threat_defense.event.infoblox.insight.threat_type |  | keyword |
| infoblox_threat_defense.event.infoblox.insight.user_comment |  | keyword |
| infoblox_threat_defense.event.infoblox.ip_space.name |  | keyword |
| infoblox_threat_defense.event.infoblox.ip_space.value |  | keyword |
| infoblox_threat_defense.event.infoblox.lease.op |  | keyword |
| infoblox_threat_defense.event.infoblox.lease.uuid |  | keyword |
| infoblox_threat_defense.event.infoblox.lifetime |  | long |
| infoblox_threat_defense.event.infoblox.log_name |  | keyword |
| infoblox_threat_defense.event.infoblox.notification.sub_type |  | keyword |
| infoblox_threat_defense.event.infoblox.notification.type |  | keyword |
| infoblox_threat_defense.event.infoblox.ns_count |  | keyword |
| infoblox_threat_defense.event.infoblox.on_prem_host_name |  | keyword |
| infoblox_threat_defense.event.infoblox.policy.id |  | keyword |
| infoblox_threat_defense.event.infoblox.pool_id |  | keyword |
| infoblox_threat_defense.event.infoblox.range.end |  | ip |
| infoblox_threat_defense.event.infoblox.range.start |  | ip |
| infoblox_threat_defense.event.infoblox.resource.desc |  | keyword |
| infoblox_threat_defense.event.infoblox.resource.id |  | keyword |
| infoblox_threat_defense.event.infoblox.resource.type |  | keyword |
| infoblox_threat_defense.event.infoblox.rpz.rule |  | keyword |
| infoblox_threat_defense.event.infoblox.rpz.value |  | keyword |
| infoblox_threat_defense.event.infoblox.service_id |  | keyword |
| infoblox_threat_defense.event.infoblox.stats.events_blocked_count |  | keyword |
| infoblox_threat_defense.event.infoblox.stats.events_not_blocked_count |  | keyword |
| infoblox_threat_defense.event.infoblox.subject.groups |  | keyword |
| infoblox_threat_defense.event.infoblox.subject.type |  | keyword |
| infoblox_threat_defense.event.infoblox.subnet |  | keyword |
| infoblox_threat_defense.event.infoblox.threat.class |  | keyword |
| infoblox_threat_defense.event.infoblox.threat.confidence |  | long |
| infoblox_threat_defense.event.infoblox.threat.family |  | keyword |
| infoblox_threat_defense.event.infoblox.threat.level |  | long |
| infoblox_threat_defense.event.infoblox.threat.property |  | keyword |
| infoblox_threat_defense.event.infoblox_notification.type |  | keyword |
| infoblox_threat_defense.event.message |  | keyword |
| infoblox_threat_defense.event.name |  | keyword |
| infoblox_threat_defense.event.outcome |  | keyword |
| infoblox_threat_defense.event.severity |  | long |
| infoblox_threat_defense.event.source.address |  | ip |
| infoblox_threat_defense.event.source.hostname |  | keyword |
| infoblox_threat_defense.event.source.mac_address |  | keyword |
| infoblox_threat_defense.event.source.port |  | long |
| infoblox_threat_defense.event.source.user_name |  | keyword |
| infoblox_threat_defense.event.stats.base_event_count |  | long |
| infoblox_threat_defense.event.status |  | keyword |
| infoblox_threat_defense.event.syslog.appname |  | keyword |
| infoblox_threat_defense.event.syslog.facility.code |  | long |
| infoblox_threat_defense.event.syslog.facility.name |  | keyword |
| infoblox_threat_defense.event.syslog.hostname |  | keyword |
| infoblox_threat_defense.event.syslog.msgid |  | keyword |
| infoblox_threat_defense.event.syslog.priority |  | long |
| infoblox_threat_defense.event.syslog.severity.code |  | long |
| infoblox_threat_defense.event.syslog.severity.name |  | keyword |
| infoblox_threat_defense.event.syslog.version |  | keyword |
| infoblox_threat_defense.event.transport_protocol |  | keyword |
| infoblox_threat_defense.event.version |  | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read/sent from. | keyword |

