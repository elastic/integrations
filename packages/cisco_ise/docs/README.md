# Cisco ISE

The Cisco ISE integration collects and parses data from [Cisco Identity Services Engine](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html) (ISE) using TCP/UDP.

## Compatibility

This module has been tested against `Cisco ISE server version 3.1.0.518`.

## Requirements

- Enable the integration with the TCP/UDP input.
- Sign in to Cisco ISE Portal.
- Configure Remote Syslog Collection Locations.
  - **Procedure**
      1. In Cisco ISE Administrator Portal, go to **Administration** > **System** > **Logging** > **Remote Logging Targets**.
      2. Click **Add**.
      ![Cisco ISE server setup image](../img/cisco-ise-setup.png)
      3. Enter all the **Required Details**.
      4. Set the maximum length to **8192**.
      5. Click **Submit**. 
      6. Go to the **Remote Logging Targets** page and verify the creation of the new target.

## Note
- It is recommended to have **8192** as Maximum Message Length. Segmentation for certain logs coming from Cisco ISE might cause issues with field mappings. 

## Logs

Reference link for Cisco ISE Syslog: [Here](https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/Cisco_ISE_Syslogs/m_SyslogsList.html) 

### log

This is the `log` dataset.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2020-02-21T19:13:08.328Z",
    "agent": {
        "ephemeral_id": "1c70d737-7545-456d-8fb9-7033dca67ed3",
        "id": "901f4c48-583a-4848-aa7b-89dc8e9c4b76",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.2"
    },
    "cisco_ise": {
        "log": {
            "acct": {
                "request": {
                    "flags": "Stop"
                }
            },
            "acs": {
                "session": {
                    "id": "ldnnacpsn1/359344348/952729"
                }
            },
            "authen_method": "TacacsPlus",
            "avpair": {
                "priv_lvl": 15,
                "start_time": "2020-03-26T01:17:12.000Z",
                "task_id": "2962",
                "timezone": "GMT"
            },
            "category": {
                "name": "CISE_TACACS_Accounting"
            },
            "cmdset": "[ CmdAV=show mac-address-table <cr> ]",
            "config_version": {
                "id": 1829
            },
            "cpm": {
                "session": {
                    "id": "81.2.69.144Accounting306034364"
                }
            },
            "device": {
                "type": [
                    "Device Type#All Device Types#Routers",
                    "Device Type#All Device Types#Routers"
                ]
            },
            "ipsec": [
                "IPSEC#Is IPSEC Device",
                "IPSEC#Is IPSEC Device"
            ],
            "location": [
                "Location#All Locations#EMEA",
                "Location#All Locations#EMEA"
            ],
            "message": {
                "code": "3300",
                "description": "Tacacs-Accounting: TACACS+ Accounting with Command",
                "id": "0000000001"
            },
            "model": {
                "name": "Unknown"
            },
            "network": {
                "device": {
                    "groups": [
                        "Location#All Locations#EMEA",
                        "Device Type#All Device Types#Routers",
                        "IPSEC#Is IPSEC Device"
                    ],
                    "name": "wlnwan1",
                    "profile": [
                        "Cisco",
                        "Cisco"
                    ]
                }
            },
            "port": "tty10",
            "privilege": {
                "level": 15
            },
            "request": {
                "latency": 1
            },
            "response": {
                "AcctReply-Status": "Success"
            },
            "segment": {
                "number": 0,
                "total": 4
            },
            "selected": {
                "access": {
                    "service": "Device Admin - TACACS"
                }
            },
            "service": {
                "argument": "shell",
                "name": "Login"
            },
            "software": {
                "version": "Unknown"
            },
            "step": [
                "13006",
                "15049",
                "15008",
                "15048",
                "13035"
            ],
            "type": "Accounting"
        }
    },
    "client": {
        "ip": "81.2.69.144"
    },
    "data_stream": {
        "dataset": "cisco_ise.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "81.2.69.144"
    },
    "ecs": {
        "version": "8.10.0"
    },
    "elastic_agent": {
        "id": "901f4c48-583a-4848-aa7b-89dc8e9c4b76",
        "snapshot": false,
        "version": "8.10.2"
    },
    "event": {
        "action": "tacacs-accounting",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "cisco_ise.log",
        "ingested": "2023-10-03T09:31:56Z",
        "kind": "event",
        "original": "<182>Feb 21 19:13:08 cisco-ise-host CISE_TACACS_Accounting 0000000001 4 0 2020-02-21 19:13:08.328 +00:00 0018415781 3300 NOTICE Tacacs-Accounting: TACACS+ Accounting with Command, ConfigVersionId=1829, Device IP Address=81.2.69.144, CmdSet=[ CmdAV=show mac-address-table <cr> ], RequestLatency=1, NetworkDeviceName=wlnwan1, Type=Accounting, Privilege-Level=15, Service=Login, User=psxvne, Port=tty10, Remote-Address=81.2.69.144, Authen-Method=TacacsPlus, AVPair=task_id=2962, AVPair=timezone=GMT, AVPair=start_time=1585185432, AVPair=priv-lvl=15, AcctRequest-Flags=Stop, Service-Argument=shell, AcsSessionID=ldnnacpsn1/359344348/952729, SelectedAccessService=Device Admin - TACACS, Step=13006, Step=15049, Step=15008, Step=15048, Step=13035, NetworkDeviceGroups=Location#All Locations#EMEA, NetworkDeviceGroups=Device Type#All Device Types#Routers, NetworkDeviceGroups=IPSEC#Is IPSEC Device, CPMSessionID=81.2.69.144Accounting306034364, Model Name=Unknown, Software Version=Unknown, Network Device Profile=Cisco, Location=Location#All Locations#EMEA, Device Type=Device Type#All Device Types#Routers, IPSEC=IPSEC#Is IPSEC Device, Response={AcctReply-Status=Success; }, Network Device Profile=Cisco, Location=Location#All Locations#EMEA, Device Type=Device Type#All Device Types#Routers, IPSEC=IPSEC#Is IPSEC Device, Response={AcctReply-Status=Success; }",
        "sequence": 18415781,
        "timezone": "+00:00",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "cisco-ise-host"
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": 2080,
            "inode": 88860,
            "path": "/tmp/service_logs/log.log"
        },
        "level": "notice",
        "offset": 71596,
        "syslog": {
            "priority": 182,
            "severity": {
                "name": "notice"
            }
        }
    },
    "message": "2020-02-21 19:13:08.328 +00:00 0018415781 3300 NOTICE Tacacs-Accounting: TACACS+ Accounting with Command, ConfigVersionId=1829, Device IP Address=81.2.69.144, CmdSet=[ CmdAV=show mac-address-table <cr> ], RequestLatency=1, NetworkDeviceName=wlnwan1, Type=Accounting, Privilege-Level=15, Service=Login, User=psxvne, Port=tty10, Remote-Address=81.2.69.144, Authen-Method=TacacsPlus, AVPair=task_id=2962, AVPair=timezone=GMT, AVPair=start_time=1585185432, AVPair=priv-lvl=15, AcctRequest-Flags=Stop, Service-Argument=shell, AcsSessionID=ldnnacpsn1/359344348/952729, SelectedAccessService=Device Admin - TACACS, Step=13006, Step=15049, Step=15008, Step=15048, Step=13035, NetworkDeviceGroups=Location#All Locations#EMEA, NetworkDeviceGroups=Device Type#All Device Types#Routers, NetworkDeviceGroups=IPSEC#Is IPSEC Device, CPMSessionID=81.2.69.144Accounting306034364, Model Name=Unknown, Software Version=Unknown, Network Device Profile=Cisco, Location=Location#All Locations#EMEA, Device Type=Device Type#All Device Types#Routers, IPSEC=IPSEC#Is IPSEC Device, Response={AcctReply-Status=Success; }, Network Device Profile=Cisco, Location=Location#All Locations#EMEA, Device Type=Device Type#All Device Types#Routers, IPSEC=IPSEC#Is IPSEC Device, Response={AcctReply-Status=Success; }",
    "related": {
        "hosts": [
            "cisco-ise-host"
        ],
        "ip": [
            "81.2.69.144"
        ],
        "user": [
            "psxvne"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisco_ise-log"
    ],
    "user": {
        "name": "psxvne"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_ise.log.acct.authentic |  | keyword |
| cisco_ise.log.acct.delay_time |  | long |
| cisco_ise.log.acct.input.octets |  | long |
| cisco_ise.log.acct.input.packets |  | long |
| cisco_ise.log.acct.output.octets |  | long |
| cisco_ise.log.acct.output.packets |  | long |
| cisco_ise.log.acct.request.flags |  | keyword |
| cisco_ise.log.acct.session.id |  | keyword |
| cisco_ise.log.acct.session.time |  | long |
| cisco_ise.log.acct.status.type |  | keyword |
| cisco_ise.log.acct.terminate_cause |  | keyword |
| cisco_ise.log.acme-av-pair.audit-session-id |  | keyword |
| cisco_ise.log.acme-av-pair.service-type |  | keyword |
| cisco_ise.log.acs.instance |  | keyword |
| cisco_ise.log.acs.session.id |  | keyword |
| cisco_ise.log.active_session.count |  | long |
| cisco_ise.log.ad.admin |  | keyword |
| cisco_ise.log.ad.domain.controller |  | keyword |
| cisco_ise.log.ad.domain.name |  | keyword |
| cisco_ise.log.ad.error.details |  | keyword |
| cisco_ise.log.ad.forest |  | keyword |
| cisco_ise.log.ad.hostname |  | keyword |
| cisco_ise.log.ad.ip |  | ip |
| cisco_ise.log.ad.log |  | keyword |
| cisco_ise.log.ad.log_id |  | keyword |
| cisco_ise.log.ad.organization_unit |  | text |
| cisco_ise.log.ad.site |  | keyword |
| cisco_ise.log.ad.srv.query |  | keyword |
| cisco_ise.log.ad.srv.record |  | keyword |
| cisco_ise.log.adapter_instance.name |  | keyword |
| cisco_ise.log.adapter_instance.uuid |  | keyword |
| cisco_ise.log.admin.interface |  | keyword |
| cisco_ise.log.admin.session |  | keyword |
| cisco_ise.log.airespace.wlan.id |  | long |
| cisco_ise.log.allow.easy.wired.session |  | keyword |
| cisco_ise.log.allowed_protocol.matched.rule |  | keyword |
| cisco_ise.log.assigned_targets |  | keyword |
| cisco_ise.log.auth.policy.matched.rule |  | keyword |
| cisco_ise.log.authen_method |  | keyword |
| cisco_ise.log.authentication.identity_store |  | keyword |
| cisco_ise.log.authentication.method |  | keyword |
| cisco_ise.log.authentication.status |  | keyword |
| cisco_ise.log.average.radius.request.latency |  | long |
| cisco_ise.log.average.tacacs.request.latency |  | long |
| cisco_ise.log.avpair.disc.cause |  | long |
| cisco_ise.log.avpair.disc.cause_ext |  | long |
| cisco_ise.log.avpair.elapsed_time |  | long |
| cisco_ise.log.avpair.pre_session_time |  | long |
| cisco_ise.log.avpair.priv_lvl |  | long |
| cisco_ise.log.avpair.start_time |  | date |
| cisco_ise.log.avpair.stop_time |  | date |
| cisco_ise.log.avpair.task_id |  | keyword |
| cisco_ise.log.avpair.timezone |  | keyword |
| cisco_ise.log.called_station.id |  | keyword |
| cisco_ise.log.calling_station.id |  | keyword |
| cisco_ise.log.category.name |  | keyword |
| cisco_ise.log.cisco_av_pair.coa-push |  | boolean |
| cisco_ise.log.cisco_av_pair.cts-device-capability |  | keyword |
| cisco_ise.log.cisco_av_pair.cts-environment-data |  | keyword |
| cisco_ise.log.cisco_av_pair.cts-environment-version |  | keyword |
| cisco_ise.log.cisco_av_pair.cts-pac-opaque |  | keyword |
| cisco_ise.log.class |  | keyword |
| cisco_ise.log.client.latency |  | long |
| cisco_ise.log.cmdset |  | keyword |
| cisco_ise.log.component |  | keyword |
| cisco_ise.log.config_change.data |  | keyword |
| cisco_ise.log.config_version.id |  | long |
| cisco_ise.log.connectivity |  | keyword |
| cisco_ise.log.cpm.session.id |  | keyword |
| cisco_ise.log.currentid.store_name |  | keyword |
| cisco_ise.log.delta.radius.request.count |  | long |
| cisco_ise.log.delta.tacacs.request.count |  | long |
| cisco_ise.log.detailed_info |  | text |
| cisco_ise.log.details |  | keyword |
| cisco_ise.log.device.name |  | keyword |
| cisco_ise.log.device.registration_status |  | keyword |
| cisco_ise.log.device.type |  | keyword |
| cisco_ise.log.dtls_support |  | keyword |
| cisco_ise.log.eap.authentication |  | keyword |
| cisco_ise.log.eap.chaining_result |  | keyword |
| cisco_ise.log.eap.tunnel |  | keyword |
| cisco_ise.log.eap_key.name |  | keyword |
| cisco_ise.log.enable.flag |  | keyword |
| cisco_ise.log.endpoint.coa |  | keyword |
| cisco_ise.log.endpoint.mac.address |  | keyword |
| cisco_ise.log.endpoint.policy |  | keyword |
| cisco_ise.log.endpoint.profiler |  | keyword |
| cisco_ise.log.endpoint.purge.id |  | keyword |
| cisco_ise.log.endpoint.purge.rule |  | keyword |
| cisco_ise.log.endpoint.purge.scheduletype |  | keyword |
| cisco_ise.log.ep.identity_group |  | keyword |
| cisco_ise.log.ep.mac.address |  | keyword |
| cisco_ise.log.error.message |  | keyword |
| cisco_ise.log.event.timestamp |  | date |
| cisco_ise.log.failure.flag |  | boolean |
| cisco_ise.log.failure.reason |  | keyword |
| cisco_ise.log.feed_service.feed.name |  | keyword |
| cisco_ise.log.feed_service.feed.version |  | keyword |
| cisco_ise.log.feed_service.host |  | keyword |
| cisco_ise.log.feed_service.port |  | keyword |
| cisco_ise.log.feed_service.query.from_time |  | date |
| cisco_ise.log.feed_service.query.to_time |  | date |
| cisco_ise.log.file.name |  | keyword |
| cisco_ise.log.first_name |  | keyword |
| cisco_ise.log.framed.ip |  | ip |
| cisco_ise.log.framed.mtu |  | long |
| cisco_ise.log.groups.process_failure |  | boolean |
| cisco_ise.log.guest.user.name |  | keyword |
| cisco_ise.log.identity.group |  | keyword |
| cisco_ise.log.identity.policy.matched.rule |  | keyword |
| cisco_ise.log.identity.selection.matched.rule |  | keyword |
| cisco_ise.log.ipsec |  | keyword |
| cisco_ise.log.is_third_party_device_flow |  | boolean |
| cisco_ise.log.ise.policy.set_name |  | keyword |
| cisco_ise.log.last_name |  | keyword |
| cisco_ise.log.local_logging |  | keyword |
| cisco_ise.log.location |  | keyword |
| cisco_ise.log.log_details |  | flattened |
| cisco_ise.log.log_error.message |  | keyword |
| cisco_ise.log.log_severity_level |  | keyword |
| cisco_ise.log.logger.name |  | keyword |
| cisco_ise.log.message.code |  | keyword |
| cisco_ise.log.message.description |  | text |
| cisco_ise.log.message.id |  | keyword |
| cisco_ise.log.message.text |  | keyword |
| cisco_ise.log.misconfigured.client.fix.reason |  | keyword |
| cisco_ise.log.model.name |  | keyword |
| cisco_ise.log.nas.identifier |  | keyword |
| cisco_ise.log.nas.ip |  | ip |
| cisco_ise.log.nas.port.id |  | keyword |
| cisco_ise.log.nas.port.number |  | long |
| cisco_ise.log.nas.port.type |  | keyword |
| cisco_ise.log.network.device.groups |  | keyword |
| cisco_ise.log.network.device.name |  | keyword |
| cisco_ise.log.network.device.profile |  | keyword |
| cisco_ise.log.network.device.profile_id |  | keyword |
| cisco_ise.log.network.device.profile_name |  | keyword |
| cisco_ise.log.object.internal.id |  | keyword |
| cisco_ise.log.object.name |  | keyword |
| cisco_ise.log.object.type |  | keyword |
| cisco_ise.log.objects.purged |  | keyword |
| cisco_ise.log.openssl.error.message |  | keyword |
| cisco_ise.log.openssl.error.stack |  | keyword |
| cisco_ise.log.operation.id |  | keyword |
| cisco_ise.log.operation.status |  | keyword |
| cisco_ise.log.operation.type |  | keyword |
| cisco_ise.log.operation_counters.counters |  | flattened |
| cisco_ise.log.operation_counters.original |  | text |
| cisco_ise.log.operation_message.text |  | keyword |
| cisco_ise.log.original.user.name |  | keyword |
| cisco_ise.log.policy.type |  | keyword |
| cisco_ise.log.port |  | keyword |
| cisco_ise.log.portal.name |  | keyword |
| cisco_ise.log.posture.assessment.status |  | keyword |
| cisco_ise.log.privilege.level |  | long |
| cisco_ise.log.probe |  | keyword |
| cisco_ise.log.profiler.server |  | keyword |
| cisco_ise.log.protocol |  | keyword |
| cisco_ise.log.psn.hostname |  | keyword |
| cisco_ise.log.radius.flow.type |  | keyword |
| cisco_ise.log.radius.packet.type |  | keyword |
| cisco_ise.log.radius_identifier |  | long |
| cisco_ise.log.radius_packet.type |  | keyword |
| cisco_ise.log.request.latency |  | long |
| cisco_ise.log.request.received_time |  | date |
| cisco_ise.log.request_response.type |  | keyword |
| cisco_ise.log.response |  | flattened |
| cisco_ise.log.segment.number |  | long |
| cisco_ise.log.segment.total |  | long |
| cisco_ise.log.selected.access.service |  | keyword |
| cisco_ise.log.selected.authentication.identity_stores |  | keyword |
| cisco_ise.log.selected.authorization.profiles |  | keyword |
| cisco_ise.log.sequence.number |  | long |
| cisco_ise.log.server.name |  | keyword |
| cisco_ise.log.server.type |  | keyword |
| cisco_ise.log.service.argument |  | keyword |
| cisco_ise.log.service.name |  | keyword |
| cisco_ise.log.service.type |  | keyword |
| cisco_ise.log.session.timeout |  | long |
| cisco_ise.log.severity.level |  | long |
| cisco_ise.log.software.version |  | keyword |
| cisco_ise.log.state |  | text |
| cisco_ise.log.static.assignment |  | boolean |
| cisco_ise.log.status |  | keyword |
| cisco_ise.log.step |  | keyword |
| cisco_ise.log.step_data |  | keyword |
| cisco_ise.log.step_latency |  | keyword |
| cisco_ise.log.sysstats.acs.process.health |  | flattened |
| cisco_ise.log.sysstats.cpu.count |  | long |
| cisco_ise.log.sysstats.process_memory_mb |  | long |
| cisco_ise.log.sysstats.utilization.cpu |  | double |
| cisco_ise.log.sysstats.utilization.disk.io |  | double |
| cisco_ise.log.sysstats.utilization.disk.space |  | keyword |
| cisco_ise.log.sysstats.utilization.load_avg |  | double |
| cisco_ise.log.sysstats.utilization.memory |  | double |
| cisco_ise.log.sysstats.utilization.network |  | keyword |
| cisco_ise.log.tls.cipher |  | keyword |
| cisco_ise.log.tls.version |  | keyword |
| cisco_ise.log.total.authen.latency |  | long |
| cisco_ise.log.total.failed_attempts |  | long |
| cisco_ise.log.total.failed_time |  | long |
| cisco_ise.log.tunnel.medium.type |  | keyword |
| cisco_ise.log.tunnel.private.group_id |  | keyword |
| cisco_ise.log.tunnel.type |  | keyword |
| cisco_ise.log.type |  | keyword |
| cisco_ise.log.undefined_52 |  | keyword |
| cisco_ise.log.usecase |  | keyword |
| cisco_ise.log.user.type |  | keyword |
| cisco_ise.log.workflow |  | flattened |
| client.geo.city_name | City name. | keyword |
| client.geo.continent_code | Two-letter code representing continent's name. | keyword |
| client.geo.continent_name | Name of the continent. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| client.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| client.geo.region_iso_code | Region ISO code. | keyword |
| client.geo.region_name | Region name. | keyword |
| client.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.port | Port of the client. | long |
| client.user.name | Short name or login of the user. | keyword |
| client.user.name.text | Multi-field of `client.user.name`. | match_only_text |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_code | Two-letter code representing continent's name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| destination.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.geo.city_name | City name. | keyword |
| host.geo.continent_code | Two-letter code representing continent's name. | keyword |
| host.geo.continent_name | Name of the continent. | keyword |
| host.geo.country_iso_code | Country ISO code. | keyword |
| host.geo.country_name | Country name. | keyword |
| host.geo.location | Longitude and latitude. | geo_point |
| host.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| host.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| host.geo.region_iso_code | Region ISO code. | keyword |
| host.geo.region_name | Region name. | keyword |
| host.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.name | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different severity value (e.g. firewall, IDS), your source's text severity should go to `log.level`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `log.level`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_code | Two-letter code representing continent's name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| source.user.group.name | Name of the group. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
