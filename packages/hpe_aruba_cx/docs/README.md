# HPE Aruba CX Integration

The HPE Aruba CX integration allows you to monitor the HPE Aruba Networking CX Switch. The switch series is modern, flexible, and intelligent stackable switch series ideally for enterprise network access, aggregation, core, and data center top of rack (ToR) deployments.

Use the HPE Aruba integration and follow the setup steps listed below to forward the CX Switch logging to a deployed standalone or managed Beat at a specific port listening for TCP or UDP data. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference `log` when troubleshooting data/error issue encountered in the field.


## Compatibility

This package follows the [5200-8214 specification](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/PDF/5200-8214.pdf) and has been tested from sample logs captured from the HPE Aruba Networking CX Switches: **6000, 6300 and 8360** on the 10.07 version of the specification. As new appliances and OSes are released, they are expected to be compatible with the integration but Elastic does not guarantee compatibility with new/old version of the product line.
The integration ONLY supports logs in ENGLISH, internationalization of logs to other languages are NOT supported.


## Data streams

The HPE Aruba CX integration collects events into data stream: `log`



## Requirements

Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
We recommend using our hosted Elasticsearch Service on Elastic Cloud, or self-manage the Elastic Stack on your own hardware.


## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

### Additional Set Up Instructions

Follow the support documentation offered by HPE Aruba AOS-CX CLI to setup forwarding of logs to a self-managed or managed Beat: 
[Enables syslog forwarding to a remote syslog server](https://www.arubanetworks.com/techdocs/AOS-CX/AOSCX-CLI-Bank/cli_4100i/Content/Chp_RSyslog/RSyslog_cmds/log-10.htm)


## Logs
### Exported fields

Below are the fields from the different event types and their mapping into ECS supported fields or customer Aruba fields

To Be Removed
Note: Field types are defined within `fields.yml`
Note: Descriptions have not been filled out

#### [AAA events (Aruba Docs)](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/AAA.htm)
| Doc Fields         | Schema Mapping               |
|--------------------|------------------------------|
| <aaa_config_type>  | aruba.aaa.config_event       |
| <aaa_config_event> | aruba.aaa.config_type        |
| <tacacs_action>    | aruba.aaa.radius_action      |
| <radius_event>     | aruba.aaa.radius_event       |
| <server_address>   | server.address               |
| <server_authport>  | aruba.port                   |
| <status>           | aruba.status                 |
| <server_vrfid>     | aruba.vrf.id                 |
| <radius_type>      | event.type                   |
| <tacacs_action>    | aruba.aaa.tacacs_action      |
| <tacacs_event>     | aruba.aaa.tacacs_event       |
| <server_address>   | server.address               |
| <server_authport>  | aruba.port                   |
| <server_vrfid>     | aruba.vrf.id                 |
| <tacacs_type>      | aruba.aaa.tacacs_type        |

#### [ACLs events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ACL.htm)
| Doc Fields        | Schema Mapping         |
|-------------------|------------------------|
| <log>             | message                |
| <type>            | aruba.acl.type         |
| <ace_string>      | aruba.acl.ace_string   |
| <application>     | aruba.acl.application  |
| <direction>       | aruba.acl.direction    |
| <hit_delta>       | aruba.acl.hit_delta    |
| <interface_name>  | aruba.interface.name   |
| <name>            | aruba.acl.name         |

#### [ARP security events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ARP-SECURITY.htm)
| Doc Fields  | Schema Mapping  |
|-------------|-----------------|
| <port_name> | aruba.port      |
| <status>    | aruba.status    |
| <vlan_id>   | network.vlan.id |

#### [ASIC table full error for L3PD events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/L3_ASIC_RESOURCE.htm)
| Doc Fields | Schema Mapping |
|------------|----------------|


#### [BFD events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/BFD.htm)
| Doc Fields           | Schema Mapping               |
|----------------------|------------------------------|
| <applied_interval>   | aruba.bfd.applied_interval   |
| <dest_ip>            | destination.ip               |
| <direction>          | network.direction            |
| <from>               | aruba.bfd.from               |
| <intf>               | aruba.interface.id           |
| <invalid_ip>         | aruba.bfd.invalid_ip         |
| <ip_version>         | aruba.bfd.ip_version         |
| <local_diag>         | aruba.bfd.local_diag         |
| <local_state>        | aruba.bfd.local_state        |
| <op_mode>            | aruba.bfd.op_mode            |
| <port_name>          | aruba.port                   |
| <remote_diag>        | aruba.bfd.remote_diag        |
| <remote_state>       | aruba.bfd.remote_state       |
| <requested_interval> | aruba.bfd.requested_interval |
| <session_id>         | aruba.session.id             |
| <src_port>           | aruba.port                   |
| <vrf>                | aruba.vrf.id                 |

#### [BGP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/BGP.htm)
| Doc Fields        | Schema Mapping            |
|-------------------|---------------------------|
| <as_number>       | aruba.bgp.as_number       |
| <id>              | aruba.bgp.id              |
| <error-code>      | error.code                |
| <error-subcode>   | aruba.bgp.error_subcode   |
| <local_as>        | client.as.number          |
| <pg_name>         | aruba.bgp.pg_name         |
| <remote-addr>     | destination.address       |
| <remote_as>       | destination.as.number     |
| <src_ipaddr>      | source.ip                 |
| <threshold_limit> | aruba.bgp.threshold_limit |
| <vrf-name>        | aruba.vrf.name            |

#### [Bluetooth Management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/BLUETOOTH_MGMT.htm)
| Doc Fields               | Schema Mapping               |
|--------------------------|------------------------------|
| <connected_disconnected> | event.action                 |
| <enabled_disabled>       | event.action                 |
| <inserted_removed>       | event.action                 |
| <mac>                    | client.mac                   |

#### [CDP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CDP.htm)
| Doc Fields | Schema Mapping       |
|------------|----------------------|
| <interface> | aruba.interface.name |
| <mac>       | source.mac           |

#### [Certificate management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CERTMGR.htm)
| Doc Fields     | Schema Mapping        |
|----------------|-----------------------|
| <cert_name>    | aruba.cm.cert_name    |
| <days>         | aruba.cm.days         |
| <error>        | event.reason          |
| <est_name>     | aruba.cm.est_name     |
| <profile_name> | aruba.cm.profile_name |
| <status>       | aruba.status          |

#### [Config Management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CONFIG_MGMT.htm)
| Doc Fields | Schema Mapping       |
|------------|----------------------|
| <error>      | event.reason         |
| <from>       | aruba.config.from    |
| <info>       | event.action         |
| <to>         | aruba.config.to      |
| <type>       | aruba.config.type    |
| <value>      | aruba.config.value   |

#### [Connectivity Fault Management (CFM) events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ETH_OAM_CFM.htm)
| Doc Fields  | Schema Mapping      |
|-------------|---------------------|
| <id>        | aruba.cfm.id        |
| <interface> | aruba.cfm.interfact |

#### [Container manager events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CONTAINER.htm)
| Doc Fields | Schema Mapping   |
|------------|------------------|
| <name>     | container.name   |

#### [CoPP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/COPP.htm)
| Doc Field                    | Schema Mapping      |
|------------------------------|---------------------|
| <class>                      | aruba.copp.class    |
| <slot>                       | aruba.slot          |

#### [CPU_RX events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CPU_RX.htm)
| Doc Field                    | Schema Mapping                  |
|------------------------------|---------------------------------|
| <action>                     | event.action                    |
| <filter_description>         | aruba.cpu_rx.filter_description |
| <unit>                       | aruba.instance.id               |

#### [Credential Manager events DHCP Relay events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CREDMGR.htm)
| Doc Field | Schema Mapping |
|-----------|----------------|
| <key-id>  | user.id        |
| <user>    | user.name      |

#### [DHCP Relay events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DHCP-RELAY.htm)
| Doc Field | Schema Mapping |
|-----------|----------------|

#### [DHCP Server events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DHCP-SERVER.htm)
| Doc Field     | Schema Mapping    |
|---------------|-------------------|
| <client_id>   | user.id           |
| <config>      | aruba.dhcp.config |
| <expiry_time> | event.end         |
| <host>        | host.name         |
| <ip>          | host.ip           |
| <mac>         | host.mac          |
| <vfr>         | aruba.vrf.id      |
| <vfr_name>    | aruba.vrf.name    |

#### [DHCPv4 Snooping events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DHCPv4-SNOOPING.htm)
| Field                    | Description | Type | Common             |
|--------------------------|-------------|------|--------------------|
| aruba.dhcp.client_mac    |             |      | client.mac         |
| aruba.dhcp.existing_port |             |      | server.port        |
| aruba.dhcp.filename      |             |      | file.name          |
| aruba.dhcp.ip_address    |             |      | client.ip          |
| aruba.dhcp.lease_ip_address |          |      | destination.ip     |
| aruba.dhcp.mac           |             |      | client.mac         |
| aruba.dhcp.new_port      |             |      |                    |
| aruba.dhcp.port          |             |      | server.port        |
| aruba.dhcp.server_ip_address |         |      | server.address     |
| aruba.dhcp.source_mac    |             |      | client.mac         |
| aruba.dhcp.vid           |             |      | network.vlan.id    |
| aruba.dhcp.volume_name   |             |      |                    |

#### [DHCPv6 Relay events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DHCPv6-RELAY.htm)
| Field | Description | Type | Common |
|-------|-------------|------|--------|


#### [DHCPv6 snooping events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DHCPv6-SNOOPING.htm)
| Field                    | Description | Type | Common             |
|--------------------------|-------------|------|--------------------|
| aruba.dhcp.existing_port |             |      | server.port        |
| aruba.dhcp.filename      |             |      | file.name          |
| aruba.dhcp.ipv6_address  |             |      | client.ip          |
| aruba.dhcp.mac           |             |      | client.mac         |
| aruba.dhcp.new_port      |             |      |                    |
| aruba.dhcp.port          |             |      | server.port        |
| aruba.dhcp.vid           |             |      | network.vlan.id    |
| aruba.dhcp.volume_name   |             |      |                    |

#### [Discovery and Capability Exchange (DCBx) events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DCBX.htm)
| Field                | Description | Type | Common                          |
|----------------------|-------------|------|---------------------------------|
| aruba.dcbx.intf_name | Interface name as reported by the system | keyword | |

#### [DNS client events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DNS_CLIENT.htm)
| Field            | Description | Type | Common           |
|------------------|-------------|------|------------------|
| aruba.dns.type   | DNS event type | keyword | event.type       |
| aruba.dns.vrf_name | Virtual Routing and Forwarding name | keyword | aruba.vrf.name   |

#### [DPSE events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DPSE.htm)
| Field                    | Description | Type | Common                          |
|--------------------------|-------------|------|---------------------------------|
| aruba.dpse.linecard_name |             |      |                                 |

#### [ECMP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ECMP.htm)
| Field               | Schema Mapping  |
|---------------------|-----------------|
| aruba.ecmp.egressid |                 |
| aruba.ecmp.err      |                 |
| aruba.ecmp.route    |                 |

#### [ERPS events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ERPS.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| <ccvlan>             |             |      | network.vlan.id              |
| <dataVlan>           |             |      | network.vlan.id              |
| <ifID>               |             |      | observer.ingress.interface.id|
| <instanceID>         |             |      | aruba.instance.id            |
| <interfaceName>      |             |      | observer.ingress.interface.name|
| <node>               |             |      | client.mac                   |
| <portName>           |             |      | aruba.erps.port_name         |
| <reason>             |             |      | event.reason                 |
| <ringID>             |             |      | aruba.erps.ring_id           |
| <state>              |             |      | aruba.status                 |
| <vlandID>            |             |      | network.vlan.id              |

#### [EVPN events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/EVPN.htm)
| Doc Field |  Schema Mapping   |
|-----------|-------------------|
| <action>  |  event.action     |
| <evi>     |  network.vlan.id  |
| <ip_addr> |  client.ip        |
| <mac_addr>|  client.mac       |
| <rd>      |  aruba.evpn.rd    |
| <rt>      |  aruba.evpn.rt    |
| <vni>     |  aruba.evpn.vni   |
| <vrf>     |  aruba.vrf.id     |
| <vtep_ip> |  aruba.evpn.vtep_ip|

#### [External Storage events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/EXTERNAL-STORAGE.htm)
| Doc Field | Schema Mapping              |
|-----------|-----------------------------|
| <name>    | aruba.storage.name |
| <status>  | aruba.status                |

#### [Fan events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/FAN.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.fan.compare_mode    |             |      |                              |
| aruba.fan.count           |             |      | aruba.count                  |
| aruba.fan.en_dis          |             |      |                              |
| aruba.fan.failure_type    |             |      | error.type                   |
| aruba.fan.fan_index       |             |      |                              |
| aruba.fan.fmod_num        |             |      |                              |
| aruba.fan.ft_air_curr     |             |      |                              |
| aruba.fan.ft_air_req      |             |      |                              |
| aruba.fan.ft_dir          |             |      |                              |
| aruba.fan.ft_num          |             |      |                              |
| aruba.fan.function        |             |      |                              |
| aruba.fan.minimum         |             |      |                              |
| aruba.fan.module_idx      |             |      |                              |
| aruba.fan.name            |             |      |                              |
| aruba.fan.new_status      |             |      |                              |
| aruba.fan.num_of_failure  |             |      | error.code                   |
| aruba.fan.num_of_failure_limit |        |      | aruba.limit                  |
| aruba.fan.old_status      |             |      |                              |
| aruba.fan.reason          |             |      | event.reason                 |
| aruba.fan.speed_idx_status|             |      |                              |
| aruba.fan.speedval        |             |      |                              |
| aruba.fan.status          |             |      | aruba.status                 |
| aruba.fan.subsystem       |             |      | aruba.subsystem              |
| aruba.fan.tray_index      |             |      |                              |
| aruba.fan.air_flow_direction|           |      |                              |
| aruba.fan.zone_idx        |             |      |                              |


#### [Fault monitor events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/FAULT_MONITOR.htm)
| Doc Fields              | Schema Mapping                   |
|-------------------------|----------------------------------|
| <fault>                 | aruba.fault.type                 |
| <interface>             | aruba.interface.name             |
| <mac>                   | client.mac                       |
| <sa_diff_count>         | aruba.fault.sa_diff_count        |
| <da_diff_count>         | aruba.fault.da_diff_count        |

#### [Firmware Update events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/UPDATE.htm)
| Doc Fields      | Schema Mapping               |
|-----------------|------------------------------|
| <user>          | user.name                    |
| <image_profile> | aruba.firmware.image_profile |
| <dnld_type>     | aruba.firmware.dnld_type     |
| <host>          | source.address               |
| <before>        | aruba.firmware.before        |
| <after>         | aruba.firmware.after         |

#### [Hardware Health Monitor events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/HW-HEALTH-MONITOR.htm)
| Doc Fields   | Schema Mapping          |
|--------------|-------------------------|
| <addr>       | aruba.hardware.addr     |
| <bus>        | aruba.hardware.bus      |
| <cap>        | aruba.hardware.cap      |
| <cecount>    | aruba.hardware.cecount  |
| <channel>    | aruba.hardware.channel  |
| <cpus>       | aruba.hardware.cpus     |
| <device>     | aruba.hardware.device   |
| <error_code> | error.code              |
| <function>   | aruba.hardware.function |
| <level>      | aruba.hardware.level    |
| <location>   | aruba.hardware.location |
| <mcgstatus>  | aruba.hardware.mcgstatus|
| <misc>       | aruba.hardware.misc     |
| <offlined>   | aruba.hardware.offlined |
| <origin>     | aruba.hardware.origin   |
| <page>       | aruba.hardware.page     |
| <seg>        | aruba.hardware.seg      |
| <slot>       | aruba.slot              |
| <socket>     | aruba.hardware.socket   |
| <status>     | aruba.status            |
| <test_name>  | aruba.hardware.test_name|
| <threshold>  | aruba.limit             |
| <type>       | aruba.hardware.type     |

#### [Hardware Switch controller sync events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/HSC-SYNCD.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.hardware.ip   |             |      | server.ip                    |
| aruba.hardware.mac  |             |      | server.mac                   |
| aruba.hardware.port |             |      | server.port                  |
| aruba.hardware.vni  |             |      | network.vlan.id              |

#### [HTTPS Server events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/HTTPS_SERVER.htm)
| Field | Description | Type | Common |
|-------|-------------|------|--------|
| aruba.server.sessions | | | |
| aruba.server.status  | | | aruba.status |
| aruba.server.timeout | | | |
| aruba.server.user    | | | server.user.name |
| aruba.server.vrf     | | | aruba.vrf.id |

#### [In-System Programming events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ISP.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.system.devicespec|             |      | |
| aruba.system.file      |             |      | file.name                    |
| aruba.system.fromver   |             |      | service.version              |
| aruba.system.line      |             |      | log.syslog.severity.name     |
| aruba.system.modspec   |             |      | |
| aruba.system.numdevs   |             |      | |
| aruba.system.pass      |             |      | event.action                 |
| aruba.system.time      |             |      | |
| aruba.system.tover     |             |      | service.target.version       |

#### [Interface events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/INTERFACE.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.interface.interface |             |      | observer.ingress.interface.name |
| aruba.interface.state     |             |      | aruba.status                 |

#### [Internal storage events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/INTERNAL-STORAGE.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.storage.error       |             |      | error.message                |
| aruba.storage.module_num  |             |      | aruba.slot                   |
| aruba.storage.name        |             |      |                              |
| aruba.storage.usage       |             |      |                              |

#### [IP source lockdown events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/IP_SOURCE_LOCKDOWN.htm)
| Field                              | Description | Type | Common                       |
|------------------------------------|-------------|------|------------------------------|
| aruba.lockdown.interface           |             |      | observer.ingress.interface.name |
| aruba.lockdown.max_supported_limit |             |      | aruba.limit                  |

#### [IP tunnels events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/IP_TUNNEL.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.tunnel.dest_ip|             |      | destination.ip               |
| aruba.tunnel.ip_mtu |             |      | aruba.mtu                    |
| aruba.tunnel.name   |             |      | observer.ingress.interface.name |
| aruba.tunnel.src_ip |             |      | source.ip                    |
| aruba.tunnel.ttl    |             |      |                              |
| aruba.tunnel.type   |             |      |                              |
| aruba.tunnel.vrf    |             |      | aruba.vrf.id                 |

#### [IP-SLA events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/IPSLA.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.ip_sla.interface |             |      | observer.ingress.interface.name |
| aruba.ip_sla.name      |             |      |                              |
| aruba.ip_sla.operation |             |      | event.action                 |
| aruba.ip_sla.reason    |             |      | event.reason                 |
| aruba.ip_sla.state     |             |      | aruba.status                 |

#### [IPv6 Router Advertisement events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/IPV6-RA.htm)
| Field                       | Description | Type | Common                       |
|-----------------------------|-------------|------|------------------------------|
| aruba.ipv6_router.intf      |             |      | observer.ingress.interface.name |
| aruba.ipv6_router.ipv6_addr |             |      | server.ip                    |
| aruba.ipv6_router.prefix    |             |      | aruba.prefix                 |
| aruba.ipv6_router.prefixlen |             |      | aruba.len                    |

#### [IRDP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/IRDP.htm)
| Field                       | Description | Type | Common                       |
|-----------------------------|-------------|------|------------------------------|
| aruba.irdp.interface        |             |      | observer.ingress.interface.name |

#### [L3 Encap capacity events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/L3_ENCAP.htm)
| Field                       | Description | Type | Common                       |
|-----------------------------|-------------|------|------------------------------|
| aruba.l3.encaps_allocated   |             |      |                              |
| aruba.l3.encaps_free        |             |      |                              |

#### [L3 Resource Manager events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/L3_RESMGR.htm)
| Field                       | Description | Type | Common                       |
|-----------------------------|-------------|------|------------------------------|
| aruba.l3.prefix             |             |      | aruba.prefix                 |

#### [LACP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LACP.htm)
| Field                       | Description | Type | Common                       |
|-----------------------------|-------------|------|------------------------------|
| aruba.lacp.actor_state      |             |      |                              |
| aruba.lacp.fallback         |             |      |                              |
| aruba.lacp.fsm_state        |             |      |                              |
| aruba.lacp.intf_id          |             |      | observer.ingress.interface.id|
| aruba.lacp.lacp_fallback_mode |           |      |                              |
| aruba.lacp.lacp_fallback_timeout |        |      | aruba.timeout                |
| aruba.lacp.lacp_mode        |             |      |                              |
| aruba.lacp.lacp_rate        |             |      |                              |
| aruba.lacp.lag_id           |             |      | aruba.instance.id            |
| aruba.lacp.lag_number       |             |      |                              |
| aruba.lacp.lag_speed        |             |      |                              |
| aruba.lacp.mode             |             |      |                              |
| aruba.lacp.partner_state    |             |      |                              |
| aruba.lacp.partner_sys_id   |             |      |                              |
| aruba.lacp.port_speed       |             |      |                              |
| aruba.lacp.system_id        |             |      |                              |
| aruba.lacp.system_priority  |             |      |                              |

#### [LAG events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LAG.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.lag.error     |             |      | error.message                |
| aruba.lag.hw_port   |             |      | server.port                  |
| aruba.lag.interface |             |      | observer.ingress.interface.name |
| aruba.lag.lag_id    |             |      | aruba.instance.id            |
| aruba.lag.mode      |             |      | event.type                   |
| aruba.lag.port      |             |      | server.port                  |
| aruba.lag.psc       |             |      |                              |
| aruba.lag.rc        |             |      | error.code                   |
| aruba.lag.tid       |             |      | process.thread.id            |
| aruba.lag.unit      |             |      | aruba.unit                   |
| aruba.lag.vlan      |             |      | network.vlan.id              |

#### [Layer 3 Interface events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/L3INTERFACE.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.l3.addr       |             |      | destination.address          |
| aruba.l3.addr_status|             |      | aruba.status                 |
| aruba.l3.egress_id  |             |      | observer.egress.interface.id |
| aruba.l3.err        |             |      | error.message                |
| aruba.l3.interface  |             |      | observer.ingress.interface.name |
| aruba.l3.ipaddr     |             |      | destination.ip               |
| aruba.l3.mtu        |             |      | aruba.mtu                    |
| aruba.l3.nexthop    |             |      | destination.address          |
| aruba.l3.port       |             |      | server.port                  |
| aruba.l3.prefix     |             |      | aruba.prefix                 |
| aruba.l3.state      |             |      | aruba.status                 |
| aruba.l3.vlanid     |             |      | network.vlan.id              |

#### [LED events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LED.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.led.count     |             |      | aruba.count                  |
| aruba.led.subsystem |             |      | aruba.subsystem              |

#### [LLDP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LLDP.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.lldp.chassisid   |             |      | aruba.instance.id            |
| aruba.lldp.interface   |             |      | observer.ingress.interface.name |
| aruba.lldp.ip          |             |      | source.ip                    |
| aruba.lldp.ninterface  |             |      |                              |
| aruba.lldp.npvid       |             |      |                              |
| aruba.lldp.port        |             |      | server.port                  |
| aruba.lldp.pvid        |             |      | network.vlan.id              |
| aruba.lldp.reinit_delay|             |      |                              |
| aruba.lldp.tx_delay    |             |      |                              |
| aruba.lldp.tx_hold     |             |      |                              |
| aruba.lldp.tx_timer    |             |      |                              |


#### [Loop Protect events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LOOP-PROTECT.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.loop.portName    |             |      | source.port                  |
| aruba.loop.rx_port     |             |      |                              |
| aruba.loop.tx_port     |             |      |                              |
| aruba.loop.vlan        |             |      | network.vlan.id              |

#### [Loopback events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LOOPBACK.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.loopback.interface |           |      | observer.ingress.interface.name |
| aruba.loopback.status  |             |      | aruba.status                 |


#### [MAC Address mode configuration events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/L3_MAC_ADDRESS_CONFIGURATION.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.mac.mac       |             |      | server.mac                   |
| aruba.mac.new_mode  |             |      |                              |
| aruba.mac.old_mode  |             |      |                              |
| aruba.mac.vlan      |             |      | network.vlan.id              |

#### [MAC Learning events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MAC-LEARN.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.mac.from-intf |             |      | observer.ingress.interface.name |
| aruba.mac.mac       |             |      | server.mac                   |
| aruba.mac.to-intf   |             |      | observer.egress.interface.name |
| aruba.mac.vlan      |             |      | network.vlan.id              |

#### [MACsec events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MACSEC.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.mac.ckn       |             |      |                              |
| aruba.mac.ifname    |             |      | observer.ingress.interface.name |
| aruba.mac.latest_an |             |      |                              |
| aruba.mac.latest_kn |             |      |                              |
| aruba.mac.old_an    |             |      |                              |
| aruba.mac.old_kn    |             |      |                              |
| aruba.mac.sci       |             |      |                              |

#### [Management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MGMT.htm)
| Field                                      | Description | Type | Common                       |
|--------------------------------------------|-------------|------|------------------------------|
| aruba.management.mgmt_intf_config_crit     |             |      | log.syslog.severity.name     |
| aruba.management.mgmt_intf_config_err      |             |      | error.message                |
| aruba.management.config_param              |             |      |                              |

#### [MDNS events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MDNS.htm)
| Field                                      | Description | Type | Common                       |
|--------------------------------------------|-------------|------|------------------------------|


#### [MGMD events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MGMD.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.mgmd.if_name     |             |      | observer.ingress.interface.name |
| aruba.mgmd.ip_address  |             |      | client.ip                    |
| aruba.mgmd.l3Port      |             |      |                              |
| aruba.mgmd.pkt_type    |             |      |                              |
| aruba.mgmd.port        |             |      | server.port                  |
| aruba.mgmd.ring_id     |             |      | aruba.instance.id            |
| aruba.mgmd.size_value  |             |      | aruba.len                    |
| aruba.mgmd.state       |             |      | aruba.status                 |
| aruba.mgmd.status      |             |      | aruba.status                 |
| aruba.mgmd.sub_system  |             |      | aruba.subsystem              |
| aruba.mgmd.vlan        |             |      | network.vlan.id              |

#### [Mirroring events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MIRRORING.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.mirroring.session|             |      | aruba.session.id             |

#### [Module events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MODULE.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.module.name      |             |      | observer.ingress.interface.name |
| aruba.module.part_number |           |      | aruba.unit                   |
| aruba.module.priority  |             |      | aruba.priority               |
| aruba.module.reason    |             |      | event.reason                 |
| aruba.module.type      |             |      |                              |

#### [MSDP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MSDP.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.msdp.grp_ip      |             |      |                              |
| aruba.msdp.if_name     |             |      | observer.ingress.interface.name |
| aruba.msdp.peer_ip     |             |      | client.ip                    |
| aruba.msdp.port        |             |      | server.port                  |
| aruba.msdp.rp_ip       |             |      |                              |
| aruba.msdp.src_ip      |             |      | source.ip                    |
| aruba.msdp.state       |             |      | aruba.status                 |
| aruba.msdp.status      |             |      | aruba.status                 |
| aruba.msdp.tcp_entity  |             |      |                              |
| aruba.msdp.vrf_name    |             |      | aruba.vrf.name               |

#### [Multicast Traffic Manager events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MTM.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.multicast.limit  |             |      | aruba.limit                  |

#### [Multiple spanning tree protocol events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MSTP.htm)
| Field                       | Description | Type | Common                       |
|-----------------------------|-------------|------|------------------------------|
| aruba.mstp.config_parameter |             |      |                              |
| aruba.mstp.config_value     |             |      |                              |
| aruba.mstp.instance         |             |      | aruba.instance.id            |
| aruba.mstp.mac              |             |      | source.mac                   |
| aruba.mstp.new_mac          |             |      | source.mac                   |
| aruba.mstp.new_mode         |             |      |                              |
| aruba.mstp.new_priority     |             |      | aruba.priority               |
| aruba.mstp.old_mac          |             |      |                              |
| aruba.mstp.old_mode         |             |      |                              |
| aruba.mstp.old_priority     |             |      |                              |
| aruba.mstp.pk_type          |             |      |                              |
| aruba.mstp.port             |             |      | server.port                  |
| aruba.mstp.priority_mac     |             |      | source.mac                   |
| aruba.mstp.proto            |             |      |                              |
| aruba.mstp.reconfig_parameter |           |      |                              |
| aruba.mstp.state            |             |      | aruba.status                 |


#### [MVRP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MVRP.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.mvrp.port     |             |      | server.port                  |
| aruba.mvrp.vlan     |             |      | network.vlan.id              |
| aruba.mvrp.vlan_max |             |      | aruba.limit                  |

#### [NAE Agents events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/NAE_ALERT.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.nae.name      |             |      | agent.name                   |

#### [NAE events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/TSDBD.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.nae.condition |             |      |                              |
| aruba.nae.name      |             |      | agent.name                   |
| aruba.nae.uri       |             |      | url.full                     |
| aruba.nae.user      |             |      | user.name                    |
| aruba.nae.monitorName |           |      |                              |

#### [NAE Scripts events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/POLICYD.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.nae.action_type  |             |      |                              |
| aruba.nae.agent        |             |      | agent.name                   |
| aruba.nae.condition    |             |      |                              |
| aruba.nae.description  |             |      |                              |
| aruba.nae.msg          |             |      | message                      |
| aruba.nae.name         |             |      | agent.name                   |

#### [ND snooping events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ND-SNOOPING.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.nd.count      |             |      | aruba.count                  |
| aruba.nd.ip         |             |      | client.ip                    |
| aruba.nd.src_mac    |             |      | source.mac                   |
| aruba.nd.port       |             |      | server.port                  |
| aruba.nd.status     |             |      | aruba.status                 |
| aruba.nd.type       |             |      |                              |
| aruba.nd.vid        |             |      | network.vlan.id              |
| aruba.nd.vlan       |             |      | network.vlan.id              |

#### [NDM events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/NDM.htm)
| Field               | Description | Type | Common                       |
|---------------------|-------------|------|------------------------------|
| aruba.ndm.ip        |             |      | client.ip                    |
| aruba.ndm.mac       |             |      | client.mac                   |
| aruba.ndm.new_mac   |             |      |                              |
| aruba.ndm.old_mac   |             |      |                              |
| aruba.ndm.port      |             |      | client.port                  |
| aruba.ndm.prev_mac  |             |      | client.mac                   |
| aruba.ndm.role      |             |      | aruba.role                   |
| aruba.ndm.role1     |             |      |                              |
| aruba.ndm.role2     |             |      |                              |
| aruba.ndm.time      |             |      | aruba.time.local             |
| aruba.ndm.vrf       |             |      | aruba.vrf.id                 |

#### [NTP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/NTP.htm)
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| aruba.ntp.event        |             |      | event.code                   |
| aruba.ntp.old_state    |             |      |                              |
| aruba.ntp.server       |             |      | server.address               |
| aruba.ntp.server_info  |             |      |                              |
| aruba.ntp.state        |             |      | aruba.status                 |
| aruba.ntp.trusted_keys |             |      |                              |
| aruba.ntp.untrusted_keys |           |      |                              |

#### [OSPFv2 events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/OSPFv2.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.ospf.action         |             |      | event.action                 |
| aruba.ospf.area           |             |      |                              |
| aruba.ospf.destination    |             |      | destination.address          |
| aruba.ospf.err            |             |      | error.message                |
| aruba.ospf.event          |             |      | event.code                   |
| aruba.ospf.fp_id          |             |      |                              |
| aruba.ospf.group_id       |             |      | group.id                     |
| aruba.ospf.input          |             |      |                              |
| aruba.ospf.nexthops       |             |      |                              |
| aruba.ospf.old_router_id  |             |      |                              |
| aruba.ospf.old_state      |             |      | aruba.status                 |
| aruba.ospf.ospf_interface |             |      | observer.ingress.interface.name |
| aruba.ospf.router_id      |             |      |                              |
| aruba.ospf.rule           |             |      | rule.name                    |
| aruba.ospf.state          |             |      | aruba.status                 |
| aruba.ospf.stats_id       |             |      |                              |

#### [OSPFv3 events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/OSPFv3.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.ospf.action         |             |      | event.action                 |
| aruba.ospf.area           |             |      |                              |
| aruba.ospf.err            |             |      | error.message                |
| aruba.ospf.fp_id          |             |      |                              |
| aruba.ospf.group_id       |             |      | group.id                     |
| aruba.ospf.input          |             |      |                              |
| aruba.ospf.interface      |             |      | observer.ingress.interface.name |
| aruba.ospf.link_local     |             |      |                              |
| aruba.ospf.old_state      |             |      |                              |
| aruba.ospf.router_id      |             |      |                              |
| aruba.ospf.rule           |             |      | rule.name                    |
| aruba.ospf.state          |             |      | aruba.status                 |
| aruba.ospf.stats_id       |             |      |                              |

#### [Password Reset events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PASSWD_RESET.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|

#### [PIM events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PIM.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.pim.callerid        |             |      |                              |
| aruba.pim.dip             |             |      |                              |
| aruba.pim.ebsr_ip         |             |      | server.ip                    |
| aruba.pim.err             |             |      | error.message                |
| aruba.pim.error           |             |      | error.message                |
| aruba.pim.error_value     |             |      | error.code                   |
| aruba.pim.event           |             |      | event.code                   |
| aruba.pim.fd              |             |      |                              |
| aruba.pim.flowtype        |             |      |                              |
| aruba.pim.group           |             |      |                              |
| aruba.pim.ifname          |             |      | observer.ingress.interface.name |
| aruba.pim.interfaceName   |             |      | observer.ingress.interface.name |
| aruba.pim.ip_address      |             |      | server.ip                    |
| aruba.pim.ip_version      |             |      |                              |
| aruba.pim.isl_status      |             |      | aruba.status                 |
| aruba.pim.neighbor_ip     |             |      | client.ip                    |
| aruba.pim.pkt             |             |      | network.packets              |
| aruba.pim.pkt_type        |             |      |                              |
| aruba.pim.port            |             |      | server.port                  |
| aruba.pim.priority        |             |      | aruba.priority               |
| aruba.pim.reason          |             |      | event.reason                 |
| aruba.pim.sip             |             |      | source.ip                    |
| aruba.pim.source          |             |      |                              |
| aruba.pim.srcport         |             |      | source.port                  |
| aruba.pim.srcvid          |             |      | network.vlan.id              |
| aruba.pim.state           |             |      | aruba.status                 |
| aruba.pim.status          |             |      | aruba.status                 |
| aruba.pim.totalvid        |             |      |                              |
| aruba.pim.type            |             |      |                              |
| aruba.pim.vrf_name        |             |      | aruba.vrf.name               |

#### [Policies events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/POLICY.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.policy.application  |             |      | network.application          |
| aruba.policy.name         |             |      |                              |

#### [Port access roles events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ROLE.htm)
| Field                         | Description | Type | Common                       |
|-------------------------------|-------------|------|------------------------------|
| aruba.port.cprole_error_string|             |      | error.message                |
| aruba.port.role_name          |             |      | aruba.role                   |

#### [Port events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PORT.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.port.error     |             |      | error.message                |
| aruba.port.interface |             |      | observer.ingress.interface.name |
| aruba.port.ip_address|             |      | destination.ip               |
| aruba.port.mtu       |             |      | aruba.mtu                    |
| aruba.port.policy    |             |      |                              |
| aruba.port.status    |             |      | aruba.status                 |
| aruba.port.vlan      |             |      | network.vlan.id              |

#### [Port security events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PORT-SECURITY.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.port.if_name   |             |      | observer.ingress.interface.name |
| aruba.port.mac_addr  |             |      | server.mac                   |
| aruba.port.port      |             |      | server.port                  |

#### [Port Statistics events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/COUNTERS.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.port.name      |             |      | server.port                  |

#### [PORT_ACCESS events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PORT_ACCESS.htm)
| Field                   | Description | Type | Common                       |
|-------------------------|-------------|------|------------------------------|
| aruba.port.limit        |             |      | aruba.limit                  |
| aruba.port.mac_address  |             |      | client.mac                   |
| aruba.port.mode         |             |      |                              |
| aruba.port.name         |             |      | server.port                  |
| aruba.port.old_limit    |             |      |                              |
| aruba.port.old_mode     |             |      |                              |
| aruba.port.old_name     |             |      |                              |
| aruba.port.policy_name  |             |      |                              |
| aruba.port.port         |             |      | server.port                  |

#### [Power events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/POWER.htm)
| Field                   | Description | Type | Common                       |
|-------------------------|-------------|------|------------------------------|
| aruba.power.failures    |             |      | aruba.count                  |
| aruba.power.fanidx      |             |      |                              |
| aruba.power.psu         |             |      |                              |
| aruba.power.redund      |             |      |                              |
| aruba.power.sensorid    |             |      |                              |
| aruba.power.state       |             |      | aruba.status                 |
| aruba.power.status      |             |      | aruba.status                 |
| aruba.power.support     |             |      |                              |
| aruba.power.type        |             |      |                              |
| aruba.power.warning     |             |      |                              |

#### [Power over Ethernet events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/POE.htm)
| Field                       | Description | Type | Common                       |
|-----------------------------|-------------|------|------------------------------|
| aruba.power.assign_class    |             |      |                              |
| aruba.power.assign_class_a  |             |      |                              |
| aruba.power.assign_class_b  |             |      |                              |
| aruba.power.available       |             |      |                              |
| aruba.power.drawn           |             |      |                              |
| aruba.power.fault_type      |             |      | error.type                   |
| aruba.power.interface_name  |             |      |                              |
| aruba.power.limit           |             |      | aruba.limit                  |
| aruba.power.pair            |             |      |                              |
| aruba.power.paira_class     |             |      |                              |
| aruba.power.pairb_class     |             |      |                              |
| aruba.power.pd_class        |             |      |                              |
| aruba.power.pd_type         |             |      |                              |
| aruba.power.req_class       |             |      |                              |
| aruba.power.req_class_a     |             |      |                              |
| aruba.power.req_class_b     |             |      |                              |

#### [Proxy ARP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PROXY-ARP.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.proxy_arp.port |             |      | server.port                  |
| aruba.proxy_arp.vrf  |             |      | aruba.vrf.id                 |

#### [QoS ASIC Provider events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/QOS_ASIC.htm)
| Field                       | Description | Type | Common                       |
|-----------------------------|-------------|------|------------------------------|
| aruba.qos.error_string      |             |      | error.message                |
| aruba.qos.error_val         |             |      | error.code                   |
| aruba.qos.existing_slot     |             |      | aruba.slot                   |
| aruba.qos.local_slot        |             |      | aruba.slot                   |
| aruba.qos.new_slot          |             |      |                              |
| aruba.qos.port_name         |             |      | server.port                  |
| aruba.qos.pri               |             |      | aruba.priority               |
| aruba.qos.queue             |             |      |                              |

#### [Quality of Service events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/QOS.htm)
| Field                       | Description | Type | Common                       |
|-----------------------------|-------------|------|------------------------------|
| aruba.qos.error             |             |      | error.message                |
| aruba.qos.error_string      |             |      | error.message                |

#### [Rapid per VLAN Spanning Tree Protocol events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/RPVST.htm)
| Field                            | Description | Type | Common                       |
|----------------------------------|-------------|------|------------------------------|
| aruba.vlan.current_virtual_ports |             |      |                              |
| aruba.vlan.interface             |             |      | observer.ingress.interface.name |
| aruba.vlan.mac                   |             |      | client.mac                   |
| aruba.vlan.Maximum_Virtual_Ports |             |      |                              |
| aruba.vlan.new_mac               |             |      | client.mac                   |
| aruba.vlan.new_mode              |             |      |                              |
| aruba.vlan.new_port              |             |      | server.port                  |
| aruba.vlan.new_priority          |             |      | aruba.priority               |
| aruba.vlan.npvid                 |             |      |                              |
| aruba.vlan.old_mac               |             |      |                              |
| aruba.vlan.old_mode              |             |      |                              |
| aruba.vlan.old_port              |             |      |                              |
| aruba.vlan.old_priority          |             |      |                              |
| aruba.vlan.port                  |             |      | server.port                  |
| aruba.vlan.pkt_type              |             |      | event.type                   |
| aruba.vlan.priority_mac          |             |      | client.mac                   |
| aruba.vlan.proto                 |             |      |                              |
| aruba.vlan.pvid                  |             |      |                              |
| aruba.vlan.rpvst_instance        |             |      |                              |
| aruba.vlan.vlan                  |             |      | network.vlan.id              |

#### [RBAC events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/RBACD.htm)
| Field                 | Description | Type | Common            |
|-----------------------|-------------|------|-------------------|
| aruba.rbac.tac_status |             |      | aruba.status      |


#### [Redundant Management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/REDUNDANT_MANAGEMENT.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.redund.mgmt_module  |             |      |                              |
| aruba.redund.reason       |             |      | event.reason                 |

#### [Replication Manager events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/REPLD.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.replication.uuid_str|             |      | aruba.instance.id            |

#### [REST events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/RESTD.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.rest.action         |             |      | event.action                 |
| aruba.rest.activate_address |           |      | server.address               |
| aruba.rest.added_user     |             |      |                              |
| aruba.rest.added_user_role |            |      | aruba.role                   |
| aruba.rest.agent_name     |             |      | agent.name                   |
| aruba.rest.autztype       |             |      |                              |
| aruba.rest.central_location |           |      | server.address               |
| aruba.rest.reboot_command |             |      |                              |
| aruba.rest.config_from_name |           |      |                              |
| aruba.rest.config_to_name |             |      |                              |
| aruba.rest.deleted_user   |             |      |                              |
| aruba.rest.dns            |             |      |                              |
| aruba.rest.dns_nameserver |             |      | dns.id                       |
| aruba.rest.error          |             |      | error.message                |
| aruba.rest.match          |             |      |                              |
| aruba.rest.mode           |             |      |                              |
| aruba.rest.resource       |             |      |                              |
| aruba.rest.rest_operation |             |      |                              |
| aruba.rest.script_name    |             |      |                              |
| aruba.rest.sessionid      |             |      |                              |
| aruba.rest.source_ip      |             |      | source.ip                    |
| aruba.rest.subscriber     |             |      |                              |
| aruba.rest.subscription   |             |      |                              |
| aruba.rest.config_value   |             |      |                              |
| aruba.rest.uri            |             |      | url.full                     |
| aruba.rest.url            |             |      | url.full                     |
| aruba.rest.user           |             |      | user.name                    |
| aruba.rest.vrf            |             |      | aruba.vrf.id                 |

#### [Self Test events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/SELFTEST.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.self_test.error     |             |      | error.message                |
| aruba.self_test.interface |             |      |                              |
| aruba.self_test.slot      |             |      | aruba.slot                   |
| aruba.self_test.stack     |             |      |                              |
| aruba.self_test.subsystem |             |      | aruba.subsystem              |

#### [sFlow events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/SFLOW.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.sflow.bridge        |             |      |                              |
| aruba.sflow.chain         |             |      |                              |
| aruba.sflow.desc          |             |      |                              |
| aruba.sflow.dgramsize     |             |      |                              |
| aruba.sflow.error         |             |      | error.message                |
| aruba.sflow.file          |             |      | file.name                    |
| aruba.sflow.hdrlen        |             |      | aruba.len                    |
| aruba.sflow.ifIndex       |             |      | observer.ingress.interface.id|
| aruba.sflow.intvl         |             |      |                              |
| aruba.sflow.ip_address    |             |      | destination.ip               |
| aruba.sflow.mode          |             |      |                              |
| aruba.sflow.new_rate      |             |      |                              |
| aruba.sflow.old_rate      |             |      |                              |
| aruba.sflow.operation     |             |      | event.action                 |
| aruba.sflow.port          |             |      | server.port                  |
| aruba.sflow.port_name     |             |      | server.port                  |
| aruba.sflow.unit          |             |      | aruba.unit                   |

#### [SFTP Client events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/SFTP_CLIENT.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.sftp.from      |             |      | source.address               |
| aruba.sftp.status    |             |      | aruba.status                 |
| aruba.sftp.to        |             |      | destination.address          |

#### [SNMP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/SNMP.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.snmp.truth_value    |             |      |                              |
| aruba.snmp.vrf            |             |      | aruba.vrf.id                 |

#### [SSH server events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/SSH_SERVER.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.ssh.key_name        |             |      |                              |
| aruba.ssh.username        |             |      | user.name                    |
| aruba.ssh.vrf_name        |             |      | aruba.vrf.name               |

#### [SSH_CLIENT events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/SSH_CLIENT.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.ssh.ipaddr     |             |      | server.ip                    |
| aruba.ssh.port_num   |             |      | server.port                  |
| aruba.ssh.username   |             |      | user.name                    |
| aruba.ssh.vrf_name   |             |      | aruba.vrf.name               |

#### [Supportability events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/SUPPORTABILITY.htm)
| Field                                | Description | Type | Common                       |
|--------------------------------------|-------------|------|------------------------------|
| aruba.supportability.alarm_index     |             |      |                              |
| aruba.supportability.boot_id         |             |      | host.boot.id                 |
| aruba.supportability.err_desc        |             |      | error.message                |
| aruba.supportability.module          |             |      |                              |
| aruba.supportability.oid             |             |      |                              |
| aruba.supportability.process         |             |      | process.pid                  |
| aruba.supportability.reason          |             |      | event.reason                 |
| aruba.supportability.remote_host     |             |      | server.address               |
| aruba.supportability.signal          |             |      | process.exit_code            |
| aruba.supportability.state           |             |      | service.state                |
| aruba.supportability.supported_files_name |        |      |                              |
| aruba.supportability.threshold       |             |      | aruba.limit                  |
| aruba.supportability.timestamp       |             |      | process.end                  |
| aruba.supportability.type            |             |      | file.type                    |
| aruba.supportability.vrf             |             |      | aruba.vrf.id                 |

#### [SYS events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/SYS.htm)
| Field                                | Description | Type | Common                       |
|--------------------------------------|-------------|------|------------------------------|
| aruba.sys.mem_alloc_value            |             |      |                              |

#### [SYSMON events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/SYSMON.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.sysmon.mem_usage    |             |      |                              |
| aruba.sysmon.module_name  |             |      |                              |
| aruba.sysmon.module_num   |             |      |                              |
| aruba.sysmon.partition_name |           |      |                              |
| aruba.sysmon.poll         |             |      |                              |
| aruba.sysmon.unit         |             |      |                              |
| aruba.sysmon.utilization  |             |      |                              |

#### [TCAM events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/TCAM.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.tcam.table_name     |             |      |                              |

#### [Temperature events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/TEMPERATURE.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.temp.sensor_type    |             |      |                              |
| aruba.temp.sensor_name    |             |      |                              |
| aruba.temp.celcius        |             |      |                              |
| aruba.temp.derate_old     |             |      |                              |
| aruba.temp.derate_new     |             |      |                              |
| aruba.temp.limit_type     |             |      |                              |
| aruba.temp.status         |             |      | aruba.status                 |

#### [Time management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/TIME_MGMT.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.time.new_time  |             |      | aruba.time.local             |
| aruba.time.newtz     |             |      | aruba.time.tz                |
| aruba.time.old_time  |             |      | aruba.time.local_old         |
| aruba.time.oldtz     |             |      | aruba.time.tz_old            |

#### [Transceiver events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/XCVR.htm)
| Field                          | Description | Type | Common                       |
|--------------------------------|-------------|------|------------------------------|
| aruba.transceiver.count        |             |      | aruba.count                  |
| aruba.transceiver.xcvr_desc    |             |      |                              |
| aruba.transceiver.adapter_desc |             |      |                              |
| aruba.transceiver.interface    |             |      |                              |
| aruba.transceiver.path         |             |      |                              |
| aruba.transceiver.reason       |             |      | event.reason                 |
| aruba.transceiver.status       |             |      | aruba.status                 |
| aruba.transceiver.unsupported  |             |      |                              |

#### [UDLD events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/UDLD.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.udld.intf      |             |      |                              |
| aruba.udld.intvl_a   |             |      |                              |
| aruba.udld.intvl_b   |             |      |                              |

#### [UDP Broadcast Forwarder events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/UDPFWD.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|

#### [User management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/USER-MGMT.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.user.added_user|             |      |                              |
| aruba.user.deleted_user|           |      |                              |
| aruba.user.user      |             |      | user.name                    |
| aruba.user.user_role |             |      | user.roles                   |
| aruba.user.username  |             |      | user.name                    |

#### [User-based tunnels events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/USER_BASED_TUNNEL.htm)
| Field                   | Description | Type | Common                       |
|-------------------------|-------------|------|------------------------------|
| aruba.tunnel.client_mac |             |      | client.mac                   |
| aruba.tunnel.dst_ip     |             |      | destination.ip               |
| aruba.tunnel.ecmp_id    |             |      |                              |
| aruba.tunnel.gre_key    |             |      |                              |
| aruba.tunnel.nfd_id     |             |      |                              |
| aruba.tunnel.port       |             |      | server.port                  |
| aruba.tunnel.sac_ip     |             |      | server.ip                    |
| aruba.tunnel.src_ip     |             |      | source.ip                    |
| aruba.tunnel.state      |             |      | aruba.status                 |
| aruba.tunnel.tunnel_id  |             |      | aruba.instance.id            |
| aruba.tunnel.vlan_id    |             |      | network.vlan.id              |
| aruba.tunnel.vrf        |             |      | aruba.vrf.id                 |

#### [Virtual Switching Extension (VSX) events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/VSX.htm)
| Field                       | Description | Type | Common                       |
|-----------------------------|-------------|------|------------------------------|
| aruba.vsx.bank_name         |             |      |                              |
| aruba.vsx.ifname            |             |      | observer.ingress.interface.name |
| aruba.vsx.ip_address        |             |      | source.ip                    |
| aruba.vsx.local_device_type |             |      |                              |
| aruba.vsx.local_sw_ver      |             |      |                              |
| aruba.vsx.local_vsx_role    |             |      |                              |
| aruba.vsx.peer_device_type  |             |      |                              |
| aruba.vsx.peer_sw_ver       |             |      |                              |
| aruba.vsx.peer_vsx_role     |             |      |                              |
| aruba.vsx.port              |             |      | server.port                  |
| aruba.vsx.prev_state        |             |      |                              |
| aruba.vsx.primary_version   |             |      |                              |
| aruba.vsx.reason            |             |      | event.reason                 |
| aruba.vsx.secondary_version |             |      |                              |
| aruba.vsx.state             |             |      | service.state                |
| aruba.vsx.sub_state         |             |      |                              |
| aruba.vsx.vsx_id            |             |      | aruba.instance.id            |
| aruba.vsx.vsx_role          |             |      | aruba.role                   |

#### [Virtual Switching Framework (VSF) events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/VSF.htm)
| Field                       | Description | Type | Common                          |
|-----------------------------|-------------|------|---------------------------------|
| aruba.vsf.link              |             |      | observer.ingress.interface.name |
| aruba.vsf.link_id           |             |      | observer.ingress.interface.id   |
| aruba.vsf.mac_add           |             |      | client.mac                      |
| aruba.vsf.mac_addr1         |             |      |                                 |
| aruba.vsf.mac_addr2         |             |      |                                 |
| aruba.vsf.mac_address       |             |      | client.mac                      |
| aruba.vsf.mbr_id            |             |      | aruba.instance.id               |
| aruba.vsf.member_id         |             |      | aruba.instance.id               |
| aruba.vsf.new_standby_id    |             |      |                                 |
| aruba.vsf.old_standby_id    |             |      |                                 |
| aruba.vsf.port              |             |      | server.port                     |
| aruba.vsf.port_id           |             |      | server.port                     |
| aruba.vsf.product_id        |             |      |                                 |
| aruba.vsf.product_type      |             |      |                                 |
| aruba.vsf.reason            |             |      | event.reason                    |
| aruba.vsf.status            |             |      | aruba.status                    |
| aruba.vsf.topo_type         |             |      |                                 |
| aruba.vsf.new_standby_id    |             |      |                                 |
| aruba.vsf.old_standby_id    |             |      |                                 |

#### [VLAN events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/VLAN.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.vlan.mac       |             |      | server.mac                   |
| aruba.vlan.mode_from |             |      |                              |
| aruba.vlan.mode_to   |             |      |                              |
| aruba.vlan.port      |             |      | server.port                  |
| aruba.vlan.vlan      |             |      | network.vlan.id              |
| aruba.vlan.vid       |             |      | network.vlan.id              |

#### [VLAN Interface events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/VLANINTERFACE.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.vlan.error     |             |      | error.message                |
| aruba.vlan.interface |             |      | observer.ingress.interface.name |
| aruba.vlan.vlan      |             |      | network.vlan.id              |

#### [VRF events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/VRF.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.vrf.vrf_name   |             |      | aruba.vrf.name               |

#### [VRF Manager events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/VRF_MGR.htm)
| Field                | Description | Type | Common                       |
|----------------------|-------------|------|------------------------------|
| aruba.vrf.vrf_entity |             |      | aruba.vrf.id                 |

#### [VRRP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/VRRP.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.vrrp.address        |             |      | service.address              |
| aruba.vrrp.address_type   |             |      | service.type                 |
| aruba.vrrp.delay_value    |             |      |                              |
| aruba.vrrp.interface      |             |      | observer.ingress.interface.name |
| aruba.vrrp.inet_type      |             |      |                              |
| aruba.vrrp.interval_value |             |      |                              |
| aruba.vrrp.mode_value     |             |      | event.action                 |
| aruba.vrrp.new_state      |             |      | service.state                |
| aruba.vrrp.old_state      |             |      |                              |
| aruba.vrrp.priority_value |             |      | aruba.priority               |
| aruba.vrrp.track          |             |      |                              |
| aruba.vrrp.version_value  |             |      |                              |
| aruba.vrrp.vrid           |             |      | aruba.instance.id            |


#### [VSX Sync events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/VSX_SYNC.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.vsx.id              |             |      | aruba.instance.id            |


#### [VXLAN events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/VXLAN.htm)
| Field                     | Description | Type | Common                       |
|---------------------------|-------------|------|------------------------------|
| aruba.vxlan.port_name     |             |      | server.port                  |
| aruba.vxlan.remote_ip     |             |      | destination.ip               |
| aruba.vxlan.vlan_id       |             |      | network.vlan.id              |
| aruba.vxlan.vni_id        |             |      |                              |
| aruba.vxlan.vtep          |             |      |                              |
| aruba.vxlan.vtep_peer     |             |      |                              |

#### [Zero touch provisioning events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ZTPD.htm)
| Field                              | Description | Type | Common                       |
|------------------------------------|-------------|------|------------------------------|
| aruba.zero_touch.central_location  |             |      | server.address               |
| aruba.zero_touch.config_file       |             |      | file.name                    |
| aruba.zero_touch.filename          |             |      | file.name                    |
| aruba.zero_touch.http_proxy_location |           |      | server.address               |
| aruba.zero_touch.image_file        |             |      | file.name                    |
| aruba.zero_touch.tftp_ip           |             |      | destination.ip               |

## Generated Logs

The `log` dataset collects the HPE Aruba CX logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. | keyword |
| aruba.aaa.config_event |  | keyword |
| aruba.aaa.config_type |  | keyword |
| aruba.aaa.radius_action |  | keyword |
| aruba.aaa.radius_event |  | keyword |
| aruba.aaa.radius_type |  | keyword |
| aruba.aaa.tacacs_action |  | keyword |
| aruba.aaa.tacacs_event |  | keyword |
| aruba.aaa.tacacs_type |  | keyword |
| aruba.acl.ace_string | TBD for all description fields - need to be filled in | keyword |
| aruba.acl.application |  | keyword |
| aruba.acl.direction |  | keyword |
| aruba.acl.hit_delta |  | long |
| aruba.acl.name |  | keyword |
| aruba.acl.type |  | keyword |
| aruba.bfd.applied_interval |  | long |
| aruba.bfd.direction |  | keyword |
| aruba.bfd.from |  | keyword |
| aruba.bfd.invalid_ip |  | ip |
| aruba.bfd.ip_version |  | keyword |
| aruba.bfd.local_diag |  | keyword |
| aruba.bfd.local_state |  | keyword |
| aruba.bfd.op_mode |  | keyword |
| aruba.bfd.remote_diag |  | keyword |
| aruba.bfd.remote_state |  | keyword |
| aruba.bfd.requested_interval |  | long |
| aruba.bgp.as_number |  | long |
| aruba.bgp.error_subcode |  | keyword |
| aruba.bgp.id |  | keyword |
| aruba.bgp.pg_name |  | keyword |
| aruba.bgp.threshold_limit |  | long |
| aruba.bgp.vtep_ip |  | ip |
| aruba.cfm.id | Maintenance Endpoint ID | keyword |
| aruba.cfm.interface | Interface name on which CFM event occurred | keyword |
| aruba.cm.cert_name |  | keyword |
| aruba.cm.days |  | long |
| aruba.cm.est_name |  | keyword |
| aruba.cm.profile_name |  | keyword |
| aruba.component.category |  | keyword |
| aruba.component.name |  | keyword |
| aruba.config.from |  | keyword |
| aruba.config.to |  | keyword |
| aruba.config.type |  | keyword |
| aruba.config.value |  | keyword |
| aruba.copp.class | Control Plane Policing (CoPP) class | keyword |
| aruba.cpu_rx.filter_description |  | keyword |
| aruba.dcbx.intf_name | Interface name as reported by the system | keyword |
| aruba.dhcp.config |  | keyword |
| aruba.dhcp.ipv6_address |  | keyword |
| aruba.dhcp.lease_ip_address |  | ip |
| aruba.dhcp.new_port |  | long |
| aruba.dhcp.server_ip_address |  | ip |
| aruba.dhcp.source_mac |  | keyword |
| aruba.dhcp.volume_name |  | keyword |
| aruba.dns.type |  | keyword |
| aruba.dns.vrf_name |  | keyword |
| aruba.dpse.linecard_name |  | keyword |
| aruba.ecmp.egressid |  | keyword |
| aruba.ecmp.err |  | keyword |
| aruba.ecmp.route |  | keyword |
| aruba.erps.port_name |  | keyword |
| aruba.erps.ring_id |  | keyword |
| aruba.event_type |  | keyword |
| aruba.evpn.rd |  | keyword |
| aruba.evpn.rt |  | keyword |
| aruba.evpn.vni |  | keyword |
| aruba.evpn.vtep_ip |  | ip |
| aruba.fan.air_flow_direction |  | keyword |
| aruba.fan.compare_mode |  | keyword |
| aruba.fan.en_dis |  | keyword |
| aruba.fan.fan_index |  | long |
| aruba.fan.fmod_num |  | long |
| aruba.fan.ft_air_curr |  | keyword |
| aruba.fan.ft_air_req |  | keyword |
| aruba.fan.ft_dir |  | keyword |
| aruba.fan.ft_num |  | long |
| aruba.fan.function |  | keyword |
| aruba.fan.minimum |  | long |
| aruba.fan.module_idx |  | keyword |
| aruba.fan.name |  | keyword |
| aruba.fan.new_status |  | keyword |
| aruba.fan.old_status |  | keyword |
| aruba.fan.speed_idx_status |  | keyword |
| aruba.fan.speedval |  | long |
| aruba.fan.tray_index |  | long |
| aruba.fan.zone_idx |  | keyword |
| aruba.fault.da_diff_count |  | long |
| aruba.fault.sa_diff_count |  | long |
| aruba.fault.type |  | keyword |
| aruba.firmware.after |  | keyword |
| aruba.firmware.before |  | keyword |
| aruba.firmware.dnld_type |  | keyword |
| aruba.firmware.image_profile |  | keyword |
| aruba.hardware.addr |  | keyword |
| aruba.hardware.bus |  | keyword |
| aruba.hardware.cap |  | keyword |
| aruba.hardware.cecount |  | long |
| aruba.hardware.channel |  | keyword |
| aruba.hardware.cpus |  | long |
| aruba.hardware.device |  | keyword |
| aruba.hardware.function |  | keyword |
| aruba.hardware.ip |  | ip |
| aruba.hardware.level |  | keyword |
| aruba.hardware.location |  | keyword |
| aruba.hardware.mcgstatus |  | keyword |
| aruba.hardware.misc |  | keyword |
| aruba.hardware.offlined |  | long |
| aruba.hardware.origin |  | keyword |
| aruba.hardware.page |  | keyword |
| aruba.hardware.seg |  | keyword |
| aruba.hardware.socket |  | keyword |
| aruba.hardware.test_name |  | keyword |
| aruba.hardware.type |  | keyword |
| aruba.hardware.vni |  | keyword |
| aruba.instance.id |  | keyword |
| aruba.interface.id |  | keyword |
| aruba.interface.name |  | keyword |
| aruba.ip_sla.name |  | keyword |
| aruba.l3.encaps_allocated |  | keyword |
| aruba.l3.encaps_free |  | keyword |
| aruba.lacp.actor_state |  | keyword |
| aruba.lacp.fallback |  | keyword |
| aruba.lacp.fsm_state |  | keyword |
| aruba.lacp.lacp_fallback_mode |  | keyword |
| aruba.lacp.lacp_mode |  | keyword |
| aruba.lacp.lacp_rate |  | long |
| aruba.lacp.lag_number |  | long |
| aruba.lacp.lag_speed |  | long |
| aruba.lacp.mode |  | keyword |
| aruba.lacp.partner_state |  | keyword |
| aruba.lacp.partner_sys_id |  | long |
| aruba.lacp.port_speed |  | long |
| aruba.lacp.system_id |  | long |
| aruba.lacp.system_priority |  | keyword |
| aruba.lag.actor_state |  | keyword |
| aruba.lag.fallback |  | keyword |
| aruba.lag.fsm_state |  | keyword |
| aruba.lag.lacp_fallback_mode |  | keyword |
| aruba.lag.lacp_mode |  | keyword |
| aruba.lag.lacp_rate |  | long |
| aruba.lag.lag_number |  | long |
| aruba.lag.lag_speed |  | long |
| aruba.lag.mode |  | keyword |
| aruba.lag.partner_state |  | keyword |
| aruba.lag.partner_sys_id |  | long |
| aruba.lag.port_speed |  | long |
| aruba.lag.system_id |  | long |
| aruba.lag.system_priority |  | keyword |
| aruba.len |  | long |
| aruba.limit |  | long |
| aruba.lldp.ninterface |  | keyword |
| aruba.lldp.npvid |  | long |
| aruba.lldp.reinit_delay |  | long |
| aruba.lldp.tx_delay |  | long |
| aruba.lldp.tx_hold |  | long |
| aruba.lldp.tx_timer |  | long |
| aruba.loop.rx_port |  | long |
| aruba.loop.tx_port |  | long |
| aruba.mac.ckn |  | keyword |
| aruba.mac.latest_an |  | keyword |
| aruba.mac.latest_kn |  | keyword |
| aruba.mac.new_mode |  | keyword |
| aruba.mac.old_an |  | keyword |
| aruba.mac.old_kn |  | keyword |
| aruba.mac.old_mode |  | keyword |
| aruba.mac.sci |  | keyword |
| aruba.management.config_param |  | keyword |
| aruba.mgmd.l3Port |  | long |
| aruba.mgmd.pkt_type |  | keyword |
| aruba.mstp.config_parameter |  | keyword |
| aruba.mstp.config_value |  | keyword |
| aruba.mstp.new_mode |  | keyword |
| aruba.mstp.old_mac |  | keyword |
| aruba.mstp.old_mode |  | keyword |
| aruba.mstp.old_priority |  | keyword |
| aruba.mstp.pk_type |  | keyword |
| aruba.mstp.proto |  | keyword |
| aruba.mstp.psc |  | keyword |
| aruba.mstp.reconfig_parameter |  | keyword |
| aruba.mtu |  | keyword |
| aruba.nae.action_type |  | keyword |
| aruba.nae.condition |  | keyword |
| aruba.nae.description |  | keyword |
| aruba.nae.monitorName |  | keyword |
| aruba.nd.type |  | keyword |
| aruba.ndm.new_mac |  | keyword |
| aruba.ndm.old_mac |  | keyword |
| aruba.ndm.role1 |  | keyword |
| aruba.ndm.role2 |  | keyword |
| aruba.port |  | keyword |
| aruba.prefix |  | keyword |
| aruba.sequence |  | keyword |
| aruba.server.sessions |  | keyword |
| aruba.server.timeout |  | long |
| aruba.session.id |  | keyword |
| aruba.session.name |  | keyword |
| aruba.slot |  | long |
| aruba.status |  | keyword |
| aruba.storage.name |  | keyword |
| aruba.storage.usage |  | keyword |
| aruba.system.devicespec |  | keyword |
| aruba.system.modspec |  | keyword |
| aruba.system.numdevs |  | long |
| aruba.system.time |  | date |
| aruba.tunnel.ttl |  | keyword |
| aruba.tunnel.type |  | keyword |
| aruba.vrf.id |  | keyword |
| aruba.vrf.name |  | keyword |
| aruba.zero_touch.central_location |  | keyword |
| aruba.zero_touch.http_proxy_location |  | keyword |
| aruba.zero_touch.image_file |  | keyword |
| client.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.mac | MAC address of the client. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| input.type | Input type | keyword |
| log.file.device_id | Device Id of the log file this event came from. | keyword |
| log.file.inode | Inode of the log file this event came from. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.origin.file.line | The line number of the file containing the source code which originated the log event. | long |
| log.origin.file.name | The name of the file containing the source code which originated the log event. Note that this field is not meant to capture the log file. The correct field to capture the log file is `log.file.path`. | keyword |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.appname | The device or application that originated the Syslog message, if available. | keyword |
| log.syslog.procid | The process name or ID that originated the Syslog message, if available. | keyword |
| log.syslog.severity.name | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different severity value (e.g. firewall, IDS), your source's text severity should go to `log.level`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `log.level`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.vlan.id | VLAN ID as reported by the observer. | keyword |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.interface.id | Interface ID as reported by an observer (typically SNMP interface ID). | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| package.installed | Time when package was installed. | date |
| package.version | Package version | keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.mac | MAC address of the server. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| server.port | Port of the server. | long |
| server.user.name | Short name or login of the user. | keyword |
| server.user.name.text | Multi-field of `server.user.name`. | match_only_text |
| service.target.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
