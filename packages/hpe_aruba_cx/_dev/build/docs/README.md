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
| Doc Fields           | Schema Mapping               |
|----------------------|------------------------------|
| `<aaa_config_type>`  | aruba.aaa.config_event       |
| `<aaa_config_event>` | aruba.aaa.config_type        |
| `<tacacs_action>`    | aruba.aaa.radius_action      |
| `<radius_event>`     | aruba.aaa.radius_event       |
| `<server_address>`   | server.address               |
| `<server_authport>`  | aruba.port                   |
| `<status>`           | aruba.status                 |
| `<server_vrfid>`     | aruba.vrf.id                 |
| `<radius_type>`      | event.type                   |
| `<tacacs_action>`    | aruba.aaa.tacacs_action      |
| `<tacacs_event>`     | aruba.aaa.tacacs_event       |
| `<server_address>`   | server.address               |
| `<server_authport>`  | aruba.port                   |
| `<server_vrfid>`     | aruba.vrf.id                 |
| `<tacacs_type>`      | aruba.aaa.tacacs_type        |

#### [ACLs events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ACL.htm)
| Doc Fields          | Schema Mapping         |
|---------------------|------------------------|
| `<log>`             | message                |
| `<type>`            | aruba.acl.type         |
| `<ace_string>`      | aruba.acl.ace_string   |
| `<application>`     | aruba.acl.application  |
| `<direction>`       | aruba.acl.direction    |
| `<hit_delta>`       | aruba.acl.hit_delta    |
| `<interface_name>`  | aruba.interface.name   |
| `<name>`            | aruba.acl.name         |

#### [ARP security events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ARP-SECURITY.htm)
| Doc Fields    | Schema Mapping  |
|---------------|-----------------|
| `<port_name>` | aruba.port      |
| `<status>`    | aruba.status    |
| `<vlan_id>`   | network.vlan.id |

#### [ASIC table full error for L3PD events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/L3_ASIC_RESOURCE.htm)
| Doc Fields | Schema Mapping |
|------------|----------------|


#### [BFD events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/BFD.htm)
| Doc Fields             | Schema Mapping               |
|------------------------|------------------------------|
| `<applied_interval>`   | aruba.bfd.applied_interval   |
| `<dest_ip>`            | destination.ip               |
| `<direction>`          | network.direction            |
| `<from>`               | aruba.bfd.from               |
| `<intf>`               | aruba.interface.id           |
| `<invalid_ip>`         | aruba.bfd.invalid_ip         |
| `<ip_version>`         | aruba.bfd.ip_version         |
| `<local_diag>`         | aruba.bfd.local_diag         |
| `<local_state>`        | aruba.bfd.local_state        |
| `<op_mode>`            | aruba.bfd.op_mode            |
| `<port_name>`          | aruba.port                   |
| `<remote_diag>`        | aruba.bfd.remote_diag        |
| `<remote_state>`       | aruba.bfd.remote_state       |
| `<requested_interval>` | aruba.bfd.requested_interval |
| `<session_id>`         | aruba.session.id             |
| `<src_port>`           | aruba.port                   |
| `<vrf>`                | aruba.vrf.id                 |

#### [BGP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/BGP.htm)
| Doc Fields          | Schema Mapping            |
|---------------------|---------------------------|
| `<as_number>`       | aruba.bgp.as_number       |
| `<id>`              | aruba.bgp.id              |
| `<error-code>`      | error.code                |
| `<error-subcode>`   | aruba.bgp.error_subcode   |
| `<local_as>`        | client.as.number          |
| `<pg_name>`         | aruba.bgp.pg_name         |
| `<remote-addr>`     | destination.address       |
| `<remote_as>`       | destination.as.number     |
| `<src_ipaddr>`      | source.ip                 |
| `<threshold_limit>` | aruba.limit.threshold     |
| `<vrf-name>`        | aruba.vrf.name            |

#### [Bluetooth Management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/BLUETOOTH_MGMT.htm)
| Doc Fields                 | Schema Mapping               |
|----------------------------|------------------------------|
| `<connected_disconnected>` | event.action                 |
| `<enabled_disabled>`       | event.action                 |
| `<inserted_removed>`       | event.action                 |
| `<mac>`                    | client.mac                   |

#### [CDP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CDP.htm)
| Doc Fields    | Schema Mapping       |
|---------------|----------------------|
| `<interface>` | aruba.interface.name |
| `<mac>`       | source.mac           |

#### [Certificate management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CERTMGR.htm)
| Doc Fields       | Schema Mapping        |
|------------------|-----------------------|
| `<cert_name>`    | aruba.cm.cert_name    |
| `<days>`         | aruba.cm.days         |
| `<error>`        | event.reason          |
| `<est_name>`     | aruba.cm.est_name     |
| `<profile_name>` | aruba.cm.profile_name |
| `<status>`       | aruba.status          |

#### [Config Management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CONFIG_MGMT.htm)
| Doc Fields     | Schema Mapping       |
|----------------|----------------------|
| `<error>`      | event.reason         |
| `<from>`       | aruba.config.from    |
| `<info>`       | event.action         |
| `<to>`         | aruba.config.to      |
| `<type>`       | aruba.config.type    |
| `<value>`      | aruba.config.value   |

#### [Connectivity Fault Management (CFM) events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ETH_OAM_CFM.htm)
| Doc Fields    | Schema Mapping      |
|---------------|---------------------|
| `<id>`        | aruba.cfm.id        |
| `<interface>` | aruba.cfm.interfact |

#### [Container manager events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CONTAINER.htm)
| Doc Fields   | Schema Mapping   |
|--------------|------------------|
| `<name>`     | container.name   |

#### [CoPP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/COPP.htm)
| Doc Field                      | Schema Mapping      |
|--------------------------------|---------------------|
| `<class>`                      | aruba.copp.class    |
| `<slot>`                       | aruba.slot          |

#### [CPU_RX events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CPU_RX.htm)
| Doc Field                      | Schema Mapping                  |
|--------------------------------|---------------------------------|
| `<action>`                     | event.action                    |
| `<filter_description>`         | aruba.cpu_rx.filter_description |
| `<unit>`                       | aruba.instance.id               |

#### [Credential Manager events DHCP Relay events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/CREDMGR.htm)
| Doc Field   | Schema Mapping |
|-------------|----------------|
| `<key-id>`  | user.id        |
| `<user>`    | user.name      |

#### [DHCP Relay events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DHCP-RELAY.htm)
| Doc Field | Schema Mapping |
|-----------|----------------|

#### [DHCP Server events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DHCP-SERVER.htm)
| Doc Field       | Schema Mapping    |
|-----------------|-------------------|
| `<client_id>`   | user.id           |
| `<config>`      | aruba.dhcp.config |
| `<expiry_time>` | event.end         |
| `<host>`        | host.name         |
| `<ip>`          | host.ip           |
| `<mac>`         | host.mac          |
| `<vfr>`         | aruba.vrf.id      |
| `<vfr_name>`    | aruba.vrf.name    |

#### [DHCPv4 Snooping events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DHCPv4-SNOOPING.htm)
| Doc Field             | Schema Mapping      |
|-----------------------|---------------------|
| `<client_mac>`        | client.mac          |
| `<existing_port>`     | server.port         |
| `<filename>`          | file.name           |
| `<ip_address>`        | client.ip           |
| `<lease_ip_address>`  | client.ip           |
| `<mac>`               | client.mac          |
| `<new_port>`          | aruba.dhcp.new_port |
| `<port>`              | aruba.port          |
| `<server_ip_address>` | server.ip           |
| `<source_mac>`        | client.mac          |
| `<vid>`               | network.vlan.id     |
| `<volume_name>`       | aruba.volume_name   |

#### [DHCPv6 Relay events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DHCPv6-RELAY.htm)
| Field | Description | Type | Common |
|-------|-------------|------|--------|


#### [DHCPv6 snooping events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/DHCPv6-SNOOPING.htm)

| Doc Fields                       | Schema Mapping         |
|----------------------------------|------------------------|
| `<ipv6_address>`                 | client.ip, server.ip   |
| `<port>`                         | aruba.port             |
| `<mac>`                          | client.mac             |
| `<existing_port>`                | aruba.port             |
| `<new_port>`                     | aruba.dhcp.new_port    |
| `<ip>`                           | client.ip              |
| `<vid>`                          | network.vlan.id        |
| `<volume_name>`                  | aruba.dhcp.volume_name |
| `<file_name>`                    | file.name              |

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
| Field                  | Description | Type | Common                       |
|------------------------|-------------|------|------------------------------|
| `<ccvlan>`             |             |      | network.vlan.id              |
| `<dataVlan>`           |             |      | network.vlan.id              |
| `<ifID>`               |             |      | observer.ingress.interface.id|
| `<instanceID>`         |             |      | aruba.instance.id            |
| `<interfaceName>`      |             |      | observer.ingress.interface.name|
| `<node>`               |             |      | client.mac                   |
| `<portName>`           |             |      | aruba.erps.port_name         |
| `<reason>`             |             |      | event.reason                 |
| `<ringID>`             |             |      | aruba.erps.ring_id           |
| `<state>`              |             |      | aruba.status                 |
| `<vlandID>`            |             |      | network.vlan.id              |

#### [EVPN events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/EVPN.htm)
| Doc Field   |  Schema Mapping   |
|-------------|-------------------|
| `<action>`  |  event.action     |
| `<evi>`     |  network.vlan.id  |
| `<ip_addr>` |  client.ip        |
| `<mac_addr>`|  client.mac       |
| `<rd>`      |  aruba.evpn.rd    |
| `<rt>`      |  aruba.evpn.rt    |
| `<vni>`     |  aruba.evpn.vni   |
| `<vrf>`     |  aruba.vrf.id     |
| `<vtep_ip>` |  aruba.evpn.vtep_ip|

#### [External Storage events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/EXTERNAL-STORAGE.htm)
| Doc Field   | Schema Mapping              |
|-------------|-----------------------------|
| `<name>`    | aruba.storage.name |
| `<status>`  | aruba.status                |

#### [Fan events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/FAN.htm)
| Doc Field                  | Schema Mapping               |
|----------------------------|------------------------------|
| `<count>`                  | aruba.fan.count              |
| `<subsystem>`              | aruba.subsystem              |
| `<speedval>`               | aruba.fan.speedval           |
| `<value>`                  | aruba.fan.value              |
| `<FT_Num>`                 | aruba.fan.ft_num             |
| `<FMod_Num>`               | aruba.fan.fmod_num           |
| `<num_of_failure>`         | aruba.error.count            |
| `<failure_type>`           | error.type                   |
| `<compare_mode>`           | aruba.fan.compare_mode       |
| `<num_of_failure_limit>`   | aruba.limit.threshold        |
| `<seconds>`                | aruba.time.seconds           |
| `<reason>`                 | event.reason                 |
| `<function>`               | aruba.fan.function           |
| `<tray_index>`             | aruba.fan.tray_idx           |
| `<fan_index>`              | aruba.fan.index              |
| `<FanName>`                | aruba.fan.name               |
| `<FanStatus>`              | aruba.fan.status             |
| `<FanModuleIdx>`           | aruba.fan.module_idx         |
| `<FanTrayIdx>`             | aruba.fan.tray_idx           |
| `<OldStatus>`              | aruba.fan.old_status         |
| `<NewStatus>`              | aruba.fan.status             |
| `<FanCount>`               | aruba.fan.count              |
| `<FanMinimum>`             | aruba.fan.minimum            |
| `<ZoneIdx>`                | aruba.fan.zone_idx           |
| `<FanSpdIdxStatus>`        | aruba.fan.speed_idx_status   |
| `<Status>`                 | aruba.fan.status             |
| `<FT_Dir>`                 | aruba.fan.ft_dir             |
| `<FT_air_curr>`            | aruba.fan.ft_air_curr        |
| `<FT_air_req>`             | aruba.fan.ft_air_req         |
| `<En_Dis>`                 | aruba.fan.status             |

#### [Fault monitor events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/FAULT_MONITOR.htm)
| Doc Fields                | Schema Mapping                   |
|---------------------------|----------------------------------|
| `<fault>`                 | aruba.fault.type                 |
| `<interface>`             | aruba.interface.name             |
| `<mac>`                   | client.mac                       |
| `<sa_diff_count>`         | aruba.fault.sa_diff_count        |
| `<da_diff_count>`         | aruba.fault.da_diff_count        |

#### [Firmware Update events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/UPDATE.htm)
| Doc Fields        | Schema Mapping               |
|-------------------|------------------------------|
| `<user>`          | user.name                    |
| `<image_profile>` | aruba.firmware.image_profile |
| `<dnld_type>`     | aruba.firmware.dnld_type     |
| `<host>`          | source.address               |
| `<before>`        | aruba.firmware.before        |
| `<after>`         | aruba.firmware.after         |

#### [Hardware Health Monitor events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/HW-HEALTH-MONITOR.htm)
| Doc Fields     | Schema Mapping           |
|----------------|--------------------------|
| `<addr>`       | aruba.hardware.addr      |
| `<bus>`        | aruba.hardware.bus       |
| `<cap>`        | aruba.hardware.cap       |
| `<cecount>`    | aruba.hardware.cecount   |
| `<channel>`    | aruba.hardware.channel   |
| `<cpus>`       | aruba.hardware.cpus      |
| `<device>`     | aruba.hardware.device    |
| `<error_code>` | error.code               |
| `<function>`   | aruba.hardware.function  |
| `<level>`      | aruba.hardware.level     |
| `<location>`   | aruba.hardware.location  |
| `<mcgstatus>`  | aruba.hardware.mcgstatus |
| `<misc>`       | aruba.hardware.misc      |
| `<offlined>`   | aruba.hardware.offlined  |
| `<origin>`     | aruba.hardware.origin    |
| `<page>`       | aruba.hardware.page      |
| `<seg>`        | aruba.hardware.seg       |
| `<slot>`       | aruba.slot               |
| `<socket>`     | aruba.hardware.socket    |
| `<status>`     | aruba.status             |
| `<test_name>`  | aruba.hardware.test_name |
| `<threshold>`  | aruba.limit.threshold    |
| `<type>`       | aruba.hardware.type      |

#### [Hardware Switch controller sync events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/HSC-SYNCD.htm)
| Doc Fields   | Schema Mapping   |
|--------------|------------------|
| `<ip>`       | server.ip        |
| `<mac>`      | server.mac       |
| `<mac>`      | destination.mac  |
| `<port>`     | aruba.port       |
| `<vni>`      | network.vlan.id  |

#### [HTTPS Server events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/HTTPS_SERVER.htm)
| Doc Fields   | Schema Mapping        |
|--------------|-----------------------|
| `<mode>`     | aruba.server.mode     |
| `<sessions>` | aruba.server.sessions |
| `<status>`   | aruba.status          |
| `<timeout>`  | aruba.timeout         |
| `<user>`     | server.user.name      |
| `<vrf>`      | aruba.vrf.id          |

#### [In-System Programming events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ISP.htm)
| Doc Fields     | Schema Mapping           |
|----------------|--------------------------|
| `<devicespec>` | aruba.system.devicespec  |
| `<file>`       | file.name                |
| `<fromver>`    | service.version          |
| `<line>`       | aruba.system.line        |
| `<modspec>`    | aruba.system.modspec     |
| `<numdevs>`    | aruba.system.numdevs     |
| `<pass>`       | event.action             |
| `<time>`       | aruba.system.time        |
| `<tover>`      | service.target.version   |

#### [Interface events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/INTERFACE.htm)
| Doc Fields     | Schema Mapping             |
|----------------|----------------------------|
| `<interface>`  | aruba.interface.id         |
| `<port_speed>` | aruba.interface.port_speed |
| `<state>`      | aruba.interface.state      |

#### [Internal storage events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/INTERNAL-STORAGE.htm)
| Doc Fields      | Schema Mapping        |
|-----------------|-----------------------|
| `<error>`       | event.reason          |
| `<module_num>`  | aruba.slot            |
| `<name>`        | aruba.storage.name    |
| `<usage>`       | aruba.storage.usage   |

#### [IP source lockdown events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/IP_SOURCE_LOCKDOWN.htm)
| Field                              | Description | Type | Common                       |
|------------------------------------|-------------|------|------------------------------|
| aruba.lockdown.interface           |             |      | observer.ingress.interface.name |
| aruba.lockdown.max_supported_limit |             |      | aruba.limit.threshold           |

#### [IP tunnels events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/IP_TUNNEL.htm)
| Doc Fields     | Schema Mapping            |
|----------------|---------------------------|
| `<dst_ip>`     | destination.ip            |
| `<ip_mtu>`     | aruba.mtu                 |
| `<tunnel_name>`| aruba.tunnel.name         |
| `<src_ip>`     | source.ip                 |
| `<ttl>`        | aruba.tunnel.ttl          |
| `<type>`       | aruba.tunnel.type         |
| `<vrf>`        | aruba.vrf.id              |

#### [IP-SLA events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/IPSLA.htm)
| Doc Fields    | Schema Mapping         |
|---------------|------------------------|
| `<interface>` | aruba.interface.id    |
| `<name>`      | aruba.ip_sla.name     |
| `<operation>` | event.action          |
| `<reason>`    | event.reason          |
| `<state>`     | aruba.state           |

#### [IPv6 Router Advertisement events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/IPV6-RA.htm)
| Doc Fields    | Schema Mapping       |
|---------------|----------------------|
| `<intf>`      | aruba.interface.id   |
| `<ipv6_addr>` | server.ip            |
| `<prefix>`    | aruba.prefix         |
| `<prefixlen>` | aruba.len            |

#### [IRDP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/IRDP.htm)
| Docs Field    | Schema Mapping       |
|---------------|----------------------|
| `<interface>` | aruba.interface.id   |

#### [L3 Encap capacity events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/L3_ENCAP.htm)
| Docs Field            | Schema Mapping               |
|-----------------------|------------------------------|
| `<encaps_allocated>`  | aruba.l3.encaps_allocated    |
| `<encaps_free>`       | aruba.l3.encaps_free         |

#### [L3 Resource Manager events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/L3_RESMGR.htm)
| Docs Field   | Schema Mapping  |
|--------------|-----------------|
| `<prefix>`   | aruba.prefix    |

#### [LACP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LACP.htm)
| Docs Field                | Schema Mapping             |
|---------------------------|----------------------------|
| `<actor_state>`           | aruba.lacp.actor_state     |
| `<fallback>`              | aruba.lacp.fallback        |
| `<fsm_state>`             | aruba.lacp.fsm_state       |
| `<intf_id>`               | aruba.interface.id         |
| `<intf_id>`               | aruba.interface.prev_id    |
| `<intf_name>`             | aruba.interface.name       |
| `<lacp_fallback_mode>`    | aruba.lacp.fallback_mode   |
| `<lacp_fallback_timeout>` | aruba.timeout              |
| `<mode>`                  | aruba.lacp.mode            |
| `<lacp_rate>`             | aruba.lacp.rate            |
| `<lag_id>`                | aruba.instance.id          |
| `<lag_number>`            | aruba.lacp.lag_number      |
| `<lag_speed>`             | aruba.lacp.lag_speed       |
| `<lacp_mode>`             | aruba.lacp.lacp_mode       |
| `<partner_state>`         | aruba.lacp.partner_state   |
| `<partner_sys_id>`        | aruba.lacp.partner_sys_id  |
| `<port_speed>`            | aruba.lacp.port_speed      |
| `<system_id>`             | aruba.lacp.system_id       |
| `<system_priority>`       | aruba.lacp.system_priority |

#### [LAG events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LAG.htm)
| Docs Field   | Schema Mapping               |
|--------------|------------------------------|
| `<error>`    | event.reason                 |
| `<hw_port>`  | aruba.port                   |
| `<interface>`| aruba.interface.id           |
| `<lag_id>`   | aruba.instance.id            |
| `<mode>`     | aruba.lag.mode               |
| `<port>`     | aruba.port                   |
| `<psc>`      | aruba.lag.psc                |
| `<rc>`       | error.code                   |
| `<tid>`      | process.thread.id            |
| `<unit>`     | aruba.unit                   |
| `<vlan>`     | network.vlan.id              |

#### [Layer 3 Interface events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/L3INTERFACE.htm)
| Docs Field      | Schema Mapping               |
|-----------------|-------------------------------|
| `<addr>`        | server.address                 |
| `<addr_status>` | aruba.status                   |
| `<egress_id>`   | observer.egress.interface.id   |
| `<err>`         | event.reason                   |
| `<interface>`   | aruba.interface.id             |
| `<intf>`        | aruba.interface.id             |
| `<ipaddr>`      | host.ip                        |
| `<mtu>`         | aruba.mtu                      |
| `<nexthop>`     | aruba.l3.nexthop               |
| `<port>`        | aruba.port                     |
| `<prefix>`      | aruba.prefix                   |
| `<state>`       | aruba.state                    |
| `<value>`       | server.ip                      |
| `<vlanid>`      | network.vlan.id                |

#### [LED events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LED.htm)
| Docs Field    | Schema Mapping         |
|---------------|------------------------|
| `<count>`     | aruba.count            |
| `<subsystem>` | aruba.subsystem        |

#### [LLDP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LLDP.htm)
| Docs Field     | Schema Mapping               |
|----------------|------------------------------|
| `<chassisid>`  | aruba.instance.id            |
| `<interface>`  | aruba.interface.id           |
| `<ninterface>` | aruba.lldp.ninterface        |
| `<npvid>`      | aruba.lldp.npvid             |
| `<pvid>`       | aruba.lldp.pvid              |
| `<hold>`       | aruba.lldp.tx_hold           |
| `<value>`      | aruba.lldp.tx_delay          |
| `<value>`      | aruba.lldp.reinit_delay      |
| `<value>`      | aruba.lldp.tx_timer          |
| `<value>`      | server.ip                    |


#### [Loop Protect events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LOOP-PROTECT.htm)
| Docs Field     | Schema Mapping         |
|----------------|------------------------|
| `<portName>`   | aruba.port             |
| `<rxportName>` | aruba.loop.rx_port     |
| `<txportName>` | aruba.loop.tx_port     |
| `<vlan>`       | network.vlan.id        |

#### [Loopback events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/LOOPBACK.htm)
| Docs Field    | Schema Mapping        |
|---------------|-----------------------|
| `<interface>` | aruba.interface.id    |
| `<state>`     | aruba.interface.state |


#### [MAC Address mode configuration events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/L3_MAC_ADDRESS_CONFIGURATION.htm)
| Docs Field   | Schema Mapping       |
|--------------|----------------------|
| `<mac>`      | server.mac           |
| `<new_mode>` | aruba.mac.new_mode   |
| `<old_mode>` | aruba.mac.old_mode   |
| `<vlan>`     | network.vlan.id      |

#### [MAC Learning events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MAC-LEARN.htm)
| Docs Field    | Schema Mapping               |
|---------------|------------------------------|
| `<from-intf>` | aruba.interface.prev_id      |
| `<intf>`      | aruba.interface.id           |
| `<mac>`       | server.mac                   |
| `<to-intf>`   | aruba.mac.interface.id       |
| `<vlan>`      | network.vlan.id              |

#### [MACsec events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MACSEC.htm)
| Docs Field     | Schema Mapping               |
|----------------|------------------------------|
| `<ckn>`        | aruba.mac.ckn                |
| `<ifname>`     | aruba.interface.name         |
| `<latest_an>`  | aruba.mac.latest_an          |
| `<latest_kn>`  | aruba.mac.latest_kn          |
| `<old_an>`     | aruba.mac.old_an             |
| `<old_kn>`     | aruba.mac.old_kn             |
| `<sci>`        | aruba.mac.sci                |

#### [Management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MGMT.htm)
| Docs Field                    | Schema Mapping           |
|-------------------------------|--------------------------|
| `<mgmt_intf_config_crit>`     | aruba.mgmt.config_crit   |
| `<mgmt_intf_config_err>`      | aruba.mgmt.config_err    |
| `<mgmt_intf_config_param>`    | aruba.mgmt.config_param  |

#### [MDNS events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MDNS.htm)
| Docs Field                  | Schema Mapping           |
|-----------------------------|--------------------------|


#### [MGMD events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MGMD.htm)
| Docs Field    | Schema Mapping              |
|---------------|-----------------------------|
| `<if_name>`   | aruba.interface.name        |
| `<ip_address>`| client.ip                   |
| `<l3Port>`    | aruba.mgmd.l3_port          |
| `<mgmd_type>` | aruba.mgmd.mgmd_type        |
| `<pkt_type>`  | aruba.mgmd.pkt_type         |
| `<port>`      | aruba.port                  |
| `<port0>`     | aruba.port                  |
| `<port1>`     | aruba.mgmd.port1            |
| `<ring_id>`   | aruba.mgmd.ring_id          |
| `<size_value>`| aruba.len                   |
| `<state>`     | aruba.state                 |
| `<status>`    | aruba.status                |
| `<sub_system>`| aruba.subsystem             |
| `<type>`      | aruba.mgmd.type             |
| `<vlan>`      | network.vlan.id             |

#### [Mirroring events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MIRRORING.htm)
| Docs Field   | Schema Mapping       |
|--------------|----------------------|
| `<number>`   | aruba.session.id     |

#### [Module events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MODULE.htm)
| Docs Field      | Schema Mapping         |
|-----------------|------------------------|
| `<name>`        | aruba.module.name      |
| `<part_number>` | aruba.unit             |
| `<priority>`    | aruba.priority         |
| `<reason>`      | event.reason           |
| `<type>`        | aruba.module.type      |

#### [MSDP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MSDP.htm)
| Docs Field    | Schema Mapping               |
|---------------|------------------------------|
| `<grp_ip>`    | aruba.msdp.grp_ip            |
| `<if_name>`   | aruba.interface.name         |
| `<peer_ip>`   | client.ip                    |
| `<port>`      | aruba.port                   |
| `<rp_ip>`     | aruba.msdp.rp_ip             |
| `<src_ip>`    | source.ip                    |
| `<state>`     | aruba.state                  |
| `<status>`    | aruba.status                 |
| `<tcp_entity>`| aruba.msdp.tcp_entity        |
| `<vrf_name>`  | aruba.vrf.name               |

#### [Multicast Traffic Manager events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MTM.htm)
| Docs Field   | Schema Mapping |
|--------------|----------------|
| `<limit>`    | aruba.limit.threshold    |

#### [Multiple spanning tree protocol events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MSTP.htm)
| Docs Field            | Schema Mapping               |
|-----------------------|------------------------------|
| `<config_parameter>`  | aruba.mstp.config_parameter  |
| `<instance>`          | aruba.instance.id            |
| `<mac>`               | source.mac                   |
| `<new_mac>`           | source.mac                   |
| `<new_mode>`          | aruba.mstp.new_mode          |
| `<new_port>`          | aruba.port                   |
| `<new_priority>`      | aruba.priority               |
| `<old_mac>`           | aruba.mstp.old_mac           |
| `<old_mode>`          | aruba.mstp.old_mode          |
| `<old_port>`          | aruba.mstp.old_port          |
| `<old_priority>`      | aruba.mstp.old_priority      |
| `<pkt_type>`          | aruba.mstp.pkt_type          |
| `<port>`              | aruba.port                   |
| `<priority_mac>`      | aruba.mstp.priority_mac      |
| `<proto>`             | aruba.mstp.proto             |
| `<reconfig_parameter>`| aruba.mstp.reconfig_parameter|
| `<state>`             | aruba.state                  |
| `<value>`             | aruba.mstp.config_value      |

#### [MVRP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/MVRP.htm)
| Docs Field   | Schema Mapping     |
|--------------|--------------------|
| `<port>`     | aruba.port         |
| `<vlan>`     | network.vlan.id    |
| `<vlan_max>` | aruba.limit.threshold |

#### [NAE Agents events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/NAE_ALERT.htm)
| Docs Field | Schema Mapping      |
|------------|---------------------|
| `<name>`     | aruba.nae.name      |

#### [NAE events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/TSDBD.htm)
| Docs Field     | Schema Mapping               |
|----------------|------------------------------|
| `<condition>`  | aruba.nae.condition          |
| `<monitorName>`| aruba.nae.monitor_name       |
| `<name>`       | aruba.nae.name               |
| `<uri>`        | url.original                 |
| `<user>`       | user.name                    |

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
| Docs Field   | Schema Mapping         |
|--------------|------------------------|
| `<count>`    | aruba.count            |
| `<ip>`       | server.ip              |
| `<src_mac>`  | source.mac             |
| `<port>`     | aruba.port             |
| `<status>`   | aruba.status           |
| `<type>`     | aruba.nd.type          |
| `<vid>`      | network.vlan.id        |
| `<vlan>`     | network.vlan.id        |

#### [NDM events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/NDM.htm)
| Docs Field         | Schema Mapping         |
|--------------------|------------------------|
| `<ip>`             | client.ip              |
| `<mac>`            | client.mac             |
| `<new_mac>`        | client.mac             |
| `<old_mac>`        | aruba.ndm.old_mac      |
| `<port>`           | aruba.port             |
| `<role>`           | aruba.role             |
| `<role1>`          | aruba.ndm.old_role     |
| `<role2>`          | aruba.role             |
| `<time>`           | aruba.time.seconds     |
| `<throttle_count>` | aruba.throttle_count   |
| `<vrf>`            | aruba.vrf.id           |

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
| Docs Field         | Schema Mapping                      |
|--------------------|-------------------------------------|
| `<action>`         | event.action                        |
| `<area>`           | aruba.ospf.area                     |
| `<destination>`    | destination.address                 |
| `<err>`            | event.reason                        |
| `<event>`          | aruba.ospf.event                    |
| `<fp_id>`          | aruba.ospf.fp_id                    |
| `<group_id>`       | group.id                            |
| `<input>`          | aruba.ospf.input                    |
| `<interface>`      | aruba.interface.id                  |
| `<new>`            | aruba.ospf.router_id                |
| `<new_state>`      | aruba.state                         |
| `<next_state>`     | aruba.state                         |
| `<nexthops>`       | aruba.ospf.nexthops                 |
| `<old>`            | aruba.ospf.old_router_id            |
| `<old_state>`      | aruba.ospf.old_state                |
| `<ospf-interface>` | aruba.interface.id                  |
| `<router-id>`      | aruba.ospf.router_id                |
| `<rule>`           | rule.name                           |
| `<state>`          | aruba.state / aruba.ospf.old_state  |
| `<stats_id>`       | aruba.ospf.stats_id                 |

#### [OSPFv3 events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/OSPFv3.htm)
| Docs Field         | Schema Mapping                      |
|--------------------|-------------------------------------|
| `<action>`         | event.action                        |
| `<area>`           | aruba.ospf.area                     |
| `<err>`            | event.reason                        |
| `<fp_id>`          | aruba.ospf.fp_id                    |
| `<group_id>`       | group.id                            |
| `<input>`          | aruba.ospf.input                    |
| `<interface>`      | aruba.interface.id                  |
| `<link-local>`     | aruba.ospf.link_local               |
| `<new_state>`      | aruba.state                         |
| `<old_state>`      | aruba.ospf.old_state                |
| `<router-id>`      | aruba.ospf.router_id                |
| `<rule>`           | rule.name                           |
| `<stats_id>`       | aruba.ospf.stats_id                 |

#### [Password Reset events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PASSWD_RESET.htm)
| Docs Field               | Schema Mapping               |
|--------------------------|------------------------------|

#### [PIM events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PIM.htm)
| Docs Field          | Schema Mapping               |
|---------------------|------------------------------|
| `<callerid>`        | aruba.pim.callerid           |
| `<dip0>`            | aruba.pim.dip0               |
| `<dip1>`            | aruba.pim.dip1               |
| `<dip2>`            | aruba.pim.dip2               |
| `<dip3>`            | aruba.pim.dip3               |
| `<ebsr_ip>`         | aruba.pim.ebsr_ip            |
| `<err>`             | aruba.error.description      |
| `<error>`           | event.reason                 |
| `<error_value>`     | aruba.pim.error_value        |
| `<event>`           | aruba.pim.event              |
| `<fd>`              | aruba.pim.fd                 |
| `<flowtype>`        | aruba.pim.flowtype           |
| `<group>`           | group.name                   |
| `<ifname>`          | aruba.interface.name         |
| `<InterfaceName>`   | aruba.interface.name         |
| `<ip_address>`      | server.ip                    |
| `<ip_version>`      | aruba.pim.ip_version         |
| `<isl_status>`      | aruba.status                 |
| `<limit>`           | aruba.limit.threshold        |
| `<mode>`            | aruba.limit.mode             |
| `<neighbor_ip>`     | client.ip                    |
| `<pim_version>`     | package.version              |
| `<pkt>`             | network.packets              |
| `<pkt_type>`        | aruba.pim.pkt_type           |
| `<port>`            | aruba.port                   |
| `<priority>`        | aruba.priority               |
| `<qsize>`           | aruba.pim.qsize              |
| `<reason>`          | event.reason                 |
| `<sip0>`            | aruba.pim.sip0               |
| `<sip1>`            | aruba.pim.sip1               |
| `<sip2>`            | aruba.pim.sip2               |
| `<sip3>`            | aruba.pim.sip3               |
| `<source>`          | source.ip                    |
| `<srcport>`         | aruba.port                   |
| `<srcvid>`          | network.vlan.id              |
| `<state>`           | aruba.state                  |
| `<status>`          | aruba.status                 |
| `<totalvid>`        | aruba.pim.totalvid           |
| `<type>`            | aruba.pim.type               |
| `<val>`             | aruba.limit.read_value       |
| `<value>`           | aruba.pim.error_value        |
| `<vrf_name> / <vrfname>` | aruba.vrf.name          |

#### [Policies events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/POLICY.htm)
| Docs Field       | Schema Mapping               |
|------------------|------------------------------|
| `<application>`  | aruba.policy.application     |
| `<policy_name>`  | aruba.policy.name            |

#### [Port access roles events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/ROLE.htm)
| Docs Field              | Schema Mapping               |
|-------------------------|------------------------------|
| `<cprole_error_string>` | event.reason                 |
| `<role_name>`           | aruba.role                   |

#### [Port events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PORT.htm)
| Docs Field     | Schema Mapping               |
|----------------|------------------------------|
| `<error>`      | event.reason                 |
| `<interface>`  | aruba.interface.id           |
| `<ip_address>` | client.ip                    |
| `<mtu>`        | aruba.mtu                    |
| `<policy>`     | aruba.policy.name            |
| `<status>`     | aruba.status                 |
| `<vlan>`       | network.vlan.id              |

#### [Port security events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PORT-SECURITY.htm)
| Docs Field     | Schema Mapping       |
|----------------|----------------------|
| `<if_name>`    | aruba.interface.name |
| `<mac_addr>`   | client.mac           |
| `<port>`       | aruba.port           |

#### [Port Statistics events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/COUNTERS.htm)
| Docs Field | Schema Mapping       |
|------------|----------------------|
| `<name>`     | aruba.port           |

#### [PORT_ACCESS events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PORT_ACCESS.htm)
| Docs Field      | Schema Mapping               |
|-----------------|------------------------------|
| `<limit>`       | aruba.limit.threshold        |
| `<mac_address>` | client.mac                   |
| `<mode>`        | aruba.port_access.mode       |
| `<new_limit>`   | aruba.limit.threshold        |
| `<new_name>`    | aruba.port_access.name       |
| `<new_mode>`    | aruba.port_access.mode       |
| `<old_limit>`   | aruba.port_access.old_limit  |
| `<old_mode>`    | aruba.port_access.old_mode   |
| `<old_name>`    | aruba.port_access.old_name   |
| `<policy_name>` | aruba.policy.name            |
| `<port>`        | aruba.port                   |
| `<vlan_id>`     | network.vlan.id              |


#### [Power events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/POWER.htm)
| Docs Field    | Schema Mapping         |
|---------------|------------------------|
| `<failures>`  | aruba.count            |
| `<fanidx>`    | aruba.power.fanidx     |
| `<name>`      | aruba.power.name       |
| `<redund>`    | aruba.power.redund     |
| `<sensorid>`  | aruba.power.sensorid   |
| `<state>`     | aruba.state            |
| `<status>`    | aruba.status           |
| `<Support>`   | aruba.power.support    |
| `<Type>`      | aruba.power.type       |
| `<warnings>`  | aruba.count            |

#### [Power over Ethernet events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/POE.htm)
| Docs Field           | Schema Mapping               |
|----------------------|------------------------------|
| `<assigned_class>`   | aruba.poe.assigned_class     |
| `<assigned_class_A>` | aruba.poe.assigned_class_a   |
| `<assigned_class_B>` | aruba.poe.assigned_class_b   |
| `<cntrl_name>`       | aruba.poe.cntrl_name         |
| `<duration>`         | aruba.poe.duration           |
| `<fault_type>`       | aruba.poe.fault_type         |
| `<interface_name>`   | aruba.interface.name         |
| `<threshold_limit>`  | aruba.limit.threshold        |
| `<pair>`             | aruba.poe.pair               |
| `<paira_class>`      | aruba.poe.paira_class        |
| `<pairb_class>`      | aruba.poe.pairb_class        |
| `<pd_class>`         | aruba.poe.pd_class           |
| `<pd_type>`          | aruba.poe.pd_type            |
| `<power>`            | aruba.power.value            |
| `<power_available>`  | aruba.power.available        |
| `<power_drawn>`      | aruba.power.value            |
| `<req_class>`        | aruba.poe.req_class          |
| `<req_class_a>`      | aruba.poe.req_class_a        |
| `<req_class_b>`      | aruba.poe.req_class_b        |
| `<subsys_name>`      | aruba.poe.subsys_name        |

#### [Proxy ARP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/PROXY-ARP.htm)
| Docs Field    | Schema Mapping |
|---------------|----------------|
| `<port>`      | aruba.port     |
| `<vrf>`       | aruba.vrf.id   |

#### [QoS ASIC Provider events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/QOS_ASIC.htm)
| Docs Field           | Schema Mapping       |
|----------------------|----------------------|
| `<error_string>`     | event.reason         |
| `<existing_slot>`    | aruba.slot           |
| `<local_slot>`       | aruba.slot           |
| `<new_slot>`         | aruba.qos.new_slot   |
| `<port_name>`        | aruba.port           |
| `<pri>`              | aruba.priority       |
| `<queue>`            | aruba.qos.queue      |
| `<val>`              | error.code           |

#### [Quality of Service events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/QOS.htm)
| Docs Field         | Schema Mapping       |
|--------------------|----------------------|
| `<error>`          | event.reason         |
| `<error_string>`   | event.reason         |

#### [Rapid per VLAN Spanning Tree Protocol events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/RPVST.htm)
| Docs Field                | Schema Mapping               |
|---------------------------|------------------------------|
| `<Current_Virtual_Ports>` | aruba.limit.read_value       |
| `<interface>`             | aruba.interface.id           |
| `<mac>`                   | client.mac                   |
| `<Maximum_Virtual_Ports>` | aruba.limit.threshold        |
| `<new_mac>`               | client.mac                   |
| `<new_mode>`              | aruba.rpvst.new_mode         |
| `<new_port>`              | aruba.port                   |
| `<new_priority>`          | aruba.priority               |
| `<npvid>`                 | aruba.rpvst.npvid            |
| `<old_mac>`               | aruba.rpvst.old_mac          |
| `<old_mode>`              | aruba.rpvst.old_mode         |
| `<old_port>`              | aruba.rpvst.old_port         |
| `<old_priority>`          | aruba.rpvst.old_priority     |
| `<port>`                  | aruba.port                   |
| `<pkt_type>`              | aruba.rpvst.pkt_type         |
| `<priority_mac>`          | client.mac                   |
| `<proto>`                 | aruba.rpvst.proto            |
| `<pvid>`                  | aruba.rpvst.pvid             |
| `<instance>`              | aruba.instance.id            |
| `<vlan>`                  | network.vlan.id              |

#### [RBAC events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/RBACD.htm)
| Docs Field    | Schema Mapping |
|---------------|----------------|
| `<tac_status>` | aruba.status  |


#### [Redundant Management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/REDUNDANT_MANAGEMENT.htm)
| Docs Field      | Schema Mapping               |
|-----------------|------------------------------|
| `<mgmt_module>` | aruba.redundant.mgmt_module  |
| `<reason>`      | event.reason                 |

#### [Replication Manager events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/REPLD.htm)
| Docs Field   | Schema Mapping               |
|--------------|------------------------------|
| `<uuid_str>` | aruba.instance.id            |

#### [REST events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/RESTD.htm)
| Docs Field           | Schema Mapping             |
|----------------------|----------------------------|
| `<action>`           | event.action               |
| `<activate_address>` | aruba.rest.activate_address|
| `<added_user>`       | aruba.rest.added_user      |
| `<added_user_role>`  | aruba.role                 |
| `<autztype>`         | aruba.rest.autztype        |
| `<central_location>` | aruba.rest.central_location|
| `<central_source>`   | aruba.rest.central_source  |
| `<command>`          | aruba.rest.command         |
| `<config_name>`      | aruba.rest.config_name     |
| `<deleted_user>`     | aruba.rest.deleted_user    |
| `<dns>`              | aruba.rest.ip              |
| `<dns_nameserver>`   | aruba.rest.dns_nameserver  |
| `<error>`            | event.reason               |
| `<from_name>`        | aruba.rest.config_from_name|
| `<identity>`         | aruba.rest.identity        |
| `<ip_address>`       | client.ip                  |
| `<match>`            | aruba.rest.match           |
| `<mgmt_intf>`        | aruba.interface.id         |
| `<mode>`             | aruba.rest.mode            |
| `<name>`             | aruba.rest.name            |
| `<resource>`         | aruba.rest.resource        |
| `<rest_operation>`   | aruba.rest.operation       |
| `<sessionid>`        | aruba.session.id           |
| `<source_ip>`        | source.ip                  |
| `<subscriber>`       | aruba.rest.subscriber      |
| `<subscription>`     | aruba.rest.subscription    |
| `<to_name>`          | aruba.rest.config_to_name  |
| `<uri>`              | url.original               |
| `<url>`              | url.original               |
| `<user>`             | user.name                  |
| `<vrf>`              | aruba.vrf.id               |
| `<vrf_name>`         | aruba.vrf.name             |
| `<value>`            | aruba.rest.type            |

#### [Self Test events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/SELFTEST.htm)
| Docs Field   | Schema Mapping              |
|--------------|-----------------------------|
| `<interface>`| aruba.interface.id          |
| `<slot>`     | aruba.slot                  |
| `<stack>`    | aruba.self_test.stack       |
| `<subsystem>`| aruba.subsystem             |
| `<value>`    | event.reason                |

#### [Self Test Monitor events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/SelfTestMonitor.htm)
| Docs Field   | Schema Mapping              |
|--------------|-----------------------------|

#### [sFlow events](https://www.arubanetworks.com/techdocs/AOS-CX/10.07/HTML/5200-8214/Content/events/SFLOW.htm)
| Docs Field        | Schema Mapping                             |
|-------------------|--------------------------------------------|
| `<bridge>`        | aruba.sflow.bridge                         |
| `<chain>`         | aruba.sflow.chain                          |
| `<desc>`          | aruba.error.description                    |
| `<dgramsize>`     | aruba.sflow.dgramsize                      |
| `<error>`         | event.reason                               |
| `<file>`          | file.name                                  |
| `<hdrlen>`        | aruba.len                                  |
| `<ifIndex>`       | aruba.interface.id                         |
| `<interface>`     | aruba.interface.id                         |
| `<intvl>`         | aruba.sflow.intvl                          |
| `<ip_addr>`       | client.ip                                  |
| `<ip_address>`    | client.ip                                  |
| `<mode>`          | aruba.sflow.mode                           |
| `<new_rate>`      | aruba.sflow.new_rate                       |
| `<old_rate>`      | aruba.sflow.old_rate                       |
| `<operation>`     | aruba.sflow.operation                      |
| `<port>`          | aruba.port                                 |
| `<port_name>`     | aruba.port                                 |
| `<unit>`          | aruba.unit                                 |

#### [SFTP Client events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/SFTP_CLIENT.htm)
| Docs Field | Schema Mapping         |
|------------|------------------------|
| `<from>`   | source.address         |
| `<status>` | aruba.status           |
| `<to>`     | destination.address    |

#### [Smartlink events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/SMARTLINK.htm)
| Docs Field | Schema Mapping         |
|------------|------------------------|
| `<id>`     | group.id               |
| `<id>`     | network.vlan.id        |
| `<ifName>` | aruba.interface.name   |

#### [SNMP events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/SNMP.htm)
| Docs Field          | Schema Mapping               |
|---------------------|------------------------------|
| `<truth_value>`     | aruba.snmp.truth_value       |
| `<vrf>`             | aruba.vrf.id                 |

#### [SSH client events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/SSH_CLIENT.htm)
| Docs Field   | Schema Mapping        |
|--------------|-----------------------|
| `<ipaddr>`   | server.ip             |
| `<port_num>` | server.port           |
| `<username>` | user.name             |
| `<vrf_name>` | aruba.vrf.name        |

#### [SSH server events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/SSH_SERVER.htm)
| Docs Field       | Schema Mapping        |
|------------------|-----------------------|
| `<ip_address>`   | client.ip             |
| `<key_name>`     | aruba.ssh.key_name    |
| `<mgmt_intf>`    | aruba.interface.id    |
| `<new_ip>`       | aruba.ssh.new_ip      |
| `<original_ip>`  | client.ip             |
| `<username>`     | user.name             |
| `<vrf_name>`     | aruba.vrf.name        |

#### [Supportability events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/SUPPORTABILITY.htm)
| Docs Field           | Schema Mapping                   |
|----------------------|----------------------------------|
| `<boot_id>`          | host.boot.id                     |
| `<boot_count_status>`| aruba.status                     |
| `<daemons>`          | aruba.supportability.daemons     |
| `<err_desc>`         | aruba.error.description          |
| `<index>`            | aruba.supportability.alarm_index |
| `<log_type>`         | aruba.supportability.log_type    |
| `<module>`           | aruba.supportability.module      |
| `<name>`             | file.name                        |
| `<oid>`              | aruba.supportability.oid         |
| `<process>`          | process.name                     |
| `<reason>`           | event.reason                     |
| `<remote_host>`      | client.address                   |
| `<signal>`           | process.exit_code                |
| `<state>`            | aruba.state                      |
| `<threshold>`        | aruba.limit.threshold            |
| `<timestamp>`        | process.end                      |
| `<type>`             | file.type                        |
| `<vrf>`              | aruba.vrf.id                     |

#### [SYS events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/SYS.htm)
| Docs Field       | Schema Mapping               |
|------------------|------------------------------|
| `<error_sbe>`    | aruba.error.description      |
| `<module>`       | aruba.sys.module             |
| `<value>`        | aruba.sys.name               |

#### [SYSMON events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/SYSMON.htm)
| Docs Field         | Schema Mapping               |
|--------------------|------------------------------|
| `<mem_usage>`      | aruba.sysmon.mem_usage       |
| `<module_name>`    | aruba.sysmon.module_name     |
| `<module_num>`     | aruba.sysmon.module_num      |
| `<partition_name>` | aruba.sysmon.partition_name  |
| `<poll>`           | aruba.sysmon.poll            |
| `<unit>`           | aruba.sysmon.unit            |
| `<unit_count>`     | aruba.sysmon.unit_count      |
| `<utilization>`    | aruba.sysmon.utilization     |

#### [TCAM events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/TCAM.htm)
| Docs Field         | Schema Mapping               |
|--------------------|------------------------------|
| `<table_name>`     | aruba.tcam.table_name        |

#### [Telnet server events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/TELNET_SERVER.htm)
| Docs Field         | Schema Mapping               |
|--------------------|------------------------------|
| `<ip_address>`     | client.ip                    |
| `<mgmt_intf>`      | aruba.interface.id           |
| `<user_name>`      | user.name                    |
| `<vrf_name>`       | aruba.vrf.name               |

#### [Temperature events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/TEMPERATURE.htm)
| Docs Field    | Schema Mapping               |
|---------------|------------------------------|
| `<name>`      | aruba.temp.name              |
| `<new>`       | aruba.temp.new               |
| `<limit_high>`| aruba.limit.threshold        |
| `<limit_low>` | aruba.limit.threshold        |
| `<limit_type>`| aruba.temp.limit_type        |
| `<module>`    | aruba.temp.module            |
| `<old>`       | aruba.temp.old               |
| `<status>`    | aruba.status                 |
| `<temp>`      | aruba.temp.celsius           |
| `<type>`      | aruba.temp.type              |
| `<t_high>`    | aruba.temp.t_high            |
| `<t_low>`     | aruba.temp.t_low             |

#### [Time management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/TIME_MGMT.htm)
| Docs Field     | Schema Mapping             |
|----------------|----------------------------|
| `<new_time>`   | aruba.time.new_time        |
| `<newtz>`      | aruba.time.new_tz          |
| `<old_time>`   | aruba.time.old_time        |
| `<oldtz>`      | aruba.time.old_tz          |

#### [TPM events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/TPMD.htm)
| Docs Field       | Schema Mapping       |
|------------------|----------------------|
| `<process_name>` | process.name         |
| `<reason>`       | event.reason         |
| `<reboot_num>`   | aruba.tpm.reboot_num |

#### [Traffic Insight events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/TRAFFIC_INSIGHT.htm)
| Docs Field       | Schema Mapping             |
|------------------|----------------------------|
| `<instance_name>`| aruba.instance.id          |
| `<monitor_name>` | aruba.traffic.monitor_name |

#### [Transceiver events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/XCVR.htm)
| Docs Field         | Schema Mapping          |
|--------------------|-------------------------|
| `<adapter_desc>`   | aruba.xcvr.desc         |
| `<count>`          | aruba.count             |
| `<disabled_reason>`| event.reason            |
| `<interface>`      | aruba.interface.id      |
| `<list>`           | aruba.xcvr.list         |
| `<path>`           | aruba.xcvr.path         |
| `<reason>`         | event.reason            |
| `<status>`         | aruba.status            |
| `<xcvr_desc>`      | aruba.xcvr.desc         |

#### [UDLD events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/UDLD.htm)
| Docs Field | Schema Mapping               |
|------------|------------------------------|
| `<intf>`   | aruba.interface.id           |
| `<intvl_a>`| aruba.udld.intvl_a           |
| `<intvl_b>`| aruba.udld.intvl_b           |

#### [UDP Broadcast Forwarder events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/UDPFWD.htm)
| Docs Field | Schema Mapping               |
|------------|------------------------------|

#### [UFD events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/UFD.htm)
| Docs Field   | Schema Mapping        |
|--------------|-----------------------|
| `<from_state>` | aruba.ufd.from_state |
| `<id>`         | aruba.instance.id    |
| `<to_state>`   | aruba.state          |

#### [User management events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/USER-MGMT.htm)
| Docs Field      | Schema Mapping          |
|-----------------|-------------------------|
| `<added_user>`  | aruba.user.added_user   |
| `<deleted_user>`| aruba.user.deleted_user |
| `<user>`        | user.name               |
| `<user_role>`   | aruba.user.role         |
| `<username>`    | user.name               |

#### [User-based tunnels events](https://www.arubanetworks.com/techdocs/AOS-CX/10.15/HTML/elmrg/Content/events/USER_BASED_TUNNEL.htm)
| Docs Field     | Schema Mapping             |
|----------------|----------------------------|
| `<client_mac>` | client.mac                 |
| `<dst_ip>`     | destination.ip             |
| `<ecmp_id>`    | aruba.tunnel.ecmp_id       |
| `<gre_key>`    | aruba.tunnel.gre_key       |
| `<mac_addr>`   | client.mac                 |
| `<nfd_id>`     | aruba.tunnel.nfd_id        |
| `<port>`       | aruba.port                 |
| `<reason>`     | event.reason               |
| `<sac_ip>`     | server.ip                  |
| `<src_ip>`     | source.ip                  |
| `<state>`      | aruba.state                |
| `<tunnel_id>`  | aruba.instance.id          |
| `<uac_ip>`     | client.ip                  |
| `<version>`    | service.version            |
| `<vlan_id>`    | network.vlan.id            |
| `<vrf>`        | aruba.vrf.id               |
| `<zone>`       | aruba.tunnel.zone          |

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

{{fields "log"}}