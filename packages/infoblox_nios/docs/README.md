# Infoblox NIOS

The Infoblox NIOS integration collects and parses DNS, DHCP, and Audit data collected from [Infoblox NIOS](https://www.infoblox.com/products/nios8/) via TCP/UDP or logfile.

## Setup steps
1. Enable the integration with TCP/UDP input.
2. Log in to the NIOS appliance.
3. Configure the NIOS appliance to send messages to a Syslog server using the following steps. For further information, refer to [Using a Syslog Server](https://docs.infoblox.com/display/NAG8/Using+a+Syslog+Server#UsingaSyslogServer-SpecifyingSyslogServers).
    1. From the Grid tab, select the Grid Manager tab -> Members tab, and then navigate to Grid Properties -> Edit -> Monitoring from the Toolbar.
    2. Select **Log to External Syslog Servers** to send messages to a specified Syslog server.
    3. Click the **Add** icon to define a new Syslog server.
    4. Enter the IP **Address** of the Elastic Agent that is running the integration.
    5. Select **Transport** to connect to the external Syslog server.
    6. If you are using Secure TCP transport, upload a self-signed or a CA-signed **Server Certificate**.
    7. From the drop-down list select the **Interface** through which the appliance sends Syslog messages to the Syslog server.
    8. Select **Source** as **Any** so that the appliance sends both internal and external Syslog messages.
    9. From the drop-down list, select **Node ID** i.e. the host or node identification string that identifies the appliance from which Syslog messages are originated.
    10. Enter the **Port** of the Elastic Agent that is running the integration.
    11. Select **Debug** **Severity** so that the appliance sends all Syslog messages to the server.
    12. Select the following **Logging categories**:
        - Common Authentication
        - DHCP Process
        - DNS Client
        - DNSSEC
        - DNS General
        - DNS Notifies
        - DNS Queries
        - DNS Query Rewrites
        - DNS Resolver
        - DNS Responses
        - DNS RPZ
        - DNS Updates
        - Non-system Authentication
        - Zone Transfer In
        - Zone Transfer Out
    13. Enable **Copy Audit Log Message to Syslog** to include audit log messages it sends to the Syslog server.
    14. Select **Syslog Facility** that determines the processes from which the log messages are generated.

## Compatibility

This module has been tested against `Infoblox NIOS version 8.6.1` with the below-given logs pattern.

## Log samples
Below are the samples logs of the respective category:

## Audit Logs:
```
<141>Apr 13 22:14:36  ns1.infoblox.localdomain 10.50.1.227 httpd: 2022-04-13 16:44:36.850Z [user\040name]: Login_Denied - - to=AdminConnector ip=10.50.0.1 info=Local apparently_via=GUI
<29>Mar 21 09:53:51 infoblox.localdomain 10.0.0.1 httpd: 2022-03-21 08:53:51.087Z [service_account_test]: Login_Allowed - - to=AdminConnector ip=10.0.0.2 auth=LOCAL group=some-Group apparently_via=API
<29>Mar 22 14:26:54 10.0.0.1 httpd: 2011-10-19 19:48:37.299Z [admin]: Login_Allowed - - to=Serial\040Console apparently_via=Direct auth=Local group=admin-group
<29>Mar 22 14:26:54 10.0.0.1 httpd: 2011-10-19 14:02:32.750Z [admin]: Login_Denied - - to=Serial\040Console apparently_via=Direct error=invalid\040login\040or\040password
<29>Mar 22 14:26:54 10.0.0.1 httpd: 2011-10-19 12:43:47.375Z [user]: First_Login - - to=AdminConnector ip=10.0.0.2 auth=LOCAL group=admin-group apparently_via=GUI\040first\040login
<29>Mar 22 14:26:54 10.0.0.1 httpd: 2011-10-19 13:07:33.343Z [user]: Password_Reset_Error - - to=AdminConnector auth=LOCALgroup=admin-group apparently_via=GUI
<29>Mar 18 13:40:05 10.0.0.1 httpd: 2022-03-21 17:19:02.204Z [admin]: Modified Network 192.168.0.0/24 network_view=default: Changed dhcp_members:[]->[[grid_member=Member:infoblox.localdomain]]
<29>Mar 18 13:40:05 10.0.0.1 httpd: 2022-03-24 09:37:29.261Z [admin]: Created Network 192.168.0.0/24 network_view=default: Set extensible_attributes=[],address="192.168.2.0",auto_create_reversezone=False,cidr=24,comment="",common_properties=[domain_name_servers=[],routers=[]],dhcp_members=[[grid_member=Member:infoblox.localdomain]],disabled=False,discovery_member=NULL,enable_discovery=False,enable_immediate_discovery=False,network_view=NetworkView:default,use_basic_polling_settings=False,use_member_enable_discovery=False,vlans=[]
<29>Mar 18 13:40:05 10.0.0.1 httpd: 2022-03-18 11:46:38.877Z [admin]: Modified MemberDhcp infoblox.localdomain: Changed enable_service:False->True
<29>Mar 18 13:40:05 10.0.0.1 httpd: 2022-03-29 19:29:20.468Z [admin]: Called - RestartService: Args services=["ALL"],parents=[],force=True,mode="GROUPED"
<29>Mar 18 13:40:05 10.0.0.1 httpd: 2022-03-29 18:30:58.656Z [admin]: Created Ruleset Block: Set comment="",disabled=True,name="Block",type="BLACKLIST"
<29>Mar 18 13:40:05 10.0.0.1 httpd: 2022-03-24 09:28:24.476Z [admin]: Called - TransferTrafficCapture message=Download\040Traffic\040capture\040file: Args message="Download Traffic capture file",members=[Member:infoblox.localdomain]
<29>Mar 21 16:08:08 10.0.0.1 httpd: 2022-03-21 15:08:08.238Z [service_account_test]: Created HostAddress 10.0.0.1 network_view=default: Set address="10.0.0.1",configure_for_dhcp=False,match_option="MAC_ADDRESS",parent=HostRecord:._default.tld.domain.subdomain.hostrecord
<29>Mar 21 16:08:08 10.0.0.1 httpd: 2022-03-21 15:08:08.239Z [service_account_test]: Created HostRecord somerecord.subdomain.domain.tld DnsView=default alias=somealias.subdomain.domain.tld address=10.0.0.1: Set extensible_attributes=[[name="NAC-Policy",value="Host"]],addresses=[address="10.0.0.1"],aliases=[HostAlias:._default.tld.domain.subdomain.somealias.._default.tld.domain.subdomain.somehostrecord],fqdn="somerecord.subdomain.domain.tld"
<29>Mar 21 16:08:48 10.0.0.1 httpd: 2022-03-21 15:08:48.455Z [service_account_test]: Deleted HostRecord somerecord.subdomain.domain.tld DnsView=default address=10.0.0.0
<29>Mar 22 14:26:54 10.0.0.1 httpd: 2022-03-22 13:26:54.596Z [some_admin_account]: Deleted CaaRecord somecaarecord.domain.tld DnsView=default 
<29>Mar 22 14:26:54 10.0.0.1 httpd: 2022-03-22 13:26:54.596Z [some_admin_account]: Created HostAddress 192.168.0.0 network_view=default: Set address="192.168.0.0",configure_for_dhcp=True,mac_address="01:01:01:01:01:01",match_option="MAC_ADDRESS",network=Network:192.168.0.0/24\054network_view\075default,parent=HostRecord:._default.test.test3,reserved_interface=NULL,use_for_ea_inheritance=True
<29>Mar 22 14:26:54 10.0.0.1 httpd: 2022-03-22 13:26:54.596Z [some_admin_account]: Modified Network 192.168.0.0/24 network_view=default: Changed dhcp_members:[]->[[grid_member=Member:infoblox.localdomain]]
<29>Mar 18 13:40:05 10.0.0.1 httpd: 2022-03-18 12:40:05.241Z [adminuser]: Modified Grid Unibe-DNS-Grid: Changed backup_setting:[password="******",restore_password="******"]->[password="******",restore_password="******"],csp_api_config:[password="******"]->[password="******"],csp_settings:[csp_join_token="******"]->[csp_join_token="******"],download_member_conf:[[interface="ANY",is_online=True,member="Member:Grid Master"]]->[[interface="ANY",is_online=True,member=NULL]],email_setting:[password="******"]->[password="******"],http_proxy_server_setting:NULL->[password="******"],snmp_setting:[snmpv3_queries_users=NULL]->[snmpv3_queries_users=[]],syslog_servers:[[address="10.0.0.2"],[address="10.0.0.3"]]->[[address="10.0.0.4"]]
```
## DNS Logs:
```
<45>Mar 11 23:51:31 infoblox.localdomain named[17742]: 07-Apr-2022 08:08:10.043 client 192.168.0.1#50565 UDP: query: test.com IN A response: REFUSED -
<30>Mar 11 23:51:31 infoblox.localdomain named[17742]: 07-Apr-2022 08:08:10.043 client 192.168.0.1#57398 UDP: query: a2.foo.com IN A response: NOERROR +AED a2.foo.com 28800 IN A 192.168.0.3;
<30>Mar 11 23:51:31 infoblox.localdomain named[17742]: 07-Apr-2022 08:08:10.043 client 192.168.0.1#57398 UDP: query: non-exist.foo.com IN A response: NXDOMAIN +ED
<45>Mar 11 23:51:31 infoblox.localdomain named[17742]: 07-Apr-2022 08:08:10.043 client 192.168.0.1#57398 UDP: query: a1.foo.com IN A response: NOERROR +ED a1.foo.com 28800 IN A 192.168.0.2; a1.foo.com 28800 IN A 192.168.0.3;
<30>Mar  9 23:59:59 infoblox.localdomain named[17742]: client @0x7f1dd4114af0 192.168.0.1#59735 (config.nos-avg.cz): query failed (REFUSED) for config.nos-avg.cz/IN/TXT at query.c:10288
<30>Mar  9 23:59:59 infoblox.localdomain named[17742]: client @0x7f1dd4114af0 192.168.0.1#59735 (config.nos-avg.cz): query: config.nos-avg.cz IN TXT + (192.168.0.1)
<30>Mar 11 23:51:31 infoblox.localdomain named[27014]: rpz: rpz1.com: reload start
<30>Mar 11 23:51:31 infoblox.localdomain named[29914]: client @0x7ff42c168b50 192.168.0.1#50460 (test.com): rewriting query name 'test.com' to 'query123-10-120-20-93.test.com', type A
<30>Mar 11 23:51:31 infoblox.localdomain named[19204]: client @0x7fec7c11dab0 192.168.0.1#36483: updating zone 'test1.com/IN': adding an RR at 'a6.test1.com' A 192.168.0.2
<30>Mar 11 23:51:31 infoblox.localdomain named[28468]: CEF:0|Infoblox|NIOS|8.6.2-49634-e88e9df276a8|RPZ-QNAME|NXDOMAIN|7|app=DNS dst=192.168.0.1 src=192.168.0.1 spt=51424 view=_default qtype=A msg="rpz QNAME NXDOMAIN rewrite nxd1.com [A] via nxd1.com.rpz1.com" CAT=RPZ
<30>Mar 11 23:51:31 infoblox.localdomain named[7741]: zone local_7.com/IN: notify from 192.168.0.1#46982: zone is up to date
<30>Mar 11 23:51:31 infoblox.localdomain named[7741]: responses: client @0x7fb550117f90 192.168.0.1#46982: received notify for zone 'local_14.com'
<30>Mar 11 23:51:31 infoblox.localdomain named[15242]: transfer of 'test.com/IN' from 192.168.0.1#53: Transfer status: success
<30>Mar 11 23:51:31 infoblox.localdomain named[15242]: transfer of 'test.com/IN' from 192.168.0.1#53: Transfer completed: 1 messages, 9 records, 326 bytes, 0.001 secs (326000 bytes/sec)
<30>Mar 11 23:51:31 infoblox.localdomain named[56199]: client @0x7f7e6c2809f0 192.168.0.1#57027 (test.com): transfer of 'test.com/IN': AXFR started (serial 3)
<30>Mar 11 23:51:31 infoblox.localdomain named[56199]: client @0x7f7e6c2809f0 192.168.0.1#57027 (test.com): transfer of 'test.com/IN': AXFR ended
<30>Mar 11 23:51:31 infoblox.localdomain named[30325]: resolver priming query complete
<30>Mar 11 23:51:31 infoblox.localdomain named[1127]: validating test.com/DNSKEY: unable to find a DNSKEY which verifies the DNSKEY RRset and also matches a trusted key for 'test.com'
<30>Mar 11 23:51:31 infoblox.localdomain named[1127]: validating test.com/NSEC: bad cache hit (test.com/DNSKEY)
<30>Mar 11 23:51:31 infoblox.localdomain named[1127]: validating hostrec3.test.com/NSEC: bad cache hit (test.com/DNSKEY)
<30>Apr 14 16:17:20 10.0.0.1 named[2588]: infoblox-responses: 14-Apr-2022 16:17:20.046 client 192.168.0.1#57738: UDP: query: settings-win.data.microsoft.com IN A response: REFUSED -
<30>Apr 14 16:16:05 10.0.0.1 named[2588]: queries: client @0x7f97e40eb500 192.168.0.1#64727 (ocsp.digicert.com): query: ocsp.digicert.com IN A + (192.168.1.10)
<30>Apr 14 16:16:05 10.0.0.1 named[2588]: query-errors: client @0x7f97e40eb500 192.168.0.1#64727 (ocsp.digicert.com): query failed (REFUSED) for ocsp.digicert.com/IN/A at query.c:10288
```
## DHCP Logs:
```
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[1761]: DHCPDISCOVER from 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 TransID a76ecf84 uid 01:00:50:56:83:6c:a0
<30>Mar 27 08:32:59 infoblox.localdomain 10.0.0.1 dhcpd[7024]: DHCPDISCOVER from 00:50:56:83:6c:a0 via eth3 TransID b5e92c59 uid 01:00:50:56:83:6c:a0
<30>Mar 27 08:32:59 10.0.0.1 dhcpd[2750]: DHCPDISCOVER from 00:50:56:83:d0:f6 via eth1 TransID 6214ab45: network 10.50.0.0/20: no free leases
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[21114]: DHCPDISCOVER from 00:50:56:83:6c:a0 via eth3 TransID 748f30ab
<30>Mar 27 08:32:59 infoblox_localdomain.com dhcpd[29258]: DHCPDISCOVER from 00:00:00:00:00:00 (h000000000000) via 192.168.0.2 TransID 01000000
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[2567]: DHCPOFFER on 192.168.0.4 to 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 relay eth3 lease-duration 119 offered-duration 1800 uid 01:00:50:56:83:6c:a0
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[21114]: DHCPOFFER on 192.168.0.4 to 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 relay eth3 lease-duration 120 offered-duration 1800
<30>Mar 31 15:30:05 10.0.0.1 dhcpd[15752]: DHCPOFFER on 192.168.0.4 to 26:9a:76:87:8a:06 via eth2 relay 192.168.0.3 lease-duration 1795 uid 01:26:9a:76:87:8a:06
<30>Mar 27 08:32:59 infoblox_localdomain.com dhcpd[29258]: DHCPOFFER on 192.168.0.4 to 00:00:00:00:00:00 via eth1 relay 192.168.0.3 lease-duration 43137 offered-duration 43200
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[6939]: DHCPOFFER on 192.168.0.4 to cc:bb:cc:dd:ee:ff via eth1 relay 192.168.0.3 lease-duration 120
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[2567]: DHCPREQUEST for 192.168.0.4 (192.168.0.1) from 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 TransID 54737448 uid 01:00:50:56:83:6c:a0 (RENEW)
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[2567]: DHCPREQUEST for 192.168.0.4 (192.168.0.1) from 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 TransID 8767dc3c uid 01:00:50:56:83:6c:a0
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[4495]: DHCPREQUEST for 192.168.0.4 from 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 TransID 54ade258 uid 01:00:50:56:83:6c:a0 (RENEW)
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[4495]: DHCPREQUEST for 192.168.0.4 from 00:50:56:83:6c:a0 via eth3 TransID a18a70a0 uid 01:00:50:56:83:6c:a0
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[25637]: DHCPREQUEST for 192.168.0.4 (192.168.0.1) from 00:50:56:83:d3:83 via eth1 TransID 3ca1e0b7: unknown lease 192.168.0.4.
<30>Apr  6 10:13:31 infoblox.localdomain dhcpd[22730]: DHCPREQUEST for 192.168.0.4 from 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 TransID 542900fa uid 01:00:50:56:83:6c:a0: database update failed
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[21114]: DHCPREQUEST for 192.168.0.4 (192.168.0.1) from 00:50:56:83:6c:a0 via eth3 TransID 748f30ab
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[30827]: DHCPREQUEST for 192.168.0.4 from 00:50:56:83:96:03 via eth1 TransID 9cf7c9e9: ignored (not authoritative).
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[21114]: DHCPREQUEST for 192.168.0.4 from 00:50:56:83:6c:a0 via eth3 TransID 2d422d0c
<30>Mar 31 15:30:06 10.0.0.1 dhcpd[15752]: DHCPREQUEST for 192.168.0.4 from 9a:df:6e:f6:1f:23 via 192.168.0.2 TransID 15ca711f uid 01:9a:df:6e:f6:1f:23 (RENEW)
<30>Mar 27 08:32:59 infoblox_localdomain.com dhcpd[29258]: DHCPREQUEST for 192.168.0.4 (192.168.0.1) from 00:00:00:00:00:00 via 192.168.0.3 TransID 01000000 (RENEW)
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[17530]: DHCPACK on 192.168.0.4 to 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 relay eth3 lease-duration 1800 (RENEW) uid 01:00:50:56:83:6c:a0
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[2567]: DHCPACK on 192.168.0.4 to 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 relay eth3 lease-duration 1800 uid 01:00:50:56:83:6c:a0
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[21114]: DHCPACK on 192.168.0.4 to 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 relay eth3 lease-duration 1800
<30>Mar 27 08:32:59 10.0.0.1 dhcpd[15752]: DHCPACK on 192.168.0.4 to 9a:df:6e:f6:1f:23 via eth2 relay 192.168.0.3 lease-duration 7257600 (RENEW) uid 01:9a:df:6e:f6:1f:23
<30>Mar 27 08:32:59 infoblox_localdomain.com dhcpd[29258]: DHCPACK on 192.168.0.4 to 00:00:00:00:00:00 (h000000000000) via eth1 relay 192.168.0.3 lease-duration 43200 (RENEW)
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[6939]: DHCPACK on 192.168.0.4 to cc:bb:cc:dd:ee:ff via eth1 relay 192.168.0.3 lease-duration 43200
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[1761]: DHCPRELEASE of 192.168.0.4 from 00:50:56:83:6c:a0 (DESKTOP-ABCD) via eth3 (found) TransID 0286f3d0 uid 01:00:50:56:83:6c:a0
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[21114]: DHCPRELEASE of 192.168.0.4 from 00:50:56:83:6c:a0 via eth3 (not found) TransID 665fd9f1
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[20397]: DHCPEXPIRE on 192.168.0.4 to 00:50:56:83:6c:a0
<30>Mar 18 13:35:15 10.0.0.1 dhcpd[18078]: DHCPINFORM from 192.168.0.4 via 192.168.0.2 TransID 5713b740
<30>Mar 18 13:35:15 10.0.0.1 dhcpd[18078]: DHCPINFORM from 192.168.0.4 via eth2 TransID 5713b740
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[6939]: DHCPINFORM from 192.168.0.4 via 192.168.0.2 TransID 78563412: not authoritative for subnet 10.0.0.0
<30>Mar 18 11:44:52 10.0.0.1 dhcpd[32243]: DHCPDECLINE of 192.168.0.4 from 34:29:8f:71:b8:99 via 192.168.0.2 TransID 00000000: not found
<30>Mar 7 08:32:59 infoblox.localdomain dhcpd[20397]: DHCPDECLINE of 192.168.0.4 from 00:c0:dd:07:18:e2 via 192.168.0.2: abandoned\n
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[20397]: DHCPNAK on 192.168.0.4 to f4:30:b9:17:ab:0e via 192.168.0.2
<30>Mar 27 08:32:59 infoblox.localdomain dhcpd[6939]: DHCPLEASEQUERY from 192.168.0.4: LEASEQUERY not allowed, query ignored
<30>Jul 12 15:07:57 67.43.156.0 dhcpd[8061]: DHCPOFFER on 67.43.156.0 to 9a:df:6e:f6:1f:23 via eth2 relay 67.43.156.0 lease-duration 40977 offered-duration 43200 uid 01:9a:df:6e:f6:1f:23
<30>Jul 12 15:10:48 67.43.156.0 dhcpd[13468]: DHCPACK on 67.43.156.0 to 9a:df:6e:f6:1f:23 via eth2 relay 67.43.156.0 lease-duration 7257600 (RENEW)
<30>Jul 12 15:55:55 67.43.156.0 dhcpdv6[12271]: Encapsulated Solicit message from 2a02:cf40:: port 547 from client DUID 01:9a:df:6e:f6:1f:23:01:9a:df:6e:f6:1f:23, transaction ID 0x698AD400
<30>Jul 12 15:55:55 67.43.156.0 dhcpdv6[12271]: Advertise NA: address 2a02:cf40:: to client with duid 01:9a:df:6e:f6:1f:23:01:9a:df:6e:f6:1f:23 iaid = -1620146908 valid for 43200 seconds
<30>Jul 12 15:55:55 67.43.156.0 dhcpdv6[12271]: Relay-forward message from 2a02:cf40:: port 547, link address 2a02:cf40::1, peer address 2a02:cf40::2
<30>Jul 12 15:55:55 67.43.156.0 dhcpdv6[12271]: Encapsulating Advertise message to send to 2a02:cf40:: port 547
<30>Jul 12 15:55:55 67.43.156.0 dhcpdv6[12271]: Sending Relay-reply message to 2a02:cf40:: port 547
<30>Sep 28 09:25:49 infoblox.localdomain 10.0.0.1 dhcpd[25691]: DHCPACK on 192.168.0.4 to 00:50:56:83:96:03 via eth2 relay 192.168.0.4 lease-duration 3600 uid 01:9a:df:6e:f6:1f:23
<30>Sep 30 11:27:26 anudhcp.anu.edu.au 10.0.0.1 dhcpd[11411]: RELEASE on 192.168.0.4 to ce:93:30:8e:db:ac
<30>Sep 30 11:30:55 anudhcp.anu.edu.au 10.0.0.1 dhcpd[11411]: DHCPACK to 192.168.0.4 (9c:ad:97:7a:fd:33) via eth2
<30>Sep 30 11:33:03 anudhcp.anu.edu.au 10.0.0.1 dhcpd[11411]: DHCPACK on 192.168.0.4 to 4a:34:bf:d2:78:24 (my-iPhone) via eth2 relay 67.43.156.0 lease-duration 900 offered-duration 3600 (RENEW) uid 01:4a:34:bf:d2:78:24
<30>Sep 30 11:33:03 anudhcp.anu.edu.au 10.0.0.1 dhcpd[11411]: DHCPACK on 192.168.0.4 to 4a:34:bf:d2:78:24 via eth2 relay 67.43.156.0 lease-duration 900 offered-duration 3600 (RENEW) uid 01:4a:34:bf:d2:78:24
<30>Sep 30 11:33:03 anudhcp.anu.edu.au 10.0.0.1 dhcpd[11411]: DHCPACK on 192.168.0.4 to 4a:34:bf:d2:78:24 (my-iPhone) via eth2 relay 67.43.156.0 lease-duration 900 offered-duration 3600 (RENEW)
```

## Logs

This is the `log` dataset.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2011-10-19T12:43:47.375Z",
    "agent": {
        "ephemeral_id": "efe7a458-adf8-47ea-bfc1-ad839cc9aa39",
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "infoblox_nios.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "action": "first_login",
        "agent_id_status": "verified",
        "created": "2023-03-22T14:26:54.000+05:00",
        "dataset": "infoblox_nios.log",
        "ingested": "2023-09-26T13:59:18Z",
        "original": "<29>Mar 22 14:26:54 10.0.0.1 httpd: 2011-10-19 12:43:47.375Z [user]: First_Login - - to=AdminConnector ip=10.0.0.2 auth=LOCAL group=admin-group apparently_via=GUI\\040first\\040login",
        "timezone": "+0500"
    },
    "host": {
        "ip": [
            "10.0.0.1"
        ]
    },
    "infoblox_nios": {
        "log": {
            "audit": {
                "apparently_via": "GUI first login",
                "auth": "LOCAL",
                "group": "admin-group",
                "ip": "10.0.0.2",
                "to": "AdminConnector"
            },
            "service_name": "httpd",
            "type": "AUDIT"
        }
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "192.168.80.7:39304"
        },
        "syslog": {
            "priority": 29
        }
    },
    "message": "2011-10-19 12:43:47.375Z [user]: First_Login - - to=AdminConnector ip=10.0.0.2 auth=LOCAL group=admin-group apparently_via=GUI\\040first\\040login",
    "related": {
        "ip": [
            "10.0.0.2",
            "10.0.0.1"
        ],
        "user": [
            "user"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "infoblox_nios-log"
    ],
    "user": {
        "name": "user"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| infoblox_nios.log.audit.apparently_via |  | keyword |
| infoblox_nios.log.audit.auth |  | keyword |
| infoblox_nios.log.audit.error |  | text |
| infoblox_nios.log.audit.group |  | keyword |
| infoblox_nios.log.audit.info |  | text |
| infoblox_nios.log.audit.ip |  | ip |
| infoblox_nios.log.audit.message |  | text |
| infoblox_nios.log.audit.object.name |  | keyword |
| infoblox_nios.log.audit.object.value |  | keyword |
| infoblox_nios.log.audit.to |  | keyword |
| infoblox_nios.log.audit.trigger_event |  | keyword |
| infoblox_nios.log.dhcp.client_hostname |  | keyword |
| infoblox_nios.log.dhcp.decline.message |  | keyword |
| infoblox_nios.log.dhcp.discover.message |  | keyword |
| infoblox_nios.log.dhcp.duid |  | keyword |
| infoblox_nios.log.dhcp.forward_name |  | keyword |
| infoblox_nios.log.dhcp.iaid |  | keyword |
| infoblox_nios.log.dhcp.inform.message |  | keyword |
| infoblox_nios.log.dhcp.interface.ip |  | ip |
| infoblox_nios.log.dhcp.ip |  | ip |
| infoblox_nios.log.dhcp.lease.duration |  | long |
| infoblox_nios.log.dhcp.lease.message |  | keyword |
| infoblox_nios.log.dhcp.lease_query.message |  | keyword |
| infoblox_nios.log.dhcp.link_address |  | keyword |
| infoblox_nios.log.dhcp.message |  | text |
| infoblox_nios.log.dhcp.network |  | keyword |
| infoblox_nios.log.dhcp.offered.duration |  | long |
| infoblox_nios.log.dhcp.peer_address |  | keyword |
| infoblox_nios.log.dhcp.relay.interface.ip |  | ip |
| infoblox_nios.log.dhcp.relay.interface.name |  | keyword |
| infoblox_nios.log.dhcp.release.info |  | keyword |
| infoblox_nios.log.dhcp.request.message |  | keyword |
| infoblox_nios.log.dhcp.router.ip |  | ip |
| infoblox_nios.log.dhcp.trans_id |  | keyword |
| infoblox_nios.log.dhcp.uid |  | keyword |
| infoblox_nios.log.dhcp.validation_second |  | long |
| infoblox_nios.log.dns.after_query |  | text |
| infoblox_nios.log.dns.answers_policy |  | text |
| infoblox_nios.log.dns.before_query |  | text |
| infoblox_nios.log.dns.category |  | text |
| infoblox_nios.log.dns.failed_message |  | text |
| infoblox_nios.log.dns.header_flags |  | keyword |
| infoblox_nios.log.dns.message |  | text |
| infoblox_nios.log.dns.rpz.action |  | keyword |
| infoblox_nios.log.dns.rpz.domain |  | keyword |
| infoblox_nios.log.dns.rpz.domain_rewrite |  | keyword |
| infoblox_nios.log.dns.rpz.query_class |  | keyword |
| infoblox_nios.log.dns.rpz.query_class_rewrite |  | keyword |
| infoblox_nios.log.dns.rpz.rule_type |  | keyword |
| infoblox_nios.log.dns.rpz.type |  | keyword |
| infoblox_nios.log.dns.version |  | text |
| infoblox_nios.log.dns.view_name |  | text |
| infoblox_nios.log.service_name |  | keyword |
| infoblox_nios.log.type |  | keyword |
| infoblox_nios.log.view |  | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Log source address | keyword |

