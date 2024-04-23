# Stormshield SNS

Stormshield Network Security (SNS) firewalls are a stable and efficient security solution to protect corporate networks from cyberattacks. Real-time protection (intrusion prevention and detection, application control, antivirus, etc.), control and supervision (URL filtering, IP geolocation, vulnerability detection, etc.) and content filtering (antispam, antispyware, antiphishing, etc.) all guarantee secure communications. All Stormshield Network Security firewalls are based on the same firmware, and with their core features, Stormshield Network Security firewalls give you comprehensive security and high performance network protection.

Use the Stormshield SNS integration to ingest syslog data into your Elasticsearch cluster, then visualize that data in Kibana. Create alerts to notify you if something goes wrong.


## Data streams

The Stormshield SNS integration collects one type of data streams: logs.

**Logs** help you keep a record of events happening in your firewalls.
Log data streams collected by the SNS integration include syslogs and more. See more details in the [Logs](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

The SNS integration ingests logs via a UDP/syslog parser, so the SNS appliance needs to be configured to send syslogs to a listening Agent. This is configured in the `CONFIGURATION` tab, in the `NOTIFICATIONS` / `LOGS-SYSLOG-IPFIX` section.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->

<!-- If applicable -->
<!-- ## Metrics reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

<!-- Optional -->
<!-- #### Example

An example event for `{data stream name}` looks as following:

{code block with example} -->

<!-- #### Exported fields

{insert table} -->

### Log

The `log` dataset collects SNS logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| input.type | Type of input. | keyword |
| log.source.address | Source address for the log. | keyword |
| log.syslog.appname | The device or application that originated the Syslog message, if available. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.facility.name | The Syslog text-based facility of the log event, if available. | keyword |
| log.syslog.hostname | The hostname, FQDN, or IP of the machine that originally sent the Syslog message. This is sourced from the hostname field of the syslog header. Depending on the environment, this value may be different from the host that handled the event, especially if the host handling the events is acting as a collector. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| log.syslog.severity.name | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different severity value (e.g. firewall, IDS), your source's text severity should go to `log.level`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `log.level`. | keyword |
| log.syslog.version | The version of the Syslog protocol specification. Only applicable for RFC 5424 messages. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| stormshield.alarm.action | Behavior associated with the filter rule.  Value: pass or block | keyword |
| stormshield.alarm.alarmid | Stormshield Network alarm ID Decimal format. Example: "85" | keyword |
| stormshield.alarm.class | Information about the alarms category. String of characters in UTF-8 format. Example: protocol, system, filter | keyword |
| stormshield.alarm.classification | Code number indicating alarm category. Example: "0" | keyword |
| stormshield.alarm.confid | Index of the security inspection profile used.  Value from 0 to 9. Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.domain | Authentication method used or LDAP directory of the user authenticated by the firewall. String of characters in UTF-8 format. Example: domain="documentation.stormshield.eu" Available from: SNS v3.0.0. | keyword |
| stormshield.alarm.dst | IP address of the destination host  Decimal format. Example: 192.168.0.2 Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.dstcontinent | Continent to which the destination IP address of the connection belongs. Value: continent's ISO code Example: dstcontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.alarm.dstcountry | Country to which the destination IP address of the connection belongs. Format: country's ISO code Example: dstcountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.alarm.dsthostrep | Reputation of the connection's target hosts Available only if reputation management has been enabled for the relevant hosts. Format: unrestricted integer. Example: dsthostrep=506 Available from: SNS v3.0.0. | keyword |
| stormshield.alarm.dstif | Name of the destination interface. String of characters in UTF-8 format. Example: Ethernet 1 Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.dstifname | Name of the object representing the traffics destination interface. String of characters in UTF-8 format. Example: dmz1 Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.dstiprep | Reputation of the destination IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: dstiprep="spam" Available from: SNS v3.0.0. | keyword |
| stormshield.alarm.dstmac | MAC address of the destination host. Format: Hexadecimal values separated by ":". Example: dstmac=00:25:90:01:ce:e7 Available from: SNS v4.0.0. | keyword |
| stormshield.alarm.dstname | Name of the object corresponding to the IP address of the destination host.  String of characters in UTF-8 format. Example: intranet_server Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.dstport | Destination TCP/UDP port number. Example: "22" Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.dstportname | Name of the object corresponding to the destination port. String of characters in UTF-8 format. Example: ssh Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.etherproto | Type of Ethernet protocol. Format: String of characters in UTF-8 format. Example: etherproto="profinet-rt" Available from: SNS v4.0.0. | keyword |
| stormshield.alarm.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.icmpcode | Code number of the icmp message. Example: 1 (meaning Destination host unreachable). Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.icmptype | Number of the type of icmp message. Example: 3 (meaning Destination unreachable). Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.alarm.ipproto | Name of the protocol above IP (transport layer).  String of characters in UTF-8 format. Example: tcp Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.ipv | Version of the IP protocol used in the traffic Values: 4, 6 Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.modsrc | Translated IP address of the source host. May be displayed anonymously depending on the administrator's access privileges.  Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.modsrcport | Translated TCP/UDP source port number. Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.msg | Text message explaining the alarm.  String of characters in UTF-8 format. Example: Port probe | keyword |
| stormshield.alarm.origdst | Original IP address of the destination host (before translation or the application of a virtual connection).  Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.origdstport | Original port number of the destination TCP/UDP port (before translation or the application of a virtual connection). Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.pktdump | Network packet captured and encoded in hexadecimal for deeper analysis by a third-party tool. Example: 450000321fd240008011c2f50a00007b0a3c033d0035c | keyword |
| stormshield.alarm.pktdumplen | Size of the packet captured for deeper analysis by a third-party tool. This value may differ from the value of the pktlen field. Example: "133" | keyword |
| stormshield.alarm.pktlen | Size of the network packet that activated the alarm (in bytes). Example: "133" | keyword |
| stormshield.alarm.pri | Represents the alarm level. Values(cannot be customized): "0" (emergency), "1" (alert), "2" (critical), "3" (error), "4" (warning), "5" (notice), "6" (information) or "7" (debug). Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.proto | Name of the associated plugin. If this is not available, the name of the standard service corresponding to the destination port. String of characters in UTF-8 format. Example: http, ssh Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.repeat | Number of occurrences of the alarm over a given period. Decimal format. Example: "4" Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.risk | Risk relating to the connection. This value contributes to the reputation score of the connection's source host. Value: between 1 (low risk) and 100 (very high risk). Example: risk=20 Available from: SNS v3.0.0. | keyword |
| stormshield.alarm.rt | Name of the gateway used for the connection. Present only if the gateway does not match the default route. String of characters in UTF-8 format. Example: "my_gateway" Available from: SNS v4.3.0. | keyword |
| stormshield.alarm.rtname | Name of the router object used for the connection. Present only if the router does not match the default route. String of characters in UTF-8 format. Example: "my_gateway" Available from: SNS v4.3.0. | keyword |
| stormshield.alarm.ruleid | Number of the filter rule applied. Example: 1, 2  Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.slotlevel | Indicates the type of rule that activated logging.  Values: 0(implicit), 1 (global), or 2(local). Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.srccontinent | Continent to which the source IP address of the connection belongs. Value: continent's ISO code Example: srccontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.alarm.srccountry | Country to which the source IP address of the connection belongs. Format: country's ISO code Example: srccountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.alarm.srchostrep | Reputation of the connection's source hosts. Available only if reputation management has been enabled for the relevant hosts. Format: unrestricted integer. Example: srchostrep=26123 Available from: SNS v3.0.0. | keyword |
| stormshield.alarm.srcif | Internal name of the interface at the source of the traffic. String of characters in UTF-8 format. Example: Ethernet0 Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.srcifname | Name of the object representing the interface at the source of the traffic. String of characters in UTF-8 format. Example: out Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.srciprep | Reputation of the source IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: srciprep="anonymizer,tor" Available from: SNS v3.0.0. | keyword |
| stormshield.alarm.srcmac | MAC address of the source host.  May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.srcname | Name of the object corresponding to the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.srcport | Source TCP/UDP port number. Example: "49753" Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.srcportname | Source port name if it is known. String of characters in UTF-8 format. Example: http, ephemeral_fw_tcp Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.target | Shows whether the src or dst fields correspond to the target of the packet that had raised the alarm. Values: "src" or "dst" Available from: SNS v3.0.0. | keyword |
| stormshield.alarm.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.alarm.user | User authenticated by the firewall.  String of characters in UTF-8 format. Example: John.smith May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.auth.agentid | SSO agent ID. Value: from 0 to 5. Example: agentid=0 Available from: SNS v3.0.0. | keyword |
| stormshield.auth.confid | Index of the security inspection profile used. Value from 0 to 9. Available from: SNS v1.0.0. | keyword |
| stormshield.auth.domain | Authentication method used or LDAP directory of the user authenticated by the firewall. String of characters in UTF-8 format. Example: domain="documentation.stormshield.eu" Available from: SNS v3.0.0. | keyword |
| stormshield.auth.error | Authentication return code. Decimal format. Example: 0, 3, 4", etc. | keyword |
| stormshield.auth.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.auth.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.auth.msg | Message associated with the authentication return code. String of characters in UTF-8 format. Example:User logged in | keyword |
| stormshield.auth.ruleid | Number of the authentication rule applied (no value if the AGENT method is used). Example: "1" Available from: SNS v1.0.0. | keyword |
| stormshield.auth.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0 | keyword |
| stormshield.auth.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.auth.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.auth.totp | Indicates whether authentication required a TOTP Values: "yes" if a TOTP was used, "no" if no TOTP was used. Example: totp=yes Available from: SNS v4.5.0. | keyword |
| stormshield.auth.tsagentname | Indicates the name of the TS agent used. String of characters in UTF-8 format. Example: tsagentname="agent_name_test" Available from: SNS v4.7.0. | keyword |
| stormshield.auth.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.auth.user | ID of the user (when the authentication phase has ended). String of characters in UTF-8 format. Example: John.smith May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.authstat.auth | tbd | keyword |
| stormshield.authstat.authcaptive | tbd | keyword |
| stormshield.authstat.authconsole | tbd | keyword |
| stormshield.authstat.authipsec | tbd | keyword |
| stormshield.authstat.authsslvpn | tbd | keyword |
| stormshield.authstat.authtotp | tbd | keyword |
| stormshield.authstat.authwebadmin | tbd | keyword |
| stormshield.authstat.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.authstat.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.authstat.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.authstat.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.authstat.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.connection.action | Behavior associated with the filter rule. Value: pass or block (empty field for Log action). | keyword |
| stormshield.connection.clientappid | Last client application detected on the connection. Character string. Example: clientappid=firefox Available from: SNS v3.2.0. | keyword |
| stormshield.connection.confid | Index of the security inspection profile used.  Value from 0 to 9. Available from: SNS v1.0.0. | keyword |
| stormshield.connection.domain | Authentication method used or LDAP directory of the user authenticated by the firewall. String of characters in UTF-8 format. Example: domain="documentation.stormshield.eu" Available from: SNS v3.0.0. | keyword |
| stormshield.connection.dst | IP address of the destination host  Decimal format. Example: 192.168.0.2 Available from: SNS v1.0.0. | keyword |
| stormshield.connection.dstcontinent | Continent to which the destination IP address of the connection belongs. Value: continent's ISO code Example: dstcontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.connection.dstcountry | Country to which the destination IP address of the connection belongs. Format: country's ISO code Example: dstcountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.connection.dsthostrep | Reputation of the connection's target hosts Available only if reputation management has been enabled for the relevant hosts. Format: unrestricted integer. Example: dsthostrep=506 Available from: SNS v3.0.0. | keyword |
| stormshield.connection.dstif | Name of the destination interface. String of characters in UTF-8 format. Example: Ethernet 1 Available from: SNS v1.0.0. | keyword |
| stormshield.connection.dstifname | Name of the object representing the traffics destination interface. String of characters in UTF-8 format. Example: dmz1 Available from: SNS v1.0.0. | keyword |
| stormshield.connection.dstiprep | Reputation of the destination IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: dstiprep="spam" Available from: SNS v3.0.0. | keyword |
| stormshield.connection.dstmac | MAC address of the destination host. Format: Hexadecimal values separated by ":". Example: dstmac=00:25:90:01:ce:e7 Available from: SNS v4.0.0. | keyword |
| stormshield.connection.dstname | Name of the object corresponding to the IP address of the destination host.  String of characters in UTF-8 format. Example: intranet_server Available from: SNS v1.0.0. | keyword |
| stormshield.connection.dstport | Destination TCP/UDP port number. Example: "22" Available from: SNS v1.0.0. | keyword |
| stormshield.connection.dstportname | Name of the object corresponding to the destination port. String of characters in UTF-8 format. Example: ssh Available from: SNS v1.0.0. | keyword |
| stormshield.connection.duration | Duration of the connection in seconds. Decimal format. Example: "173.15" | keyword |
| stormshield.connection.etherproto | Type of Ethernet protocol. Format: String of characters in UTF-8 format. Example: etherproto="profinet-rt" Available from: SNS v4.0.0. | keyword |
| stormshield.connection.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.connection.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.connection.ipproto | Name of the protocol above IP (transport layer).  String of characters in UTF-8 format. Example: tcp Available from: SNS v1.0.0. | keyword |
| stormshield.connection.ipv | Version of the IP protocol used in the traffic Values: 4, 6 Available from: SNS v1.0.0. | keyword |
| stormshield.connection.modsrc | Translated IP address of the source host. May be displayed anonymously depending on the administrator's access privileges.  Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.connection.modsrcport | Translated TCP/UDP source port number. Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.connection.origdst | Original IP address of the destination host (before translation or the application of a virtual connection).  Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.connection.origdstport | Original port number of the destination TCP/UDP port (before translation or the application of a virtual connection). Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.connection.pri | Represents the alarm level. Values(cannot be customized): "0" (emergency), "1" (alert), "2" (critical), "3" (error), "4" (warning), "5" (notice), "6" (information) or "7" (debug). Available from: SNS v1.0.0. | keyword |
| stormshield.connection.proto | Name of the associated plugin. If this is not available, the name of the standard service corresponding to the destination port. String of characters in UTF-8 format. Example: http, ssh Available from: SNS v1.0.0. | keyword |
| stormshield.connection.rcvd | Number of bytes received. Decimal format. Example: "23631" Available from: SNS v1.0.0. | keyword |
| stormshield.connection.rt | Name of the gateway used for the connection. Present only if the gateway does not match the default route. String of characters in UTF-8 format. Example: "my_gateway" Available from: SNS v4.3.0. | keyword |
| stormshield.connection.rtname | Name of the router object used for the connection. Present only if the router does not match the default route. String of characters in UTF-8 format. Example: "my_gateway" Available from: SNS v4.3.0. | keyword |
| stormshield.connection.ruleid | Number of the filter rule applied. Example: 1, 2  Available from: SNS v1.0.0. | keyword |
| stormshield.connection.sent | Number of bytes sent. Decimal format. Example: "14623" Available from: SNS v1.0.0. | keyword |
| stormshield.connection.serverappid | Last server application detected on the connection. Character string. Example: serverappid=google Available from: SNS v3.2.0. | keyword |
| stormshield.connection.slotlevel | Indicates the type of rule that activated logging.  Values: 0(implicit), 1 (global), or 2(local). Available from: SNS v1.0.0. | keyword |
| stormshield.connection.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.connection.srccontinent | Continent to which the source IP address of the connection belongs. Value: continent's ISO code Example: srccontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.connection.srccountry | Country to which the source IP address of the connection belongs. Format: country's ISO code Example: srccountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.connection.srchostrep | Reputation of the connection's source hosts. Available only if reputation management has been enabled for the relevant hosts. Format: unrestricted integer. Example: srchostrep=26123 Available from: SNS v3.0.0. | keyword |
| stormshield.connection.srcif | Internal name of the interface at the source of the traffic. String of characters in UTF-8 format. Example: Ethernet0 Available from: SNS v1.0.0. | keyword |
| stormshield.connection.srcifname | Name of the object representing the interface at the source of the traffic. String of characters in UTF-8 format. Example: out Available from: SNS v1.0.0. | keyword |
| stormshield.connection.srciprep | Reputation of the source IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: srciprep="anonymizer,tor" Available from: SNS v3.0.0. | keyword |
| stormshield.connection.srcmac | MAC address of the source host.  May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.connection.srcname | Name of the object corresponding to the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.connection.srcport | Source TCP/UDP port number. Example: "49753" Available from: SNS v1.0.0. | keyword |
| stormshield.connection.srcportname | Source port name if it is known. String of characters in UTF-8 format. Example: http, ephemeral_fw_tcp Available from: SNS v1.0.0. | keyword |
| stormshield.connection.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.connection.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.connection.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.connection.user | User authenticated by the firewall.  String of characters in UTF-8 format. Example: John.smith May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.connection.version | Protocol version number Character string in UTF-8 format. Example: version=TLSv1.2 Available from: SNS 4.2.1 | keyword |
| stormshield.count.Rule.byte_count | The number of bytes that have passed through the designated rule | unsigned_long |
| stormshield.count.Rule.category | Rule Category | keyword |
| stormshield.count.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.count.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.count.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.count.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.count.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.filter.action | Behavior associated with the filter rule. Value: Pass or Block (empty field for Log). | keyword |
| stormshield.filter.confid | Index of the security inspection profile used.  Value from 0 to 9. Available from: SNS v1.0.0. | keyword |
| stormshield.filter.dst | IP address of the destination host  Decimal format. Example: 192.168.0.2 Available from: SNS v1.0.0. | keyword |
| stormshield.filter.dstcontinent | Continent to which the destination IP address of the connection belongs. Value: continent's ISO code Example: dstcontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.filter.dstcountry | Country to which the destination IP address of the connection belongs. Format: country's ISO code Example: dstcountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.filter.dsthostrep | Reputation of the connection's target hosts Available only if reputation management has been enabled for the relevant hosts. Format: unrestricted integer. Example: dsthostrep=506 Available from: SNS v3.0.0. | keyword |
| stormshield.filter.dstif | Name of the destination interface. String of characters in UTF-8 format. Example: Ethernet 1 Available from: SNS v1.0.0. | keyword |
| stormshield.filter.dstifname | Name of the object representing the traffics destination interface. String of characters in UTF-8 format. Example: dmz1 Available from: SNS v1.0.0. | keyword |
| stormshield.filter.dstiprep | Reputation of the destination IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: dstiprep="spam" Available from: SNS v3.0.0. | keyword |
| stormshield.filter.dstmac | MAC address of the destination host. Format: Hexadecimal values separated by ":". Example: dstmac=00:25:90:01:ce:e7 Available from: SNS v4.0.0. | keyword |
| stormshield.filter.dstname | Name of the object corresponding to the IP address of the destination host.  String of characters in UTF-8 format. Example: intranet_server Available from: SNS v1.0.0. | keyword |
| stormshield.filter.dstport | Destination TCP/UDP port number. Example: "22" Available from: SNS v1.0.0. | keyword |
| stormshield.filter.dstportname | Name of the object corresponding to the destination port. String of characters in UTF-8 format. Example: ssh Available from: SNS v1.0.0. | keyword |
| stormshield.filter.etherproto | Type of Ethernet protocol. Format: String of characters in UTF-8 format. Example: etherproto="profinet-rt" Available from: SNS v4.0.0. | keyword |
| stormshield.filter.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.filter.icmpcode | Code number of the icmp message. Example: 1 (meaning Destination host unreachable). Available from: SNS v1.0.0. | keyword |
| stormshield.filter.icmptype | Number of the type of icmp message. Example: 3 (meaning Destination unreachable). Available from: SNS v1.0.0. | keyword |
| stormshield.filter.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.filter.ipproto | Name of the protocol above IP (transport layer).  String of characters in UTF-8 format. Example: tcp Available from: SNS v1.0.0. | keyword |
| stormshield.filter.ipv | Version of the IP protocol used in the traffic Values: 4, 6 Available from: SNS v1.0.0. | keyword |
| stormshield.filter.modsrc | Translated IP address of the source host. May be displayed anonymously depending on the administrator's access privileges.  Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.filter.modsrcport | Translated TCP/UDP source port number. Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.filter.origdst | Original IP address of the destination host (before translation or the application of a virtual connection).  Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.filter.origdstport | Original port number of the destination TCP/UDP port (before translation or the application of a virtual connection). Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.filter.pri | Represents the alarm level. Values(cannot be customized): "0" (emergency), "1" (alert), "2" (critical), "3" (error), "4" (warning), "5" (notice), "6" (information) or "7" (debug). Available from: SNS v1.0.0. | keyword |
| stormshield.filter.proto | Name of the associated plugin. If this is not available, the name of the standard service corresponding to the destination port. String of characters in UTF-8 format. Example: http, ssh Available from: SNS v1.0.0. | keyword |
| stormshield.filter.rcvd | Number of bytes received. Decimal format.  Example: "23631" Available from: SNS v1.0.0. | keyword |
| stormshield.filter.rt | Name of the gateway used for the connection. Present only if the gateway does not match the default route. String of characters in UTF-8 format. Example: "my_gateway" Available from: SNS v4.3.0. | keyword |
| stormshield.filter.rtname | Name of the router object used for the connection. Present only if the router does not match the default route. String of characters in UTF-8 format. Example: "my_gateway" Available from: SNS v4.3.0. | keyword |
| stormshield.filter.ruleid | Number of the filter rule applied. Example: 1, 2  Available from: SNS v1.0.0. | keyword |
| stormshield.filter.sent | Number of bytes sent. Decimal format. Example: "14623" Available from: SNS v1.0.0. | keyword |
| stormshield.filter.slotlevel | Indicates the type of rule that activated logging.  Values: 0(implicit), 1 (global), or 2(local). Available from: SNS v1.0.0. | keyword |
| stormshield.filter.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.filter.srccontinent | Continent to which the source IP address of the connection belongs. Value: continent's ISO code Example: srccontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.filter.srccountry | Country to which the source IP address of the connection belongs. Format: country's ISO code Example: srccountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.filter.srchostrep | Reputation of the connection's source hosts. Available only if reputation management has been enabled for the relevant hosts. Format: unrestricted integer. Example: srchostrep=26123 Available from: SNS v3.0.0. | keyword |
| stormshield.filter.srcif | Internal name of the interface at the source of the traffic. String of characters in UTF-8 format. Example: Ethernet0 Available from: SNS v1.0.0. | keyword |
| stormshield.filter.srcifname | Name of the object representing the interface at the source of the traffic. String of characters in UTF-8 format. Example: out Available from: SNS v1.0.0. | keyword |
| stormshield.filter.srciprep | Reputation of the source IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: srciprep="anonymizer,tor" Available from: SNS v3.0.0. | keyword |
| stormshield.filter.srcmac | MAC address of the source host.  May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.filter.srcname | Name of the object corresponding to the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.filter.srcport | Source TCP/UDP port number. Example: "49753" Available from: SNS v1.0.0. | keyword |
| stormshield.filter.srcportname | Source port name if it is known. String of characters in UTF-8 format. Example: http, ephemeral_fw_tcp Available from: SNS v1.0.0. | keyword |
| stormshield.filter.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.filter.target | Shows whether the src or dst fields correspond to the target of the packet that had raised the alarm. Values: "src" or "dst" Available from: SNS v3.0.0. | keyword |
| stormshield.filter.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.filter.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.filter.user | User authenticated by the firewall.  String of characters in UTF-8 format. Example: John.smith May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.filterstat.Accepted | Number of packets corresponding to the application of Pass rules. Example: Accepted=2430. | keyword |
| stormshield.filterstat.AssocMem | The memory used for ... | keyword |
| stormshield.filterstat.Blocked | Number of packets corresponding to the application of Block rules. Example: Blocked=1254. | keyword |
| stormshield.filterstat.Byte.in_count | Number of bytes that have passed through the firewall (incoming) | unsigned_long |
| stormshield.filterstat.Byte.out_count | Number of bytes that have passed through the firewall (outgoing) | unsigned_long |
| stormshield.filterstat.ConnMem | Percentage of memory allocated to connections. Value from 0 to 100. | keyword |
| stormshield.filterstat.DTrackMem | The memory used for ... | keyword |
| stormshield.filterstat.DtrackMem | Percentage of memory used for data tracking (TCP/UDP packets). Value from 0 to 100. | keyword |
| stormshield.filterstat.DynamicMem | Percentage of the ASQs dynamic memory in use. Value from 0 to 100. | keyword |
| stormshield.filterstat.EtherStateByte.in_count | Number of bytes that have passed through the firewall (incoming) | unsigned_long |
| stormshield.filterstat.EtherStateByte.out_count | Number of bytes that have passed through the firewall (outgoing) | unsigned_long |
| stormshield.filterstat.EtherStateConn | Number of stateful statuses for Ethernet exchanges without IP layer. Digital format. Example: EtherStateConn=0 Available from: SNS v4.0.0. | keyword |
| stormshield.filterstat.EtherStateMem | The memory used for ... | keyword |
| stormshield.filterstat.EtherStatePacket | Number of packets for Ethernet traffic without IP layer. Digital format. Example: EtherStatePacket=128 Available from: SNS v4.0.0. | keyword |
| stormshield.filterstat.FragMem | Percentage of memory allocated to the treatment of fragmented packets. Value from 0 to 100. | keyword |
| stormshield.filterstat.Fragmented | Number of fragmented packets that have passed through the Firewall. | keyword |
| stormshield.filterstat.HostMem | Percentage of memory allocated to a host processed by the Firewall. Value from 0 to 100. | keyword |
| stormshield.filterstat.HostrepMax | Highest reputation score of monitored hosts. Value: decimal integer between 0 and 65535. Example: HostrepMax=6540 Available from: SNS v3.0.0. | keyword |
| stormshield.filterstat.HostrepRequests | Number of reputation score requests submitted. Value: unrestricted decimal integer. Example: HostrepRequests=445 Available from: SNS v3.0.0. | keyword |
| stormshield.filterstat.HostrepScore | Average reputation score of monitored hosts. Value: decimal integer between 0 and 65535. Example: HostrepScore=1234 Available from: SNS v3.0.0. | keyword |
| stormshield.filterstat.ICMPByte.in_count | Number of bytes that have passed through the firewall (incoming) | unsigned_long |
| stormshield.filterstat.ICMPByte.out_count | Number of bytes that have passed through the firewall (outgoing) | unsigned_long |
| stormshield.filterstat.ICMPMem | Percentage of memory allocated to ICMP. Value from 0 to 100. | keyword |
| stormshield.filterstat.ICMPPacket | Number of ICMP packets that have passed through the Firewall. | keyword |
| stormshield.filterstat.IPStateByte.in_count | Number of bytes that have passed through the firewall (incoming) | unsigned_long |
| stormshield.filterstat.IPStateByte.out_count | Number of bytes that have passed through the firewall (outgoing) | unsigned_long |
| stormshield.filterstat.IPStateConn | Number of active pseudo-connections relating to protocols other than TCP, UDP or ICMP (e.g.: GRE). | keyword |
| stormshield.filterstat.IPStateConnNatDst | Number of active pseudo-connections with address translation on the destination. | keyword |
| stormshield.filterstat.IPStateConnNatSrc | Number of active pseudo-connections with address translation on the source. | keyword |
| stormshield.filterstat.IPStateConnNoNatDst | Number of active pseudo-connections that explicitly include "No NAT" instructions on the destination. | keyword |
| stormshield.filterstat.IPStateConnNoNatSrc | Number of active pseudo-connections that explicitly include "No NAT" instructions on the source. | keyword |
| stormshield.filterstat.IPStateMem | Percentage of memory allocated to processing pseudo-connections relating to protocols other than TCP, UDP or ICMP (e.g.: GRE) that have passed through the firewall. | keyword |
| stormshield.filterstat.IPStatePacket | Number of network packets originating from protocols other than TCP, UDP or ICMP (e.g.: GRE) that have passed through the firewall. | keyword |
| stormshield.filterstat.LogOverflow | Number of log lines that could not be generated by the intrusion prevention engine. | keyword |
| stormshield.filterstat.Logged | Number of log lines generated by the intrusion prevention engine. | keyword |
| stormshield.filterstat.PvmFacts | Number of events sent by ASQ to the vulnerability management process. | keyword |
| stormshield.filterstat.PvmOverflow | Number of events intended for the vulnerability management process that were ignored by ASQ. | keyword |
| stormshield.filterstat.SCTPAssoc | Number of SCTP associations. Digital format. Example: SCTPAssoc=2. Available from: SNS v3.9.0. | keyword |
| stormshield.filterstat.SCTPAssocByte.in_count | Number of bytes that have passed through the firewall (incoming) | unsigned_long |
| stormshield.filterstat.SCTPAssocByte.out_count | Number of bytes that have passed through the firewall (outgoing) | unsigned_long |
| stormshield.filterstat.SCTPAssocPacket | Number of packets exchanged for an SCTP association. Digital format. Example: SCTPAssocPacket=128 Available from: SNS v3.9.0. | keyword |
| stormshield.filterstat.SavedEvaluation | Number of rule evaluations that did not use intrusion prevention technology. | keyword |
| stormshield.filterstat.TCPByte.in_count | Number of bytes that have passed through the firewall (incoming) | unsigned_long |
| stormshield.filterstat.TCPByte.out_count | Number of bytes that have passed through the firewall (outgoing) | unsigned_long |
| stormshield.filterstat.TCPConn | Number of TCP connections that have passed through the Firewall. | keyword |
| stormshield.filterstat.TCPConnNatDst | Number of TCP connections with a translated destination. | keyword |
| stormshield.filterstat.TCPConnNatSrc | Number of TCP connections with a translated source. | keyword |
| stormshield.filterstat.TCPConnNoNatDst | Number of TCP connections with a translated destination. | keyword |
| stormshield.filterstat.TCPConnNoNatSrc | Number of TCP connections with a translated source. | keyword |
| stormshield.filterstat.TCPPacket | Number of TCP packets that have passed through the Firewall. | keyword |
| stormshield.filterstat.TLSCertCacheEntriesNb | Number of entries currently in the TLS certificate cache. Digital format. Example: TLSCertCacheEntriesNb=3456 Available from: SNS v4.3.0 | keyword |
| stormshield.filterstat.TLSCertCacheExpiredNb | Number of entries deleted from the TLS certificate cache after a TTL expired. Digital format. Example: TLSCertCacheExpiredNb=789 Available from: SNS v4.3.0 | keyword |
| stormshield.filterstat.TLSCertCacheFlushOp | Number of "flush" operations (manual deletion of entries, or after reloading signatures) performed on the TLS certificate cache. Digital format. Example: TLSCertCacheFlushOp=7 Available from: SNS v4.3.0 | keyword |
| stormshield.filterstat.TLSCertCacheFlushedNb | Number of entries deleted from the TLS certificate cache after a "flush operation. Digital format. Example: TLSCertCacheFlushedNb=123 Available from: SNS v4.3.0 | keyword |
| stormshield.filterstat.TLSCertCacheInsert | Number of entries inserted in the TLS certificate cache. Digital format. Example: TLSCertCacheInsert=789 Available from: SNS v4.3.0 | keyword |
| stormshield.filterstat.TLSCertCacheLookup.miss_count | Number of lookups missed in the TLS certificate cache. | unsigned_long |
| stormshield.filterstat.TLSCertCacheLookup.total | Number of total TLS certificate cache lookups | unsigned_long |
| stormshield.filterstat.TLSCertCachePurgeOp | Number of "purge" operations (automatic deletion of a percentage of entries when the cache reaches full capacity) performed on the TLS certificate cache. Digital format. Example: TLSCertCachePurgeOp=4 Available from: SNS v4.3.0 | keyword |
| stormshield.filterstat.TLSCertCachePurgedNb | Number of entries deleted from the TLS certificate cache after a "purge operation. Digital format. Example: TLSCertCachePurgedNb=456 Available from: SNS v4.3.0 | keyword |
| stormshield.filterstat.UDPByte.in_count | Number of bytes that have passed through the firewall (incoming) | unsigned_long |
| stormshield.filterstat.UDPByte.out_count | Number of bytes that have passed through the firewall (outgoing) | unsigned_long |
| stormshield.filterstat.UDPConn | Number of UDP connections that have passed through the Firewall. | keyword |
| stormshield.filterstat.UDPConnNatDst | Number of UDP connections with a translated destination. | keyword |
| stormshield.filterstat.UDPConnNatSrc | Number of UDP connections with a translated source. | keyword |
| stormshield.filterstat.UDPConnNoNatDst | Number of UDP connections with a translated destination. | keyword |
| stormshield.filterstat.UDPConnNoNatSrc | Number of UDP connections with a translated source. | keyword |
| stormshield.filterstat.UDPPacket | Number of UDP packets that have passed through the Firewall. | keyword |
| stormshield.filterstat.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.filterstat.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.filterstat.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.filterstat.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.filterstat.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.action | Behavior associated with the filter rule. Values: pass or block | keyword |
| stormshield.ftp.arg | Argument of the FTP command (file forwarded, etc). String of characters in UTF-8 format. Example: my_file.txt | keyword |
| stormshield.ftp.contentpolicy | Number of the SSL filter policy used. String of characters in UTF-8 format. Example: "3" Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.dst | IP address of the destination host Decimal format. Example: 192.168.100.1 Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.dstport | Service's destination port number. Example: "465" Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.dstportname | Name of the object corresponding to the destination port. String of characters in UTF-8 format. Example: "smtps" Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.duration | Duration of the connection in seconds. Example: "0.5" | keyword |
| stormshield.ftp.filename | Name of the file scanned by the sandboxing option.  String of characters in UTF-8 format. Example: "mydocument.doc" | keyword |
| stormshield.ftp.filetype | Type of file scanned by the sandboxing option. This may be a document (word processing, table, presentation, etc), a Portable Document Format file (PDF - Adobe Acrobat), and executable file or an archive. Value: "document", "pdf", "executable", "archive". | keyword |
| stormshield.ftp.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.groupid | ID number allowing the tracking of child connections. Example: 0, 1, 2 etc. | keyword |
| stormshield.ftp.hash | Results of the file content hash (SHA2 method) String of characters in UTF-8 format.Example: "f4d1be410a6102b9ae7d1c32612bed4f12158df3cd1ab6440a9ac0cad417446d" | keyword |
| stormshield.ftp.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.ftp.modsrc | Translated IP address of the source host. May be displayed anonymously depending on the administrator's access privileges. Decimal format. Example: 192.168.15.1 Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.modsrcport | Number of the translated TCP/UDP source port. Example: "49690" Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.msg | Error message or additional information on the virus detected. String of characters in UTF-8 format. Example: virus:EICAR-Test-File | keyword |
| stormshield.ftp.op | Operation performed on the FTP server. Example: "LIST", "RETR", "QUIT". | keyword |
| stormshield.ftp.origdst | Original IP address of the destination host (before translation or the application of a virtual connection). Decimal format. Example:192.168.200.1 Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.origdstport | Original port number of the destination TCP/UDP port (before translation or the application of a virtual connection). Example: "465" Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.pri | Set to 5 (notice) to ensure WELF compatibility. Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.proto | Name of the standard service corresponding to the destination port. String of characters in UTF-8 format. Example: smtp Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.rcvd | Volume of application data received (bytes). Example: "26657" Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.risk | Risk relating to the connection. This value contributes to the reputation score of the connection's source host. Value: between 1 (low risk) and 100 (very high risk). Example: risk=20 Available from: SNS v3.0.0. | keyword |
| stormshield.ftp.rulename | Name of the filter rule applied Character string Example: rulename="myrule" Available from: SNS v3.2.0. | keyword |
| stormshield.ftp.sandboxing | Classification of the file according to the sandboxing option.  Value: "clean", "suspicious", "malicious", "unknown", forward", "failed".  Sandboxing indicates a "clean", "suspicious" or "malicious" status if the file has already been scanned and classified. The "unknown" status is returned if sandboxing does not know the file concerned. In this case, the whole file will be sent to the firewall to be scanned. | keyword |
| stormshield.ftp.sandboxinglevel | Indicates the level of the file's infection on a scale of 0 to 100. Value: "0" (clean) to "100" (malicious). | keyword |
| stormshield.ftp.sent | Volume of application data sent (bytes). Example: "26657" Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.slotlevel | Indicates the type of rule that activated logging.  Values: 0(implicit), 1 (global), or 2(local). Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.srcmac | MAC address of the source host. May be displayed anonymously depending on the administrator's access privileges. | keyword |
| stormshield.ftp.srcname | Name of the object corresponding to the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.srcport | Source port number of the service.  Example: "51166" Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.srcportname | Source port name if it is known.  String of characters in UTF-8 format. Example: ephemeral_fw_tcp Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.user | ID used for logging on to the FTP server. String of characters in UTF-8 format. Example: john.smith May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.ftp.virus | Message indicating whether a virus has been detected (the antivirus has to be enabled) Example: clean | keyword |
| stormshield.logtype | The specific type of log this is from. | keyword |
| stormshield.monitor.CPU.kernel_time | Time consumed by the kernel | unsigned_long |
| stormshield.monitor.CPU.system_disruption | Time allocated to system disruptions | unsigned_long |
| stormshield.monitor.CPU.user_time | Time allocated to the management of user processes | unsigned_long |
| stormshield.monitor.Ethernet.incoming_throughput | Incoming throughput (bits/second) | unsigned_long |
| stormshield.monitor.Ethernet.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.Ethernet.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.Ethernet.name | Name of the interface | keyword |
| stormshield.monitor.Ethernet.original | Original name of this field | keyword |
| stormshield.monitor.Ethernet.outgoing_throughput | Outgoing throughput (bits/second) | unsigned_long |
| stormshield.monitor.Ethernet.packets_accepted | Number of packets accepted | unsigned_long |
| stormshield.monitor.Ethernet.packets_blocked | Number of packets blocked | unsigned_long |
| stormshield.monitor.Pvm | All indicators regarding vulnerability management:  Total number of vulnerabilities detected, number of vulnerabilities that can be exploited remotely, number of vulnerabilities requiring the installation of a server on the vulnerable host in order to be exploited, number of vulnerabilities classified as critical, number of vulnerabilities classified as minor, number of vulnerabilities classified as major, number of vulnerabilities that have a bug fix, total amount of information (all levels), number of minor data, number of major data, number of hosts for which PVM has gathered information,  Format: 11 numeric values separated by commas. Example: 0,0,0,0,0,0,0,2,0,0,2 | keyword |
| stormshield.monitor.Qid.incoming_throughput | Incoming throughput (bits/second) | unsigned_long |
| stormshield.monitor.Qid.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.Qid.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.Qid.name | Name of the interface | keyword |
| stormshield.monitor.Qid.original | Original name of this field | keyword |
| stormshield.monitor.Qid.outgoing_throughput | Outgoing throughput (bits/second) | unsigned_long |
| stormshield.monitor.Qid.packets_accepted | Number of packets accepted | unsigned_long |
| stormshield.monitor.Qid.packets_blocked | Number of packets blocked | unsigned_long |
| stormshield.monitor.Vlan.incoming_throughput | Incoming throughput (bits/second) | unsigned_long |
| stormshield.monitor.Vlan.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.Vlan.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.Vlan.name | Name of the interface | keyword |
| stormshield.monitor.Vlan.original | Original name of this field | keyword |
| stormshield.monitor.Vlan.outgoing_throughput | Outgoing throughput (bits/second) | unsigned_long |
| stormshield.monitor.Vlan.packets_accepted | Number of packets accepted | unsigned_long |
| stormshield.monitor.Vlan.packets_blocked | Number of packets blocked | unsigned_long |
| stormshield.monitor.Wifi.incoming_throughput | Incoming throughput (bits/second) | unsigned_long |
| stormshield.monitor.Wifi.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.Wifi.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.Wifi.name | Name of the interface | keyword |
| stormshield.monitor.Wifi.original | Original name of this field | keyword |
| stormshield.monitor.Wifi.outgoing_throughput | Outgoing throughput (bits/second) | unsigned_long |
| stormshield.monitor.Wifi.packets_accepted | Number of packets accepted | unsigned_long |
| stormshield.monitor.Wifi.packets_blocked | Number of packets blocked | unsigned_long |
| stormshield.monitor.agg.incoming_throughput | Incoming throughput (bits/second) | unsigned_long |
| stormshield.monitor.agg.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.agg.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.agg.name | Name of the interface | keyword |
| stormshield.monitor.agg.original | Original name of this field | keyword |
| stormshield.monitor.agg.outgoing_throughput | Outgoing throughput (bits/second) | unsigned_long |
| stormshield.monitor.agg.packets_accepted | Number of packets accepted | unsigned_long |
| stormshield.monitor.agg.packets_blocked | Number of packets blocked | unsigned_long |
| stormshield.monitor.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.monitor.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.monitor.ipsec.incoming_throughput | Incoming throughput (bits/second) | unsigned_long |
| stormshield.monitor.ipsec.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.ipsec.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.ipsec.name | Name of the interface | keyword |
| stormshield.monitor.ipsec.original | Original name of this field | keyword |
| stormshield.monitor.ipsec.outgoing_throughput | Outgoing throughput (bits/second) | unsigned_long |
| stormshield.monitor.ipsec.packets_accepted | Number of packets accepted | unsigned_long |
| stormshield.monitor.ipsec.packets_blocked | Number of packets blocked | unsigned_long |
| stormshield.monitor.mem | tbd | keyword |
| stormshield.monitor.security | Indicator of the Firewalls security status. This value is used by the fleet management tool (Stormshield Network Unified Manager) to provide information on the security status (minor, major alarms, etc). Decimal format representing a percentage. | keyword |
| stormshield.monitor.sslvpn.incoming_throughput | Incoming throughput (bits/second) | unsigned_long |
| stormshield.monitor.sslvpn.maximum_incoming_throughput | Maximum incoming throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.sslvpn.maximum_outgoing_throughput | Maximum outgoing throughput for a given period (bits/second) | unsigned_long |
| stormshield.monitor.sslvpn.name | Name of the interface | keyword |
| stormshield.monitor.sslvpn.original | Original name of this field | keyword |
| stormshield.monitor.sslvpn.outgoing_throughput | Outgoing throughput (bits/second) | unsigned_long |
| stormshield.monitor.sslvpn.packets_accepted | Number of packets accepted | unsigned_long |
| stormshield.monitor.sslvpn.packets_blocked | Number of packets blocked | unsigned_long |
| stormshield.monitor.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.monitor.system | Indicator of the Firewalls system status.  This value is used by the fleet management tool (Stormshield Network Unified Manager) to provide information on the system status (available RAM, CPU use, bandwidth, interfaces, fullness of audit logs, etc). Decimal format representing a percentage. | keyword |
| stormshield.monitor.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.monitor.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.monitor.wldev0 | Concerns only firewalls equipped with Wi-Fi antennas (W models). Indicators of bandwidth used for each physical interface that supports the firewall's Wi-Fi access points:   name of the interface. String of characters in UTF-8 format. incoming throughput (bits/second), maximum incoming throughput for a given period (bits/second), outgoing throughput (bits/second), maximum outgoing throughput for a given period (bits/second), number of packets accepted, number of packets blocked,  Format: 7 values separated by commas.  Example: "Physic_WiFi,61515,128648,788241,1890520,2130,21" | keyword |
| stormshield.plugin.UI | Sofbus/Lacbus information unit  String of characters in UTF-8 format. Example: UI=Instruction Available from: SNS v4.3.0 | keyword |
| stormshield.plugin.action | Behavior associated with the filter rule. Value: "pass". | keyword |
| stormshield.plugin.cipclassid | Value of the "Class ID" field in the CIP message. String of characters in UTF-8 format. Example: cipclassid=Connection_Manager_Object Available from: SNS v3.5.0 | keyword |
| stormshield.plugin.cipservicecode | Value of the "Service Code" field in the CIP message. String of characters in UTF-8 format. Example: cipservicecode=Get_Attribute_List Available from: SNS v3.5.0 | keyword |
| stormshield.plugin.clientappid | Last client application detected on the connection. Character string. Example: clientappid=firefox Available from: SNS v3.2.0 | keyword |
| stormshield.plugin.confid | Index of the security inspection profile used.  Value from 0 to 9. Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.domain | Authentication method used or LDAP directory of the user authenticated by the firewall. String of characters in UTF-8 format. Example: domain=documentation.stormshield.eu Available from: SNS v3.0.0 | keyword |
| stormshield.plugin.dst | IP address of the destination host  Decimal format. Example: 192.168.0.2 Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.dstcontinent | Continent to which the destination IP address of the connection belongs. Value: continent's ISO code Example: dstcontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.plugin.dstcountry | Country to which the destination IP address of the connection belongs. Format: country's ISO code Example: dstcountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.plugin.dsthostrep | Reputation of the connection's target hosts Available only if reputation management has been enabled for the relevant hosts. Format: unrestricted integer. Example: dsthostrep=506 Available from: SNS v3.0.0. | keyword |
| stormshield.plugin.dstif | Name of the destination interface. String of characters in UTF-8 format. Example: Ethernet 1 Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.dstifname | Name of the object representing the traffics destination interface. String of characters in UTF-8 format. Example: dmz1 Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.dstiprep | Reputation of the destination IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: dstiprep="spam" Available from: SNS v3.0.0. | keyword |
| stormshield.plugin.dstmac | MAC address of the destination host. Format: Hexadecimal values separated by ":". Example: dstmac=00:25:90:01:ce:e7 Available from: SNS v4.0.0. | keyword |
| stormshield.plugin.dstname | Name of the object corresponding to the IP address of the destination host.  String of characters in UTF-8 format. Example: intranet_server Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.dstport | Destination TCP/UDP port number. Example: "22" Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.dstportname | Name of the object corresponding to the destination port. String of characters in UTF-8 format. Example: ssh Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.duration | Duration of the connection in seconds. Decimal format.  Example: "173.15" | keyword |
| stormshield.plugin.error_class | Number of the error class in an S7 response. Digital format. Available from: SNS v2.3.0 | keyword |
| stormshield.plugin.error_code | Error code in the error class specified in the S7 response. Available from: SNS v2.3.0 | keyword |
| stormshield.plugin.etherproto | Type of Ethernet protocol. Format: String of characters in UTF-8 format. Example: etherproto="profinet-rt" Available from: SNS v4.0.0. | keyword |
| stormshield.plugin.format | Type of message for IEC104 Available from: SNS v3.1.0 | keyword |
| stormshield.plugin.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.group | Code of the "userdata" group for an S7 message. Available from: SNS v2.3.4 | keyword |
| stormshield.plugin.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.plugin.ipproto | Name of the protocol above IP (transport layer).  String of characters in UTF-8 format. Example: tcp Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.ipv | Version of the IP protocol used in the traffic Values: 4, 6 Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.modsrc | Translated IP address of the source host. May be displayed anonymously depending on the administrator's access privileges.  Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.modsrcport | Translated TCP/UDP source port number. Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.origdst | Original IP address of the destination host (before translation or the application of a virtual connection).  Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.origdstport | Original port number of the destination TCP/UDP port (before translation or the application of a virtual connection). Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.pri | Represents the alarm level. Values(cannot be customized): "0" (emergency), "1" (alert), "2" (critical), "3" (error), "4" (warning), "5" (notice), "6" (information) or "7" (debug). Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.proto | Name of the associated plugin. If this is not available, the name of the standard service corresponding to the destination port. String of characters in UTF-8 format. Example: http, ssh Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.rcvd | Number of bytes received. Decimal format.  Example: "23631" Available from: SNS v1.0.0 | keyword |
| stormshield.plugin.requestmode | Value of the "Mode" field for an NTP request. String of characters in UTF-8 format. Example: requestmode=client. Available from: SNS v3.8.0 | keyword |
| stormshield.plugin.responsemode | Value of the "Mode" field for an NTP response. String of characters in UTF-8 format. Example: responsemode=server. Available from: SNS v3.8.0 | keyword |
| stormshield.plugin.rt | Name of the gateway used for the connection. Present only if the gateway does not match the default route. String of characters in UTF-8 format. Example: "my_gateway" Available from: SNS v4.3.0. | keyword |
| stormshield.plugin.rtname | Name of the router object used for the connection. Present only if the router does not match the default route. String of characters in UTF-8 format. Example: "my_gateway" Available from: SNS v4.3.0. | keyword |
| stormshield.plugin.ruleid | Number of the filter rule applied. Example: 1, 2  Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.sent | Number of bytes sent. Decimal format.  Example: "14623" Available from: SNS v1.0.0 | keyword |
| stormshield.plugin.serverappid | Last server application detected on the connection. Character string. Example: serverappid=google Available from: SNS v3.2.0 | keyword |
| stormshield.plugin.slotlevel | Indicates the type of rule that activated logging.  Values: 0(implicit), 1 (global), or 2(local). Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.srccontinent | Continent to which the source IP address of the connection belongs. Value: continent's ISO code Example: srccontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.plugin.srccountry | Country to which the source IP address of the connection belongs. Format: country's ISO code Example: srccountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.plugin.srchostrep | Reputation of the connection's source hosts. Available only if reputation management has been enabled for the relevant hosts. Format: unrestricted integer. Example: srchostrep=26123 Available from: SNS v3.0.0. | keyword |
| stormshield.plugin.srcif | Internal name of the interface at the source of the traffic. String of characters in UTF-8 format. Example: Ethernet0 Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.srcifname | Name of the object representing the interface at the source of the traffic. String of characters in UTF-8 format. Example: out Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.srciprep | Reputation of the source IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: srciprep="anonymizer,tor" Available from: SNS v3.0.0. | keyword |
| stormshield.plugin.srcmac | MAC address of the source host.  May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.srcname | Name of the object corresponding to the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.srcport | Source TCP/UDP port number. Example: "49753" Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.srcportname | Source port name if it is known. String of characters in UTF-8 format. Example: http, ephemeral_fw_tcp Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.unit_id | Value of the "Unit Id" in a Modbus message. Example: "255". Available from: SNS v2.3.0 | keyword |
| stormshield.plugin.user | User authenticated by the firewall.  String of characters in UTF-8 format. Example: John.smith May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.plugin.version | Value of the "Version number" field for the NTP protocol. Digital format. Example: version=4. Available from: SNS v3.8.0 | keyword |
| stormshield.pop3.action | Behavior associated with the filter rule. Values: pass or block | keyword |
| stormshield.pop3.ads | Indicates whether the antispam has detected an e-mail as an advertisement. Values:  0 or1. | keyword |
| stormshield.pop3.contentpolicy | Number of the SSL filter policy used. String of characters in UTF-8 format. Example: "3" Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.dst | IP address of the destination host Decimal format. Example: 192.168.100.1 Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.dstcontinent | Continent to which the destination IP address of the connection belongs. Value: continent's ISO code Example: dstcontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.pop3.dstcountry | Country to which the destination IP address of the connection belongs. Format: country's ISO code Example: dstcountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.pop3.dsthostrep | Reputation of the connection's target host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: dsthostrep=506 Available from: SNS v3.0.0. | keyword |
| stormshield.pop3.dstiprep | Reputation of the destination IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: dstiprep="spam" Available from: SNS v3.0.0. | keyword |
| stormshield.pop3.dstport | Service's destination port number. Example: "465" Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.dstportname | Name of the object corresponding to the destination port. String of characters in UTF-8 format. Example: "smtps" Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.duration | Duration of the connection in seconds. Example: "0.5" | keyword |
| stormshield.pop3.filename | Name of the file scanned by the sandboxing option.  String of characters in UTF-8 format. Example: "mydocument.doc" | keyword |
| stormshield.pop3.filetype | Type of file scanned by the sandboxing option. This may be a document (word processing, table, presentation, etc), a Portable Document Format file (PDF - Adobe Acrobat), and executable file or an archive. Value: "document", "pdf", "executable", "archive". | keyword |
| stormshield.pop3.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.hash | Results of the file content hash (SHA2 method) String of characters in UTF-8 format.Example: "f4d1be410a6102b9ae7d1c32612bed4f12158df3cd1ab6440a9ac0cad417446d" | keyword |
| stormshield.pop3.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.pop3.modsrc | Translated IP address of the source host. May be displayed anonymously depending on the administrator's access privileges. Decimal format. Example: 192.168.15.1 Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.modsrcport | Number of the translated TCP/UDP source port. Example: "49690" Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.msg | Message associated with the POP3 command executed. String of characters in UTF-8 format. Example: Username rejected | keyword |
| stormshield.pop3.op | Operation on the POP3 server (RETR, LIST, ...) Example: USER | keyword |
| stormshield.pop3.origdst | Original IP address of the destination host (before translation or the application of a virtual connection). Decimal format. Example:192.168.200.1 Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.origdstport | Original port number of the destination TCP/UDP port (before translation or the application of a virtual connection). Example: "465" Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.pri | Set to 5 (notice) to ensure WELF compatibility. Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.proto | Name of the standard service corresponding to the destination port. String of characters in UTF-8 format. Example: smtp Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.rcvd | Volume of application data received (bytes). Example: "26657" Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.risk | Risk relating to the connection. This value contributes to the reputation score of the connection's source host. Value: between 1 (low risk) and 100 (very high risk). Example: risk=20 Available from: SNS v3.0.0. | keyword |
| stormshield.pop3.ruleid | Number of the filter rule applied. Example: 1, 2  Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.rulename | Name of the filter rule applied Character string Example: rulename="myrule" Available from: SNS v3.2.0. | keyword |
| stormshield.pop3.sandboxing | Classification of the file according to the sandboxing option.  Value: "clean", "suspicious", "malicious", "unknown", forward", "failed".  Sandboxing indicates a "clean", "suspicious" or "malicious" status if the file has already been scanned and classified. The "unknown" status is returned if sandboxing does not know the file concerned. In this case, the whole file will be sent to the firewall to be scanned. | keyword |
| stormshield.pop3.sandboxinglevel | Indicates the level of the file's infection on a scale of 0 to 100. Value: "0" (clean) to "100" (malicious). | keyword |
| stormshield.pop3.sent | Volume of application data sent (bytes). Example: "26657" Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.slotlevel | Indicates the type of rule that activated logging.  Values: 0(implicit), 1 (global), or 2(local). Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.spamlevel | Results of antispam processing on the message. Values: "X": error while processing the message. "?": the nature of the message could not be determined. "0": non-spam message. "1", "2" or "3": criticality of the spam message, 3 being the most critical. Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.srccontinent | Continent to which the source IP address of the connection belongs. Value: continent's ISO code Example: srccontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.pop3.srccountry | Country to which the source IP address of the connection belongs. Format: country's ISO code Example: srccountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.pop3.srchostrep | Reputation of the connection's source host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: srchostrep=26123 Available from: SNS v3.0.0. | keyword |
| stormshield.pop3.srciprep | Reputation of the source IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: srciprep="anonymizer,tor" Available from: SNS v3.0.0. | keyword |
| stormshield.pop3.srcmac | MAC address of the source host. May be displayed anonymously depending on the administrator's access privileges. | keyword |
| stormshield.pop3.srcname | Name of the object corresponding to the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.srcport | Source port number of the service.  Example: "51166" Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.srcportname | Source port name if it is known.  String of characters in UTF-8 format. Example: ephemeral_fw_tcp Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.user | Users login. String of characters in UTF-8 format. Example: "john.smith@company.com" May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.pop3.virus | Message indicating whether a virus has been detected (the antivirus has to be enabled) Example: clean | keyword |
| stormshield.pvm.arg | Details of the detected vulnerability (version of service, operating system concerned, etc). String of characters in UTF-8 format. Example: Samba_3.6.3 | keyword |
| stormshield.pvm.detail | Additional information on the vulnerable software version.  String of characters in UTF-8 format. Example: PHP_5.2.3 | keyword |
| stormshield.pvm.discovery | Date on which the security watch team published the vulnerability (only if the level of severity is higher than 0) String in YYYY-MM-DD format. | keyword |
| stormshield.pvm.family | Name of the vulnerability family (Web Client, Web Server, Mail Client...).  String of characters in UTF-8 format. Example: SSH, Web Client . | keyword |
| stormshield.pvm.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.pvm.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.pvm.ipproto | Type of network protocol (entered only if a vulnerability has been detected). String of characters in UTF-8 format. Example: tcp Available from: SNS v1.0.0. | keyword |
| stormshield.pvm.msg | Name of the vulnerability.  String of characters in UTF-8 format. Example: Samba SWAT Clickjacking Vulnerability | keyword |
| stormshield.pvm.port | Port number (entered only if a vulnerability has been detected). Example: "22" | keyword |
| stormshield.pvm.portname | Standard service corresponding to the port number (entered only if a vulnerability has been detected). String of characters in UTF-8 format. Example: ssh | keyword |
| stormshield.pvm.pri | Alarm level (configurable by the administrator in certain cases). Values: 1 (major) or  4 (minor). Available from: SNS v1.0.0. | keyword |
| stormshield.pvm.product | Product on which the vulnerability was detected. String of characters in UTF-8 format. Example: JRE_1.6.0_27 | keyword |
| stormshield.pvm.proto | Name of the associated plugin. If this is not available, the name of the standard service corresponding to the port (entered only if a vulnerability has been detected). String of characters in UTF-8 format. Example: ssh Available from: SNS v1.0.0. | keyword |
| stormshield.pvm.remote | Indicates whether the vulnerability can be exploited remotely Values: 0 (false) or 1 (true). | keyword |
| stormshield.pvm.service | Service (product with a dedicated port) on which the vulnerability was detected.  String of characters in UTF-8 format. Example: OpenSSH_5.4 | keyword |
| stormshield.pvm.severity | Vulnerabilitys intrinsic level of severity.  Values: 0 (Information), 1 (Weak), 2 (Moderate), 3 (High) or 4 (Critical). | keyword |
| stormshield.pvm.solution | Indicates whether a fix is available in order to correct the detected vulnerability. Values: 0 (not available) or 1 (available). | keyword |
| stormshield.pvm.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.pvm.srcname | Name of the object corresponding to the IP address of the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.pvm.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.pvm.targetclient | Indicates whether the exploitation of the vulnerability requires the use of a client on the vulnerable host. Values: 0 (false) or 1 (true). | keyword |
| stormshield.pvm.targetserver | Indicates whether the exploitation of the vulnerability requires the installation of a server on the vulnerable host. Values: 0 (false) or 1 (true). | keyword |
| stormshield.pvm.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.pvm.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.pvm.vulnid | Unique Stormshield Network ID of the detected vulnerability. Example: "132710" | keyword |
| stormshield.routerstat.downrate | Indicates the percentage of time the gateway could not be reached over the last 15 minutes. String of characters in UTF-8 format. Example: downrate=0. Available from: SNS v4.3.0. | keyword |
| stormshield.routerstat.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.routerstat.gw | Name of the monitored gateway. String of characters in UTF-8 format. Example: gw=gw123. Available from: SNS v4.3.0. | keyword |
| stormshield.routerstat.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.routerstat.jitter | Indicates the average, minimum and maximum jitter (variation in latency) over a regular interval, depending on the configuration (ms). String of characters in UTF-8 format. Example: jitter=5,0,20. Available from: SNS v4.3.0. | keyword |
| stormshield.routerstat.latency | Indicates the average, minimum and maximum latency over a regular interval, depending on the configuration (ms). String of characters in UTF-8 format. Example: latency=70,50,100. Available from: SNS v4.3.0. | keyword |
| stormshield.routerstat.lossrate | Indicates the average rate of packet loss (%) over the last 15 minutes. String of characters in UTF-8 format. Example: lossrate=10. Available from: SNS v4.3.0. | keyword |
| stormshield.routerstat.router | Name of the monitored router. String of characters in UTF-8 format. Example: router=routerICMP. Available from: SNS v4.3.0. | keyword |
| stormshield.routerstat.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.routerstat.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.routerstat.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.routerstat.unreachrate | Indicates the percentage of time the gateway could not be accessed over the last 15 minutes. String of characters in UTF-8 format. Example: unreachrate=0. Available from: SNS v4.3.0. | keyword |
| stormshield.routerstat.uprate | Indicates the percentage of time the status of the gateway was active over the last 15 minutes. String of characters in UTF-8 format. Example: uprate=0. Available from: SNS v4.3.0. | keyword |
| stormshield.sandboxing.dstcontinent | Continent to which the destination IP address of the connection belongs. Value: continent's ISO code Example: dstcontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.sandboxing.dstcountry | Country to which the destination IP address of the connection belongs. Format: country's ISO code Example: dstcountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.sandboxing.dsthostrep | Reputation of the connection's target host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: dsthostrep=506 Available from: SNS v3.0.0. | keyword |
| stormshield.sandboxing.dstiprep | Reputation of the destination IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: dstiprep="spam" Available from: SNS v3.0.0. | keyword |
| stormshield.sandboxing.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.sandboxing.hash | Results of the file content hash (SHA2 method) String of characters in UTF-8 format.Example: "f4d1be410a6102b9ae7d1c32612bed4f12158df3cd1ab6440a9ac0cad417446d" | keyword |
| stormshield.sandboxing.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.sandboxing.msg | Message associated with the results of the sandboxing scan. String of characters in UTF-8 format. Example: "Virus name: thisvirus". | keyword |
| stormshield.sandboxing.proto | Name of the associated plugin. If this is not available, the name of the standard service corresponding to the destination port. String of characters in UTF-8 format. Example: http, ssh Available from: SNS v1.0.0. | keyword |
| stormshield.sandboxing.risk | Risk relating to the connection. This value contributes to the reputation score of the connection's source host. Value: between 1 (low risk) and 100 (very high risk). Example: risk=20 Available from: SNS v3.0.0. | keyword |
| stormshield.sandboxing.sandboxing | Classification of the file according to the sandboxing option.  Value: "clean", "suspicious", "malicious", "unknown", forward", "failed".  The sandboxing option indicates a "clean", "suspicious" or "malicious" status if the file has already been scanned and classified. The "unknown" status is returned if sandboxing does not know the file concerned. In this case, the whole file will be sent to the firewall to be scanned. | keyword |
| stormshield.sandboxing.sandboxinglevel | Indicates the level of the file's infection on a scale of 0 to 100. Value: "0" (clean) to "100" (malicious). | keyword |
| stormshield.sandboxing.service | Service (product with a dedicated port) on which the vulnerability was detected.  String of characters in UTF-8 format. Example: OpenSSH_5.4 | keyword |
| stormshield.sandboxing.srccontinent | Continent to which the source IP address of the connection belongs. Value: continent's ISO code Example: srccontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.sandboxing.srccountry | Country to which the source IP address of the connection belongs. Format: country's ISO code Example: srccountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.sandboxing.srchostrep | Reputation of the connection's source host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: srchostrep=26123 Available from: SNS v3.0.0. | keyword |
| stormshield.sandboxing.srciprep | Reputation of the source IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: srciprep="anonymizer,tor" Available from: SNS v3.0.0. | keyword |
| stormshield.sandboxing.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.sandboxing.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.sandboxing.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.server.address | IP address of the client workstation that initiated the connection. Decimal format.  Example: address=192.168.0.2 | keyword |
| stormshield.server.domain | Authentication method used or LDAP directory of the user authenticated by the firewall. String of characters in UTF-8 format. Example: domain="documentation.stormshield.eu" Available from: SNS v3.0.0. | keyword |
| stormshield.server.error | Commands return code number Example: 0, 3 | keyword |
| stormshield.server.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.server.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.server.msg | Executed command accompanied by its parameters where applicable. String of characters in UTF-8 format. Example: CONFIG FILTER ACTIVATE | keyword |
| stormshield.server.sessionid | Session ID number allowing simultaneous connections to be differentiated. Example: "18" | keyword |
| stormshield.server.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.server.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.server.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.server.user | ID of the administrator who executed the command.  String of characters in UTF-8 format. Example: admin May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.action | Behavior associated with the filter rule. Values: pass or block | keyword |
| stormshield.smtp.ads | Indicates whether the antispam has detected an e-mail as an advertisement. Values:  0 or1. | keyword |
| stormshield.smtp.contentpolicy | Number of the SSL filter policy used. String of characters in UTF-8 format. Example: "3" Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.dst | IP address of the destination host Decimal format. Example: 192.168.100.1 Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.dstcontinent | Continent to which the destination IP address of the connection belongs. Value: continent's ISO code Example: dstcontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.smtp.dstcountry | Country to which the destination IP address of the connection belongs. Format: country's ISO code Example: dstcountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.smtp.dsthostrep | Reputation of the connection's target host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: dsthostrep=506 Available from: SNS v3.0.0. | keyword |
| stormshield.smtp.dstiprep | Reputation of the destination IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: dstiprep="spam" Available from: SNS v3.0.0. | keyword |
| stormshield.smtp.dstname | E-mail address of the recipient. String of characters in UTF-8 format. Example: "john.doe@company2.com" Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.dstport | Service's destination port number. Example: "465" Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.dstportname | Name of the object corresponding to the destination port. String of characters in UTF-8 format. Example: "smtps" Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.duration | Duration of the connection in seconds. Example: "0.5" | keyword |
| stormshield.smtp.filename | Name of the file scanned by the sandboxing option.  String of characters in UTF-8 format. Example: "mydocument.doc" | keyword |
| stormshield.smtp.filetype | Type of file scanned by the sandboxing option. This may be a document (word processing, table, presentation, etc), a Portable Document Format file (PDF - Adobe Acrobat), and executable file or an archive. Value: "document", "pdf", "executable", "archive". | keyword |
| stormshield.smtp.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.hash | Results of the file content hash (SHA2 method) String of characters in UTF-8 format.Example: "f4d1be410a6102b9ae7d1c32612bed4f12158df3cd1ab6440a9ac0cad417446d" | keyword |
| stormshield.smtp.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.smtp.mailruleid | Number of the mail filter rule applied. Digital format Example: mailruleid=48 Available from: SNS v3.2.0. | keyword |
| stormshield.smtp.modsrc | Translated IP address of the source host. May be displayed anonymously depending on the administrator's access privileges. Decimal format. Example: 192.168.15.1 Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.modsrcport | Number of the translated TCP/UDP source port. Example: "49690" Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.msg | Message associated with the SMTP command executed. String of characters in UTF-8 format. Example: Connection interrupted | keyword |
| stormshield.smtp.origdst | Original IP address of the destination host (before translation or the application of a virtual connection). Decimal format. Example:192.168.200.1 Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.origdstport | Original port number of the destination TCP/UDP port (before translation or the application of a virtual connection). Example: "465" Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.pri | Set to 5 (notice) to ensure WELF compatibility. Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.proto | Name of the standard service corresponding to the destination port. String of characters in UTF-8 format. Example: smtp Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.rcvd | Volume of application data received (bytes). Example: "26657" Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.risk | Risk relating to the connection. This value contributes to the reputation score of the connection's source host. Value: between 1 (low risk) and 100 (very high risk). Example: risk=20 Available from: SNS v3.0.0. | keyword |
| stormshield.smtp.ruleid | Number of the filter rule applied. Example: 1, 2  Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.rulename | Name of the filter rule applied Character string Example: rulename="myrule" Available from: SNS v3.2.0. | keyword |
| stormshield.smtp.sandboxing | Classification of the file according to the sandboxing option.  Value: "clean", "suspicious", "malicious", "unknown", forward", "failed".  Sandboxing indicates a "clean", "suspicious" or "malicious" status if the file has already been scanned and classified. The "unknown" status is returned if sandboxing does not know the file concerned. In this case, the whole file will be sent to the firewall to be scanned. | keyword |
| stormshield.smtp.sandboxinglevel | Indicates the level of the file's infection on a scale of 0 to 100. Value: "0" (clean) to "100" (malicious). | keyword |
| stormshield.smtp.sent | Volume of application data sent (bytes). Example: "26657" Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.slotlevel | Indicates the type of rule that activated logging.  Values: 0(implicit), 1 (global), or 2(local). Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.spamlevel | Results of antispam processing on the message. Values: "X": error while processing the message. "?": the nature of the message could not be determined. "0": non-spam message. "1", "2" or "3": criticality of the spam message, 3 being the most critical. Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.srccontinent | Continent to which the source IP address of the connection belongs. Value: continent's ISO code Example: srccontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.smtp.srccountry | Country to which the source IP address of the connection belongs. Format: country's ISO code Example: srccountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.smtp.srchostrep | Reputation of the connection's source host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: srchostrep=26123 Available from: SNS v3.0.0. | keyword |
| stormshield.smtp.srciprep | Reputation of the source IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: srciprep="anonymizer,tor" Available from: SNS v3.0.0. | keyword |
| stormshield.smtp.srcmac | MAC address of the source host. May be displayed anonymously depending on the administrator's access privileges. | keyword |
| stormshield.smtp.srcname | Name of the object corresponding to the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.srcport | Source port number of the service.  Example: "51166" Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.srcportname | Source port name if it is known.  String of characters in UTF-8 format. Example: ephemeral_fw_tcp Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.user | E-mail address of the sender. String of characters in UTF-8 format.  Example: "john.doe@company1.com" May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.smtp.virus | Message indicating whether a virus has been detected (the antivirus has to be enabled) Example: clean | keyword |
| stormshield.ssl.action | Behavior associated with the filter rule. Values: pass or block | keyword |
| stormshield.ssl.arg | Additional information regarding the SSL negotiation Example: "Subject%... Issuer%..." | keyword |
| stormshield.ssl.cat_site | Category (URL filtering) of the website visited. String of characters in UTF-8 format.  Example: \{bank\}, \{news\}, etc. Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.cnruleid | Number of the SSL filter rule applied. Digital format. Example: cnruleid=3 Available from: SNS v3.2.0. | keyword |
| stormshield.ssl.contentpolicy | Number of the SSL filter policy used. String of characters in UTF-8 format. Example: "3" Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.domain | Authentication method used or LDAP directory of the user authenticated by the firewall. String of characters in UTF-8 format. Example: domain="documentation.stormshield.eu" Available from: SNS v3.0.0. | keyword |
| stormshield.ssl.dst | IP address of the destination host Decimal format. Example: 192.168.100.1 Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.dstcontinent | Continent to which the destination IP address of the connection belongs. Value: continent's ISO code Example: dstcontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.ssl.dstcountry | Country to which the destination IP address of the connection belongs. Format: country's ISO code Example: dstcountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.ssl.dsthostrep | Reputation of the connection's target host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: dsthostrep=506 Available from: SNS v3.0.0. | keyword |
| stormshield.ssl.dstiprep | Reputation of the destination IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: dstiprep="spam" Available from: SNS v3.0.0. | keyword |
| stormshield.ssl.dstport | Service's destination port number. Example: "465" Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.dstportname | Name of the object corresponding to the destination port. String of characters in UTF-8 format. Example: "smtps" Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.duration | Duration of the connection in seconds. Example: "0.5" | keyword |
| stormshield.ssl.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.ssl.modsrc | Translated IP address of the source host. May be displayed anonymously depending on the administrator's access privileges. Decimal format. Example: 192.168.15.1 Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.modsrcport | Number of the translated TCP/UDP source port. Example: "49690" Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.msg | Message associated with the action performed.  String of characters in UTF-8 format. Example: "Connection not deciphered (rule matches: Nodecrypt)" | keyword |
| stormshield.ssl.origdst | Original IP address of the destination host (before translation or the application of a virtual connection). Decimal format. Example:192.168.200.1 Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.origdstport | Original port number of the destination TCP/UDP port (before translation or the application of a virtual connection). Example: "465" Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.pri | Set to 5 (notice) to ensure WELF compatibility. Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.proto | Name of the standard service corresponding to the destination port. String of characters in UTF-8 format. Example: smtp Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.rcvd | Volume of application data received (bytes). Example: "26657" Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.risk | Risk relating to the connection. This value contributes to the reputation score of the connection's source host. Value: between 1 (low risk) and 100 (very high risk). Example: risk=20 Available from: SNS v3.0.0. | keyword |
| stormshield.ssl.rulename | Name of the filter rule applied Character string Example: rulename="myrule" Available from: SNS v3.2.0. | keyword |
| stormshield.ssl.sent | Volume of application data sent (bytes). Example: "26657" Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.slotlevel | Indicates the type of rule that activated logging.  Values: 0(implicit), 1 (global), or 2(local). Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.srccontinent | Continent to which the source IP address of the connection belongs. Value: continent's ISO code Example: srccontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.ssl.srccountry | Country to which the source IP address of the connection belongs. Format: country's ISO code Example: srccountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.ssl.srchostrep | Reputation of the connection's source host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: srchostrep=26123 Available from: SNS v3.0.0. | keyword |
| stormshield.ssl.srciprep | Reputation of the source IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: srciprep="anonymizer,tor" Available from: SNS v3.0.0. | keyword |
| stormshield.ssl.srcmac | MAC address of the source host. May be displayed anonymously depending on the administrator's access privileges. | keyword |
| stormshield.ssl.srcname | Name of the object corresponding to the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.srcport | Source port number of the service.  Example: "51166" Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.srcportname | Source port name if it is known.  String of characters in UTF-8 format. Example: ephemeral_fw_tcp Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.ssl.user | ID of the user (when the authentication phase has ended). String of characters in UTF-8 format. Example: John.smith May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.system.alarmid | Stormshield Network alarm ID Decimal format. Example: "85" | keyword |
| stormshield.system.dst | IP address of the destination host Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.system.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.system.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.system.msg | Reference message regarding the action. String of characters in UTF-8 format. Example: Agent (ssoagent) is active | keyword |
| stormshield.system.pri | Set to 5 meaning notice to ensure WELF compatibility. Available from: SNS v1.0.0. | keyword |
| stormshield.system.service | Name of the module that executed an action. ASCII character string. Example: SSOAgent | keyword |
| stormshield.system.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.system.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.system.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.system.tsagentname | Indicates the name of the TS agent used. String of characters in UTF-8 format. Example: tsagentname="agent_name_test" Available from: SNS v4.7.0. | keyword |
| stormshield.system.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.system.user | ID of the administrator who executed the command. String of characters in UTF-8 format. Example:admin May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.vpn.cookie_i | Temporary identity marker of the initiator of the negotiation. Character string in hexadecimal. Example: 0xae34785945ae3cbf | keyword |
| stormshield.vpn.cookie_r | Temporary identity marker of the peer of the negotiation.  Character string in hexadecimal. Example: "0x56201508549a6526". | keyword |
| stormshield.vpn.dst | IP address of the VPN tunnels remote endpoint. Decimal format.  Example: 192.168.1.1 Available from: SNS v1.0.0. | keyword |
| stormshield.vpn.dstname | Name of the object corresponding to the VPN tunnels remote endpoint. String of characters in UTF-8 format.  Example: fw_remote Available from: SNS v1.0.0. | keyword |
| stormshield.vpn.error | Error level of the log. Values: 0 (Information), 1 (Warning) or 2 (Error). | keyword |
| stormshield.vpn.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.vpn.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.vpn.ike | Version of the IKE protocol used Values: 1, 2 | keyword |
| stormshield.vpn.localnet | Local network negotiated in phase2. Decimal format. Example: 192.168.0.1 | keyword |
| stormshield.vpn.msg | Description of the operation performed. String of characters in UTF-8 format. Example: Phase established | keyword |
| stormshield.vpn.phase | Number of the IPSec VPN tunnel negotiation phase. Values: 0 (no phase), 1 (phase 1) or 2 (phase 2). | keyword |
| stormshield.vpn.pri | Set to 5 (notice) to ensure WELF compatibility. Available from: SNS v1.0.0. | keyword |
| stormshield.vpn.remoteid | ID of the peer used during the negotiation of the IKE SA. This may be an e-mail address or IP address. | keyword |
| stormshield.vpn.remotenet | Remote network negotiated in phase2. Decimal format. Example: 192.168.1.1 | keyword |
| stormshield.vpn.ruletype | Type of IPSec rule. Character string.  Values: mobile, gateway. Example: ruletype=mobile. Available from: SNS v4.2.1 | keyword |
| stormshield.vpn.side | Role of the Firewall in the negotiation of the tunnel. Values: initiator or responder. | keyword |
| stormshield.vpn.spi_in | SPI (Security Parameter Index) number of the negotiated incoming SA (Security Association). Character string in hexadecimal. Example: 0x01ae58af | keyword |
| stormshield.vpn.spi_out | SPI number of the negotiated outgoing SA. Character string in hexadecimal. Example: 0x003d098c | keyword |
| stormshield.vpn.src | IP address of the VPN tunnels local endpoint. Decimal format. Example: 192.168.0.1 Available from: SNS v1.0.0. | keyword |
| stormshield.vpn.srcname | Name of the object corresponding to the VPN tunnels local endpoint. String of characters in UTF-8 format.  Example: Pub_FW Available from: SNS v1.0.0. | keyword |
| stormshield.vpn.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.vpn.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.vpn.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.vpn.user | ID of the remote user used for the negotiation.  String of characters in UTF-8 format.  Example: john.smith May be displayed anonymously depending on the administrator's access privileges. c | keyword |
| stormshield.vpn.usergroup | The user that set up a tunnel belongs this group, defined in the VPN access privileges. String of characters in UTF-8 format. Example: usergroup="ipsec-group" Available from: SNS v3.3.0. | keyword |
| stormshield.web.action | Behavior associated with the filter rule. Values: pass or block | keyword |
| stormshield.web.arg | Argument of the HTTP command. String of characters in UTF-8 format. Example: /, /mapage.htm | keyword |
| stormshield.web.cat_site | Category (URL filtering) of the website visited. String of characters in UTF-8 format.  Example: \{bank\}, \{news\}, etc. Available from: SNS v1.0.0. | keyword |
| stormshield.web.contentpolicy | Number of the SSL filter policy used. String of characters in UTF-8 format. Example: "3" Available from: SNS v1.0.0. | keyword |
| stormshield.web.domain | Authentication method used or LDAP directory of the user authenticated by the firewall. String of characters in UTF-8 format. Example: domain="documentation.stormshield.eu" Available from: SNS v3.0.0. | keyword |
| stormshield.web.dst | IP address of the destination host Decimal format. Example: 192.168.100.1 Available from: SNS v1.0.0. | keyword |
| stormshield.web.dstcontinent | Continent to which the destination IP address of the connection belongs. Value: continent's ISO code Example: dstcontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.web.dstcountry | Country to which the destination IP address of the connection belongs. Format: country's ISO code Example: dstcountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.web.dsthostrep | Reputation of the connection's target host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: dsthostrep=506 Available from: SNS v3.0.0. | keyword |
| stormshield.web.dstiprep | Reputation of the destination IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: dstiprep="spam" Available from: SNS v3.0.0. | keyword |
| stormshield.web.dstname | Name of the target website.  String of characters in UTF-8 format. Example: webserver.company.com Available from: SNS v1.0.0. | keyword |
| stormshield.web.dstport | Service's destination port number. Example: "465" Available from: SNS v1.0.0. | keyword |
| stormshield.web.dstportname | Name of the object corresponding to the destination port. String of characters in UTF-8 format. Example: "smtps" Available from: SNS v1.0.0. | keyword |
| stormshield.web.duration | Duration of the connection in seconds. Example: "0.5" | keyword |
| stormshield.web.filename | Name of the file scanned by the sandboxing option.  String of characters in UTF-8 format. Example: "mydocument.doc" | keyword |
| stormshield.web.filetype | Type of file scanned by the sandboxing option. This may be a document (word processing, table, presentation, etc), a Portable Document Format file (PDF - Adobe Acrobat), and executable file or an archive. Value: "document", "pdf", "executable", "archive". | keyword |
| stormshield.web.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.web.hash | Results of the file content hash (SHA2 method) String of characters in UTF-8 format.Example: "f4d1be410a6102b9ae7d1c32612bed4f12158df3cd1ab6440a9ac0cad417446d" | keyword |
| stormshield.web.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.web.modsrc | Translated IP address of the source host. May be displayed anonymously depending on the administrator's access privileges. Decimal format. Example: 192.168.15.1 Available from: SNS v1.0.0. | keyword |
| stormshield.web.modsrcport | Number of the translated TCP/UDP source port. Example: "49690" Available from: SNS v1.0.0. | keyword |
| stormshield.web.msg | Additional message about the action performed.  String of characters in UTF-8 format. Example: Blocked url | keyword |
| stormshield.web.op | Operation on the http server. Example: GET, PUT ... | keyword |
| stormshield.web.origdst | Original IP address of the destination host (before translation or the application of a virtual connection). Decimal format. Example:192.168.200.1 Available from: SNS v1.0.0. | keyword |
| stormshield.web.origdstport | Original port number of the destination TCP/UDP port (before translation or the application of a virtual connection). Example: "465" Available from: SNS v1.0.0. | keyword |
| stormshield.web.pri | Set to 5 (notice) to ensure WELF compatibility. Available from: SNS v1.0.0. | keyword |
| stormshield.web.proto | Name of the standard service corresponding to the destination port. String of characters in UTF-8 format. Example: smtp Available from: SNS v1.0.0. | keyword |
| stormshield.web.rcvd | Volume of application data received (bytes). Example: "26657" Available from: SNS v1.0.0. | keyword |
| stormshield.web.result | Return code of the HTTP server. Example: 403, 404 | keyword |
| stormshield.web.risk | Risk relating to the connection. This value contributes to the reputation score of the connection's source host. Value: between 1 (low risk) and 100 (very high risk). Example: risk=20 Available from: SNS v3.0.0. | keyword |
| stormshield.web.ruleid | Number of the filter rule applied. Example: "4" Available from: SNS v1.0.0. | keyword |
| stormshield.web.rulename | Name of the filter rule applied Character string Example: rulename="myrule" Available from: SNS v3.2.0. | keyword |
| stormshield.web.sandboxing | Classification of the file according to the sandboxing option.  Value: "clean", "suspicious", "malicious", "unknown", forward", "failed".  Sandboxing indicates a "clean", "suspicious" or "malicious" status if the file has already been scanned and classified. The "unknown" status is returned if sandboxing does not know the file concerned. In this case, the whole file will be sent to the firewall to be scanned. | keyword |
| stormshield.web.sandboxinglevel | Indicates the level of the file's infection on a scale of 0 to 100. Value: "0" (clean) to "100" (malicious). | keyword |
| stormshield.web.sent | Volume of application data sent (bytes). Example: "26657" Available from: SNS v1.0.0. | keyword |
| stormshield.web.slotlevel | Indicates the type of rule that activated logging.  Values: 0(implicit), 1 (global), or 2(local). Available from: SNS v1.0.0. | keyword |
| stormshield.web.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.web.srccontinent | Continent to which the source IP address of the connection belongs. Value: continent's ISO code Example: srccontinent="eu" Available from: SNS v3.0.0. | keyword |
| stormshield.web.srccountry | Country to which the source IP address of the connection belongs. Format: country's ISO code Example: srccountry="fr" Available from: SNS v3.0.0. | keyword |
| stormshield.web.srchostrep | Reputation of the connection's source host. Available only if reputation management has been enabled for the relevant host. Format: unrestricted integer. Example: srchostrep=26123 Available from: SNS v3.0.0. | keyword |
| stormshield.web.srciprep | Reputation of the source IP address. Available only if this IP address is public and listed in the IP address reputation base. Value: "anonymizer", "botnet", "malware", "phishing", "tor", "scanner" or "spam". Example: srciprep="anonymizer,tor" Available from: SNS v3.0.0. | keyword |
| stormshield.web.srcmac | MAC address of the source host. May be displayed anonymously depending on the administrator's access privileges. | keyword |
| stormshield.web.srcname | Name of the object corresponding to the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.web.srcport | Source port number of the service.  Example: "51166" Available from: SNS v1.0.0. | keyword |
| stormshield.web.srcportname | Source port name if it is known.  String of characters in UTF-8 format. Example: ephemeral_fw_tcp Available from: SNS v1.0.0. | keyword |
| stormshield.web.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.web.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.web.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.web.urlruleid | Number of the URL filter rule applied. Digital format. Example: urlruleid=12 Available from: SNS v3.2.0. | keyword |
| stormshield.web.user | Name of the user (when authentication is enabled).  String of characters in UTF-8 format. Example: John.smith May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.web.virus | Message indicating whether a virus has been detected (the antivirus has to be enabled) Example: clean | keyword |
| stormshield.xvpn.arg | Argument of the executed command. String of characters in UTF-8 format. Example: /documentation | keyword |
| stormshield.xvpn.domain | Authentication method used or LDAP directory of the user authenticated by the firewall. String of characters in UTF-8 format. Example: domain="documentation.stormshield.eu" Available from: SNS v3.0.0. | keyword |
| stormshield.xvpn.dst | IP address of the destination host Decimal format. Example:192.168.50.1 Available from: SNS v1.0.0. | keyword |
| stormshield.xvpn.dstname | Name of the object (FQDN name) corresponding to the destination host. String of characters in UTF-8 format. Example: server.company.com Available from: SNS v1.0.0. | keyword |
| stormshield.xvpn.dstport | Destination port number. Decimal format. Example: "80" Available from: SNS v1.0.0. | keyword |
| stormshield.xvpn.dstportname | Name of the object corresponding to the destination port. String of characters in UTF-8 format. Example: http Available from: SNS v1.0.0. | keyword |
| stormshield.xvpn.error | Return code of the SSL VPN access. Example: 0, 5, 8", etc. | keyword |
| stormshield.xvpn.fw | firewall's ID This is the name entered by the administrator or, by default, its serial number. String of characters in UTF-8 format.  Example: firewall_name or V50XXXXXXXXXXXX Available from: SNS v1.0.0. | keyword |
| stormshield.xvpn.id | Type of product.  This field constantly has the value firewall for logs on the Firewall. | keyword |
| stormshield.xvpn.localnet | Network address used by the firewall to set up the SSL VPN tunnel Decimal format. Example: 192.168.53.2 | keyword |
| stormshield.xvpn.msg | Message associated with the return code. String of characters in UTF-8 format. Example: Access to host, Bad or no cookie found | keyword |
| stormshield.xvpn.remotenet | Network address assigned to the client to set up the SSL VPN tunnel Decimal format. Example: 192.168.53.3 | keyword |
| stormshield.xvpn.src | IP address of the source host. Decimal format. Example: 192.168.0.1 May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.xvpn.srcname | Name of the object corresponding to the source host. String of characters in UTF-8 format. Example: client_workstation May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| stormshield.xvpn.startime | Local time at the beginning of the logged event (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.xvpn.time | Local time at which the log was recorded in the log file (time configured on the Firewall). String in YYYY-MM-DD HH:MM:SS format. Available from: SNS v1.0.0. | keyword |
| stormshield.xvpn.tz | Time difference between the Firewalls time and GMT. This depends on the time zone used. String in +HHMM or -HHMM format. Available from: SNS v1.0.0. | keyword |
| stormshield.xvpn.user | Name of the user accessing SSL VPN. String of characters in UTF-8 format. Example: john.smith May be displayed anonymously depending on the administrator's access privileges. Available from: SNS v1.0.0. | keyword |
| tags | List of keywords used to tag each event. | keyword |

