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

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

* how to setup SNS to send syslog (with RFC) to where the Agent is running

* test out adding the integration, and then setup stormshield to send syslogs to it

* copy some cisco asa config variables into this integration

<!-- Additional set up instructions -->

<!-- If applicable -->
<!-- ## Logs reference -->

<!-- Repeat for each data stream of the current type -->
<!-- ### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}. -->

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
| stormshield.alarm.alarmid |  | keyword |
| stormshield.alarm.class |  | keyword |
| stormshield.alarm.confid |  | keyword |
| stormshield.alarm.dst |  | keyword |
| stormshield.alarm.dstcontinent |  | keyword |
| stormshield.alarm.dstcountry |  | keyword |
| stormshield.alarm.dsthostrep |  | keyword |
| stormshield.alarm.dstif |  | keyword |
| stormshield.alarm.dstifname |  | keyword |
| stormshield.alarm.dstiprep |  | keyword |
| stormshield.alarm.dstmac |  | keyword |
| stormshield.alarm.dstname |  | keyword |
| stormshield.alarm.dstport |  | keyword |
| stormshield.alarm.dstportname |  | keyword |
| stormshield.alarm.etherproto |  | keyword |
| stormshield.alarm.ipproto |  | keyword |
| stormshield.alarm.ipv |  | keyword |
| stormshield.alarm.modsrc |  | keyword |
| stormshield.alarm.modsrcport |  | keyword |
| stormshield.alarm.origdst |  | keyword |
| stormshield.alarm.origdstport |  | keyword |
| stormshield.alarm.pri |  | keyword |
| stormshield.alarm.proto |  | keyword |
| stormshield.alarm.rt |  | keyword |
| stormshield.alarm.rtname |  | keyword |
| stormshield.alarm.ruleid |  | keyword |
| stormshield.alarm.slotlevel |  | keyword |
| stormshield.alarm.src |  | keyword |
| stormshield.alarm.srccontinent |  | keyword |
| stormshield.alarm.srccountry |  | keyword |
| stormshield.alarm.srchostrep |  | keyword |
| stormshield.alarm.srcif |  | keyword |
| stormshield.alarm.srcifname |  | keyword |
| stormshield.alarm.srciprep |  | keyword |
| stormshield.alarm.srcmac |  | keyword |
| stormshield.alarm.srcname |  | keyword |
| stormshield.alarm.srcport |  | keyword |
| stormshield.alarm.srcportname |  | keyword |
| stormshield.alarm.startime |  | keyword |
| stormshield.alarm.time |  | keyword |
| stormshield.alarm.tz |  | keyword |
| stormshield.alarm.user |  | keyword |
| stormshield.authstat.auth |  | keyword |
| stormshield.authstat.authcaptive |  | keyword |
| stormshield.authstat.authconsole |  | keyword |
| stormshield.authstat.authipsec |  | keyword |
| stormshield.authstat.authsslvpn |  | keyword |
| stormshield.authstat.authtotp |  | keyword |
| stormshield.authstat.authwebadmin |  | keyword |
| stormshield.authstat.startime |  | keyword |
| stormshield.authstat.time |  | keyword |
| stormshield.authstat.tz |  | keyword |
| stormshield.connection.action |  | keyword |
| stormshield.connection.clientappid |  | keyword |
| stormshield.connection.confid |  | keyword |
| stormshield.connection.domain |  | keyword |
| stormshield.connection.dst |  | keyword |
| stormshield.connection.dstcontinent |  | keyword |
| stormshield.connection.dstcountry |  | keyword |
| stormshield.connection.dsthostrep |  | keyword |
| stormshield.connection.dstif |  | keyword |
| stormshield.connection.dstifname |  | keyword |
| stormshield.connection.dstiprep |  | keyword |
| stormshield.connection.dstmac |  | keyword |
| stormshield.connection.dstname |  | keyword |
| stormshield.connection.dstport |  | keyword |
| stormshield.connection.dstportname |  | keyword |
| stormshield.connection.duration |  | keyword |
| stormshield.connection.etherproto |  | keyword |
| stormshield.connection.ipproto |  | keyword |
| stormshield.connection.ipv |  | keyword |
| stormshield.connection.modsrc |  | keyword |
| stormshield.connection.modsrcport |  | keyword |
| stormshield.connection.origdst |  | keyword |
| stormshield.connection.origdstport |  | keyword |
| stormshield.connection.pri |  | keyword |
| stormshield.connection.proto |  | keyword |
| stormshield.connection.rcvd |  | keyword |
| stormshield.connection.rt |  | keyword |
| stormshield.connection.rtname |  | keyword |
| stormshield.connection.ruleid |  | keyword |
| stormshield.connection.sent |  | keyword |
| stormshield.connection.serverappid |  | keyword |
| stormshield.connection.slotlevel |  | keyword |
| stormshield.connection.src |  | keyword |
| stormshield.connection.srccontinent |  | keyword |
| stormshield.connection.srccountry |  | keyword |
| stormshield.connection.srchostrep |  | keyword |
| stormshield.connection.srcif |  | keyword |
| stormshield.connection.srcifname |  | keyword |
| stormshield.connection.srciprep |  | keyword |
| stormshield.connection.srcmac |  | keyword |
| stormshield.connection.srcname |  | keyword |
| stormshield.connection.srcport |  | keyword |
| stormshield.connection.srcportname |  | keyword |
| stormshield.connection.user |  | keyword |
| stormshield.connection.version |  | keyword |
| stormshield.filter.Accepted |  | keyword |
| stormshield.filter.AssocMem |  | keyword |
| stormshield.filter.Blocked |  | keyword |
| stormshield.filter.ConnMem |  | keyword |
| stormshield.filter.confid |  | keyword |
| stormshield.filter.dst |  | keyword |
| stormshield.filter.dstcontinent |  | keyword |
| stormshield.filter.dstcountry |  | keyword |
| stormshield.filter.dsthostrep |  | keyword |
| stormshield.filter.dstif |  | keyword |
| stormshield.filter.dstifname |  | keyword |
| stormshield.filter.dstiprep |  | keyword |
| stormshield.filter.dstmac |  | keyword |
| stormshield.filter.dstname |  | keyword |
| stormshield.filter.dstport |  | keyword |
| stormshield.filter.dstportname |  | keyword |
| stormshield.filter.etherproto |  | keyword |
| stormshield.filter.gw |  | keyword |
| stormshield.filter.ipproto |  | keyword |
| stormshield.filter.ipv |  | keyword |
| stormshield.filter.jitter |  | keyword |
| stormshield.filter.latency |  | keyword |
| stormshield.filter.modsrc |  | keyword |
| stormshield.filter.modsrcport |  | keyword |
| stormshield.filter.origdst |  | keyword |
| stormshield.filter.origdstport |  | keyword |
| stormshield.filter.pri |  | keyword |
| stormshield.filter.proto |  | keyword |
| stormshield.filter.router |  | keyword |
| stormshield.filter.rt |  | keyword |
| stormshield.filter.rtname |  | keyword |
| stormshield.filter.ruleid |  | keyword |
| stormshield.filter.slotlevel |  | keyword |
| stormshield.filter.src |  | keyword |
| stormshield.filter.srccontinent |  | keyword |
| stormshield.filter.srccountry |  | keyword |
| stormshield.filter.srchostrep |  | keyword |
| stormshield.filter.srcif |  | keyword |
| stormshield.filter.srcifname |  | keyword |
| stormshield.filter.srciprep |  | keyword |
| stormshield.filter.srcmac |  | keyword |
| stormshield.filter.srcname |  | keyword |
| stormshield.filter.srcport |  | keyword |
| stormshield.filter.srcportname |  | keyword |
| stormshield.filter.user |  | keyword |
| stormshield.filterstat.Accepted |  | keyword |
| stormshield.filterstat.AssocMem |  | keyword |
| stormshield.filterstat.Blocked |  | keyword |
| stormshield.filterstat.Byte.in_count |  | unsigned_long |
| stormshield.filterstat.Byte.out_count |  | unsigned_long |
| stormshield.filterstat.ConnMem |  | keyword |
| stormshield.filterstat.DTrackMem |  | keyword |
| stormshield.filterstat.DynamicMem |  | keyword |
| stormshield.filterstat.EtherStateByte.in_count |  | unsigned_long |
| stormshield.filterstat.EtherStateByte.out_count |  | unsigned_long |
| stormshield.filterstat.EtherStateConn |  | keyword |
| stormshield.filterstat.EtherStateMem |  | keyword |
| stormshield.filterstat.EtherStatePacket |  | keyword |
| stormshield.filterstat.FragMem |  | keyword |
| stormshield.filterstat.Fragmented |  | keyword |
| stormshield.filterstat.HostMem |  | keyword |
| stormshield.filterstat.HostrepMax |  | keyword |
| stormshield.filterstat.HostrepRequests |  | keyword |
| stormshield.filterstat.HostrepScore |  | keyword |
| stormshield.filterstat.ICMPByte.in_count |  | unsigned_long |
| stormshield.filterstat.ICMPByte.out_count |  | unsigned_long |
| stormshield.filterstat.ICMPMem |  | keyword |
| stormshield.filterstat.ICMPPacket |  | keyword |
| stormshield.filterstat.IPStateByte.in_count |  | unsigned_long |
| stormshield.filterstat.IPStateByte.out_count |  | unsigned_long |
| stormshield.filterstat.IPStateConn |  | keyword |
| stormshield.filterstat.IPStateConnNatDst |  | keyword |
| stormshield.filterstat.IPStateConnNatSrc |  | keyword |
| stormshield.filterstat.IPStateConnNoNatDst |  | keyword |
| stormshield.filterstat.IPStateConnNoNatSrc |  | keyword |
| stormshield.filterstat.IPStateMem |  | keyword |
| stormshield.filterstat.IPStatePacket |  | keyword |
| stormshield.filterstat.LogOverflow |  | keyword |
| stormshield.filterstat.Logged |  | keyword |
| stormshield.filterstat.PvmFacts |  | keyword |
| stormshield.filterstat.PvmOverflow |  | keyword |
| stormshield.filterstat.SCTPAssoc |  | keyword |
| stormshield.filterstat.SCTPAssocByte.in_count |  | unsigned_long |
| stormshield.filterstat.SCTPAssocByte.out_count |  | unsigned_long |
| stormshield.filterstat.SCTPAssocPacket |  | keyword |
| stormshield.filterstat.SavedEvaluation |  | keyword |
| stormshield.filterstat.TCPByte.in_count |  | unsigned_long |
| stormshield.filterstat.TCPByte.out_count |  | unsigned_long |
| stormshield.filterstat.TCPConn |  | keyword |
| stormshield.filterstat.TCPConnNatDst |  | keyword |
| stormshield.filterstat.TCPConnNatSrc |  | keyword |
| stormshield.filterstat.TCPConnNoNatDst |  | keyword |
| stormshield.filterstat.TCPConnNoNatSrc |  | keyword |
| stormshield.filterstat.TCPPacket |  | keyword |
| stormshield.filterstat.TLSCertCacheEntriesNb |  | keyword |
| stormshield.filterstat.TLSCertCacheExpiredNb |  | keyword |
| stormshield.filterstat.TLSCertCacheFlushOp |  | keyword |
| stormshield.filterstat.TLSCertCacheFlushedNb |  | keyword |
| stormshield.filterstat.TLSCertCacheInsert |  | keyword |
| stormshield.filterstat.TLSCertCacheLookup.miss_count |  | integer |
| stormshield.filterstat.TLSCertCacheLookup.total |  | integer |
| stormshield.filterstat.TLSCertCachePurgeOp |  | keyword |
| stormshield.filterstat.TLSCertCachePurgedNb |  | keyword |
| stormshield.filterstat.UDPByte.in_count |  | unsigned_long |
| stormshield.filterstat.UDPByte.out_count |  | unsigned_long |
| stormshield.filterstat.UDPConn |  | keyword |
| stormshield.filterstat.UDPConnNatDst |  | keyword |
| stormshield.filterstat.UDPConnNatSrc |  | keyword |
| stormshield.filterstat.UDPConnNoNatDst |  | keyword |
| stormshield.filterstat.UDPConnNoNatSrc |  | keyword |
| stormshield.filterstat.UDPPacket |  | keyword |
| stormshield.filterstat.startime |  | keyword |
| stormshield.filterstat.time |  | keyword |
| stormshield.filterstat.tz |  | keyword |
| stormshield.logtype |  | keyword |
| stormshield.monitor.CPU.kernel_time |  | integer |
| stormshield.monitor.CPU.system_disruption |  | integer |
| stormshield.monitor.CPU.user_time |  | integer |
| stormshield.monitor.Ethernet.incoming_throughput |  | unsigned_long |
| stormshield.monitor.Ethernet.maximum_incoming_throughput |  | unsigned_long |
| stormshield.monitor.Ethernet.maximum_outgoing_throughput |  | unsigned_long |
| stormshield.monitor.Ethernet.name |  | keyword |
| stormshield.monitor.Ethernet.original |  | keyword |
| stormshield.monitor.Ethernet.outgoing_throughput |  | unsigned_long |
| stormshield.monitor.Ethernet.packets_accepted |  | unsigned_long |
| stormshield.monitor.Ethernet.packets_blocked |  | unsigned_long |
| stormshield.monitor.Pvm |  | keyword |
| stormshield.monitor.Qid.incoming_throughput |  | unsigned_long |
| stormshield.monitor.Qid.maximum_incoming_throughput |  | unsigned_long |
| stormshield.monitor.Qid.maximum_outgoing_throughput |  | unsigned_long |
| stormshield.monitor.Qid.name |  | keyword |
| stormshield.monitor.Qid.original |  | keyword |
| stormshield.monitor.Qid.outgoing_throughput |  | unsigned_long |
| stormshield.monitor.Qid.packets_accepted |  | unsigned_long |
| stormshield.monitor.Qid.packets_blocked |  | unsigned_long |
| stormshield.monitor.ipsec.incoming_throughput |  | unsigned_long |
| stormshield.monitor.ipsec.maximum_incoming_throughput |  | unsigned_long |
| stormshield.monitor.ipsec.maximum_outgoing_throughput |  | unsigned_long |
| stormshield.monitor.ipsec.name |  | keyword |
| stormshield.monitor.ipsec.native |  | boolean |
| stormshield.monitor.ipsec.original |  | keyword |
| stormshield.monitor.ipsec.outgoing_throughput |  | unsigned_long |
| stormshield.monitor.ipsec.packets_accepted |  | unsigned_long |
| stormshield.monitor.ipsec.packets_blocked |  | unsigned_long |
| stormshield.monitor.mem |  | keyword |
| stormshield.monitor.security |  | keyword |
| stormshield.monitor.sslvpn.incoming_throughput |  | unsigned_long |
| stormshield.monitor.sslvpn.maximum_incoming_throughput |  | unsigned_long |
| stormshield.monitor.sslvpn.maximum_outgoing_throughput |  | unsigned_long |
| stormshield.monitor.sslvpn.name |  | keyword |
| stormshield.monitor.sslvpn.original |  | keyword |
| stormshield.monitor.sslvpn.outgoing_throughput |  | unsigned_long |
| stormshield.monitor.sslvpn.packets_accepted |  | unsigned_long |
| stormshield.monitor.sslvpn.packets_blocked |  | unsigned_long |
| stormshield.monitor.startime |  | keyword |
| stormshield.monitor.system |  | keyword |
| stormshield.monitor.time |  | keyword |
| stormshield.monitor.tz |  | keyword |
| stormshield.plugin.confid |  | keyword |
| stormshield.plugin.dst |  | keyword |
| stormshield.plugin.dstcontinent |  | keyword |
| stormshield.plugin.dstcountry |  | keyword |
| stormshield.plugin.dsthostrep |  | keyword |
| stormshield.plugin.dstif |  | keyword |
| stormshield.plugin.dstifname |  | keyword |
| stormshield.plugin.dstiprep |  | keyword |
| stormshield.plugin.dstmac |  | keyword |
| stormshield.plugin.dstname |  | keyword |
| stormshield.plugin.dstport |  | keyword |
| stormshield.plugin.dstportname |  | keyword |
| stormshield.plugin.etherproto |  | keyword |
| stormshield.plugin.ipproto |  | keyword |
| stormshield.plugin.ipv |  | keyword |
| stormshield.plugin.modsrc |  | keyword |
| stormshield.plugin.modsrcport |  | keyword |
| stormshield.plugin.origdst |  | keyword |
| stormshield.plugin.origdstport |  | keyword |
| stormshield.plugin.pri |  | keyword |
| stormshield.plugin.proto |  | keyword |
| stormshield.plugin.rt |  | keyword |
| stormshield.plugin.rtname |  | keyword |
| stormshield.plugin.ruleid |  | keyword |
| stormshield.plugin.slotlevel |  | keyword |
| stormshield.plugin.src |  | keyword |
| stormshield.plugin.srccontinent |  | keyword |
| stormshield.plugin.srccountry |  | keyword |
| stormshield.plugin.srchostrep |  | keyword |
| stormshield.plugin.srcif |  | keyword |
| stormshield.plugin.srcifname |  | keyword |
| stormshield.plugin.srciprep |  | keyword |
| stormshield.plugin.srcmac |  | keyword |
| stormshield.plugin.srcname |  | keyword |
| stormshield.plugin.srcport |  | keyword |
| stormshield.plugin.srcportname |  | keyword |
| stormshield.plugin.user |  | keyword |
| stormshield.routerstat.downrate |  | keyword |
| stormshield.routerstat.gw |  | keyword |
| stormshield.routerstat.jitter |  | keyword |
| stormshield.routerstat.latency |  | keyword |
| stormshield.routerstat.lossrate |  | keyword |
| stormshield.routerstat.router |  | keyword |
| stormshield.routerstat.unreachrate |  | keyword |
| stormshield.routerstat.uprate |  | keyword |
| stormshield.server.address |  | keyword |
| stormshield.server.error |  | keyword |
| stormshield.server.sessionid |  | keyword |
| stormshield.server.startime |  | keyword |
| stormshield.server.time |  | keyword |
| stormshield.server.tz |  | keyword |
| stormshield.server.user |  | keyword |
| stormshield.system.alarmid |  | keyword |
| stormshield.system.dst |  | keyword |
| stormshield.system.msg |  | keyword |
| stormshield.system.pri |  | keyword |
| stormshield.system.service |  | keyword |
| stormshield.system.src |  | keyword |
| stormshield.system.startime |  | date |
| stormshield.system.time |  | date |
| stormshield.system.tsagentname |  | keyword |
| stormshield.system.tz |  | keyword |
| stormshield.system.user |  | keyword |
| tags | List of keywords used to tag each event. | keyword |
