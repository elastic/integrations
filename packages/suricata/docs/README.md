# Suricata Integration

This integration is for [Suricata](https://suricata-ids.org/). It reads the EVE
JSON output file. The EVE output writes alerts, anomalies, metadata, file info
and protocol specific records as JSON.

## Compatibility

This module has been developed against Suricata v4.0.4, but is expected to work
with other versions of Suricata.

## EVE

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| destination.address | Destination network address. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | Destination domain. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| dns.answers | An array containing an object for each answer section returned by the server. The main keys that should be present in these objects are defined by ECS. Records that have more information may contain more keys than what ECS defines. Not all DNS data sources give all details about DNS answers. At minimum, answer objects must contain the `data` key. If more information is available, map as much of it to ECS as possible, and add any additional fields to the answer objects as custom fields. | object |
| dns.answers.class | The class of DNS data contained in this resource record. | keyword |
| dns.answers.data | The data describing the resource. The meaning of this data depends on the type and class of the resource record. | wildcard |
| dns.answers.name | The domain name to which this resource record pertains. If a chain of CNAME is being resolved, each answer's `name` should be the one that corresponds with the answer's `data`. It should not simply be the original `question.name` repeated. | keyword |
| dns.answers.ttl | The time interval in seconds that this resource record may be cached before it should be discarded. Zero values mean that the data should not be cached. | long |
| dns.answers.type | The type of data contained in this resource record. | keyword |
| dns.header_flags | Array of 2 letter DNS header flags. Expected values are: AA, TC, RD, RA, AD, CD, DO. | keyword |
| dns.id | The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response. | keyword |
| dns.op_code | The DNS operation code that specifies the kind of query in the message. This value is set by the originator of a query and copied into the response. | keyword |
| dns.question.class | The class of records being queried. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | wildcard |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.google.com" is "google.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for google.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.resolved_ip | Array containing all IPs seen in `answers.data`. The `answers` array can be difficult to use, because of the variety of data formats it can contain. Extracting all IP addresses seen in there to `dns.resolved_ip` makes it possible to index them as IP addresses, and makes them easier to visualize and query for. | ip |
| dns.response_code | The DNS response code. | keyword |
| dns.type | The type of DNS event captured, query or answer. If your source of DNS events only gives you DNS queries, you should only create dns events of type `dns.type:query`. If your source of DNS events gives you answers as well, you should create one event per query (optionally as soon as the query is seen). And a second event containing all query details as well as an array of answers. | keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.duration | Duration of the event in nanoseconds. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` < `event.created` < `event.ingested`. | date |
| event.original | Raw text message of entire event. Used to demonstrate log integrity. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | wildcard |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | wildcard |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| input.type | Filebeat input type used to collect the log. | keyword |
| log.file.path | The file from which the line was read. This field contains the absolute path to the file. For example: `/var/log/system.log`. | wildcard |
| log.offset | The file offset the reported line starts at. | long |
| message | Log message optimized for viewing in a log viewer. | text |
| network.bytes | Total bytes transferred in both directions. | long |
| network.community_id | A hash of source and destination IPs and ports. | keyword |
| network.packets | Total packets transferred in both directions. | long |
| network.protocol | L7 Network protocol name. ex. http, lumberjack, transport protocol. The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| related.hash | All the hashes seen on your event. | keyword |
| related.hosts | All the host identifiers seen on your event. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| rule.category | Rule category | keyword |
| rule.id | Rule ID | keyword |
| rule.name | Rule name | keyword |
| source.address | Source network address. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| suricata.eve.alert.category |  | keyword |
| suricata.eve.alert.gid |  | long |
| suricata.eve.alert.rev |  | long |
| suricata.eve.alert.signature |  | keyword |
| suricata.eve.alert.signature_id |  | long |
| suricata.eve.app_proto_expected |  | keyword |
| suricata.eve.app_proto_orig |  | keyword |
| suricata.eve.app_proto_tc |  | keyword |
| suricata.eve.app_proto_ts |  | keyword |
| suricata.eve.dns.id |  | long |
| suricata.eve.dns.rcode |  | keyword |
| suricata.eve.dns.rdata |  | keyword |
| suricata.eve.dns.rrname |  | keyword |
| suricata.eve.dns.rrtype |  | keyword |
| suricata.eve.dns.ttl |  | long |
| suricata.eve.dns.tx_id |  | long |
| suricata.eve.dns.type |  | keyword |
| suricata.eve.email.status |  | keyword |
| suricata.eve.event_type |  | keyword |
| suricata.eve.fileinfo.gaps |  | boolean |
| suricata.eve.fileinfo.md5 |  | keyword |
| suricata.eve.fileinfo.sha1 |  | keyword |
| suricata.eve.fileinfo.sha256 |  | keyword |
| suricata.eve.fileinfo.state |  | keyword |
| suricata.eve.fileinfo.stored |  | boolean |
| suricata.eve.fileinfo.tx_id |  | long |
| suricata.eve.flow.age |  | long |
| suricata.eve.flow.alerted |  | boolean |
| suricata.eve.flow.end |  | date |
| suricata.eve.flow.reason |  | keyword |
| suricata.eve.flow.state |  | keyword |
| suricata.eve.flow_id |  | keyword |
| suricata.eve.http.http_content_type |  | keyword |
| suricata.eve.http.protocol |  | keyword |
| suricata.eve.http.redirect |  | keyword |
| suricata.eve.icmp_code |  | long |
| suricata.eve.icmp_type |  | long |
| suricata.eve.in_iface |  | keyword |
| suricata.eve.pcap_cnt |  | long |
| suricata.eve.smtp.helo |  | keyword |
| suricata.eve.smtp.mail_from |  | keyword |
| suricata.eve.smtp.rcpt_to |  | keyword |
| suricata.eve.ssh.client.proto_version |  | keyword |
| suricata.eve.ssh.client.software_version |  | keyword |
| suricata.eve.ssh.server.proto_version |  | keyword |
| suricata.eve.ssh.server.software_version |  | keyword |
| suricata.eve.stats.app_layer.flow.dcerpc_tcp |  | long |
| suricata.eve.stats.app_layer.flow.dcerpc_udp |  | long |
| suricata.eve.stats.app_layer.flow.dns_tcp |  | long |
| suricata.eve.stats.app_layer.flow.dns_udp |  | long |
| suricata.eve.stats.app_layer.flow.failed_tcp |  | long |
| suricata.eve.stats.app_layer.flow.failed_udp |  | long |
| suricata.eve.stats.app_layer.flow.ftp |  | long |
| suricata.eve.stats.app_layer.flow.http |  | long |
| suricata.eve.stats.app_layer.flow.imap |  | long |
| suricata.eve.stats.app_layer.flow.msn |  | long |
| suricata.eve.stats.app_layer.flow.smb |  | long |
| suricata.eve.stats.app_layer.flow.smtp |  | long |
| suricata.eve.stats.app_layer.flow.ssh |  | long |
| suricata.eve.stats.app_layer.flow.tls |  | long |
| suricata.eve.stats.app_layer.tx.dcerpc_tcp |  | long |
| suricata.eve.stats.app_layer.tx.dcerpc_udp |  | long |
| suricata.eve.stats.app_layer.tx.dns_tcp |  | long |
| suricata.eve.stats.app_layer.tx.dns_udp |  | long |
| suricata.eve.stats.app_layer.tx.ftp |  | long |
| suricata.eve.stats.app_layer.tx.http |  | long |
| suricata.eve.stats.app_layer.tx.smb |  | long |
| suricata.eve.stats.app_layer.tx.smtp |  | long |
| suricata.eve.stats.app_layer.tx.ssh |  | long |
| suricata.eve.stats.app_layer.tx.tls |  | long |
| suricata.eve.stats.capture.kernel_drops |  | long |
| suricata.eve.stats.capture.kernel_ifdrops |  | long |
| suricata.eve.stats.capture.kernel_packets |  | long |
| suricata.eve.stats.decoder.avg_pkt_size |  | long |
| suricata.eve.stats.decoder.bytes |  | long |
| suricata.eve.stats.decoder.dce.pkt_too_small |  | long |
| suricata.eve.stats.decoder.erspan |  | long |
| suricata.eve.stats.decoder.ethernet |  | long |
| suricata.eve.stats.decoder.gre |  | long |
| suricata.eve.stats.decoder.icmpv4 |  | long |
| suricata.eve.stats.decoder.icmpv6 |  | long |
| suricata.eve.stats.decoder.ieee8021ah |  | long |
| suricata.eve.stats.decoder.invalid |  | long |
| suricata.eve.stats.decoder.ipraw.invalid_ip_version |  | long |
| suricata.eve.stats.decoder.ipv4 |  | long |
| suricata.eve.stats.decoder.ipv4_in_ipv6 |  | long |
| suricata.eve.stats.decoder.ipv6 |  | long |
| suricata.eve.stats.decoder.ipv6_in_ipv6 |  | long |
| suricata.eve.stats.decoder.ltnull.pkt_too_small |  | long |
| suricata.eve.stats.decoder.ltnull.unsupported_type |  | long |
| suricata.eve.stats.decoder.max_pkt_size |  | long |
| suricata.eve.stats.decoder.mpls |  | long |
| suricata.eve.stats.decoder.null |  | long |
| suricata.eve.stats.decoder.pkts |  | long |
| suricata.eve.stats.decoder.ppp |  | long |
| suricata.eve.stats.decoder.pppoe |  | long |
| suricata.eve.stats.decoder.raw |  | long |
| suricata.eve.stats.decoder.sctp |  | long |
| suricata.eve.stats.decoder.sll |  | long |
| suricata.eve.stats.decoder.tcp |  | long |
| suricata.eve.stats.decoder.teredo |  | long |
| suricata.eve.stats.decoder.udp |  | long |
| suricata.eve.stats.decoder.vlan |  | long |
| suricata.eve.stats.decoder.vlan_qinq |  | long |
| suricata.eve.stats.defrag.ipv4.fragments |  | long |
| suricata.eve.stats.defrag.ipv4.reassembled |  | long |
| suricata.eve.stats.defrag.ipv4.timeouts |  | long |
| suricata.eve.stats.defrag.ipv6.fragments |  | long |
| suricata.eve.stats.defrag.ipv6.reassembled |  | long |
| suricata.eve.stats.defrag.ipv6.timeouts |  | long |
| suricata.eve.stats.defrag.max_frag_hits |  | long |
| suricata.eve.stats.detect.alert |  | long |
| suricata.eve.stats.dns.memcap_global |  | long |
| suricata.eve.stats.dns.memcap_state |  | long |
| suricata.eve.stats.dns.memuse |  | long |
| suricata.eve.stats.file_store.open_files |  | long |
| suricata.eve.stats.flow.emerg_mode_entered |  | long |
| suricata.eve.stats.flow.emerg_mode_over |  | long |
| suricata.eve.stats.flow.icmpv4 |  | long |
| suricata.eve.stats.flow.icmpv6 |  | long |
| suricata.eve.stats.flow.memcap |  | long |
| suricata.eve.stats.flow.memuse |  | long |
| suricata.eve.stats.flow.spare |  | long |
| suricata.eve.stats.flow.tcp |  | long |
| suricata.eve.stats.flow.tcp_reuse |  | long |
| suricata.eve.stats.flow.udp |  | long |
| suricata.eve.stats.flow_mgr.bypassed_pruned |  | long |
| suricata.eve.stats.flow_mgr.closed_pruned |  | long |
| suricata.eve.stats.flow_mgr.est_pruned |  | long |
| suricata.eve.stats.flow_mgr.flows_checked |  | long |
| suricata.eve.stats.flow_mgr.flows_notimeout |  | long |
| suricata.eve.stats.flow_mgr.flows_removed |  | long |
| suricata.eve.stats.flow_mgr.flows_timeout |  | long |
| suricata.eve.stats.flow_mgr.flows_timeout_inuse |  | long |
| suricata.eve.stats.flow_mgr.new_pruned |  | long |
| suricata.eve.stats.flow_mgr.rows_busy |  | long |
| suricata.eve.stats.flow_mgr.rows_checked |  | long |
| suricata.eve.stats.flow_mgr.rows_empty |  | long |
| suricata.eve.stats.flow_mgr.rows_maxlen |  | long |
| suricata.eve.stats.flow_mgr.rows_skipped |  | long |
| suricata.eve.stats.http.memcap |  | long |
| suricata.eve.stats.http.memuse |  | long |
| suricata.eve.stats.tcp.insert_data_normal_fail |  | long |
| suricata.eve.stats.tcp.insert_data_overlap_fail |  | long |
| suricata.eve.stats.tcp.insert_list_fail |  | long |
| suricata.eve.stats.tcp.invalid_checksum |  | long |
| suricata.eve.stats.tcp.memuse |  | long |
| suricata.eve.stats.tcp.no_flow |  | long |
| suricata.eve.stats.tcp.overlap |  | long |
| suricata.eve.stats.tcp.overlap_diff_data |  | long |
| suricata.eve.stats.tcp.pseudo |  | long |
| suricata.eve.stats.tcp.pseudo_failed |  | long |
| suricata.eve.stats.tcp.reassembly_gap |  | long |
| suricata.eve.stats.tcp.reassembly_memuse |  | long |
| suricata.eve.stats.tcp.rst |  | long |
| suricata.eve.stats.tcp.segment_memcap_drop |  | long |
| suricata.eve.stats.tcp.sessions |  | long |
| suricata.eve.stats.tcp.ssn_memcap_drop |  | long |
| suricata.eve.stats.tcp.stream_depth_reached |  | long |
| suricata.eve.stats.tcp.syn |  | long |
| suricata.eve.stats.tcp.synack |  | long |
| suricata.eve.stats.uptime |  | long |
| suricata.eve.tcp.ack |  | boolean |
| suricata.eve.tcp.fin |  | boolean |
| suricata.eve.tcp.psh |  | boolean |
| suricata.eve.tcp.rst |  | boolean |
| suricata.eve.tcp.state |  | keyword |
| suricata.eve.tcp.syn |  | boolean |
| suricata.eve.tcp.tcp_flags |  | keyword |
| suricata.eve.tcp.tcp_flags_tc |  | keyword |
| suricata.eve.tcp.tcp_flags_ts |  | keyword |
| suricata.eve.tls.fingerprint |  | keyword |
| suricata.eve.tls.issuerdn |  | keyword |
| suricata.eve.tls.ja3.hash |  | keyword |
| suricata.eve.tls.ja3.string |  | keyword |
| suricata.eve.tls.ja3s.hash |  | keyword |
| suricata.eve.tls.ja3s.string |  | keyword |
| suricata.eve.tls.notafter |  | date |
| suricata.eve.tls.notbefore |  | date |
| suricata.eve.tls.serial |  | keyword |
| suricata.eve.tls.session_resumed |  | boolean |
| suricata.eve.tls.sni |  | keyword |
| suricata.eve.tls.subject |  | keyword |
| suricata.eve.tls.version |  | keyword |
| suricata.eve.tx_id |  | long |
| tags | List of keywords used to tag each event. | keyword |
| tls.client.ja3 | A hash that identifies clients based on how they perform an SSL/TLS handshake. | keyword |
| tls.client.server_name | Hostname the client is trying to connect to. Also called the SNI. | keyword |
| tls.resumed | Boolean flag indicating if this TLS connection was resumed from an existing TLS negotiation. | boolean |
| tls.server.hash.sha1 | Certificate fingerprint using the SHA1 digest of DER-encoded version of certificate offered by the server. | keyword |
| tls.server.issuer | Subject of the issuer of the x.509 certificate presented by the server. | keyword |
| tls.server.ja3s | A hash that identifies servers based on how they perform an SSL/TLS handshake. | keyword |
| tls.server.not_after | Timestamp indicating when server certificate is no longer considered valid. | date |
| tls.server.not_before | Timestamp indicating when server certificate is first considered valid. | date |
| tls.server.subject | Subject of the x.509 certificate presented by the server. | keyword |
| tls.server.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.country | List of country (C) codes | keyword |
| tls.server.x509.issuer.locality | List of locality names (L) | keyword |
| tls.server.x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.server.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| tls.server.x509.not_before | Time at which the certificate is first considered valid. | date |
| tls.server.x509.serial_number | Unique serial number issued by the certificate authority. | keyword |
| tls.server.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| tls.server.x509.subject.country | List of country (C) code | keyword |
| tls.server.x509.subject.locality | List of locality names (L) | keyword |
| tls.server.x509.subject.organization | List of organizations (O) of subject. | keyword |
| tls.server.x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| tls.server.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | keyword |
| url.path | Path of the request, such as "/search". | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

