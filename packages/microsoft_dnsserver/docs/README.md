# Microsoft DNS Server Audit and Analytical logs

The Elastic integration for DNS Server logs is designed to facilitate the collection, aggregation, and analysis of DNS logs from both Audit and Analytical categories. By capturing detailed DNS event data, this integration enables organizations to enhance their visibility into DNS transactions, detect potential security threats, and optimize their network performance. Leveraging the powerful capabilities of Elastic Stack, this integration provides real-time insights and analytics, empowering IT and security teams to quickly respond to incidents and maintain robust network infrastructure integrity.

## Data streams

The Microsoft DNS Server integration collects two type of data: audit and analytical.

**Analytical** events represent the bulk of DNS events, an analytic event is logged each time the server sends or receives DNS information.

**Audit** events enable change tracking on the DNS server. An audit event is logged each time server, zone, or resource record settings are changed. This includes operational events such as dynamic updates, zone transfers, and DNSSEC zone signing and unsigning.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

This integration is supported in every Windows versions supported by [`Filebeat`](https://www.elastic.co/support/matrix), starting from Windows 10 and Windows Server 2016.

The minimum **kibana.version** required is **8.13.0**.

## Configuration
 
DNS analytical events are not enabled by default. To enable it, you can follow the [guide to enable DNS diagnostics logging](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v=ws.11)#to-enable-dns-diagnostic-logging) of Microsoft's documentation.

**Note:**  DNS logging and diagnostics feature in Windows is designed to have a very low impact on performance. However, according to the [Audit and analytic event logging section](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v=ws.11)#audit-and-analytic-event-logging) of the docs, typically will only affect DNS server performance at very high DNS query rates. For example, a DNS server running on modern hardware that is receiving 100,000 queries per second (QPS) can experience a performance degradation of 5% when analytic logs are enabled.

## Usage

**DNS Analytical** events are collected through [Event Tracing for Windows (ETW)](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-etw.html), a mechanism that allows real-time logging and capturing of Windows system events. This collection can be done either by initiating a new ETW session to gather logs directly from the DNS Server provider or by reading pre-existing logs from a .etl (Event Trace Log) file.

This integration provides a native filtering mechanism called `Match All Keyword`. This filter uses a 64-bit bitmask to specify which events to capture based on their defined keywords. Each keyword corresponds to a specific type of event detailed in the DNS Server provider's manifest.

To view these keywords and understand what types of events can be traced, you can run the following command in a command prompt: `logman query providers "Microsoft-Windows-DNSServer"`. Here is an example of the output:

```text
PS> logman query providers "Microsoft-Windows-DNSServer"

Provider                                 GUID
-------------------------------------------------------------------------------
Microsoft-Windows-DNSServer              {EB79061A-A566-4698-9119-3ED2807060E7}

Value               Keyword              Description
-------------------------------------------------------------------------------
0x0000000000000001  QUERY_RECEIVED
0x0000000000000002  RESPONSE_SUCCESS
0x0000000000000004  RESPONSE_FAILURE
0x0000000000000008  IGNORED_QUERY
0x0000000000000010  RECURSE_QUERY_OUT
0x0000000000000020  RECURSE_RESPONSE_IN
0x0000000000000040  RECURSE_QUERY_DROP
0x0000000000000080  DYN_UPDATE_RECV
0x0000000000000100  DYN_UPDATE_RESPONSE
0x0000000000000200  IXFR_REQ_OUT
0x0000000000000400  IXFR_REQ_RECV
0x0000000000000800  IXFR_RESP_OUT
0x0000000000001000  IXFR_RESP_RECV
0x0000000000002000  AXFR_REQ_OUT
0x0000000000004000  AXFR_REQ_RECV
0x0000000000008000  AXFR_RESP_OUT
0x0000000000010000  AXFR_RESP_RECV
0x0000000000020000  XFR_NOTIFY_IN
0x0000000000040000  XFR_NOTIFY_OUT
0x0000000000080000  AUDIT_ZONES
0x0000000000100000  AUDIT_REC_ADMIN
0x0000000000200000  AUDIT_ZONESCOPE
0x0000000000400000  AUDIT_ZONE_SIGN
0x0000000000800000  AUDIT_ROLLOVER
0x0000000001000000  AUDIT_FORWARDER
0x0000000002000000  AUDIT_REC_DYN_UPDATE
0x0000000004000000  AUDIT_ROOTHINTS
0x0000000008000000  AUDIT_SERVER_CONFIG
0x0000000010000000  AUDIT_RECURSIONSCOPE
0x0000000020000000  AUDIT_EXPORT_IMPORT
0x0000000040000000  AUDIT_REC_SCAVENGER
0x0000000080000000  AUDIT_CACHE
0x0000000100000000  AUDIT_TRUST_ANCHOR
0x0000000200000000  XFR_NOTIFY_ACK_IN
0x0000000400000000  DYN_UPDATE_FORWARD
0x0000000800000000  INTERNAL_LOOKUP_CNAME
0x0000001000000000  INTERNAL_LOOKUP_ADDITIONAL
0x0000002000000000  AUDIT_SERVER_ADMIN
0x0000004000000000  AUDIT_SERVER
0x0000008000000000  DYN_UPDATE_RESPONSE_IN
0x0000010000000000  XFR_NOTIFY_ACK_OUT
0x0000020000000000  AUDIT_POLICY
0x0000040000000000  RRL_TO_BE_DROPPED_RESPONSE
0x0000080000000000  RRL_TO_BE_TRUNCATED_RESPONSE
0x0000100000000000  RRL_TO_BE_LEAKED_RESPONSE
0x0000200000000000  AUDIT_RRL
0x0000400000000000  AUDIT_TENANT
0x0000800000000000  RECURSE_ALIAS_FAILURE
0x8000000000000000  Microsoft-Windows-DNSServer/Analytical Microsoft-Windows-DNS-Server/Analytical
0x4000000000000000  Microsoft-Windows-DNSServer/Audit Microsoft-Windows-DNS-Server/Audit

Value               Level                Description
-------------------------------------------------------------------------------
0x02                win:Error            Error
0x03                win:Warning          Warning
0x04                win:Informational    Information

PID                 Image
-------------------------------------------------------------------------------
0x00000354          C:\Windows\System32\dns.exe
0x00000354          C:\Windows\System32\dns.exe


The command completed successfully.
```

The output lists various event types with corresponding keywords, allowing you to select which events to monitor. For example, if you want to track recursive queries, you would look for keywords like `RECURSE_QUERY_OUT`, `RECURSE_RESPONSE_IN`, and `RECURSE_QUERY_DROP`. To set up filtering for these specific events, you would calculate the sum of their bitmask values. The result for this particular case would be `0x8000000000000070` (notice that it includes `0x8000000000000000` to match Analytical events as well).

On the other hand, **Audit** events are exposed through Microsoft-Windows-DNS-Server/Audit event log channel.

## Logs reference

### Analytical

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
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
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
| destination.port | Port of the destination. | long |
| dns.header_flags | Array of 2 letter DNS header flags. | keyword |
| dns.id | The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.response_code | The DNS response code. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
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
| input.type | Input type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| microsoft_dnsserver.analytical.additional_info | Any additional information relevant to the event. | keyword |
| microsoft_dnsserver.analytical.bytes_sent | The number of bytes sent in the DNS response. | long |
| microsoft_dnsserver.analytical.cache_scope | Indicates whether the DNS data came from a cache and the scope of that cache. | keyword |
| microsoft_dnsserver.analytical.description | A textual description of the event. | keyword |
| microsoft_dnsserver.analytical.destination.ip | The IP address of the destination where the DNS query is sent or the response is received. | ip |
| microsoft_dnsserver.analytical.destination.port | The network port on the destination host used in the DNS transaction. | long |
| microsoft_dnsserver.analytical.dnssec | Indicates whether DNSSEC (DNS Security Extensions) was used in the DNS transaction. | keyword |
| microsoft_dnsserver.analytical.elapsed_time | The time taken to process the DNS query or transaction. | keyword |
| microsoft_dnsserver.analytical.forward_interface_ip | The IP address of the network interface used to forward DNS queries to an upstream server. | ip |
| microsoft_dnsserver.analytical.guid | A globally unique identifier associated with the event. | keyword |
| microsoft_dnsserver.analytical.interface_ip | The IP address of the network interface on the DNS server that handled the transaction. | keyword |
| microsoft_dnsserver.analytical.keywords | Keywords associated with the event, useful for categorizing or filtering. | keyword |
| microsoft_dnsserver.analytical.packet_data | The raw data of the DNS packet. | keyword |
| microsoft_dnsserver.analytical.policy_name | The name of any policy that influenced the handling of the DNS query or response. | keyword |
| microsoft_dnsserver.analytical.queries_attached | Number of queries that are associated with a particular event or transaction within the DNS server. | keyword |
| microsoft_dnsserver.analytical.question_name | The domain name queried in the DNS request. | keyword |
| microsoft_dnsserver.analytical.question_type | The type of DNS query, e.g., A, AAAA, MX, etc. | keyword |
| microsoft_dnsserver.analytical.qxid | The query transaction identifier. | keyword |
| microsoft_dnsserver.analytical.reason | The reason for any actions taken during the DNS transaction. | keyword |
| microsoft_dnsserver.analytical.recursion_depth | The depth of the recursion used in resolving the DNS query. | keyword |
| microsoft_dnsserver.analytical.recursion_scope | Indicates the scope of recursion allowed in the DNS query handling. | keyword |
| microsoft_dnsserver.analytical.response_code | The DNS response code, such as NOERROR, NXDOMAIN, etc. | keyword |
| microsoft_dnsserver.analytical.scope | General scope of the log or event, potentially indicating the context or breadth of impact. | keyword |
| microsoft_dnsserver.analytical.secure | Indicates whether the transaction was conducted over a secure channel. | keyword |
| microsoft_dnsserver.analytical.source.ip | The IP address of the source from which the DNS query originated. | ip |
| microsoft_dnsserver.analytical.source.port | The network port on the source host used in the DNS transaction. | long |
| microsoft_dnsserver.analytical.xid | The transaction identifier for the DNS request. | keyword |
| microsoft_dnsserver.analytical.zone | The DNS zone that is the subject of the query or affected by the event. | keyword |
| microsoft_dnsserver.analytical.zone_scope | Specifies the scope of the DNS zone involved in the event. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| related.ip | All of the IPs seen on your event. | ip |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
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
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| winlog.activity_id | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. | keyword |
| winlog.channel | Used to enable special event processing. Channel values below 16 are reserved for use by Microsoft to enable special treatment by the ETW runtime. Channel values 16 and above will be ignored by the ETW runtime (treated the same as channel 0) and can be given user-defined semantics. | keyword |
| winlog.flags | Flags that provide information about the event such as the type of session it was logged to and if the event contains extended data. | keyword |
| winlog.keywords | The keywords are used to classify an event. | keyword |
| winlog.opcode | Code used to mark events with special semantics. Internal ETW metadata. | keyword |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.session | Configured session to forward ETW events from providers to consumers. | keyword |
| winlog.task | A categorical identifier for the type of task performed during the event. | keyword |
| winlog.version | Specify the version of a manifest-based event. | long |


### Audit

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
| dns.answers.ttl | The time interval in seconds that this resource record may be cached before it should be discarded. Zero values mean that the data should not be cached. | long |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.type | The type of record being queried. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
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
| input.type | Input type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| microsoft_dnsserver.audit.action |  | keyword |
| microsoft_dnsserver.audit.active_key |  | keyword |
| microsoft_dnsserver.audit.base64_data |  | keyword |
| microsoft_dnsserver.audit.bytes_sent |  | keyword |
| microsoft_dnsserver.audit.child_zone |  | keyword |
| microsoft_dnsserver.audit.client_subnet_list |  | keyword |
| microsoft_dnsserver.audit.client_subnet_record |  | keyword |
| microsoft_dnsserver.audit.condition |  | keyword |
| microsoft_dnsserver.audit.criteria |  | keyword |
| microsoft_dnsserver.audit.crypto_algorithm |  | keyword |
| microsoft_dnsserver.audit.current_rollover_status |  | keyword |
| microsoft_dnsserver.audit.current_state |  | keyword |
| microsoft_dnsserver.audit.denial_of_existence |  | keyword |
| microsoft_dnsserver.audit.digest |  | keyword |
| microsoft_dnsserver.audit.digest_type |  | keyword |
| microsoft_dnsserver.audit.distribute_trust_anchor |  | keyword |
| microsoft_dnsserver.audit.ds_record_generation_algorithm |  | keyword |
| microsoft_dnsserver.audit.ds_record_set_ttl |  | keyword |
| microsoft_dnsserver.audit.ds_signature_validity_periodzx |  | keyword |
| microsoft_dnsserver.audit.enable_rfc_5011_key_rollover |  | keyword |
| microsoft_dnsserver.audit.errors_per_second |  | keyword |
| microsoft_dnsserver.audit.event_string |  | keyword |
| microsoft_dnsserver.audit.file_path |  | keyword |
| microsoft_dnsserver.audit.forwarders |  | keyword |
| microsoft_dnsserver.audit.friendly_name |  | keyword |
| microsoft_dnsserver.audit.guid |  | keyword |
| microsoft_dnsserver.audit.initial_rollover_offset |  | keyword |
| microsoft_dnsserver.audit.ipv4_prefix_length |  | keyword |
| microsoft_dnsserver.audit.ipv6_prefix_length |  | keyword |
| microsoft_dnsserver.audit.is_enabled |  | keyword |
| microsoft_dnsserver.audit.is_key_master_server |  | keyword |
| microsoft_dnsserver.audit.key_id |  | keyword |
| microsoft_dnsserver.audit.key_length |  | keyword |
| microsoft_dnsserver.audit.key_master_server |  | keyword |
| microsoft_dnsserver.audit.key_or_zone |  | keyword |
| microsoft_dnsserver.audit.key_protocol |  | keyword |
| microsoft_dnsserver.audit.key_record_set_ttl |  | keyword |
| microsoft_dnsserver.audit.key_signature_validity_period |  | keyword |
| microsoft_dnsserver.audit.key_storage_provider |  | keyword |
| microsoft_dnsserver.audit.key_tag |  | keyword |
| microsoft_dnsserver.audit.key_type |  | keyword |
| microsoft_dnsserver.audit.ksk_or_zsk |  | keyword |
| microsoft_dnsserver.audit.last_rollover_time |  | keyword |
| microsoft_dnsserver.audit.leak_rate |  | keyword |
| microsoft_dnsserver.audit.listen_addresses |  | keyword |
| microsoft_dnsserver.audit.master_server |  | keyword |
| microsoft_dnsserver.audit.mode |  | keyword |
| microsoft_dnsserver.audit.name |  | keyword |
| microsoft_dnsserver.audit.name_server |  | keyword |
| microsoft_dnsserver.audit.new_friendly_name |  | keyword |
| microsoft_dnsserver.audit.new_property_values |  | keyword |
| microsoft_dnsserver.audit.new_scope |  | keyword |
| microsoft_dnsserver.audit.new_value |  | keyword |
| microsoft_dnsserver.audit.next_key |  | keyword |
| microsoft_dnsserver.audit.next_rollover_action |  | keyword |
| microsoft_dnsserver.audit.next_rollover_time |  | keyword |
| microsoft_dnsserver.audit.node_name |  | keyword |
| microsoft_dnsserver.audit.nsec3_hash_algorithm |  | keyword |
| microsoft_dnsserver.audit.nsec3_iterations |  | keyword |
| microsoft_dnsserver.audit.nsec3_opt_out |  | keyword |
| microsoft_dnsserver.audit.nsec3_random_salt_length |  | keyword |
| microsoft_dnsserver.audit.nsec3_user_salt |  | keyword |
| microsoft_dnsserver.audit.old_friendly_name |  | keyword |
| microsoft_dnsserver.audit.old_property_values |  | keyword |
| microsoft_dnsserver.audit.old_scope |  | keyword |
| microsoft_dnsserver.audit.parent_has_secure_delegation |  | keyword |
| microsoft_dnsserver.audit.policy |  | keyword |
| microsoft_dnsserver.audit.processing_order |  | keyword |
| microsoft_dnsserver.audit.propagation_time |  | keyword |
| microsoft_dnsserver.audit.property_key |  | keyword |
| microsoft_dnsserver.audit.question_name |  | keyword |
| microsoft_dnsserver.audit.question_type |  | keyword |
| microsoft_dnsserver.audit.recursion_scope |  | keyword |
| microsoft_dnsserver.audit.resolved_data |  | keyword |
| microsoft_dnsserver.audit.response_per_second |  | keyword |
| microsoft_dnsserver.audit.rollover_period |  | keyword |
| microsoft_dnsserver.audit.rollover_type |  | keyword |
| microsoft_dnsserver.audit.rrl_exception_list |  | keyword |
| microsoft_dnsserver.audit.scavenge_servers |  | keyword |
| microsoft_dnsserver.audit.scope |  | keyword |
| microsoft_dnsserver.audit.scope_weight |  | keyword |
| microsoft_dnsserver.audit.scope_weight_new |  | keyword |
| microsoft_dnsserver.audit.scope_weight_old |  | keyword |
| microsoft_dnsserver.audit.scopes |  | keyword |
| microsoft_dnsserver.audit.secure_delegation_polling_period |  | keyword |
| microsoft_dnsserver.audit.seized_or_transfered |  | keyword |
| microsoft_dnsserver.audit.setting |  | keyword |
| microsoft_dnsserver.audit.signature_inception_offset |  | keyword |
| microsoft_dnsserver.audit.source_ip |  | ip |
| microsoft_dnsserver.audit.standby_key |  | keyword |
| microsoft_dnsserver.audit.store_keys_in_AD |  | keyword |
| microsoft_dnsserver.audit.subtree_aging |  | keyword |
| microsoft_dnsserver.audit.tc_rate |  | keyword |
| microsoft_dnsserver.audit.total_responses_in_window |  | keyword |
| microsoft_dnsserver.audit.ttl |  | long |
| microsoft_dnsserver.audit.type |  | keyword |
| microsoft_dnsserver.audit.virtualization_id |  | keyword |
| microsoft_dnsserver.audit.window_size |  | keyword |
| microsoft_dnsserver.audit.with_new_keys |  | keyword |
| microsoft_dnsserver.audit.with_without |  | keyword |
| microsoft_dnsserver.audit.zone |  | keyword |
| microsoft_dnsserver.audit.zone_scope |  | keyword |
| microsoft_dnsserver.audit.zone_signature_validity_period |  | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
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
| tags | List of keywords used to tag each event. | keyword |
| winlog.activity_id | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. | keyword |
| winlog.api | The event log API type used to read the record. The possible values are "wineventlog" for the Windows Event Log API or "eventlogging" for the Event Logging API. The Event Logging API was designed for Windows Server 2003 or Windows 2000 operating systems. In Windows Vista, the event logging infrastructure was redesigned. On Windows Vista or later operating systems, the Windows Event Log API is used. Winlogbeat automatically detects which API to use for reading event logs. | keyword |
| winlog.channel | The name of the channel from which this record was read. This value is one of the names from the `event_logs` collection in the configuration. | keyword |
| winlog.computer_name | The name of the computer that generated the record. When using Windows event forwarding, this name can differ from `agent.hostname`. | keyword |
| winlog.event_id | The event identifier. The value is specific to the source of the event. | keyword |
| winlog.flags | Flags that provide information about the event such as the type of session it was logged to and if the event contains extended data. | keyword |
| winlog.keywords | The keywords are used to classify an event. | keyword |
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.task | A categorical identifier for the type of task performed during the event. | keyword |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | The security identifier (SID) of the account associated with this event. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.version | The version number of the event's definition. | long |

