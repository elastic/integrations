# Netflow Integration

This integration is for receiving NetFlow and IPFIX flow records over UDP. It
supports NetFlow versions 1, 5, 6, 7, 8 and 9, as well as IPFIX. For NetFlow 
versions older than 9, fields are mapped automatically to NetFlow v9.

It includes the following dataset:

- `log` dataset

## Compatibility

## Logs

### log

The `log` dataset collects netflow logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. If no name is given, the name is often left empty. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
| as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| as.organization.name | Organization name. | keyword |
| as.organization.name.text | Multi-field of `as.organization.name`. | match_only_text |
| client.address | Some event client addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| client.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| client.as.organization.name | Organization name. | keyword |
| client.as.organization.name.text | Multi-field of `client.as.organization.name`. | match_only_text |
| client.bytes | Bytes sent from the client to the server. | long |
| client.domain | The domain name of the client system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| client.geo.city_name | City name. | keyword |
| client.geo.continent_name | Name of the continent. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| client.geo.region_iso_code | Region ISO code. | keyword |
| client.geo.region_name | Region name. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| client.mac | MAC address of the client. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| client.nat.ip | Translated IP of source based NAT sessions (e.g. internal client to internet). Typically connections traversing load balancers, firewalls, or routers. | ip |
| client.nat.port | Translated port of source based NAT sessions (e.g. internal client to internet). Typically connections traversing load balancers, firewalls, or routers. | long |
| client.packets | Packets sent from the client to the server. | long |
| client.port | Port of the client. | long |
| client.registered_domain | The highest registered client domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| client.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| client.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| client.user.email | User email address. | keyword |
| client.user.full_name | User's full name, if available. | keyword |
| client.user.full_name.text | Multi-field of `client.user.full_name`. | match_only_text |
| client.user.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| client.user.group.id | Unique identifier for the group on the system/platform. | keyword |
| client.user.group.name | Name of the group. | keyword |
| client.user.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| client.user.id | Unique identifier of the user. | keyword |
| client.user.name | Short name or login of the user. | keyword |
| client.user.name.text | Multi-field of `client.user.name`. | match_only_text |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.image.tag | Container image tags. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
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
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.locality | Whether the destination IP is private or public. | keyword |
| destination.mac | MAC address of the destination. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| destination.registered_domain | The highest registered destination domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| destination.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| destination.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| destination.user.email | User email address. | keyword |
| destination.user.full_name | User's full name, if available. | keyword |
| destination.user.full_name.text | Multi-field of `destination.user.full_name`. | match_only_text |
| destination.user.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| destination.user.group.id | Unique identifier for the group on the system/platform. | keyword |
| destination.user.group.name | Name of the group. | keyword |
| destination.user.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| dns.answers | An array containing an object for each answer section returned by the server. The main keys that should be present in these objects are defined by ECS. Records that have more information may contain more keys than what ECS defines. Not all DNS data sources give all details about DNS answers. At minimum, answer objects must contain the `data` key. If more information is available, map as much of it to ECS as possible, and add any additional fields to the answer objects as custom fields. | object |
| dns.answers.class | The class of DNS data contained in this resource record. | keyword |
| dns.answers.data | The data describing the resource. The meaning of this data depends on the type and class of the resource record. | keyword |
| dns.answers.name | The domain name to which this resource record pertains. If a chain of CNAME is being resolved, each answer's `name` should be the one that corresponds with the answer's `data`. It should not simply be the original `question.name` repeated. | keyword |
| dns.answers.ttl | The time interval in seconds that this resource record may be cached before it should be discarded. Zero values mean that the data should not be cached. | long |
| dns.answers.type | The type of data contained in this resource record. | keyword |
| dns.header_flags | Array of 2 letter DNS header flags. Expected values are: AA, TC, RD, RA, AD, CD, DO. | keyword |
| dns.id | The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response. | keyword |
| dns.op_code | The DNS operation code that specifies the kind of query in the message. This value is set by the originator of a query and copied into the response. | keyword |
| dns.question.class | The class of records being queried. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.resolved_ip | Array containing all IPs seen in `answers.data`. The `answers` array can be difficult to use, because of the variety of data formats it can contain. Extracting all IP addresses seen in there to `dns.resolved_ip` makes it possible to index them as IP addresses, and makes them easier to visualize and query for. | ip |
| dns.response_code | The DNS response code. | keyword |
| dns.type | The type of DNS event captured, query or answer. If your source of DNS events only gives you DNS queries, you should only create dns events of type `dns.type:query`. If your source of DNS events gives you answers as well, you should create one event per query (optionally as soon as the query is seen). And a second event containing all query details as well as an array of answers. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.id | Unique identifier for the error. | keyword |
| error.message | Error message. | match_only_text |
| error.stack_trace | The stack trace of this error in plain text. | wildcard |
| error.stack_trace.text | Multi-field of `error.stack_trace`. | match_only_text |
| error.type | The type of the error, for example the class name of the exception. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.hash | Hash (perhaps logstash fingerprint) of raw field to be able to demonstrate log integrity. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.risk_score_norm | Normalized risk score or priority of the event, on a scale of 0 to 100. This is mainly useful if you use more than one system that assigns risk scores, and you want to see a normalized value across all systems. | float |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.accessed | Last time the file was accessed. Note that not all filesystems keep track of access time. | date |
| file.created | File creation time. Note that not all filesystems store the creation time. | date |
| file.ctime | Last time the file attributes or metadata changed. Note that changes to the file content will update `mtime`. This implies `ctime` will be adjusted at the same time, since `mtime` is an attribute of the file. | date |
| file.device | Device that is the source of the file. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.gid | Primary group ID (GID) of the file. | keyword |
| file.group | Primary group name of the file. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.hash.sha512 | SHA512 hash. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.mode | Mode of the file in octal representation. | keyword |
| file.mtime | Last time the file content was modified. | date |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.owner | File owner's username. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.target_path | Target path for symlinks. | keyword |
| file.target_path.text | Multi-field of `file.target_path`. | match_only_text |
| file.type | File type (file, dir, or symlink). | keyword |
| file.uid | The user ID (UID) or security identifier (SID) of the file owner. | keyword |
| flow.id | Hash of source and destination IPs. | keyword |
| flow.locality | Identifies whether the flow involved public IP addresses or only private address. | keyword |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.country_name | Country name. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| geo.region_iso_code | Region ISO code. | keyword |
| geo.region_name | Region name. | keyword |
| group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| hash.md5 | MD5 hash. | keyword |
| hash.sha1 | SHA1 hash. | keyword |
| hash.sha256 | SHA256 hash. | keyword |
| hash.sha512 | SHA512 hash. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.geo.city_name | City name. | keyword |
| host.geo.continent_name | Name of the continent. | keyword |
| host.geo.country_iso_code | Country ISO code. | keyword |
| host.geo.country_name | Country name. | keyword |
| host.geo.location | Longitude and latitude. | geo_point |
| host.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| host.geo.region_iso_code | Region ISO code. | keyword |
| host.geo.region_name | Region name. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.full | Operating system name, including the version or code name. | keyword |
| host.os.full.text | Multi-field of `host.os.full`. | match_only_text |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| host.uptime | Seconds the host has been up. | long |
| http.request.body.bytes | Size in bytes of the request body. | long |
| http.request.body.content | The full HTTP request body. | wildcard |
| http.request.body.content.text | Multi-field of `http.request.body.content`. | match_only_text |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.body.content | The full HTTP response body. | wildcard |
| http.response.body.content.text | Multi-field of `http.response.body.content`. | match_only_text |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.origin.file.line | The line number of the file containing the source code which originated the log event. | long |
| log.origin.file.name | The name of the file containing the source code which originated the log event. Note that this field is not meant to capture the log file. The correct field to capture the log file is `log.file.path`. | keyword |
| log.origin.function | The name of the function or method which originated the log event. | keyword |
| log.syslog | The Syslog metadata of the event, if the event was transmitted via Syslog. Please see RFCs 5424 or 3164. | object |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.facility.name | The Syslog text-based facility of the log event, if available. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| log.syslog.severity.name | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different severity value (e.g. firewall, IDS), your source's text severity should go to `log.level`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `log.level`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| netflow.absolute_error |  | double |
| netflow.address_pool_high_threshold |  | long |
| netflow.address_pool_low_threshold |  | long |
| netflow.address_port_mapping_high_threshold |  | long |
| netflow.address_port_mapping_low_threshold |  | long |
| netflow.address_port_mapping_per_user_high_threshold |  | long |
| netflow.afc_protocol |  | integer |
| netflow.afc_protocol_name |  | keyword |
| netflow.anonymization_flags |  | integer |
| netflow.anonymization_technique |  | integer |
| netflow.application_business-relevance |  | long |
| netflow.application_category_name |  | keyword |
| netflow.application_description |  | keyword |
| netflow.application_group_name |  | keyword |
| netflow.application_http_uri_statistics |  | short |
| netflow.application_http_user-agent |  | short |
| netflow.application_id |  | short |
| netflow.application_name |  | keyword |
| netflow.application_sub_category_name |  | keyword |
| netflow.application_traffic-class |  | long |
| netflow.art_client_network_time_maximum |  | long |
| netflow.art_client_network_time_minimum |  | long |
| netflow.art_client_network_time_sum |  | long |
| netflow.art_clientpackets |  | long |
| netflow.art_count_late_responses |  | long |
| netflow.art_count_new_connections |  | long |
| netflow.art_count_responses |  | long |
| netflow.art_count_responses_histogram_bucket1 |  | long |
| netflow.art_count_responses_histogram_bucket2 |  | long |
| netflow.art_count_responses_histogram_bucket3 |  | long |
| netflow.art_count_responses_histogram_bucket4 |  | long |
| netflow.art_count_responses_histogram_bucket5 |  | long |
| netflow.art_count_responses_histogram_bucket6 |  | long |
| netflow.art_count_responses_histogram_bucket7 |  | long |
| netflow.art_count_retransmissions |  | long |
| netflow.art_count_transactions |  | long |
| netflow.art_network_time_maximum |  | long |
| netflow.art_network_time_minimum |  | long |
| netflow.art_network_time_sum |  | long |
| netflow.art_response_time_maximum |  | long |
| netflow.art_response_time_minimum |  | long |
| netflow.art_response_time_sum |  | long |
| netflow.art_server_network_time_maximum |  | long |
| netflow.art_server_network_time_minimum |  | long |
| netflow.art_server_network_time_sum |  | long |
| netflow.art_server_response_time_maximum |  | long |
| netflow.art_server_response_time_minimum |  | long |
| netflow.art_server_response_time_sum |  | long |
| netflow.art_serverpackets |  | long |
| netflow.art_total_response_time_maximum |  | long |
| netflow.art_total_response_time_minimum |  | long |
| netflow.art_total_response_time_sum |  | long |
| netflow.art_total_transaction_time_maximum |  | long |
| netflow.art_total_transaction_time_minimum |  | long |
| netflow.art_total_transaction_time_sum |  | long |
| netflow.assembled_fragment_count |  | long |
| netflow.audit_counter |  | long |
| netflow.average_interarrival_time |  | long |
| netflow.bgp_destination_as_number |  | long |
| netflow.bgp_next_adjacent_as_number |  | long |
| netflow.bgp_next_hop_ipv4_address |  | ip |
| netflow.bgp_next_hop_ipv6_address |  | ip |
| netflow.bgp_prev_adjacent_as_number |  | long |
| netflow.bgp_source_as_number |  | long |
| netflow.bgp_validity_state |  | short |
| netflow.biflow_direction |  | short |
| netflow.bind_ipv4_address |  | ip |
| netflow.bind_transport_port |  | integer |
| netflow.class_id |  | long |
| netflow.class_name |  | keyword |
| netflow.classification_engine_id |  | short |
| netflow.collection_time_milliseconds |  | date |
| netflow.collector_certificate |  | short |
| netflow.collector_ipv4_address |  | ip |
| netflow.collector_ipv6_address |  | ip |
| netflow.collector_transport_port |  | integer |
| netflow.common_properties_id |  | long |
| netflow.confidence_level |  | double |
| netflow.conn_ipv4_address |  | ip |
| netflow.conn_transport_port |  | integer |
| netflow.connection_sum_duration_seconds |  | long |
| netflow.connection_transaction_id |  | long |
| netflow.conntrack_id |  | long |
| netflow.data_byte_count |  | long |
| netflow.data_link_frame_section |  | short |
| netflow.data_link_frame_size |  | integer |
| netflow.data_link_frame_type |  | integer |
| netflow.data_records_reliability |  | boolean |
| netflow.delta_flow_count |  | long |
| netflow.destination_ipv4_address |  | ip |
| netflow.destination_ipv4_prefix |  | ip |
| netflow.destination_ipv4_prefix_length |  | short |
| netflow.destination_ipv6_address |  | ip |
| netflow.destination_ipv6_prefix |  | ip |
| netflow.destination_ipv6_prefix_length |  | short |
| netflow.destination_mac_address |  | keyword |
| netflow.destination_transport_port |  | integer |
| netflow.digest_hash_value |  | long |
| netflow.distinct_count_of_destination_ip_address |  | long |
| netflow.distinct_count_of_destination_ipv4_address |  | long |
| netflow.distinct_count_of_destination_ipv6_address |  | long |
| netflow.distinct_count_of_source_ip_address |  | long |
| netflow.distinct_count_of_source_ipv4_address |  | long |
| netflow.distinct_count_of_source_ipv6_address |  | long |
| netflow.dns_authoritative |  | short |
| netflow.dns_cname |  | keyword |
| netflow.dns_id |  | integer |
| netflow.dns_mx_exchange |  | keyword |
| netflow.dns_mx_preference |  | integer |
| netflow.dns_nsd_name |  | keyword |
| netflow.dns_nx_domain |  | short |
| netflow.dns_ptrd_name |  | keyword |
| netflow.dns_qname |  | keyword |
| netflow.dns_qr_type |  | integer |
| netflow.dns_query_response |  | short |
| netflow.dns_rr_section |  | short |
| netflow.dns_soa_expire |  | long |
| netflow.dns_soa_minimum |  | long |
| netflow.dns_soa_refresh |  | long |
| netflow.dns_soa_retry |  | long |
| netflow.dns_soa_serial |  | long |
| netflow.dns_soam_name |  | keyword |
| netflow.dns_soar_name |  | keyword |
| netflow.dns_srv_port |  | integer |
| netflow.dns_srv_priority |  | integer |
| netflow.dns_srv_target |  | integer |
| netflow.dns_srv_weight |  | integer |
| netflow.dns_ttl |  | long |
| netflow.dns_txt_data |  | keyword |
| netflow.dot1q_customer_dei |  | boolean |
| netflow.dot1q_customer_destination_mac_address |  | keyword |
| netflow.dot1q_customer_priority |  | short |
| netflow.dot1q_customer_source_mac_address |  | keyword |
| netflow.dot1q_customer_vlan_id |  | integer |
| netflow.dot1q_dei |  | boolean |
| netflow.dot1q_priority |  | short |
| netflow.dot1q_service_instance_id |  | long |
| netflow.dot1q_service_instance_priority |  | short |
| netflow.dot1q_service_instance_tag |  | short |
| netflow.dot1q_vlan_id |  | integer |
| netflow.dropped_layer2_octet_delta_count |  | long |
| netflow.dropped_layer2_octet_total_count |  | long |
| netflow.dropped_octet_delta_count |  | long |
| netflow.dropped_octet_total_count |  | long |
| netflow.dropped_packet_delta_count |  | long |
| netflow.dropped_packet_total_count |  | long |
| netflow.dst_traffic_index |  | long |
| netflow.egress_broadcast_packet_total_count |  | long |
| netflow.egress_interface |  | long |
| netflow.egress_interface_type |  | long |
| netflow.egress_physical_interface |  | long |
| netflow.egress_unicast_packet_total_count |  | long |
| netflow.egress_vrfid |  | long |
| netflow.encrypted_technology |  | keyword |
| netflow.engine_id |  | short |
| netflow.engine_type |  | short |
| netflow.ethernet_header_length |  | short |
| netflow.ethernet_payload_length |  | integer |
| netflow.ethernet_total_length |  | integer |
| netflow.ethernet_type |  | integer |
| netflow.expired_fragment_count |  | long |
| netflow.export_interface |  | long |
| netflow.export_protocol_version |  | short |
| netflow.export_sctp_stream_id |  | integer |
| netflow.export_transport_protocol |  | short |
| netflow.exported_flow_record_total_count |  | long |
| netflow.exported_message_total_count |  | long |
| netflow.exported_octet_total_count |  | long |
| netflow.exporter.address | Exporter's network address in IP:port format. | keyword |
| netflow.exporter.source_id | Observation domain ID to which this record belongs. | long |
| netflow.exporter.timestamp | Time and date of export. | date |
| netflow.exporter.uptime_millis | How long the exporter process has been running, in milliseconds. | long |
| netflow.exporter.version | NetFlow version used. | integer |
| netflow.exporter_certificate |  | short |
| netflow.exporter_ipv4_address |  | ip |
| netflow.exporter_ipv6_address |  | ip |
| netflow.exporter_transport_port |  | integer |
| netflow.exporting_process_id |  | long |
| netflow.external_address_realm |  | short |
| netflow.firewall_event |  | short |
| netflow.first_eight_non_empty_packet_directions |  | short |
| netflow.first_non_empty_packet_size |  | integer |
| netflow.first_packet_banner |  | keyword |
| netflow.flags_and_sampler_id |  | long |
| netflow.flow_active_timeout |  | integer |
| netflow.flow_attributes |  | integer |
| netflow.flow_direction |  | short |
| netflow.flow_duration_microseconds |  | long |
| netflow.flow_duration_milliseconds |  | long |
| netflow.flow_end_delta_microseconds |  | long |
| netflow.flow_end_microseconds |  | date |
| netflow.flow_end_milliseconds |  | date |
| netflow.flow_end_nanoseconds |  | date |
| netflow.flow_end_reason |  | short |
| netflow.flow_end_seconds |  | date |
| netflow.flow_end_sys_up_time |  | long |
| netflow.flow_id |  | long |
| netflow.flow_idle_timeout |  | integer |
| netflow.flow_key_indicator |  | long |
| netflow.flow_label_ipv6 |  | long |
| netflow.flow_sampling_time_interval |  | long |
| netflow.flow_sampling_time_spacing |  | long |
| netflow.flow_selected_flow_delta_count |  | long |
| netflow.flow_selected_octet_delta_count |  | long |
| netflow.flow_selected_packet_delta_count |  | long |
| netflow.flow_selector_algorithm |  | integer |
| netflow.flow_start_delta_microseconds |  | long |
| netflow.flow_start_microseconds |  | date |
| netflow.flow_start_milliseconds |  | date |
| netflow.flow_start_nanoseconds |  | date |
| netflow.flow_start_seconds |  | date |
| netflow.flow_start_sys_up_time |  | long |
| netflow.flow_table_flush_event_count |  | long |
| netflow.flow_table_peak_count |  | long |
| netflow.forwarding_status |  | short |
| netflow.fragment_flags |  | short |
| netflow.fragment_identification |  | long |
| netflow.fragment_offset |  | integer |
| netflow.fw_blackout_secs |  | long |
| netflow.fw_configured_value |  | long |
| netflow.fw_cts_src_sgt |  | long |
| netflow.fw_event_level |  | long |
| netflow.fw_event_level_id |  | long |
| netflow.fw_ext_event |  | integer |
| netflow.fw_ext_event_alt |  | long |
| netflow.fw_ext_event_desc |  | keyword |
| netflow.fw_half_open_count |  | long |
| netflow.fw_half_open_high |  | long |
| netflow.fw_half_open_rate |  | long |
| netflow.fw_max_sessions |  | long |
| netflow.fw_rule |  | keyword |
| netflow.fw_summary_pkt_count |  | long |
| netflow.fw_zone_pair_id |  | long |
| netflow.fw_zone_pair_name |  | long |
| netflow.global_address_mapping_high_threshold |  | long |
| netflow.gre_key |  | long |
| netflow.hash_digest_output |  | boolean |
| netflow.hash_flow_domain |  | integer |
| netflow.hash_initialiser_value |  | long |
| netflow.hash_ip_payload_offset |  | long |
| netflow.hash_ip_payload_size |  | long |
| netflow.hash_output_range_max |  | long |
| netflow.hash_output_range_min |  | long |
| netflow.hash_selected_range_max |  | long |
| netflow.hash_selected_range_min |  | long |
| netflow.http_content_type |  | keyword |
| netflow.http_message_version |  | keyword |
| netflow.http_reason_phrase |  | keyword |
| netflow.http_request_host |  | keyword |
| netflow.http_request_method |  | keyword |
| netflow.http_request_target |  | keyword |
| netflow.http_status_code |  | integer |
| netflow.http_user_agent |  | keyword |
| netflow.icmp_code_ipv4 |  | short |
| netflow.icmp_code_ipv6 |  | short |
| netflow.icmp_type_code_ipv4 |  | integer |
| netflow.icmp_type_code_ipv6 |  | integer |
| netflow.icmp_type_ipv4 |  | short |
| netflow.icmp_type_ipv6 |  | short |
| netflow.igmp_type |  | short |
| netflow.ignored_data_record_total_count |  | long |
| netflow.ignored_layer2_frame_total_count |  | long |
| netflow.ignored_layer2_octet_total_count |  | long |
| netflow.ignored_octet_total_count |  | long |
| netflow.ignored_packet_total_count |  | long |
| netflow.information_element_data_type |  | short |
| netflow.information_element_description |  | keyword |
| netflow.information_element_id |  | integer |
| netflow.information_element_index |  | integer |
| netflow.information_element_name |  | keyword |
| netflow.information_element_range_begin |  | long |
| netflow.information_element_range_end |  | long |
| netflow.information_element_semantics |  | short |
| netflow.information_element_units |  | integer |
| netflow.ingress_broadcast_packet_total_count |  | long |
| netflow.ingress_interface |  | long |
| netflow.ingress_interface_type |  | long |
| netflow.ingress_multicast_packet_total_count |  | long |
| netflow.ingress_physical_interface |  | long |
| netflow.ingress_unicast_packet_total_count |  | long |
| netflow.ingress_vrfid |  | long |
| netflow.initial_tcp_flags |  | short |
| netflow.initiator_octets |  | long |
| netflow.initiator_packets |  | long |
| netflow.interface_description |  | keyword |
| netflow.interface_name |  | keyword |
| netflow.intermediate_process_id |  | long |
| netflow.internal_address_realm |  | short |
| netflow.ip_class_of_service |  | short |
| netflow.ip_diff_serv_code_point |  | short |
| netflow.ip_header_length |  | short |
| netflow.ip_header_packet_section |  | short |
| netflow.ip_next_hop_ipv4_address |  | ip |
| netflow.ip_next_hop_ipv6_address |  | ip |
| netflow.ip_payload_length |  | long |
| netflow.ip_payload_packet_section |  | short |
| netflow.ip_precedence |  | short |
| netflow.ip_sec_spi |  | long |
| netflow.ip_total_length |  | long |
| netflow.ip_ttl |  | short |
| netflow.ip_version |  | short |
| netflow.ipv4_ihl |  | short |
| netflow.ipv4_options |  | long |
| netflow.ipv4_router_sc |  | ip |
| netflow.ipv6_extension_headers |  | long |
| netflow.is_multicast |  | short |
| netflow.ixia_browser_id |  | short |
| netflow.ixia_browser_name |  | keyword |
| netflow.ixia_device_id |  | short |
| netflow.ixia_device_name |  | keyword |
| netflow.ixia_dns_answer |  | keyword |
| netflow.ixia_dns_classes |  | keyword |
| netflow.ixia_dns_query |  | keyword |
| netflow.ixia_dns_record_txt |  | keyword |
| netflow.ixia_dst_as_name |  | keyword |
| netflow.ixia_dst_city_name |  | keyword |
| netflow.ixia_dst_country_code |  | keyword |
| netflow.ixia_dst_country_name |  | keyword |
| netflow.ixia_dst_latitude |  | float |
| netflow.ixia_dst_longitude |  | float |
| netflow.ixia_dst_region_code |  | keyword |
| netflow.ixia_dst_region_node |  | keyword |
| netflow.ixia_encrypt_cipher |  | keyword |
| netflow.ixia_encrypt_key_length |  | integer |
| netflow.ixia_encrypt_type |  | keyword |
| netflow.ixia_http_host_name |  | keyword |
| netflow.ixia_http_uri |  | keyword |
| netflow.ixia_http_user_agent |  | keyword |
| netflow.ixia_imsi_subscriber |  | keyword |
| netflow.ixia_l7_app_id |  | long |
| netflow.ixia_l7_app_name |  | keyword |
| netflow.ixia_latency |  | long |
| netflow.ixia_rev_octet_delta_count |  | long |
| netflow.ixia_rev_packet_delta_count |  | long |
| netflow.ixia_src_as_name |  | keyword |
| netflow.ixia_src_city_name |  | keyword |
| netflow.ixia_src_country_code |  | keyword |
| netflow.ixia_src_country_name |  | keyword |
| netflow.ixia_src_latitude |  | float |
| netflow.ixia_src_longitude |  | float |
| netflow.ixia_src_region_code |  | keyword |
| netflow.ixia_src_region_name |  | keyword |
| netflow.ixia_threat_ipv4 |  | ip |
| netflow.ixia_threat_ipv6 |  | ip |
| netflow.ixia_threat_type |  | keyword |
| netflow.large_packet_count |  | long |
| netflow.layer2_frame_delta_count |  | long |
| netflow.layer2_frame_total_count |  | long |
| netflow.layer2_octet_delta_count |  | long |
| netflow.layer2_octet_delta_sum_of_squares |  | long |
| netflow.layer2_octet_total_count |  | long |
| netflow.layer2_octet_total_sum_of_squares |  | long |
| netflow.layer2_segment_id |  | long |
| netflow.layer2packet_section_data |  | short |
| netflow.layer2packet_section_offset |  | integer |
| netflow.layer2packet_section_size |  | integer |
| netflow.line_card_id |  | long |
| netflow.log_op |  | short |
| netflow.lower_ci_limit |  | double |
| netflow.mark |  | long |
| netflow.max_bib_entries |  | long |
| netflow.max_entries_per_user |  | long |
| netflow.max_export_seconds |  | date |
| netflow.max_flow_end_microseconds |  | date |
| netflow.max_flow_end_milliseconds |  | date |
| netflow.max_flow_end_nanoseconds |  | date |
| netflow.max_flow_end_seconds |  | date |
| netflow.max_fragments_pending_reassembly |  | long |
| netflow.max_packet_size |  | integer |
| netflow.max_session_entries |  | long |
| netflow.max_subscribers |  | long |
| netflow.maximum_ip_total_length |  | long |
| netflow.maximum_layer2_total_length |  | long |
| netflow.maximum_ttl |  | short |
| netflow.mean_flow_rate |  | long |
| netflow.mean_packet_rate |  | long |
| netflow.message_md5_checksum |  | short |
| netflow.message_scope |  | short |
| netflow.metering_process_id |  | long |
| netflow.metro_evc_id |  | keyword |
| netflow.metro_evc_type |  | short |
| netflow.mib_capture_time_semantics |  | short |
| netflow.mib_context_engine_id |  | short |
| netflow.mib_context_name |  | keyword |
| netflow.mib_index_indicator |  | long |
| netflow.mib_module_name |  | keyword |
| netflow.mib_object_description |  | keyword |
| netflow.mib_object_identifier |  | short |
| netflow.mib_object_name |  | keyword |
| netflow.mib_object_syntax |  | keyword |
| netflow.mib_object_value_bits |  | short |
| netflow.mib_object_value_counter |  | long |
| netflow.mib_object_value_gauge |  | long |
| netflow.mib_object_value_integer |  | integer |
| netflow.mib_object_value_ip_address |  | ip |
| netflow.mib_object_value_octet_string |  | short |
| netflow.mib_object_value_oid |  | short |
| netflow.mib_object_value_time_ticks |  | long |
| netflow.mib_object_value_unsigned |  | long |
| netflow.mib_sub_identifier |  | long |
| netflow.min_export_seconds |  | date |
| netflow.min_flow_start_microseconds |  | date |
| netflow.min_flow_start_milliseconds |  | date |
| netflow.min_flow_start_nanoseconds |  | date |
| netflow.min_flow_start_seconds |  | date |
| netflow.minimum_ip_total_length |  | long |
| netflow.minimum_layer2_total_length |  | long |
| netflow.minimum_ttl |  | short |
| netflow.mobile_imsi |  | keyword |
| netflow.mobile_msisdn |  | keyword |
| netflow.monitoring_interval_end_milli_seconds |  | date |
| netflow.monitoring_interval_start_milli_seconds |  | date |
| netflow.mpls_label_stack_depth |  | long |
| netflow.mpls_label_stack_length |  | long |
| netflow.mpls_label_stack_section |  | short |
| netflow.mpls_label_stack_section10 |  | short |
| netflow.mpls_label_stack_section2 |  | short |
| netflow.mpls_label_stack_section3 |  | short |
| netflow.mpls_label_stack_section4 |  | short |
| netflow.mpls_label_stack_section5 |  | short |
| netflow.mpls_label_stack_section6 |  | short |
| netflow.mpls_label_stack_section7 |  | short |
| netflow.mpls_label_stack_section8 |  | short |
| netflow.mpls_label_stack_section9 |  | short |
| netflow.mpls_payload_length |  | long |
| netflow.mpls_payload_packet_section |  | short |
| netflow.mpls_top_label_exp |  | short |
| netflow.mpls_top_label_ipv4_address |  | ip |
| netflow.mpls_top_label_ipv6_address |  | ip |
| netflow.mpls_top_label_prefix_length |  | short |
| netflow.mpls_top_label_stack_section |  | short |
| netflow.mpls_top_label_ttl |  | short |
| netflow.mpls_top_label_type |  | short |
| netflow.mpls_vpn_route_distinguisher |  | short |
| netflow.mptcp_address_id |  | short |
| netflow.mptcp_flags |  | short |
| netflow.mptcp_initial_data_sequence_number |  | long |
| netflow.mptcp_maximum_segment_size |  | integer |
| netflow.mptcp_receiver_token |  | long |
| netflow.multicast_replication_factor |  | long |
| netflow.nat_event |  | short |
| netflow.nat_inside_svcid |  | integer |
| netflow.nat_instance_id |  | long |
| netflow.nat_originating_address_realm |  | short |
| netflow.nat_outside_svcid |  | integer |
| netflow.nat_pool_id |  | long |
| netflow.nat_pool_name |  | keyword |
| netflow.nat_quota_exceeded_event |  | long |
| netflow.nat_sub_string |  | keyword |
| netflow.nat_threshold_event |  | long |
| netflow.nat_type |  | short |
| netflow.netscale_ica_client_version |  | keyword |
| netflow.netscaler_aaa_username |  | keyword |
| netflow.netscaler_app_name |  | keyword |
| netflow.netscaler_app_name_app_id |  | long |
| netflow.netscaler_app_name_incarnation_number |  | long |
| netflow.netscaler_app_template_name |  | keyword |
| netflow.netscaler_app_unit_name_app_id |  | long |
| netflow.netscaler_application_startup_duration |  | long |
| netflow.netscaler_application_startup_time |  | long |
| netflow.netscaler_cache_redir_client_connection_core_id |  | long |
| netflow.netscaler_cache_redir_client_connection_transaction_id |  | long |
| netflow.netscaler_client_rtt |  | long |
| netflow.netscaler_connection_chain_hop_count |  | long |
| netflow.netscaler_connection_chain_id |  | short |
| netflow.netscaler_connection_id |  | long |
| netflow.netscaler_current_license_consumed |  | long |
| netflow.netscaler_db_clt_host_name |  | keyword |
| netflow.netscaler_db_database_name |  | keyword |
| netflow.netscaler_db_login_flags |  | long |
| netflow.netscaler_db_protocol_name |  | short |
| netflow.netscaler_db_req_string |  | keyword |
| netflow.netscaler_db_req_type |  | short |
| netflow.netscaler_db_resp_length |  | long |
| netflow.netscaler_db_resp_status |  | long |
| netflow.netscaler_db_resp_status_string |  | keyword |
| netflow.netscaler_db_user_name |  | keyword |
| netflow.netscaler_flow_flags |  | long |
| netflow.netscaler_http_client_interaction_end_time |  | keyword |
| netflow.netscaler_http_client_interaction_start_time |  | keyword |
| netflow.netscaler_http_client_render_end_time |  | keyword |
| netflow.netscaler_http_client_render_start_time |  | keyword |
| netflow.netscaler_http_content_type |  | keyword |
| netflow.netscaler_http_domain_name |  | keyword |
| netflow.netscaler_http_req_authorization |  | keyword |
| netflow.netscaler_http_req_cookie |  | keyword |
| netflow.netscaler_http_req_forw_fb |  | long |
| netflow.netscaler_http_req_forw_lb |  | long |
| netflow.netscaler_http_req_host |  | keyword |
| netflow.netscaler_http_req_method |  | keyword |
| netflow.netscaler_http_req_rcv_fb |  | long |
| netflow.netscaler_http_req_rcv_lb |  | long |
| netflow.netscaler_http_req_referer |  | keyword |
| netflow.netscaler_http_req_url |  | keyword |
| netflow.netscaler_http_req_user_agent |  | keyword |
| netflow.netscaler_http_req_via |  | keyword |
| netflow.netscaler_http_req_xforwarded_for |  | keyword |
| netflow.netscaler_http_res_forw_fb |  | long |
| netflow.netscaler_http_res_forw_lb |  | long |
| netflow.netscaler_http_res_location |  | keyword |
| netflow.netscaler_http_res_rcv_fb |  | long |
| netflow.netscaler_http_res_rcv_lb |  | long |
| netflow.netscaler_http_res_set_cookie |  | keyword |
| netflow.netscaler_http_res_set_cookie2 |  | keyword |
| netflow.netscaler_http_rsp_len |  | long |
| netflow.netscaler_http_rsp_status |  | integer |
| netflow.netscaler_ica_app_module_path |  | keyword |
| netflow.netscaler_ica_app_process_id |  | long |
| netflow.netscaler_ica_application_name |  | keyword |
| netflow.netscaler_ica_application_termination_time |  | long |
| netflow.netscaler_ica_application_termination_type |  | integer |
| netflow.netscaler_ica_channel_id1 |  | long |
| netflow.netscaler_ica_channel_id1_bytes |  | long |
| netflow.netscaler_ica_channel_id2 |  | long |
| netflow.netscaler_ica_channel_id2_bytes |  | long |
| netflow.netscaler_ica_channel_id3 |  | long |
| netflow.netscaler_ica_channel_id3_bytes |  | long |
| netflow.netscaler_ica_channel_id4 |  | long |
| netflow.netscaler_ica_channel_id4_bytes |  | long |
| netflow.netscaler_ica_channel_id5 |  | long |
| netflow.netscaler_ica_channel_id5_bytes |  | long |
| netflow.netscaler_ica_client_host_name |  | keyword |
| netflow.netscaler_ica_client_ip |  | ip |
| netflow.netscaler_ica_client_launcher |  | integer |
| netflow.netscaler_ica_client_side_rto_count |  | integer |
| netflow.netscaler_ica_client_side_window_size |  | integer |
| netflow.netscaler_ica_client_type |  | integer |
| netflow.netscaler_ica_clientside_delay |  | long |
| netflow.netscaler_ica_clientside_jitter |  | long |
| netflow.netscaler_ica_clientside_packets_retransmit |  | integer |
| netflow.netscaler_ica_clientside_rtt |  | long |
| netflow.netscaler_ica_clientside_rx_bytes |  | long |
| netflow.netscaler_ica_clientside_srtt |  | long |
| netflow.netscaler_ica_clientside_tx_bytes |  | long |
| netflow.netscaler_ica_connection_priority |  | integer |
| netflow.netscaler_ica_device_serial_no |  | long |
| netflow.netscaler_ica_domain_name |  | keyword |
| netflow.netscaler_ica_flags |  | long |
| netflow.netscaler_ica_host_delay |  | long |
| netflow.netscaler_ica_l7_client_latency |  | long |
| netflow.netscaler_ica_l7_server_latency |  | long |
| netflow.netscaler_ica_launch_mechanism |  | integer |
| netflow.netscaler_ica_network_update_end_time |  | long |
| netflow.netscaler_ica_network_update_start_time |  | long |
| netflow.netscaler_ica_rtt |  | long |
| netflow.netscaler_ica_server_name |  | keyword |
| netflow.netscaler_ica_server_side_rto_count |  | integer |
| netflow.netscaler_ica_server_side_window_size |  | integer |
| netflow.netscaler_ica_serverside_delay |  | long |
| netflow.netscaler_ica_serverside_jitter |  | long |
| netflow.netscaler_ica_serverside_packets_retransmit |  | integer |
| netflow.netscaler_ica_serverside_rtt |  | long |
| netflow.netscaler_ica_serverside_srtt |  | long |
| netflow.netscaler_ica_session_end_time |  | long |
| netflow.netscaler_ica_session_guid |  | short |
| netflow.netscaler_ica_session_reconnects |  | short |
| netflow.netscaler_ica_session_setup_time |  | long |
| netflow.netscaler_ica_session_update_begin_sec |  | long |
| netflow.netscaler_ica_session_update_end_sec |  | long |
| netflow.netscaler_ica_username |  | keyword |
| netflow.netscaler_license_type |  | short |
| netflow.netscaler_main_page_core_id |  | long |
| netflow.netscaler_main_page_id |  | long |
| netflow.netscaler_max_license_count |  | long |
| netflow.netscaler_msi_client_cookie |  | short |
| netflow.netscaler_round_trip_time |  | long |
| netflow.netscaler_server_ttfb |  | long |
| netflow.netscaler_server_ttlb |  | long |
| netflow.netscaler_syslog_message |  | keyword |
| netflow.netscaler_syslog_priority |  | short |
| netflow.netscaler_syslog_timestamp |  | long |
| netflow.netscaler_transaction_id |  | long |
| netflow.netscaler_unknown270 |  | long |
| netflow.netscaler_unknown271 |  | long |
| netflow.netscaler_unknown272 |  | long |
| netflow.netscaler_unknown273 |  | long |
| netflow.netscaler_unknown274 |  | long |
| netflow.netscaler_unknown275 |  | long |
| netflow.netscaler_unknown276 |  | long |
| netflow.netscaler_unknown277 |  | long |
| netflow.netscaler_unknown278 |  | long |
| netflow.netscaler_unknown279 |  | long |
| netflow.netscaler_unknown280 |  | long |
| netflow.netscaler_unknown281 |  | long |
| netflow.netscaler_unknown282 |  | long |
| netflow.netscaler_unknown283 |  | long |
| netflow.netscaler_unknown284 |  | long |
| netflow.netscaler_unknown285 |  | long |
| netflow.netscaler_unknown286 |  | long |
| netflow.netscaler_unknown287 |  | long |
| netflow.netscaler_unknown288 |  | long |
| netflow.netscaler_unknown289 |  | long |
| netflow.netscaler_unknown290 |  | long |
| netflow.netscaler_unknown291 |  | long |
| netflow.netscaler_unknown292 |  | long |
| netflow.netscaler_unknown293 |  | long |
| netflow.netscaler_unknown294 |  | long |
| netflow.netscaler_unknown295 |  | long |
| netflow.netscaler_unknown296 |  | long |
| netflow.netscaler_unknown297 |  | long |
| netflow.netscaler_unknown298 |  | long |
| netflow.netscaler_unknown299 |  | long |
| netflow.netscaler_unknown300 |  | long |
| netflow.netscaler_unknown301 |  | long |
| netflow.netscaler_unknown302 |  | long |
| netflow.netscaler_unknown303 |  | long |
| netflow.netscaler_unknown304 |  | long |
| netflow.netscaler_unknown305 |  | long |
| netflow.netscaler_unknown306 |  | long |
| netflow.netscaler_unknown307 |  | long |
| netflow.netscaler_unknown308 |  | long |
| netflow.netscaler_unknown309 |  | long |
| netflow.netscaler_unknown310 |  | long |
| netflow.netscaler_unknown311 |  | long |
| netflow.netscaler_unknown312 |  | long |
| netflow.netscaler_unknown313 |  | long |
| netflow.netscaler_unknown314 |  | long |
| netflow.netscaler_unknown315 |  | long |
| netflow.netscaler_unknown316 |  | keyword |
| netflow.netscaler_unknown317 |  | long |
| netflow.netscaler_unknown318 |  | long |
| netflow.netscaler_unknown319 |  | keyword |
| netflow.netscaler_unknown320 |  | integer |
| netflow.netscaler_unknown321 |  | long |
| netflow.netscaler_unknown322 |  | long |
| netflow.netscaler_unknown323 |  | integer |
| netflow.netscaler_unknown324 |  | integer |
| netflow.netscaler_unknown325 |  | integer |
| netflow.netscaler_unknown326 |  | integer |
| netflow.netscaler_unknown327 |  | long |
| netflow.netscaler_unknown328 |  | integer |
| netflow.netscaler_unknown329 |  | integer |
| netflow.netscaler_unknown330 |  | integer |
| netflow.netscaler_unknown331 |  | integer |
| netflow.netscaler_unknown332 |  | long |
| netflow.netscaler_unknown333 |  | keyword |
| netflow.netscaler_unknown334 |  | keyword |
| netflow.netscaler_unknown335 |  | long |
| netflow.netscaler_unknown336 |  | long |
| netflow.netscaler_unknown337 |  | long |
| netflow.netscaler_unknown338 |  | long |
| netflow.netscaler_unknown339 |  | long |
| netflow.netscaler_unknown340 |  | long |
| netflow.netscaler_unknown341 |  | long |
| netflow.netscaler_unknown342 |  | long |
| netflow.netscaler_unknown343 |  | long |
| netflow.netscaler_unknown344 |  | long |
| netflow.netscaler_unknown345 |  | long |
| netflow.netscaler_unknown346 |  | long |
| netflow.netscaler_unknown347 |  | long |
| netflow.netscaler_unknown348 |  | integer |
| netflow.netscaler_unknown349 |  | keyword |
| netflow.netscaler_unknown350 |  | keyword |
| netflow.netscaler_unknown351 |  | keyword |
| netflow.netscaler_unknown352 |  | integer |
| netflow.netscaler_unknown353 |  | long |
| netflow.netscaler_unknown354 |  | long |
| netflow.netscaler_unknown355 |  | long |
| netflow.netscaler_unknown356 |  | long |
| netflow.netscaler_unknown357 |  | long |
| netflow.netscaler_unknown363 |  | short |
| netflow.netscaler_unknown383 |  | short |
| netflow.netscaler_unknown391 |  | long |
| netflow.netscaler_unknown398 |  | long |
| netflow.netscaler_unknown404 |  | long |
| netflow.netscaler_unknown405 |  | long |
| netflow.netscaler_unknown427 |  | long |
| netflow.netscaler_unknown429 |  | short |
| netflow.netscaler_unknown432 |  | short |
| netflow.netscaler_unknown433 |  | short |
| netflow.netscaler_unknown453 |  | long |
| netflow.netscaler_unknown465 |  | long |
| netflow.new_connection_delta_count |  | long |
| netflow.next_header_ipv6 |  | short |
| netflow.non_empty_packet_count |  | long |
| netflow.not_sent_flow_total_count |  | long |
| netflow.not_sent_layer2_octet_total_count |  | long |
| netflow.not_sent_octet_total_count |  | long |
| netflow.not_sent_packet_total_count |  | long |
| netflow.observation_domain_id |  | long |
| netflow.observation_domain_name |  | keyword |
| netflow.observation_point_id |  | long |
| netflow.observation_point_type |  | short |
| netflow.observation_time_microseconds |  | date |
| netflow.observation_time_milliseconds |  | date |
| netflow.observation_time_nanoseconds |  | date |
| netflow.observation_time_seconds |  | date |
| netflow.observed_flow_total_count |  | long |
| netflow.octet_delta_count |  | long |
| netflow.octet_delta_sum_of_squares |  | long |
| netflow.octet_total_count |  | long |
| netflow.octet_total_sum_of_squares |  | long |
| netflow.opaque_octets |  | short |
| netflow.original_exporter_ipv4_address |  | ip |
| netflow.original_exporter_ipv6_address |  | ip |
| netflow.original_flows_completed |  | long |
| netflow.original_flows_initiated |  | long |
| netflow.original_flows_present |  | long |
| netflow.original_observation_domain_id |  | long |
| netflow.os_finger_print |  | keyword |
| netflow.os_name |  | keyword |
| netflow.os_version |  | keyword |
| netflow.p2p_technology |  | keyword |
| netflow.packet_delta_count |  | long |
| netflow.packet_total_count |  | long |
| netflow.padding_octets |  | short |
| netflow.payload |  | keyword |
| netflow.payload_entropy |  | short |
| netflow.payload_length_ipv6 |  | integer |
| netflow.policy_qos_classification_hierarchy |  | long |
| netflow.policy_qos_queue_index |  | long |
| netflow.policy_qos_queuedrops |  | long |
| netflow.policy_qos_queueindex |  | long |
| netflow.port_id |  | long |
| netflow.port_range_end |  | integer |
| netflow.port_range_num_ports |  | integer |
| netflow.port_range_start |  | integer |
| netflow.port_range_step_size |  | integer |
| netflow.post_destination_mac_address |  | keyword |
| netflow.post_dot1q_customer_vlan_id |  | integer |
| netflow.post_dot1q_vlan_id |  | integer |
| netflow.post_ip_class_of_service |  | short |
| netflow.post_ip_diff_serv_code_point |  | short |
| netflow.post_ip_precedence |  | short |
| netflow.post_layer2_octet_delta_count |  | long |
| netflow.post_layer2_octet_total_count |  | long |
| netflow.post_mcast_layer2_octet_delta_count |  | long |
| netflow.post_mcast_layer2_octet_total_count |  | long |
| netflow.post_mcast_octet_delta_count |  | long |
| netflow.post_mcast_octet_total_count |  | long |
| netflow.post_mcast_packet_delta_count |  | long |
| netflow.post_mcast_packet_total_count |  | long |
| netflow.post_mpls_top_label_exp |  | short |
| netflow.post_napt_destination_transport_port |  | integer |
| netflow.post_napt_source_transport_port |  | integer |
| netflow.post_nat_destination_ipv4_address |  | ip |
| netflow.post_nat_destination_ipv6_address |  | ip |
| netflow.post_nat_source_ipv4_address |  | ip |
| netflow.post_nat_source_ipv6_address |  | ip |
| netflow.post_octet_delta_count |  | long |
| netflow.post_octet_total_count |  | long |
| netflow.post_packet_delta_count |  | long |
| netflow.post_packet_total_count |  | long |
| netflow.post_source_mac_address |  | keyword |
| netflow.post_vlan_id |  | integer |
| netflow.private_enterprise_number |  | long |
| netflow.procera_apn |  | keyword |
| netflow.procera_base_service |  | keyword |
| netflow.procera_content_categories |  | keyword |
| netflow.procera_device_id |  | long |
| netflow.procera_external_rtt |  | integer |
| netflow.procera_flow_behavior |  | keyword |
| netflow.procera_ggsn |  | keyword |
| netflow.procera_http_content_type |  | keyword |
| netflow.procera_http_file_length |  | long |
| netflow.procera_http_language |  | keyword |
| netflow.procera_http_location |  | keyword |
| netflow.procera_http_referer |  | keyword |
| netflow.procera_http_request_method |  | keyword |
| netflow.procera_http_request_version |  | keyword |
| netflow.procera_http_response_status |  | integer |
| netflow.procera_http_url |  | keyword |
| netflow.procera_http_user_agent |  | keyword |
| netflow.procera_imsi |  | long |
| netflow.procera_incoming_octets |  | long |
| netflow.procera_incoming_packets |  | long |
| netflow.procera_incoming_shaping_drops |  | long |
| netflow.procera_incoming_shaping_latency |  | integer |
| netflow.procera_internal_rtt |  | integer |
| netflow.procera_local_ipv4_host |  | ip |
| netflow.procera_local_ipv6_host |  | ip |
| netflow.procera_msisdn |  | long |
| netflow.procera_outgoing_octets |  | long |
| netflow.procera_outgoing_packets |  | long |
| netflow.procera_outgoing_shaping_drops |  | long |
| netflow.procera_outgoing_shaping_latency |  | integer |
| netflow.procera_property |  | keyword |
| netflow.procera_qoe_incoming_external |  | float |
| netflow.procera_qoe_incoming_internal |  | float |
| netflow.procera_qoe_outgoing_external |  | float |
| netflow.procera_qoe_outgoing_internal |  | float |
| netflow.procera_rat |  | keyword |
| netflow.procera_remote_ipv4_host |  | ip |
| netflow.procera_remote_ipv6_host |  | ip |
| netflow.procera_rnc |  | integer |
| netflow.procera_server_hostname |  | keyword |
| netflow.procera_service |  | keyword |
| netflow.procera_sgsn |  | keyword |
| netflow.procera_subscriber_identifier |  | keyword |
| netflow.procera_template_name |  | keyword |
| netflow.procera_user_location_information |  | keyword |
| netflow.protocol_identifier |  | short |
| netflow.pseudo_wire_control_word |  | long |
| netflow.pseudo_wire_destination_ipv4_address |  | ip |
| netflow.pseudo_wire_id |  | long |
| netflow.pseudo_wire_type |  | integer |
| netflow.reason |  | long |
| netflow.reason_text |  | keyword |
| netflow.relative_error |  | double |
| netflow.responder_octets |  | long |
| netflow.responder_packets |  | long |
| netflow.reverse_absolute_error |  | double |
| netflow.reverse_anonymization_flags |  | integer |
| netflow.reverse_anonymization_technique |  | integer |
| netflow.reverse_application_category_name |  | keyword |
| netflow.reverse_application_description |  | keyword |
| netflow.reverse_application_group_name |  | keyword |
| netflow.reverse_application_id |  | keyword |
| netflow.reverse_application_name |  | keyword |
| netflow.reverse_application_sub_category_name |  | keyword |
| netflow.reverse_average_interarrival_time |  | long |
| netflow.reverse_bgp_destination_as_number |  | long |
| netflow.reverse_bgp_next_adjacent_as_number |  | long |
| netflow.reverse_bgp_next_hop_ipv4_address |  | ip |
| netflow.reverse_bgp_next_hop_ipv6_address |  | ip |
| netflow.reverse_bgp_prev_adjacent_as_number |  | long |
| netflow.reverse_bgp_source_as_number |  | long |
| netflow.reverse_bgp_validity_state |  | short |
| netflow.reverse_class_id |  | short |
| netflow.reverse_class_name |  | keyword |
| netflow.reverse_classification_engine_id |  | short |
| netflow.reverse_collection_time_milliseconds |  | long |
| netflow.reverse_collector_certificate |  | keyword |
| netflow.reverse_confidence_level |  | double |
| netflow.reverse_connection_sum_duration_seconds |  | long |
| netflow.reverse_connection_transaction_id |  | long |
| netflow.reverse_data_byte_count |  | long |
| netflow.reverse_data_link_frame_section |  | keyword |
| netflow.reverse_data_link_frame_size |  | integer |
| netflow.reverse_data_link_frame_type |  | integer |
| netflow.reverse_data_records_reliability |  | short |
| netflow.reverse_delta_flow_count |  | long |
| netflow.reverse_destination_ipv4_address |  | ip |
| netflow.reverse_destination_ipv4_prefix |  | ip |
| netflow.reverse_destination_ipv4_prefix_length |  | short |
| netflow.reverse_destination_ipv6_address |  | ip |
| netflow.reverse_destination_ipv6_prefix |  | ip |
| netflow.reverse_destination_ipv6_prefix_length |  | short |
| netflow.reverse_destination_mac_address |  | keyword |
| netflow.reverse_destination_transport_port |  | integer |
| netflow.reverse_digest_hash_value |  | long |
| netflow.reverse_distinct_count_of_destination_ip_address |  | long |
| netflow.reverse_distinct_count_of_destination_ipv4_address |  | long |
| netflow.reverse_distinct_count_of_destination_ipv6_address |  | long |
| netflow.reverse_distinct_count_of_source_ip_address |  | long |
| netflow.reverse_distinct_count_of_source_ipv4_address |  | long |
| netflow.reverse_distinct_count_of_source_ipv6_address |  | long |
| netflow.reverse_dot1q_customer_dei |  | short |
| netflow.reverse_dot1q_customer_destination_mac_address |  | keyword |
| netflow.reverse_dot1q_customer_priority |  | short |
| netflow.reverse_dot1q_customer_source_mac_address |  | keyword |
| netflow.reverse_dot1q_customer_vlan_id |  | integer |
| netflow.reverse_dot1q_dei |  | short |
| netflow.reverse_dot1q_priority |  | short |
| netflow.reverse_dot1q_service_instance_id |  | long |
| netflow.reverse_dot1q_service_instance_priority |  | short |
| netflow.reverse_dot1q_service_instance_tag |  | keyword |
| netflow.reverse_dot1q_vlan_id |  | integer |
| netflow.reverse_dropped_layer2_octet_delta_count |  | long |
| netflow.reverse_dropped_layer2_octet_total_count |  | long |
| netflow.reverse_dropped_octet_delta_count |  | long |
| netflow.reverse_dropped_octet_total_count |  | long |
| netflow.reverse_dropped_packet_delta_count |  | long |
| netflow.reverse_dropped_packet_total_count |  | long |
| netflow.reverse_dst_traffic_index |  | long |
| netflow.reverse_egress_broadcast_packet_total_count |  | long |
| netflow.reverse_egress_interface |  | long |
| netflow.reverse_egress_interface_type |  | long |
| netflow.reverse_egress_physical_interface |  | long |
| netflow.reverse_egress_unicast_packet_total_count |  | long |
| netflow.reverse_egress_vrfid |  | long |
| netflow.reverse_encrypted_technology |  | keyword |
| netflow.reverse_engine_id |  | short |
| netflow.reverse_engine_type |  | short |
| netflow.reverse_ethernet_header_length |  | short |
| netflow.reverse_ethernet_payload_length |  | integer |
| netflow.reverse_ethernet_total_length |  | integer |
| netflow.reverse_ethernet_type |  | integer |
| netflow.reverse_export_sctp_stream_id |  | integer |
| netflow.reverse_exporter_certificate |  | keyword |
| netflow.reverse_exporting_process_id |  | long |
| netflow.reverse_firewall_event |  | short |
| netflow.reverse_first_non_empty_packet_size |  | integer |
| netflow.reverse_first_packet_banner |  | keyword |
| netflow.reverse_flags_and_sampler_id |  | long |
| netflow.reverse_flow_active_timeout |  | integer |
| netflow.reverse_flow_attributes |  | integer |
| netflow.reverse_flow_delta_milliseconds |  | long |
| netflow.reverse_flow_direction |  | short |
| netflow.reverse_flow_duration_microseconds |  | long |
| netflow.reverse_flow_duration_milliseconds |  | long |
| netflow.reverse_flow_end_delta_microseconds |  | long |
| netflow.reverse_flow_end_microseconds |  | long |
| netflow.reverse_flow_end_milliseconds |  | long |
| netflow.reverse_flow_end_nanoseconds |  | long |
| netflow.reverse_flow_end_reason |  | short |
| netflow.reverse_flow_end_seconds |  | long |
| netflow.reverse_flow_end_sys_up_time |  | long |
| netflow.reverse_flow_idle_timeout |  | integer |
| netflow.reverse_flow_label_ipv6 |  | long |
| netflow.reverse_flow_sampling_time_interval |  | long |
| netflow.reverse_flow_sampling_time_spacing |  | long |
| netflow.reverse_flow_selected_flow_delta_count |  | long |
| netflow.reverse_flow_selected_octet_delta_count |  | long |
| netflow.reverse_flow_selected_packet_delta_count |  | long |
| netflow.reverse_flow_selector_algorithm |  | integer |
| netflow.reverse_flow_start_delta_microseconds |  | long |
| netflow.reverse_flow_start_microseconds |  | long |
| netflow.reverse_flow_start_milliseconds |  | long |
| netflow.reverse_flow_start_nanoseconds |  | long |
| netflow.reverse_flow_start_seconds |  | long |
| netflow.reverse_flow_start_sys_up_time |  | long |
| netflow.reverse_forwarding_status |  | long |
| netflow.reverse_fragment_flags |  | short |
| netflow.reverse_fragment_identification |  | long |
| netflow.reverse_fragment_offset |  | integer |
| netflow.reverse_gre_key |  | long |
| netflow.reverse_hash_digest_output |  | short |
| netflow.reverse_hash_flow_domain |  | integer |
| netflow.reverse_hash_initialiser_value |  | long |
| netflow.reverse_hash_ip_payload_offset |  | long |
| netflow.reverse_hash_ip_payload_size |  | long |
| netflow.reverse_hash_output_range_max |  | long |
| netflow.reverse_hash_output_range_min |  | long |
| netflow.reverse_hash_selected_range_max |  | long |
| netflow.reverse_hash_selected_range_min |  | long |
| netflow.reverse_icmp_code_ipv4 |  | short |
| netflow.reverse_icmp_code_ipv6 |  | short |
| netflow.reverse_icmp_type_code_ipv4 |  | integer |
| netflow.reverse_icmp_type_code_ipv6 |  | integer |
| netflow.reverse_icmp_type_ipv4 |  | short |
| netflow.reverse_icmp_type_ipv6 |  | short |
| netflow.reverse_igmp_type |  | short |
| netflow.reverse_ignored_data_record_total_count |  | long |
| netflow.reverse_ignored_layer2_frame_total_count |  | long |
| netflow.reverse_ignored_layer2_octet_total_count |  | long |
| netflow.reverse_information_element_data_type |  | short |
| netflow.reverse_information_element_description |  | keyword |
| netflow.reverse_information_element_id |  | integer |
| netflow.reverse_information_element_index |  | integer |
| netflow.reverse_information_element_name |  | keyword |
| netflow.reverse_information_element_range_begin |  | long |
| netflow.reverse_information_element_range_end |  | long |
| netflow.reverse_information_element_semantics |  | short |
| netflow.reverse_information_element_units |  | integer |
| netflow.reverse_ingress_broadcast_packet_total_count |  | long |
| netflow.reverse_ingress_interface |  | long |
| netflow.reverse_ingress_interface_type |  | long |
| netflow.reverse_ingress_multicast_packet_total_count |  | long |
| netflow.reverse_ingress_physical_interface |  | long |
| netflow.reverse_ingress_unicast_packet_total_count |  | long |
| netflow.reverse_ingress_vrfid |  | long |
| netflow.reverse_initial_tcp_flags |  | short |
| netflow.reverse_initiator_octets |  | long |
| netflow.reverse_initiator_packets |  | long |
| netflow.reverse_interface_description |  | keyword |
| netflow.reverse_interface_name |  | keyword |
| netflow.reverse_intermediate_process_id |  | long |
| netflow.reverse_ip_class_of_service |  | short |
| netflow.reverse_ip_diff_serv_code_point |  | short |
| netflow.reverse_ip_header_length |  | short |
| netflow.reverse_ip_header_packet_section |  | keyword |
| netflow.reverse_ip_next_hop_ipv4_address |  | ip |
| netflow.reverse_ip_next_hop_ipv6_address |  | ip |
| netflow.reverse_ip_payload_length |  | long |
| netflow.reverse_ip_payload_packet_section |  | keyword |
| netflow.reverse_ip_precedence |  | short |
| netflow.reverse_ip_sec_spi |  | long |
| netflow.reverse_ip_total_length |  | long |
| netflow.reverse_ip_ttl |  | short |
| netflow.reverse_ip_version |  | short |
| netflow.reverse_ipv4_ihl |  | short |
| netflow.reverse_ipv4_options |  | long |
| netflow.reverse_ipv4_router_sc |  | ip |
| netflow.reverse_ipv6_extension_headers |  | long |
| netflow.reverse_is_multicast |  | short |
| netflow.reverse_large_packet_count |  | long |
| netflow.reverse_layer2_frame_delta_count |  | long |
| netflow.reverse_layer2_frame_total_count |  | long |
| netflow.reverse_layer2_octet_delta_count |  | long |
| netflow.reverse_layer2_octet_delta_sum_of_squares |  | long |
| netflow.reverse_layer2_octet_total_count |  | long |
| netflow.reverse_layer2_octet_total_sum_of_squares |  | long |
| netflow.reverse_layer2_segment_id |  | long |
| netflow.reverse_layer2packet_section_data |  | keyword |
| netflow.reverse_layer2packet_section_offset |  | integer |
| netflow.reverse_layer2packet_section_size |  | integer |
| netflow.reverse_line_card_id |  | long |
| netflow.reverse_lower_ci_limit |  | double |
| netflow.reverse_max_export_seconds |  | long |
| netflow.reverse_max_flow_end_microseconds |  | long |
| netflow.reverse_max_flow_end_milliseconds |  | long |
| netflow.reverse_max_flow_end_nanoseconds |  | long |
| netflow.reverse_max_flow_end_seconds |  | long |
| netflow.reverse_max_packet_size |  | integer |
| netflow.reverse_maximum_ip_total_length |  | long |
| netflow.reverse_maximum_layer2_total_length |  | long |
| netflow.reverse_maximum_ttl |  | short |
| netflow.reverse_message_md5_checksum |  | keyword |
| netflow.reverse_message_scope |  | short |
| netflow.reverse_metering_process_id |  | long |
| netflow.reverse_metro_evc_id |  | keyword |
| netflow.reverse_metro_evc_type |  | short |
| netflow.reverse_min_export_seconds |  | long |
| netflow.reverse_min_flow_start_microseconds |  | long |
| netflow.reverse_min_flow_start_milliseconds |  | long |
| netflow.reverse_min_flow_start_nanoseconds |  | long |
| netflow.reverse_min_flow_start_seconds |  | long |
| netflow.reverse_minimum_ip_total_length |  | long |
| netflow.reverse_minimum_layer2_total_length |  | long |
| netflow.reverse_minimum_ttl |  | short |
| netflow.reverse_monitoring_interval_end_milli_seconds |  | long |
| netflow.reverse_monitoring_interval_start_milli_seconds |  | long |
| netflow.reverse_mpls_label_stack_depth |  | long |
| netflow.reverse_mpls_label_stack_length |  | long |
| netflow.reverse_mpls_label_stack_section |  | keyword |
| netflow.reverse_mpls_label_stack_section10 |  | keyword |
| netflow.reverse_mpls_label_stack_section2 |  | keyword |
| netflow.reverse_mpls_label_stack_section3 |  | keyword |
| netflow.reverse_mpls_label_stack_section4 |  | keyword |
| netflow.reverse_mpls_label_stack_section5 |  | keyword |
| netflow.reverse_mpls_label_stack_section6 |  | keyword |
| netflow.reverse_mpls_label_stack_section7 |  | keyword |
| netflow.reverse_mpls_label_stack_section8 |  | keyword |
| netflow.reverse_mpls_label_stack_section9 |  | keyword |
| netflow.reverse_mpls_payload_length |  | long |
| netflow.reverse_mpls_payload_packet_section |  | keyword |
| netflow.reverse_mpls_top_label_exp |  | short |
| netflow.reverse_mpls_top_label_ipv4_address |  | ip |
| netflow.reverse_mpls_top_label_ipv6_address |  | ip |
| netflow.reverse_mpls_top_label_prefix_length |  | short |
| netflow.reverse_mpls_top_label_stack_section |  | keyword |
| netflow.reverse_mpls_top_label_ttl |  | short |
| netflow.reverse_mpls_top_label_type |  | short |
| netflow.reverse_mpls_vpn_route_distinguisher |  | keyword |
| netflow.reverse_multicast_replication_factor |  | long |
| netflow.reverse_nat_event |  | short |
| netflow.reverse_nat_originating_address_realm |  | short |
| netflow.reverse_nat_pool_id |  | long |
| netflow.reverse_nat_pool_name |  | keyword |
| netflow.reverse_nat_type |  | short |
| netflow.reverse_new_connection_delta_count |  | long |
| netflow.reverse_next_header_ipv6 |  | short |
| netflow.reverse_non_empty_packet_count |  | long |
| netflow.reverse_not_sent_layer2_octet_total_count |  | long |
| netflow.reverse_observation_domain_name |  | keyword |
| netflow.reverse_observation_point_id |  | long |
| netflow.reverse_observation_point_type |  | short |
| netflow.reverse_observation_time_microseconds |  | long |
| netflow.reverse_observation_time_milliseconds |  | long |
| netflow.reverse_observation_time_nanoseconds |  | long |
| netflow.reverse_observation_time_seconds |  | long |
| netflow.reverse_octet_delta_count |  | long |
| netflow.reverse_octet_delta_sum_of_squares |  | long |
| netflow.reverse_octet_total_count |  | long |
| netflow.reverse_octet_total_sum_of_squares |  | long |
| netflow.reverse_opaque_octets |  | keyword |
| netflow.reverse_original_exporter_ipv4_address |  | ip |
| netflow.reverse_original_exporter_ipv6_address |  | ip |
| netflow.reverse_original_flows_completed |  | long |
| netflow.reverse_original_flows_initiated |  | long |
| netflow.reverse_original_flows_present |  | long |
| netflow.reverse_original_observation_domain_id |  | long |
| netflow.reverse_os_finger_print |  | keyword |
| netflow.reverse_os_name |  | keyword |
| netflow.reverse_os_version |  | keyword |
| netflow.reverse_p2p_technology |  | keyword |
| netflow.reverse_packet_delta_count |  | long |
| netflow.reverse_packet_total_count |  | long |
| netflow.reverse_payload |  | keyword |
| netflow.reverse_payload_entropy |  | short |
| netflow.reverse_payload_length_ipv6 |  | integer |
| netflow.reverse_port_id |  | long |
| netflow.reverse_port_range_end |  | integer |
| netflow.reverse_port_range_num_ports |  | integer |
| netflow.reverse_port_range_start |  | integer |
| netflow.reverse_port_range_step_size |  | integer |
| netflow.reverse_post_destination_mac_address |  | keyword |
| netflow.reverse_post_dot1q_customer_vlan_id |  | integer |
| netflow.reverse_post_dot1q_vlan_id |  | integer |
| netflow.reverse_post_ip_class_of_service |  | short |
| netflow.reverse_post_ip_diff_serv_code_point |  | short |
| netflow.reverse_post_ip_precedence |  | short |
| netflow.reverse_post_layer2_octet_delta_count |  | long |
| netflow.reverse_post_layer2_octet_total_count |  | long |
| netflow.reverse_post_mcast_layer2_octet_delta_count |  | long |
| netflow.reverse_post_mcast_layer2_octet_total_count |  | long |
| netflow.reverse_post_mcast_octet_delta_count |  | long |
| netflow.reverse_post_mcast_octet_total_count |  | long |
| netflow.reverse_post_mcast_packet_delta_count |  | long |
| netflow.reverse_post_mcast_packet_total_count |  | long |
| netflow.reverse_post_mpls_top_label_exp |  | short |
| netflow.reverse_post_napt_destination_transport_port |  | integer |
| netflow.reverse_post_napt_source_transport_port |  | integer |
| netflow.reverse_post_nat_destination_ipv4_address |  | ip |
| netflow.reverse_post_nat_destination_ipv6_address |  | ip |
| netflow.reverse_post_nat_source_ipv4_address |  | ip |
| netflow.reverse_post_nat_source_ipv6_address |  | ip |
| netflow.reverse_post_octet_delta_count |  | long |
| netflow.reverse_post_octet_total_count |  | long |
| netflow.reverse_post_packet_delta_count |  | long |
| netflow.reverse_post_packet_total_count |  | long |
| netflow.reverse_post_source_mac_address |  | keyword |
| netflow.reverse_post_vlan_id |  | integer |
| netflow.reverse_private_enterprise_number |  | long |
| netflow.reverse_protocol_identifier |  | short |
| netflow.reverse_pseudo_wire_control_word |  | long |
| netflow.reverse_pseudo_wire_destination_ipv4_address |  | ip |
| netflow.reverse_pseudo_wire_id |  | long |
| netflow.reverse_pseudo_wire_type |  | integer |
| netflow.reverse_relative_error |  | double |
| netflow.reverse_responder_octets |  | long |
| netflow.reverse_responder_packets |  | long |
| netflow.reverse_rfc3550_jitter_microseconds |  | long |
| netflow.reverse_rfc3550_jitter_milliseconds |  | long |
| netflow.reverse_rfc3550_jitter_nanoseconds |  | long |
| netflow.reverse_rtp_payload_type |  | short |
| netflow.reverse_rtp_sequence_number |  | integer |
| netflow.reverse_sampler_id |  | short |
| netflow.reverse_sampler_mode |  | short |
| netflow.reverse_sampler_name |  | keyword |
| netflow.reverse_sampler_random_interval |  | long |
| netflow.reverse_sampling_algorithm |  | short |
| netflow.reverse_sampling_flow_interval |  | long |
| netflow.reverse_sampling_flow_spacing |  | long |
| netflow.reverse_sampling_interval |  | long |
| netflow.reverse_sampling_packet_interval |  | long |
| netflow.reverse_sampling_packet_space |  | long |
| netflow.reverse_sampling_population |  | long |
| netflow.reverse_sampling_probability |  | double |
| netflow.reverse_sampling_size |  | long |
| netflow.reverse_sampling_time_interval |  | long |
| netflow.reverse_sampling_time_space |  | long |
| netflow.reverse_second_packet_banner |  | keyword |
| netflow.reverse_section_exported_octets |  | integer |
| netflow.reverse_section_offset |  | integer |
| netflow.reverse_selection_sequence_id |  | long |
| netflow.reverse_selector_algorithm |  | integer |
| netflow.reverse_selector_id |  | long |
| netflow.reverse_selector_id_total_flows_observed |  | long |
| netflow.reverse_selector_id_total_flows_selected |  | long |
| netflow.reverse_selector_id_total_pkts_observed |  | long |
| netflow.reverse_selector_id_total_pkts_selected |  | long |
| netflow.reverse_selector_name |  | keyword |
| netflow.reverse_session_scope |  | short |
| netflow.reverse_small_packet_count |  | long |
| netflow.reverse_source_ipv4_address |  | ip |
| netflow.reverse_source_ipv4_prefix |  | ip |
| netflow.reverse_source_ipv4_prefix_length |  | short |
| netflow.reverse_source_ipv6_address |  | ip |
| netflow.reverse_source_ipv6_prefix |  | ip |
| netflow.reverse_source_ipv6_prefix_length |  | short |
| netflow.reverse_source_mac_address |  | keyword |
| netflow.reverse_source_transport_port |  | integer |
| netflow.reverse_src_traffic_index |  | long |
| netflow.reverse_sta_ipv4_address |  | ip |
| netflow.reverse_sta_mac_address |  | keyword |
| netflow.reverse_standard_deviation_interarrival_time |  | long |
| netflow.reverse_standard_deviation_payload_length |  | integer |
| netflow.reverse_system_init_time_milliseconds |  | long |
| netflow.reverse_tcp_ack_total_count |  | long |
| netflow.reverse_tcp_acknowledgement_number |  | long |
| netflow.reverse_tcp_control_bits |  | integer |
| netflow.reverse_tcp_destination_port |  | integer |
| netflow.reverse_tcp_fin_total_count |  | long |
| netflow.reverse_tcp_header_length |  | short |
| netflow.reverse_tcp_options |  | long |
| netflow.reverse_tcp_psh_total_count |  | long |
| netflow.reverse_tcp_rst_total_count |  | long |
| netflow.reverse_tcp_sequence_number |  | long |
| netflow.reverse_tcp_source_port |  | integer |
| netflow.reverse_tcp_syn_total_count |  | long |
| netflow.reverse_tcp_urg_total_count |  | long |
| netflow.reverse_tcp_urgent_pointer |  | integer |
| netflow.reverse_tcp_window_scale |  | integer |
| netflow.reverse_tcp_window_size |  | integer |
| netflow.reverse_total_length_ipv4 |  | integer |
| netflow.reverse_transport_octet_delta_count |  | long |
| netflow.reverse_transport_packet_delta_count |  | long |
| netflow.reverse_tunnel_technology |  | keyword |
| netflow.reverse_udp_destination_port |  | integer |
| netflow.reverse_udp_message_length |  | integer |
| netflow.reverse_udp_source_port |  | integer |
| netflow.reverse_union_tcp_flags |  | short |
| netflow.reverse_upper_ci_limit |  | double |
| netflow.reverse_user_name |  | keyword |
| netflow.reverse_value_distribution_method |  | short |
| netflow.reverse_virtual_station_interface_id |  | keyword |
| netflow.reverse_virtual_station_interface_name |  | keyword |
| netflow.reverse_virtual_station_name |  | keyword |
| netflow.reverse_virtual_station_uuid |  | keyword |
| netflow.reverse_vlan_id |  | integer |
| netflow.reverse_vr_fname |  | keyword |
| netflow.reverse_wlan_channel_id |  | short |
| netflow.reverse_wlan_ssid |  | keyword |
| netflow.reverse_wtp_mac_address |  | keyword |
| netflow.rfc3550_jitter_microseconds |  | long |
| netflow.rfc3550_jitter_milliseconds |  | long |
| netflow.rfc3550_jitter_nanoseconds |  | long |
| netflow.rtp_payload_type |  | short |
| netflow.rtp_sequence_number |  | integer |
| netflow.sampler_id |  | short |
| netflow.sampler_mode |  | short |
| netflow.sampler_name |  | keyword |
| netflow.sampler_random_interval |  | long |
| netflow.sampling_algorithm |  | short |
| netflow.sampling_flow_interval |  | long |
| netflow.sampling_flow_spacing |  | long |
| netflow.sampling_interval |  | long |
| netflow.sampling_packet_interval |  | long |
| netflow.sampling_packet_space |  | long |
| netflow.sampling_population |  | long |
| netflow.sampling_probability |  | double |
| netflow.sampling_size |  | long |
| netflow.sampling_time_interval |  | long |
| netflow.sampling_time_space |  | long |
| netflow.second_packet_banner |  | keyword |
| netflow.section_exported_octets |  | integer |
| netflow.section_offset |  | integer |
| netflow.selection_sequence_id |  | long |
| netflow.selector_algorithm |  | integer |
| netflow.selector_id |  | long |
| netflow.selector_id_total_flows_observed |  | long |
| netflow.selector_id_total_flows_selected |  | long |
| netflow.selector_id_total_pkts_observed |  | long |
| netflow.selector_id_total_pkts_selected |  | long |
| netflow.selector_name |  | keyword |
| netflow.service_name |  | keyword |
| netflow.session_scope |  | short |
| netflow.silk_app_label |  | integer |
| netflow.small_packet_count |  | long |
| netflow.source_ipv4_address |  | ip |
| netflow.source_ipv4_prefix |  | ip |
| netflow.source_ipv4_prefix_length |  | short |
| netflow.source_ipv6_address |  | ip |
| netflow.source_ipv6_prefix |  | ip |
| netflow.source_ipv6_prefix_length |  | short |
| netflow.source_mac_address |  | keyword |
| netflow.source_transport_port |  | integer |
| netflow.source_transport_ports_limit |  | integer |
| netflow.src_traffic_index |  | long |
| netflow.ssl_cert_serial_number |  | keyword |
| netflow.ssl_cert_signature |  | keyword |
| netflow.ssl_cert_validity_not_after |  | keyword |
| netflow.ssl_cert_validity_not_before |  | keyword |
| netflow.ssl_cert_version |  | short |
| netflow.ssl_certificate_hash |  | keyword |
| netflow.ssl_cipher |  | keyword |
| netflow.ssl_client_version |  | short |
| netflow.ssl_compression_method |  | short |
| netflow.ssl_object_type |  | keyword |
| netflow.ssl_object_value |  | keyword |
| netflow.ssl_public_key_algorithm |  | keyword |
| netflow.ssl_public_key_length |  | keyword |
| netflow.ssl_server_cipher |  | long |
| netflow.ssl_server_name |  | keyword |
| netflow.sta_ipv4_address |  | ip |
| netflow.sta_mac_address |  | keyword |
| netflow.standard_deviation_interarrival_time |  | long |
| netflow.standard_deviation_payload_length |  | short |
| netflow.system_init_time_milliseconds |  | date |
| netflow.tcp_ack_total_count |  | long |
| netflow.tcp_acknowledgement_number |  | long |
| netflow.tcp_control_bits |  | integer |
| netflow.tcp_destination_port |  | integer |
| netflow.tcp_fin_total_count |  | long |
| netflow.tcp_header_length |  | short |
| netflow.tcp_options |  | long |
| netflow.tcp_psh_total_count |  | long |
| netflow.tcp_rst_total_count |  | long |
| netflow.tcp_sequence_number |  | long |
| netflow.tcp_source_port |  | integer |
| netflow.tcp_syn_total_count |  | long |
| netflow.tcp_urg_total_count |  | long |
| netflow.tcp_urgent_pointer |  | integer |
| netflow.tcp_window_scale |  | integer |
| netflow.tcp_window_size |  | integer |
| netflow.template_id |  | integer |
| netflow.tftp_filename |  | keyword |
| netflow.tftp_mode |  | keyword |
| netflow.timestamp |  | long |
| netflow.timestamp_absolute_monitoring-interval |  | long |
| netflow.total_length_ipv4 |  | integer |
| netflow.traffic_type |  | short |
| netflow.transport_octet_delta_count |  | long |
| netflow.transport_packet_delta_count |  | long |
| netflow.tunnel_technology |  | keyword |
| netflow.type | The type of NetFlow record described by this event. | keyword |
| netflow.udp_destination_port |  | integer |
| netflow.udp_message_length |  | integer |
| netflow.udp_source_port |  | integer |
| netflow.union_tcp_flags |  | short |
| netflow.upper_ci_limit |  | double |
| netflow.user_name |  | keyword |
| netflow.username |  | keyword |
| netflow.value_distribution_method |  | short |
| netflow.viptela_vpn_id |  | long |
| netflow.virtual_station_interface_id |  | short |
| netflow.virtual_station_interface_name |  | keyword |
| netflow.virtual_station_name |  | keyword |
| netflow.virtual_station_uuid |  | short |
| netflow.vlan_id |  | integer |
| netflow.vmware_egress_interface_attr |  | integer |
| netflow.vmware_ingress_interface_attr |  | integer |
| netflow.vmware_tenant_dest_ipv4 |  | ip |
| netflow.vmware_tenant_dest_ipv6 |  | ip |
| netflow.vmware_tenant_dest_port |  | integer |
| netflow.vmware_tenant_protocol |  | short |
| netflow.vmware_tenant_source_ipv4 |  | ip |
| netflow.vmware_tenant_source_ipv6 |  | ip |
| netflow.vmware_tenant_source_port |  | integer |
| netflow.vmware_vxlan_export_role |  | short |
| netflow.vpn_identifier |  | short |
| netflow.vr_fname |  | keyword |
| netflow.waasoptimization_segment |  | short |
| netflow.wlan_channel_id |  | short |
| netflow.wlan_ssid |  | keyword |
| netflow.wtp_mac_address |  | keyword |
| netflow.xlate_destination_address_ip_v4 |  | ip |
| netflow.xlate_destination_port |  | integer |
| netflow.xlate_source_address_ip_v4 |  | ip |
| netflow.xlate_source_port |  | integer |
| network.application | When a specific application or service is identified from network connection details (source/dest IPs, ports, certificates, or wire format), this field captures the application's or service's name. For example, the original event identifies the network connection being from a specific web service in a `https` network connection, like `facebook` or `twitter`. The field value must be normalized to lowercase for querying. | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.forwarded_ip | Host IP address when the source IP address is the proxy. | ip |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.name | Name given by operators to sections of their network. | keyword |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. | keyword |
| observer.geo.city_name | City name. | keyword |
| observer.geo.continent_name | Name of the continent. | keyword |
| observer.geo.country_iso_code | Country ISO code. | keyword |
| observer.geo.country_name | Country name. | keyword |
| observer.geo.location | Longitude and latitude. | geo_point |
| observer.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| observer.geo.region_iso_code | Region ISO code. | keyword |
| observer.geo.region_name | Region name. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.mac | MAC addresses of the observer. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| observer.os.full | Operating system name, including the version or code name. | keyword |
| observer.os.full.text | Multi-field of `observer.os.full`. | match_only_text |
| observer.os.kernel | Operating system kernel version as a raw string. | keyword |
| observer.os.name | Operating system name, without the version. | keyword |
| observer.os.name.text | Multi-field of `observer.os.name`. | match_only_text |
| observer.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| observer.os.version | Operating system version as a raw string. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.serial_number | Observer serial number. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| organization.id | Unique identifier for the organization. | keyword |
| organization.name | Organization name. | keyword |
| organization.name.text | Multi-field of `organization.name`. | match_only_text |
| os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| os.full | Operating system name, including the version or code name. | keyword |
| os.full.text | Multi-field of `os.full`. | match_only_text |
| os.kernel | Operating system kernel version as a raw string. | keyword |
| os.name | Operating system name, without the version. | keyword |
| os.name.text | Multi-field of `os.name`. | match_only_text |
| os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| os.version | Operating system version as a raw string. | keyword |
| package.architecture | Package architecture. | keyword |
| package.checksum | Checksum of the installed package for verification. | keyword |
| package.description | Description of the package. | keyword |
| package.install_scope | Indicating how the package was installed, e.g. user-local, global. | keyword |
| package.installed | Time when package was installed. | date |
| package.license | License under which the package was released. Use a short name, e.g. the license identifier from SPDX License List where possible (https://spdx.org/licenses/). | keyword |
| package.name | Package name | keyword |
| package.path | Path where the package is installed. | keyword |
| package.size | Package size in bytes. | long |
| package.version | Package version | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.hash.sha512 | SHA512 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pgid | Identifier of the group of processes the process belongs to. | long |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| process.thread.id | Thread ID. | long |
| process.thread.name | Thread name. | keyword |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| process.uptime | Seconds the process has been up. | long |
| process.working_directory | The working directory of the process. | keyword |
| process.working_directory.text | Multi-field of `process.working_directory`. | match_only_text |
| related.ip | All of the IPs seen on your event. | ip |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| server.as.organization.name | Organization name. | keyword |
| server.as.organization.name.text | Multi-field of `server.as.organization.name`. | match_only_text |
| server.bytes | Bytes sent from the server to the client. | long |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.geo.city_name | City name. | keyword |
| server.geo.continent_name | Name of the continent. | keyword |
| server.geo.country_iso_code | Country ISO code. | keyword |
| server.geo.country_name | Country name. | keyword |
| server.geo.location | Longitude and latitude. | geo_point |
| server.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| server.geo.region_iso_code | Region ISO code. | keyword |
| server.geo.region_name | Region name. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.mac | MAC address of the server. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| server.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| server.nat.port | Translated port of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | long |
| server.packets | Packets sent from the server to the client. | long |
| server.port | Port of the server. | long |
| server.registered_domain | The highest registered server domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| server.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| server.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| server.user.email | User email address. | keyword |
| server.user.full_name | User's full name, if available. | keyword |
| server.user.full_name.text | Multi-field of `server.user.full_name`. | match_only_text |
| server.user.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| server.user.group.id | Unique identifier for the group on the system/platform. | keyword |
| server.user.group.name | Name of the group. | keyword |
| server.user.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| server.user.id | Unique identifier of the user. | keyword |
| server.user.name | Short name or login of the user. | keyword |
| server.user.name.text | Multi-field of `server.user.name`. | match_only_text |
| service.ephemeral_id | Ephemeral identifier of this service (if one exists). This id normally changes across restarts, but `service.id` does not. | keyword |
| service.id | Unique identifier of the running service. If the service is comprised of many nodes, the `service.id` should be the same for all nodes. This id should uniquely identify the service. This makes it possible to correlate logs and metrics for one specific service, no matter which particular node emitted the event. Note that if you need to see the events from one specific host of the service, you should filter on that `host.name` or `host.id` instead. | keyword |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| service.node.name | Name of a service node. This allows for two nodes of the same service running on the same host to be differentiated. Therefore, `service.node.name` should typically be unique across nodes of a given service. In the case of Elasticsearch, the `service.node.name` could contain the unique node name within the Elasticsearch cluster. In cases where the service doesn't have the concept of a node name, the host name or container name can be used to distinguish running instances that make up this service. If those do not provide uniqueness (e.g. multiple instances of the service running on the same host) - the node name can be manually set. | keyword |
| service.state | Current state of the service. | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.locality | Whether the source IP is private or public. | keyword |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| source.registered_domain | The highest registered source domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| source.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.email | User email address. | keyword |
| source.user.full_name | User's full name, if available. | keyword |
| source.user.full_name.text | Multi-field of `source.user.full_name`. | match_only_text |
| source.user.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.group.id | Unique identifier for the group on the system/platform. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.framework | Name of the threat framework used to further categorize and classify the tactic and technique of the reported threat. Framework classification can be provided by detecting systems, evaluated at ingest time, or retrospectively tagged to events. | keyword |
| threat.tactic.id | The id of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.tactic.reference | The reference url of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.technique.id | The id of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name | The name of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| threat.technique.name.text | Multi-field of `threat.technique.name`. | match_only_text |
| threat.technique.reference | The reference url of technique used by this threat. You can use a MITRE ATT&CK® technique, for example. (ex. https://attack.mitre.org/techniques/T1059/) | keyword |
| trace.id | Unique identifier of the trace. A trace groups multiple events like transactions that belong together. For example, a user request handled by multiple inter-connected services. | keyword |
| transaction.id | Unique identifier of the transaction within the scope of its trace. A transaction is the highest level of work measured within a service, such as a request to a server. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| url.username | Username of the request. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.group.domain | Name of the directory the group is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.group.name | Name of the group. | keyword |
| user.hash | Unique user hash to correlate information for a user in anonymized form. Useful if `user.id` or `user.name` contain confidential information and cannot be used. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.kernel | Operating system kernel version as a raw string. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

